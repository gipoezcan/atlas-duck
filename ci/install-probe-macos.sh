#!/usr/bin/env bash
# ci/install-probe-macos.sh <dmg-dir> <arm64|x86_64>
# ci/install-probe-macos.sh --self-test
#
# Installed-package floor probe for the macOS dmg (spec §9.4 macOS, §2.5 hardened runtime, §12.2,
# §13 scripts-enabled matrix, §15 V32). <dmg-dir> is the downloaded bundle-aarch64-apple-darwin or
# bundle-x86_64-apple-darwin artifact. CI-only: it copies the .app to /Applications, replaces this
# user's pinned paths file (ci/pinned-fixture.sh) and kills the app it started.
#
# Flow: mount the dmg -> ditto the .app to /Applications (keeps the ad-hoc signature) -> check the
# installed bundle (arch, hardened runtime, no get-task-allow) -> unconfined task_for_pid control
# -> pinned fixture (local temp data dir) -> run Contents/MacOS/atlas-duck-app --background
# directly, so the script holds its pid and that pid is the memory-read target -> poll
# <data>/logs/diag.log up to 60 s for `event=sandbox_probe` -> classify -> kill the app.
#
# TaskForPid is one of the six macOS floor probes (T13). The log line lists only the probes that
# failed (`failed=`), so floor=met with failed=none means the worker's task_for_pid on this very
# hardened app was Blocked, and so were the file, network, process-spawn and securityd probes.
# But a refusal proves something only if this runner can grant a task port at all (T18 ruling:
# a bare `FLOOR Met` is not proof). The script therefore runs an unconfined control first: as
# root it calls task_for_pid on a non-hardened child it forked itself. kr=0 means the runner can
# tell allowed from refused (task_for_pid_informative=true). The leg result is
#   proven        floor=met, failed=none, task_for_pid_informative=true
#   inconclusive  floor=met with an uninformative control, or only task_for_pid failed with an
#                 uninformative control (prints FLOOR_INCONCLUSIVE, exit 0, NOT a proof)
#   fail          anything else (exit 1)
# For x86_64 the runner is arm64: the x86_64-only binary runs translated by Rosetta, which the
# job installs and `arch -x86_64` checks first.
#
# The job log is the record T22 reads: the probe line, FLOOR and FLOOR_INCONCLUSIVE lines and a
# final PROBE_RECORD line are printed there; the evidence directory is uploaded as a copy.
#
# Written for the bash 3.2 that ships with macOS.
set -euo pipefail
export LC_ALL=C

PROBE_SECONDS="${PROBE_SECONDS:-60}"

info() { printf 'install-probe-macos: %s\n' "$*" >&2; }
die() { printf 'install-probe-macos: FAIL: %s\n' "$*" >&2; exit 1; }

# --- sandbox_probe log line (T20) -------------------------------------------------------------

# probe_field <line> <key>: the value of key=value, empty when absent.
probe_field() {
  printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n 1
}

# probe_lines <log>: every `event=sandbox_probe` summary line (those with floor=), oldest first.
probe_lines() {
  if [ -f "$1" ]; then
    grep -E '(^| )event=sandbox_probe( |$)' "$1" | grep -E ' floor=' || true
  fi
}

probe_count() {
  probe_lines "$1" | wc -l | tr -d ' '
}

# classify_verdict <line> <informative: true|false>: prints proven, inconclusive or fail.
classify_verdict() {
  local line="$1" informative="$2" floor failed ace
  floor="$(probe_field "$line" floor)"
  failed="$(probe_field "$line" failed)"
  ace="$(probe_field "$line" ace)"
  if [ "$ace" != "n/a" ]; then echo fail; return 0; fi
  if [ "$floor" = "met" ] && [ "$failed" = "none" ]; then
    if [ "$informative" = "true" ]; then echo proven; else echo inconclusive; fi
    return 0
  fi
  if [ "$floor" = "not_met" ] && [ "$failed" = "task_for_pid" ] && [ "$informative" != "true" ]; then
    echo inconclusive
    return 0
  fi
  echo fail
}

dump_log() {
  if [ -f "$1" ]; then
    echo "---- $1 (last 60 lines) ----" >&2
    tail -n 60 "$1" >&2
    echo "----" >&2
  else
    echo "(no log file at $1)" >&2
  fi
}

# wait_probe_line <log> <pid> <known count> <seconds>: sets PROBE_LINE to the newest summary line
# once the log holds more than <known count> of them. Fails when <pid> exits first or on timeout.
wait_probe_line() {
  local log="$1" pid="$2" known="$3" seconds="$4" waited=0 count
  while [ "$waited" -lt $((seconds * 4)) ]; do
    count="$(probe_count "$log")"
    if [ "$count" -gt "$known" ]; then
      PROBE_LINE="$(probe_lines "$log" | tail -n 1)"
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      dump_log "$log"
      ls -1 "$HOME/Library/Logs/DiagnosticReports" 2>/dev/null | grep -i atlas >&2 || true
      die "the app (pid $pid) exited before it logged event=sandbox_probe"
    fi
    sleep 0.25
    waited=$((waited + 1))
  done
  dump_log "$log"
  die "no event=sandbox_probe line within $seconds s in $log"
}

# --- unconfined task_for_pid control (T18 ruling) -----------------------------------------------

# Compiles a tiny helper that forks a non-hardened child and, as the caller (root under sudo),
# calls task_for_pid on it. Prints `unconfined_kr=<n>`. Sets CONTROL_KR (empty when the control
# could not run) and CONTROL_INFORMATIVE (true only when kr=0).
run_task_for_pid_control() {
  local work="$1" src bin out
  CONTROL_KR=""
  CONTROL_INFORMATIVE=false
  src="$work/tfp_control.c"
  bin="$work/tfp_control"
  cat >"$src" <<'CSRC'
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
  pid_t child = fork();
  if (child == 0) {
    for (;;) pause();
  }
  usleep(200000);
  mach_port_t port = MACH_PORT_NULL;
  kern_return_t kr = task_for_pid(mach_task_self(), child, &port);
  printf("unconfined_kr=%d\n", (int)kr);
  kill(child, SIGKILL);
  waitpid(child, NULL, 0);
  return 0;
}
CSRC
  if ! cc -o "$bin" "$src" 2>"$work/tfp_control.cc.txt"; then
    info "the control helper did not compile: $(tr '\n' ' ' <"$work/tfp_control.cc.txt")"
    return 0
  fi
  out="$(sudo -n "$bin" 2>&1 || true)"
  info "control: $out"
  CONTROL_KR="$(printf '%s\n' "$out" | sed -n 's/^unconfined_kr=//p' | head -n 1)"
  if [ "$CONTROL_KR" = "0" ]; then CONTROL_INFORMATIVE=true; fi
}

# --- self test ---------------------------------------------------------------------------------

self_test() {
  local met notmet notmet_other warn dir
  met='2026-10-07T10:00:00.123Z INFO atlas_duck_app_lib::sandbox_probe src/sandbox_probe.rs:301 event=sandbox_probe floor=met failed=none extra_layers=none engine_version=0.16.2 worker_version=0.1.0+0123456789ab ace=n/a dropped_fields=0'
  notmet='2026-10-07T10:00:01.123Z INFO atlas_duck_app_lib::sandbox_probe src/sandbox_probe.rs:301 event=sandbox_probe floor=not_met failed=task_for_pid extra_layers=none engine_version=unknown worker_version=unknown ace=n/a dropped_fields=0'
  notmet_other='2026-10-07T10:00:01.123Z INFO atlas_duck_app_lib::sandbox_probe src/sandbox_probe.rs:301 event=sandbox_probe floor=not_met failed=file_in_profile+task_for_pid extra_layers=none engine_version=unknown worker_version=unknown ace=n/a dropped_fields=0'
  warn='2026-10-07T10:00:02.123Z WARN atlas_duck_app_lib::sandbox_probe src/sandbox_probe.rs:99 event=sandbox_probe reason=install_dir_unknown dropped_fields=0'

  [ "$(probe_field "$met" floor)" = "met" ] || die "self-test: floor of the met line"
  [ "$(probe_field "$met" ace)" = "n/a" ] || die "self-test: ace of the met line"
  [ "$(probe_field "$notmet" failed)" = "task_for_pid" ] || die "self-test: failed of the not_met line"

  dir="$(mktemp -d /tmp/atlas-duck-t21-selftest.XXXXXX)"
  printf '%s\n%s\n%s\n' "$met" "$warn" "$notmet" >"$dir/diag.log"
  [ "$(probe_count "$dir/diag.log")" = "2" ] || die "self-test: expected 2 summary lines, got $(probe_count "$dir/diag.log")"
  [ "$(probe_lines "$dir/diag.log" | tail -n 1)" = "$notmet" ] || die "self-test: the newest summary line is not the not_met line"
  [ "$(probe_count "$dir/missing.log")" = "0" ] || die "self-test: a missing log has summary lines"

  # a bare floor=met is only a proof with an informative control (T18 ruling)
  [ "$(classify_verdict "$met" true)" = "proven" ] || die "self-test: met + informative is not proven"
  [ "$(classify_verdict "$met" false)" = "inconclusive" ] || die "self-test: met + uninformative control is not inconclusive"
  [ "$(classify_verdict "$notmet" false)" = "inconclusive" ] || die "self-test: only task_for_pid failed + uninformative is not inconclusive"
  [ "$(classify_verdict "$notmet" true)" = "fail" ] || die "self-test: task_for_pid failed with an informative control did not fail"
  [ "$(classify_verdict "$notmet_other" false)" = "fail" ] || die "self-test: another failed probe did not fail"
  [ "$(classify_verdict "${met/ace=n\/a/ace=present}" true)" = "fail" ] || die "self-test: an unexpected ace did not fail"
  if (wait_probe_line "$dir/diag.log" 999999 2 2) 2>/dev/null; then die "self-test: wait_probe_line passed for a dead pid"; fi
  rm -rf "$dir"
  echo "install-probe-macos self-test ok"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

# --- arguments ---------------------------------------------------------------------------------

dmg_dir="${1:?usage: ci/install-probe-macos.sh <dmg-dir> <arm64|x86_64>}"
arch="${2:?usage: ci/install-probe-macos.sh <dmg-dir> <arm64|x86_64>}"
case "$arch" in
  arm64 | x86_64) ;;
  *) die "the arch must be arm64 or x86_64, got '$arch'" ;;
esac
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
evidence="${INSTALL_PROBE_EVIDENCE:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/install-probe-evidence}"
mkdir -p "$evidence"

[ "$(uname -m)" = "arm64" ] || die "this job expects an arm64 runner, uname -m is $(uname -m)"
if [ "$arch" = "x86_64" ]; then
  arch -x86_64 /usr/bin/true || die "Rosetta 2 cannot run x86_64 code on this runner"
fi

shopt -s nullglob
dmgs=("$dmg_dir"/*.dmg)
shopt -u nullglob
[ "${#dmgs[@]}" -eq 1 ] || die "expected one .dmg in $dmg_dir, found ${#dmgs[@]}"
dmg="${dmgs[0]}"
info "dmg: $dmg"

mnt="$(mktemp -d /tmp/atlas-duck-dmg.XXXXXX)"
work="$(mktemp -d /tmp/atlas-duck-probe-work.XXXXXX)"
APP_PID=""
DATA_DIR=""
dest=""

cleanup() {
  local status=$?
  set +e
  if [ -n "$APP_PID" ]; then kill -TERM "$APP_PID" 2>/dev/null; fi
  pkill -TERM -x atlas-duck-app 2>/dev/null
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pgrep -x atlas-duck-app >/dev/null 2>&1 || break
    sleep 0.5
  done
  pkill -KILL -x atlas-duck-app 2>/dev/null
  pkill -KILL -f '/atlas-duck-sandbox( |$)' 2>/dev/null
  if [ -n "$DATA_DIR" ] && [ -f "$DATA_DIR/logs/diag.log" ]; then
    cp "$DATA_DIR/logs/diag.log" "$evidence/diag.log"
  fi
  hdiutil detach "$mnt" -force >/dev/null 2>&1
  rmdir "$mnt" 2>/dev/null
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

hdiutil attach -nobrowse -readonly -noautoopen -mountpoint "$mnt" "$dmg" >/dev/null
shopt -s nullglob
apps=("$mnt"/*.app)
shopt -u nullglob
[ "${#apps[@]}" -eq 1 ] || die "expected one .app in the dmg, found ${#apps[@]}"
src_app="${apps[0]}"
dest="/Applications/$(basename "$src_app")"
[ ! -e "$dest" ] || die "$dest already exists; this job needs a fresh machine"

info "install: ditto '$src_app' '$dest'"
if [ -w /Applications ]; then
  ditto "$src_app" "$dest"
else
  sudo ditto "$src_app" "$dest"
fi
hdiutil detach "$mnt" >/dev/null

macos_dir="$dest/Contents/MacOS"
app_exe="$macos_dir/atlas-duck-app"

# --- the installed bundle: the preconditions of the TaskForPid probe (§2.5) ------------------------

bins="$(ls -1A "$macos_dir" | sort | tr '\n' ' ')"
info "Contents/MacOS: $bins"
for b in atlas-duck-app atlas-duck atlas-duck-sandbox; do
  [ -x "$macos_dir/$b" ] || die "$b is missing from $macos_dir"
  archs="$(lipo -archs "$macos_dir/$b")"
  [ "$archs" = "$arch" ] || die "$b: lipo -archs is '$archs', expected '$arch'"
done
codesign --verify --deep --strict --verbose=2 "$dest" || die "codesign --verify failed for the installed bundle"
cs_info="$(codesign -dv --verbose=4 "$app_exe" 2>&1 || true)"
printf '%s\n' "$cs_info" | grep -E '^(Identifier|CodeDirectory|Signature)' >&2 || true
printf '%s\n' "$cs_info" | grep -Eq '^CodeDirectory .*flags=0x[0-9a-f]+\([^)]*runtime' ||
  die "atlas-duck-app has no hardened runtime flag, so task_for_pid could not be blocked"
ents="$(codesign -d --entitlements - --xml "$app_exe" 2>/dev/null || true)"
if printf '%s' "$ents" | grep -q 'get-task-allow'; then
  die "atlas-duck-app carries com.apple.security.get-task-allow"
fi
codesign -dv --verbose=4 "$app_exe" >"$evidence/codesign-app.txt" 2>&1 || true

# --- the unconfined control: can this runner grant a task port at all? -----------------------------

run_task_for_pid_control "$work"
informative="$CONTROL_INFORMATIVE"
printf 'unconfined_kr=%s task_for_pid_informative=%s\n' "${CONTROL_KR:-none}" "$informative" >"$evidence/taskforpid-control.txt"

# --- start, poll, classify ---------------------------------------------------------------------------

info "pinned fixture (a local temp data dir)"
DATA_DIR="$("$here/pinned-fixture.sh")"
[ -d "$DATA_DIR" ] || die "the fixture's data dir $DATA_DIR does not exist"
LOG="$DATA_DIR/logs/diag.log"
info "data dir: $DATA_DIR"

info "start: $app_exe --background ($arch), poll $LOG up to ${PROBE_SECONDS} s"
"$app_exe" --background >"$evidence/app-output.txt" 2>&1 &
APP_PID=$!
wait_probe_line "$LOG" "$APP_PID" 0 "$PROBE_SECONDS"
line="$PROBE_LINE"
printf '%s\n' "$line" >"$evidence/probe-line.txt"
info "$line"

verdict="$(classify_verdict "$line" "$informative")"
printf '%s\n' "$verdict" >"$evidence/verdict.txt"
floor="$(probe_field "$line" floor)"
failed="$(probe_field "$line" failed)"
echo "FLOOR $floor failed=$failed task_for_pid_informative=$informative"
echo "PROBE_RECORD arch=$arch floor=$floor failed=$failed extra_layers=$(probe_field "$line" extra_layers) engine_version=$(probe_field "$line" engine_version) worker_version=$(probe_field "$line" worker_version) task_for_pid_informative=$informative unconfined_kr=${CONTROL_KR:-none} verdict=$verdict"
case "$verdict" in
  fail) die "floor=$floor failed=$failed task_for_pid_informative=$informative: $line" ;;
  inconclusive)
    echo "FLOOR_INCONCLUSIVE TaskForPid unconfined_kr=${CONTROL_KR:-none}: the unconfined control could not get a task port here, so a refusal of the hardened app is no evidence for the task-port probe"
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
      echo "::warning::macos $arch: the floor probe is INCONCLUSIVE (task_for_pid control uninformative); not a proof"
    fi
    ;;
esac

sleep 3
kill -0 "$APP_PID" 2>/dev/null || die "the app exited within 3 s of its sandbox_probe line"
if [ "$verdict" = "proven" ]; then
  echo "OK: $arch app installed from the dmg: hardened runtime, floor=met (task_for_pid on the app blocked, control informative), the app is still alive"
else
  echo "INCONCLUSIVE: $arch app installed from the dmg: hardened runtime, floor=$floor failed=$failed, task_for_pid control uninformative, the app is still alive (not a proof)"
fi
