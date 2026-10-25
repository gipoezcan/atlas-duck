#!/bin/bash
# ci/install-test-macos.sh --release <dmg-dir> <arm64|x86_64>
# ci/install-test-macos.sh --self-test
#
# M10 Task 27 (spec §12.2, §12.5, §13 I-45 macOS release half, §15 V32; PD-179): removing and
# reinstalling the release .app keeps the user's data and keychain. Written for the /bin/bash 3.2
# of macOS. CI only: it copies the app into /Applications, replaces this user's pinned paths file
# (ci/pinned-fixture.sh) and adds a keychain item.
#
# --release: no store and no fixture binary (PD-179: the release app's keychain items are bound to
# its Developer ID / ad-hoc signature, a test binary could not share them; the I-45 store half on
# macOS is T27a's `--debug-app`). A dummy generic password, created by this job with `security
# add-generic-password` and never read by the app, stands for "the keychain is left alone".
#
# Flow (each wait is bounded): pinned fixture + dummy item -> install from the dmg (ditto into
# /Applications) -> start --background -> a new `event=sandbox_probe` floor line in the diag log ->
# SIGTERM -> `rm -rf "/Applications/Atlas Duck.app"` -> data dir, config dir, pinned file and
# anchor dir hashes and the dummy item's presence (`security find-generic-password`, no -w)
# unchanged -> reinstall -> same check -> start -> floor line -> SIGTERM.
# V32: RUNTIME_VERSIONS (macOS, WebKit framework version, the arch the app runs as).
set -euo pipefail
export LC_ALL=C

WAIT_SECONDS="${WAIT_SECONDS:-90}"
DUMMY_SERVICE="atlas-duck-ci-install-test"

info() { printf 'install-test-macos: %s\n' "$*" >&2; }
die() { printf 'install-test-macos: FAIL: %s\n' "$*" >&2; exit 1; }

PAT_PROBE='(^| )event=sandbox_probe( .*)? floor='
PAT_STOP='(^| )event=app_stop( |$)'

log_count() {
  if [ -f "$1" ]; then grep -cE "$2" "$1" || true; else echo 0; fi
}

dump_log() {
  if [ -f "$1" ]; then
    echo "---- $1 (last 60 lines) ----" >&2
    tail -n 60 "$1" >&2
    echo "----" >&2
  fi
}

# wait_log <log> <ERE> <known> <seconds> <what> [<pid>]
wait_log() {
  local log="$1" pat="$2" known="$3" seconds="$4" what="$5" pid="${6:-}" i=0
  while [ "$i" -lt $((seconds * 4)) ]; do
    if [ "$(log_count "$log" "$pat")" -gt "$known" ]; then return 0; fi
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
      dump_log "$log"
      die "the app (pid $pid) exited before it logged $what"
    fi
    sleep 0.25
    i=$((i + 1))
  done
  dump_log "$log"
  die "no new $what line within $seconds s in $log"
}

# snapshot <out> <root>...: "<sha256>  <path>" of every regular file below each root, sorted.
snapshot() {
  local out="$1" r
  shift
  : >"$out.tmp"
  for r in "$@"; do
    if [ -f "$r" ]; then
      shasum -a 256 "$r" >>"$out.tmp"
    elif [ -d "$r" ]; then
      find "$r" -type f -print0 | xargs -0 shasum -a 256 >>"$out.tmp"
    else
      echo "MISSING $r" >>"$out.tmp"
    fi
  done
  sort "$out.tmp" >"$out"
  rm -f "$out.tmp"
}

same_snapshot() {
  if ! diff -u "$1" "$2" >&2; then
    die "$3 changed the user's data (diff above)"
  fi
  info "ok: $3 left $(wc -l <"$1" | tr -d ' ') files unchanged"
}

self_test() {
  local dir log
  dir="$(mktemp -d /tmp/atlas-duck-t27-selftest.XXXXXX)"
  log="$dir/diag.log"
  printf '%s\n' \
    '2026-10-25T10:00:00.000Z INFO atlas_duck_app_lib::sandbox_probe src/sandbox_probe.rs:1 event=sandbox_probe floor=met failed=none ace=n/a dropped_fields=0' \
    '2026-10-25T10:00:00.000Z WARN atlas_duck_app_lib::sandbox_probe src/sandbox_probe.rs:1 event=sandbox_probe reason=install_dir_unknown dropped_fields=0' \
    '2026-10-25T10:00:01.000Z INFO atlas_duck_app_lib::serve src/serve.rs:1 event=app_stop reason=os_shutdown dropped_fields=0' >"$log"
  [ "$(log_count "$log" "$PAT_PROBE")" = 1 ] || die "self-test: probe count"
  [ "$(log_count "$log" "$PAT_STOP")" = 1 ] || die "self-test: app_stop count"
  wait_log "$log" "$PAT_PROBE" 0 2 probe
  if (wait_log "$log" "$PAT_PROBE" 1 1 probe) 2>/dev/null; then die "self-test: wait_log passed without a new line"; fi
  if (wait_log "$log" "$PAT_PROBE" 1 5 probe 999999) 2>/dev/null; then die "self-test: wait_log passed for a dead pid"; fi
  mkdir -p "$dir/a"
  echo one >"$dir/a/f"
  snapshot "$dir/s1" "$dir/a" "$dir/none"
  snapshot "$dir/s2" "$dir/a" "$dir/none"
  same_snapshot "$dir/s1" "$dir/s2" self-test 2>/dev/null
  echo two >>"$dir/a/f"
  snapshot "$dir/s3" "$dir/a" "$dir/none"
  if (same_snapshot "$dir/s1" "$dir/s3" self-test) 2>/dev/null; then die "self-test: a changed file passed"; fi
  rm -rf "$dir"
  echo "install-test-macos self-test ok"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

[ "${1:-}" = "--release" ] || die "usage: ci/install-test-macos.sh --release <dmg-dir> <arm64|x86_64> (--debug-app is T27a)"
dmg_dir="${2:?usage: ci/install-test-macos.sh --release <dmg-dir> <arm64|x86_64>}"
arch="${3:?usage: ci/install-test-macos.sh --release <dmg-dir> <arm64|x86_64>}"
case "$arch" in
  arm64 | x86_64) ;;
  *) die "the arch must be arm64 or x86_64, got '$arch'" ;;
esac
[ "${CI:-}" = true ] || die "CI only (CI=true): it replaces the pinned paths file and adds a keychain item"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
evidence="${INSTALL_PROBE_EVIDENCE:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/install-test-evidence}"
mkdir -p "$evidence"
[ "$(uname -m)" = arm64 ] || die "this job expects an arm64 runner, uname -m is $(uname -m)"

shopt -s nullglob
dmgs=("$dmg_dir"/*.dmg)
shopt -u nullglob
[ "${#dmgs[@]}" -eq 1 ] || die "expected one .dmg in $dmg_dir, found ${#dmgs[@]}"
dmg="${dmgs[0]}"
mnt="$(mktemp -d /tmp/atlas-duck-dmg.XXXXXX)"
work="$(mktemp -d /tmp/atlas-duck-install-test.XXXXXX)"
APP_PID=""
LOG=""
account="install-test-$$"

stop_apps() {
  pkill -TERM -x atlas-duck-app 2>/dev/null || true
  local i
  for i in $(seq 1 40); do
    pgrep -x atlas-duck-app >/dev/null 2>&1 || break
    sleep 0.5
  done
  pkill -KILL -x atlas-duck-app 2>/dev/null || true
  pkill -KILL -f '/atlas-duck-sandbox( |$)' 2>/dev/null || true
}

cleanup() {
  local status=$?
  set +e
  stop_apps
  [ -n "$LOG" ] && [ -f "$LOG" ] && cp "$LOG" "$evidence/diag.log"
  security delete-generic-password -s "$DUMMY_SERVICE" -a "$account" >/dev/null 2>&1
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
src_app="$work/$(basename "${apps[0]}")"
ditto "${apps[0]}" "$src_app"
hdiutil detach "$mnt" >/dev/null
dest="/Applications/$(basename "$src_app")"
[ "$dest" = "/Applications/Atlas Duck.app" ] || info "note: the bundle is $dest"
[ ! -e "$dest" ] || die "$dest already exists; this job needs a fresh machine"
app_exe="$dest/Contents/MacOS/atlas-duck-app"

install_app() {
  if [ -w /Applications ]; then ditto "$src_app" "$dest"; else sudo ditto "$src_app" "$dest"; fi
  [ -x "$app_exe" ] || die "no $app_exe after the install"
}

remove_app() {
  if [ -w /Applications ]; then rm -rf "$dest"; else sudo rm -rf "$dest"; fi
  [ ! -e "$dest" ] || die "$dest is still there after rm -rf"
}

webkit_version="$(defaults read /System/Library/Frameworks/WebKit.framework/Resources/Info.plist CFBundleVersion 2>/dev/null || echo unknown)"
echo "RUNTIME_VERSIONS macos=$(sw_vers -productVersion) build=$(sw_vers -buildVersion) webkit=$webkit_version app_arch=$arch runner=$(uname -m)"

info "pinned fixture and the dummy keychain item"
DATA_DIR="$("$here/pinned-fixture.sh")"
root="$(dirname "$DATA_DIR")"
CONFIG_DIR="$root/config"
ANCHOR_DIR="$root/anchors"
mkdir -p "$ANCHOR_DIR"
echo "anchor dir of the fixture (no store on macOS --release, so the app writes none)" >"$ANCHOR_DIR/README"
home="$(dscl . -read "/Users/$(id -un)" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //')"
shopt -s nullglob
pins=("$home/Library/Application Support/atlas-duck"/paths-*.toml)
shopt -u nullglob
[ "${#pins[@]}" -eq 1 ] || die "expected one pinned paths file, found ${#pins[@]}"
PINNED="${pins[0]}"
LOG="$DATA_DIR/logs/diag.log"
security add-generic-password -s "$DUMMY_SERVICE" -a "$account" -w "dummy-$$" -U
security find-generic-password -s "$DUMMY_SERVICE" -a "$account" >/dev/null || die "the dummy keychain item was not created"

# run_app <what>: start, a new floor probe line, SIGTERM, the app gone.
run_app() {
  local what="$1" known stops i line
  known="$(log_count "$LOG" "$PAT_PROBE")"
  stops="$(log_count "$LOG" "$PAT_STOP")"
  "$app_exe" --background >>"$evidence/app-output.txt" 2>&1 &
  APP_PID=$!
  wait_log "$LOG" "$PAT_PROBE" "$known" "$WAIT_SECONDS" "event=sandbox_probe floor= ($what)" "$APP_PID"
  line="$(grep -E "$PAT_PROBE" "$LOG" | tail -n 1)"
  echo "FLOOR_LINE $what: $line"
  kill -0 "$APP_PID" 2>/dev/null || die "the app exited right after its probe line ($what)"
  kill -TERM "$APP_PID"
  for i in $(seq 1 $((WAIT_SECONDS * 4))); do
    kill -0 "$APP_PID" 2>/dev/null || break
    sleep 0.25
  done
  kill -0 "$APP_PID" 2>/dev/null && die "the app did not exit within $WAIT_SECONDS s of SIGTERM ($what)"
  wait "$APP_PID" 2>/dev/null || true
  APP_PID=""
  stop_apps
  if [ "$(log_count "$LOG" "$PAT_STOP")" -gt "$stops" ]; then
    info "app_stop logged ($what)"
  else
    info "no app_stop line ($what): a first-run app has no core, so none is expected"
  fi
}

info "install, start, quit"
install_app
run_app "first install"

info "remove the .app: data, config, pinned file, anchor dir and the keychain item unchanged"
snapshot "$work/s0" "$DATA_DIR" "$CONFIG_DIR" "$ANCHOR_DIR" "$PINNED"
remove_app
snapshot "$work/s" "$DATA_DIR" "$CONFIG_DIR" "$ANCHOR_DIR" "$PINNED"
same_snapshot "$work/s0" "$work/s" "rm -rf $dest"
security find-generic-password -s "$DUMMY_SERVICE" -a "$account" >/dev/null || die "the dummy keychain item is gone after the removal"
info "ok: the dummy keychain item is still there"

info "reinstall, start, quit"
install_app
snapshot "$work/s" "$DATA_DIR" "$CONFIG_DIR" "$ANCHOR_DIR" "$PINNED"
same_snapshot "$work/s0" "$work/s" "the reinstall"
run_app "reinstall"
security find-generic-password -s "$DUMMY_SERVICE" -a "$account" >/dev/null || die "the dummy keychain item is gone after the reinstall run"
echo "I45 RELEASE OK arch=$arch: removal and reinstall kept data dir, config dir, pinned file, anchor dir and the keychain item"
