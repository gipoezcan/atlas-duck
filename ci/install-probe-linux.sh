#!/usr/bin/env bash
# ci/install-probe-linux.sh <deb|rpm|appimage> <artifact-dir>
# ci/install-probe-linux.sh --self-test
#
# Installed-package floor probe for the Linux packages (spec §9.4, §12.2, §13 scripts-enabled
# matrix, §15 V32/V33). <artifact-dir> is the downloaded bundle-x86_64-unknown-linux-gnu artifact
# (deb/*.deb, rpm/*.rpm, appimage/*.AppImage). CI-only: it installs the package, replaces this
# user's pinned paths file (ci/pinned-fixture.sh) and kills the app it started.
#
# Flow: install the test tools (xvfb, a session bus) -> install the package -> re-exec under
# `dbus-run-session -- xvfb-run -a` so the app, its tray-host check and the single-instance
# plugin share one session bus and one display -> pinned fixture (local temp data dir) ->
# start `atlas-duck-app --background` -> poll <data>/logs/diag.log up to 60 s for
# `event=sandbox_probe` -> assert floor=met and failed=none -> assert where the app and the
# worker live -> kill the app.
#
# The log line carries no path (spec §7.7 metadata only), so "the worker is spawned from the
# app's own install dir" is shown by three facts: floor=met (the worker was spawned), the app's
# own /proc/<pid>/exe, and the worker binary next to it (T20 derives the worker path from
# current_exe().parent()). Under an AppImage the app exe must lie in its own /tmp/.mount_* mount.
#
# Fedora (rpm) additionally asserts `event=tray_host_checked tray_host=missing` (the session bus
# has no org.kde.StatusNotifierWatcher owner) and that the app is still alive afterwards.
#
# The job log is the record T22 reads: the probe line and a final PROBE_RECORD line are printed
# there; the evidence directory is uploaded as a copy.
set -euo pipefail
export LC_ALL=C

PROBE_SECONDS="${PROBE_SECONDS:-60}"

info() { printf 'install-probe-linux: %s\n' "$*" >&2; }
die() { printf 'install-probe-linux: FAIL: %s\n' "$*" >&2; exit 1; }

# --- sandbox_probe log line (T20) -------------------------------------------------------------

# probe_field <line> <key>: the value of key=value, empty when absent.
probe_field() {
  printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n 1
}

# probe_lines <log>: every `event=sandbox_probe` summary line (those with floor=), oldest first.
# The sandbox_probe warnings carry reason= and no floor=, so they are not summary lines.
probe_lines() {
  if [ -f "$1" ]; then
    grep -E '(^| )event=sandbox_probe( |$)' "$1" | grep -E ' floor=' || true
  fi
}

probe_count() {
  probe_lines "$1" | wc -l | tr -d ' '
}

# assert_probe_line <line> <expected ace>
assert_probe_line() {
  local line="$1" want_ace="$2" floor failed ace
  floor="$(probe_field "$line" floor)"
  failed="$(probe_field "$line" failed)"
  ace="$(probe_field "$line" ace)"
  [ "$floor" = "met" ] || die "floor=$floor (failed=$failed), expected met: $line"
  [ "$failed" = "none" ] || die "failed=$failed although floor=met: $line"
  [ "$ace" = "$want_ace" ] || die "ace=$ace, expected $want_ace: $line"
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
      [ -f "${APP_OUT:-/nonexistent}" ] && sed 's/^/app: /' "$APP_OUT" >&2
      die "the app (pid $pid) exited before it logged event=sandbox_probe"
    fi
    sleep 0.25
    waited=$((waited + 1))
  done
  dump_log "$log"
  die "no event=sandbox_probe line within $seconds s in $log"
}

# --- self test ---------------------------------------------------------------------------------

self_test() {
  local met notmet warn other dir
  met='2026-10-07T10:00:00.123Z INFO atlas_duck_app_lib::sandbox_probe src/sandbox_probe.rs:301 event=sandbox_probe floor=met failed=none extra_layers=landlock:on engine_version=0.16.2 worker_version=0.1.0+0123456789ab ace=n/a dropped_fields=0'
  notmet='2026-10-07T10:00:01.123Z INFO atlas_duck_app_lib::sandbox_probe src/sandbox_probe.rs:301 event=sandbox_probe floor=not_met failed=raw_clone+mem_read_proc_mem extra_layers=landlock:off engine_version=unknown worker_version=unknown ace=n/a dropped_fields=0'
  warn='2026-10-07T10:00:02.123Z WARN atlas_duck_app_lib::sandbox_probe src/sandbox_probe.rs:99 event=sandbox_probe reason=install_dir_unknown dropped_fields=0'
  other='2026-10-07T10:00:03.123Z INFO atlas_duck_app_lib::tray_host src/tray_host.rs:58 event=tray_host_checked tray_host=missing dropped_fields=0'

  [ "$(probe_field "$met" floor)" = "met" ] || die "self-test: floor of the met line"
  [ "$(probe_field "$met" ace)" = "n/a" ] || die "self-test: ace of the met line"
  [ "$(probe_field "$met" extra_layers)" = "landlock:on" ] || die "self-test: extra_layers of the met line"
  [ "$(probe_field "$notmet" failed)" = "raw_clone+mem_read_proc_mem" ] || die "self-test: failed of the not_met line"
  [ -z "$(probe_field "$met" nonexistent)" ] || die "self-test: a missing field is not empty"

  dir="$(mktemp -d)"
  printf '%s\n%s\n%s\n%s\n' "$other" "$met" "$warn" "$notmet" >"$dir/diag.log"
  [ "$(probe_count "$dir/diag.log")" = "2" ] || die "self-test: expected 2 summary lines, got $(probe_count "$dir/diag.log")"
  [ "$(probe_lines "$dir/diag.log" | tail -n 1)" = "$notmet" ] || die "self-test: the newest summary line is not the not_met line"
  [ "$(probe_count "$dir/missing.log")" = "0" ] || die "self-test: a missing log has summary lines"

  assert_probe_line "$met" 'n/a'
  if (assert_probe_line "$notmet" 'n/a') 2>/dev/null; then die "self-test: a not_met line passed"; fi
  if (assert_probe_line "$met" 'present') 2>/dev/null; then die "self-test: the wrong ace passed"; fi

  # wait_probe_line returns the line once the count grows, and fails when the pid is gone.
  (
    PROBE_LINE=""
    sleep 30 &
    holder=$!
    wait_probe_line "$dir/diag.log" "$holder" 1 5
    kill "$holder" 2>/dev/null || true
    [ "$PROBE_LINE" = "$notmet" ] || exit 1
  ) || die "self-test: wait_probe_line did not return the newest line"
  if (wait_probe_line "$dir/diag.log" 999999 2 2) 2>/dev/null; then die "self-test: wait_probe_line passed for a dead pid"; fi
  rm -rf "$dir"
  echo "install-probe-linux self-test ok"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

# --- arguments ---------------------------------------------------------------------------------

package="${1:?usage: ci/install-probe-linux.sh <deb|rpm|appimage> <artifact-dir>}"
dist="${2:?usage: ci/install-probe-linux.sh <deb|rpm|appimage> <artifact-dir>}"
case "$package" in
  deb | rpm | appimage) ;;
  *) die "the package must be deb, rpm or appimage, got '$package'" ;;
esac
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
evidence="${INSTALL_PROBE_EVIDENCE:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/install-probe-evidence}"
mkdir -p "$evidence"
sudo_cmd=""
if [ "$(id -u)" -ne 0 ]; then sudo_cmd="sudo"; fi

# only_file <dir> <glob>: prints the single match.
only_file() {
  local dir="$1" pattern="$2" matches
  shopt -s nullglob
  # shellcheck disable=SC2206 # the pattern is a glob on purpose
  matches=("$dir"/$pattern)
  shopt -u nullglob
  [ "${#matches[@]}" -eq 1 ] || die "expected exactly one $pattern in $dir, found ${#matches[@]}"
  realpath "${matches[0]}"
}

# Fedora 40 is past end of life; when its mirrors are gone, use the archive.
use_archive_repos() {
  info "Fedora 40 mirrors unavailable; switching to archives.fedoraproject.org"
  sed -i \
    -e 's|^metalink=|#metalink=|' \
    -e 's|^#baseurl=http://download.example/pub/fedora/linux|baseurl=https://archives.fedoraproject.org/pub/archive/fedora/linux|' \
    /etc/yum.repos.d/fedora.repo /etc/yum.repos.d/fedora-updates.repo
  if [ -f /etc/yum.repos.d/fedora-cisco-openh264.repo ]; then
    sed -i 's|^enabled=1|enabled=0|' /etc/yum.repos.d/fedora-cisco-openh264.repo
  fi
}

# --- outer phase: tools, package, then re-exec under a session bus and a display ----------------

if [ -z "${ATLAS_DUCK_PROBE_INNER:-}" ]; then
  case "$package" in
    deb)
      deb="$(only_file "$dist/deb" '*.deb')"
      $sudo_cmd apt-get update
      $sudo_cmd apt-get install -y --no-install-recommends xvfb dbus-x11 xauth procps
      info "installing $deb"
      $sudo_cmd apt-get install -y "$deb"
      dpkg-query -W -f='${Package} ${Version}\n' atlas-duck
      app_cmd="/usr/bin/atlas-duck-app"
      ;;
    appimage)
      appimage="$(only_file "$dist/appimage" '*.AppImage')"
      # Runtime support only: FUSE for the type-2 runtime, WebKitGTK and the appindicator
      # library the AppImage relies on the host for, the test tools. No atlas-duck package.
      $sudo_cmd apt-get update
      $sudo_cmd apt-get install -y --no-install-recommends \
        fuse libfuse2 libwebkit2gtk-4.1-0 libayatana-appindicator3-1 xvfb dbus-x11 xauth procps
      chmod +x "$appimage"
      app_cmd="$appimage"
      ;;
    rpm)
      rpm_file="$(only_file "$dist/rpm" '*.rpm')"
      [ "$(id -u)" -eq 0 ] || die "the rpm job runs as root inside the fedora:40 container"
      grep -qx 'VERSION_ID=40' /etc/os-release || die "this job expects Fedora 40"
      if ! dnf -y makecache; then
        use_archive_repos
        dnf -y makecache
      fi
      dnf -y install xorg-x11-server-Xvfb dbus-daemon xorg-x11-xauth procps-ng
      info "installing $rpm_file"
      dnf -y install "$rpm_file"
      rpm -q atlas-duck
      app_cmd="/usr/bin/atlas-duck-app"
      ;;
  esac
  export ATLAS_DUCK_PROBE_INNER=1
  export ATLAS_DUCK_PROBE_APP="$app_cmd"
  exec dbus-run-session -- xvfb-run -a -s "-screen 0 1280x1024x24" bash "$0" "$@"
fi

# --- inner phase: the probe --------------------------------------------------------------------

app_cmd="${ATLAS_DUCK_PROBE_APP:?the outer phase sets ATLAS_DUCK_PROBE_APP}"
[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] || die "no session bus: the inner phase must run under dbus-run-session"
[ -n "${DISPLAY:-}" ] || die "no display: the inner phase must run under xvfb-run"
APP_OUT="$evidence/app-output.txt"
: >"$APP_OUT"
APP_PID=""
SAMPLER_PID=""
DATA_DIR=""

cleanup() {
  local status=$?
  set +e
  if [ -n "$SAMPLER_PID" ]; then kill "$SAMPLER_PID" 2>/dev/null; fi
  pkill -TERM -u "$(id -u)" -x atlas-duck-app 2>/dev/null
  if [ -n "$APP_PID" ]; then kill -TERM "$APP_PID" 2>/dev/null; fi
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pgrep -u "$(id -u)" -x atlas-duck-app >/dev/null 2>&1 || break
    sleep 0.5
  done
  pkill -KILL -u "$(id -u)" -x atlas-duck-app 2>/dev/null
  pkill -KILL -u "$(id -u)" -x atlas-duck-sandbox 2>/dev/null
  if [ -n "$DATA_DIR" ] && [ -f "$DATA_DIR/logs/diag.log" ]; then
    cp "$DATA_DIR/logs/diag.log" "$evidence/diag.log"
  fi
  exit "$status"
}
trap cleanup EXIT

info "pinned fixture (a local temp data dir)"
DATA_DIR="$("$here/pinned-fixture.sh")"
[ -d "$DATA_DIR" ] || die "the fixture's data dir $DATA_DIR does not exist"
LOG="$DATA_DIR/logs/diag.log"
info "data dir: $DATA_DIR"

# Records every distinct executable path a process named atlas-duck-sandbox runs from. The probe
# worker lives for milliseconds, so this is best effort; a worker that is seen must be in the
# app's own mount.
SAMPLE_FILE="$evidence/worker-paths.txt"
: >"$SAMPLE_FILE"
(
  set +e
  while :; do
    for d in /proc/[0-9]*; do
      case "$(cat "$d/comm" 2>/dev/null)" in
        atlas-duck-sand*) readlink "$d/exe" 2>/dev/null >>"$SAMPLE_FILE" ;;
      esac
    done
    sleep 0.02
  done
) &
SAMPLER_PID=$!

info "start: $app_cmd --background (DISPLAY=$DISPLAY), poll $LOG up to ${PROBE_SECONDS} s"
"$app_cmd" --background >>"$APP_OUT" 2>&1 &
APP_PID=$!
wait_probe_line "$LOG" "$APP_PID" 0 "$PROBE_SECONDS"
line="$PROBE_LINE"
printf '%s\n' "$line" >"$evidence/probe-line.txt"
info "$line"
assert_probe_line "$line" 'n/a'

# The real app process: for an AppImage the runtime and AppRun come first.
app_pid="$(pgrep -u "$(id -u)" -x atlas-duck-app | head -n 1 || true)"
[ -n "$app_pid" ] || die "no atlas-duck-app process although it logged sandbox_probe"
app_exe="$(readlink -f "/proc/$app_pid/exe")"
info "app pid $app_pid runs $app_exe"
app_dir="$(dirname "$app_exe")"
[ -x "$app_dir/atlas-duck-sandbox" ] || die "no atlas-duck-sandbox next to the app in $app_dir"
case "$package" in
  deb | rpm)
    [ "$app_exe" = "/usr/bin/atlas-duck-app" ] || die "the installed app runs $app_exe, expected /usr/bin/atlas-duck-app"
    expected_worker_dir="/usr/bin"
    ;;
  appimage)
    case "$app_exe" in
      "${TMPDIR:-/tmp}"/.mount_*/usr/bin/atlas-duck-app) ;;
      *) die "the AppImage app runs $app_exe, expected ${TMPDIR:-/tmp}/.mount_*/usr/bin/atlas-duck-app (its own mount)" ;;
    esac
    expected_worker_dir="$app_dir"
    ;;
esac
sleep 1   # let the sampler see the last probe workers
if [ -s "$SAMPLE_FILE" ]; then
  sort -u "$SAMPLE_FILE" | while IFS= read -r seen; do
    [ "$seen" = "$expected_worker_dir/atlas-duck-sandbox" ] ||
      die "a worker ran from $seen, expected $expected_worker_dir/atlas-duck-sandbox"
    info "worker observed at $seen"
  done
else
  info "no worker process was sampled (the probe workers lived between two samples); floor=met proves they were spawned"
fi

# tray-host check (spec §2.5, §15 V33): logged on every Linux start.
tray_line="$(grep -E 'event=tray_host_checked' "$LOG" | tail -n 1 || true)"
[ -n "$tray_line" ] || die "no event=tray_host_checked line in $LOG"
info "$tray_line"
tray_host="$(probe_field "$tray_line" tray_host)"
case "$tray_host" in
  present | missing) ;;
  *) die "tray_host=$tray_host is neither present nor missing" ;;
esac
if [ "$package" = "rpm" ]; then
  [ "$tray_host" = "missing" ] || die "Fedora container: tray_host=$tray_host, expected missing (no StatusNotifierWatcher on this bus)"
fi

# The app must survive its tray creation without a tray host (§15 V33) and the probe.
sleep 3
kill -0 "$APP_PID" 2>/dev/null || die "the app exited within 3 s of its sandbox_probe line"
pgrep -u "$(id -u)" -x atlas-duck-app >/dev/null || die "the atlas-duck-app process is gone 3 s after its sandbox_probe line"
echo "PROBE_RECORD package=$package floor=$(probe_field "$line" floor) failed=$(probe_field "$line" failed) extra_layers=$(probe_field "$line" extra_layers) engine_version=$(probe_field "$line" engine_version) worker_version=$(probe_field "$line" worker_version) tray_host=$tray_host"
echo "OK: $package: floor=met, worker beside the app in $app_dir, tray_host=$tray_host, the app is still alive"
