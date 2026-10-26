#!/usr/bin/env bash
# ci/install-test-linux.sh <deb|rpm|appimage> <artifact-dir> <fixture-dir>
# ci/install-test-linux.sh --self-test
#
# M10 Task 27 (spec §12.2, §12.5, §13 I-45, S-04, §15 V19, V32; PD-179): uninstall and reinstall
# of a Linux package keep the user's data and keychain entries, and the app's runs chain
# APP_START/APP_STOP. <artifact-dir> is the bundle-x86_64-unknown-linux-gnu artifact (deb/*.deb,
# rpm/*.rpm, appimage/*.AppImage); <fixture-dir> holds the ci_fixture test binary (artifact
# ci-fixture-x86_64-unknown-linux-gnu, built by bundle.yml on ubuntu-22.04; Fedora 40's glibc is
# newer, so it runs in the container too). The job has no cargo. CI only: it installs the package,
# writes this user's pinned paths file (ci/pinned-fixture.sh) and keychain entries.
#
# Secret Service: a GNOME Keyring daemon on the session bus of `dbus-run-session`, started and
# unlocked as ci/keyring-ci.sh and ci/shared-keyring.sh start it; the test binary and the installed
# app share it (the Secret Service does not bind an item to the program that created it, PD-179).
# In the fedora:40 container the passwd home is an overlayfs, where the keyring locality check fails
# closed, so XDG_DATA_HOME is a dir on the /tmp tmpfs and an absent <home>/.local/share points at
# it (as ci/keyring-ci.sh does; ci/fedora-rpm.sh sets no XDG_*).
#
# Flow (each wait is bounded):
#   1. pinned fixture -> ci_fixture_store (the real Secret Service, anchor dir, pinned install_id)
#      -> ci_fixture_entries (E0)
#   2. start --background -> `event=serve_started serve_state=core` (APP_START appended) ->
#      `atlas-duck doctor` exit 0 with the core's answer -> SIGTERM -> `event=app_stop` line, app gone
#   3. snapshot S0 (sha256 of every file of the data dir, config dir, anchor dir, pinned file) ->
#      uninstall (deb: apt-get remove, then apt-get purge, each checked; rpm: dnf remove;
#      AppImage: the file is removed) -> S == S0, entries == E0 after each step
#   4. reinstall -> S == S0 -> start -> serve core -> SIGTERM -> app_stop
#   5. ci_fixture_verify (Ready, full verification, no incident, APP_START/APP_STOP chained, >= 2)
#   6. S-04 against the installed app (ci/s04-no-debug-port.sh, TAURI_WEBVIEW_AUTOMATION=true)
#   V32: RUNTIME_VERSIONS line (WebKitGTK, appindicator, FUSE / AppImage runtime).
set -euo pipefail
export LC_ALL=C

WAIT_SECONDS="${WAIT_SECONDS:-90}"

info() { printf 'install-test-linux: %s\n' "$*" >&2; }
die() { printf 'install-test-linux: FAIL: %s\n' "$*" >&2; exit 1; }

# log_count <log> <ERE>: lines of <log> matching <ERE> (0 for a missing log).
log_count() {
  local n=""
  if [ -f "$1" ]; then n="$(grep -cE "$2" "$1" 2>/dev/null || true)"; fi
  echo "${n:-0}"
}

PAT_SERVING='(^| )event=serve_started( .*)? serve_state=core( |$)'
PAT_STOP='(^| )event=app_stop( |$)'

dump_log() {
  if [ -f "$1" ]; then
    echo "---- $1 (last 60 lines) ----" >&2
    tail -n 60 "$1" >&2
    echo "----" >&2
  fi
}

# wait_log <log> <ERE> <known> <seconds> <what> [<pid>]: until <log> has more than <known>
# matching lines. Fails on timeout, or when <pid> (if given) is gone first.
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

# snapshot <out> <root>...: "<path> <sha256>" for every regular file below each root (a file root
# is hashed itself), sorted; a missing root is a "MISSING" row.
snapshot() {
  local out="$1" r
  shift
  : >"$out.tmp"
  for r in "$@"; do
    if [ -f "$r" ]; then
      sha256sum "$r" >>"$out.tmp"
    elif [ -d "$r" ]; then
      find "$r" -type f -print0 | xargs -0 -r sha256sum >>"$out.tmp"
    else
      echo "MISSING $r" >>"$out.tmp"
    fi
  done
  sort "$out.tmp" >"$out"
  rm -f "$out.tmp"
}

# same_snapshot <before> <after> <what>
same_snapshot() {
  if ! diff -u "$1" "$2" >&2; then
    die "$3 changed the user's data (diff above)"
  fi
  info "ok: $3 left $(wc -l <"$1" | tr -d ' ') files unchanged"
}

self_test() {
  local dir log
  dir="$(mktemp -d)"
  log="$dir/diag.log"
  printf '%s\n' \
    '2026-10-25T10:00:00.000Z INFO atlas_duck_app_lib::serve src/serve.rs:1 event=serve_started serve_state=first_run dropped_fields=0' \
    '2026-10-25T10:00:01.000Z INFO atlas_duck_app_lib::serve src/serve.rs:1 event=serve_started serve_state=core dropped_fields=0' \
    '2026-10-25T10:00:02.000Z INFO atlas_duck_app_lib::serve src/serve.rs:1 event=app_stop reason=os_shutdown dropped_fields=0' \
    '2026-10-25T10:00:03.000Z INFO atlas_duck_app_lib::serve src/serve.rs:1 event=app_stopped_not reason=x' >"$log"
  [ "$(log_count "$log" "$PAT_SERVING")" = 1 ] || die "self-test: serving count"
  [ "$(log_count "$log" "$PAT_STOP")" = 1 ] || die "self-test: app_stop count"
  [ "$(log_count "$dir/missing" "$PAT_STOP")" = 0 ] || die "self-test: missing log count"
  wait_log "$log" "$PAT_STOP" 0 2 app_stop
  if (wait_log "$log" "$PAT_STOP" 1 1 app_stop) 2>/dev/null; then die "self-test: wait_log passed without a new line"; fi
  if (wait_log "$log" "$PAT_STOP" 1 5 app_stop 999999) 2>/dev/null; then die "self-test: wait_log passed for a dead pid"; fi
  mkdir -p "$dir/a/b"
  echo one >"$dir/a/b/f"
  echo pin >"$dir/pin"
  snapshot "$dir/s1" "$dir/a" "$dir/pin" "$dir/none"
  snapshot "$dir/s2" "$dir/a" "$dir/pin" "$dir/none"
  same_snapshot "$dir/s1" "$dir/s2" "self-test" 2>/dev/null
  grep -q "MISSING $dir/none" "$dir/s1" || die "self-test: a missing root is not listed"
  echo two >>"$dir/a/b/f"
  snapshot "$dir/s3" "$dir/a" "$dir/pin" "$dir/none"
  if (same_snapshot "$dir/s1" "$dir/s3" "self-test") 2>/dev/null; then die "self-test: a changed file passed"; fi
  rm -rf "$dir"
  echo "install-test-linux self-test ok"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

package="${1:?usage: ci/install-test-linux.sh <deb|rpm|appimage> <artifact-dir> <fixture-dir>}"
dist="${2:?usage: ci/install-test-linux.sh <deb|rpm|appimage> <artifact-dir> <fixture-dir>}"
fixture_dir="${3:?usage: ci/install-test-linux.sh <deb|rpm|appimage> <artifact-dir> <fixture-dir>}"
case "$package" in
  deb | rpm | appimage) ;;
  *) die "the package must be deb, rpm or appimage, got '$package'" ;;
esac
[ "${CI:-}" = true ] || die "CI only (CI=true): it replaces the pinned paths file and writes keychain entries"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dist="$(cd "$dist" && pwd)"
fixture_dir="$(cd "$fixture_dir" && pwd)"
evidence="${INSTALL_PROBE_EVIDENCE:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/install-test-evidence}"
mkdir -p "$evidence"
sudo_cmd=""
if [ "$(id -u)" -ne 0 ]; then sudo_cmd="sudo"; fi

only_file() {
  local dir="$1" pattern="$2" matches
  shopt -s nullglob
  # shellcheck disable=SC2206 # the pattern is a glob on purpose
  matches=("$dir"/$pattern)
  shopt -u nullglob
  [ "${#matches[@]}" -eq 1 ] || die "expected exactly one $pattern in $dir, found ${#matches[@]}"
  realpath "${matches[0]}"
}

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

# install_package / remove_package: the package manager steps (AppImage: copy / remove the file).
install_package() {
  case "$package" in
    deb) $sudo_cmd apt-get install -y "$(only_file "$dist/deb" '*.deb')" >&2 ;;
    rpm) dnf -y install "$(only_file "$dist/rpm" '*.rpm')" >&2 ;;
    appimage)
      mkdir -p "$appimage_home"
      cp "$(only_file "$dist/appimage" '*.AppImage')" "$appimage_path"
      chmod +x "$appimage_path"
      ;;
  esac
}

runtime_versions() {
  local v=""
  case "$package" in
    deb | appimage)
      v="$(dpkg-query -W -f='${Package}=${Version} ' libwebkit2gtk-4.1-0 libayatana-appindicator3-1 libfuse2 2>/dev/null || true)"
      ;;
    rpm)
      v="$(rpm -q --qf '%{NAME}=%{VERSION}-%{RELEASE} ' webkit2gtk4.1 libayatana-appindicator-gtk3 libappindicator-gtk3 2>/dev/null | grep -v 'not installed' || true)"
      ;;
  esac
  if [ "$package" = appimage ] && [ -x "${appimage_path:-/nonexistent}" ]; then
    v="$v appimage_runtime=$(timeout 20 "$appimage_path" --appimage-version 2>&1 | head -n 1 | tr ' ' '_' || true)"
  fi
  echo "RUNTIME_VERSIONS package=$package $(uname -sr | tr ' ' '_') $v"
}

appimage_home="${RUNNER_TEMP:-/tmp}/install-test-appimage"
appimage_path="$appimage_home/atlas-duck.AppImage"

# --- outer phase: tools and the first install, then a session bus and a display ----------------

if [ -z "${ATLAS_DUCK_INSTALL_TEST_INNER:-}" ]; then
  case "$package" in
    deb | appimage)
      $sudo_cmd apt-get update >&2
      extra=""
      [ "$package" = appimage ] && extra="fuse libfuse2 libwebkit2gtk-4.1-0 libayatana-appindicator3-1"
      # shellcheck disable=SC2086 # extra is a word list on purpose
      $sudo_cmd apt-get install -y --no-install-recommends \
        xvfb dbus-x11 xauth procps iproute2 python3 gnome-keyring $extra >&2
      ;;
    rpm)
      [ "$(id -u)" -eq 0 ] || die "the rpm job runs as root inside the fedora:40 container"
      grep -qx 'VERSION_ID=40' /etc/os-release || die "this job expects Fedora 40"
      if ! dnf -y makecache >&2; then
        use_archive_repos
        dnf -y makecache >&2
      fi
      dnf -y install xorg-x11-server-Xvfb xorg-x11-xauth dbus-daemon procps-ng iproute python3 \
        gnome-keyring diffutils findutils >&2
      ;;
  esac
  install_package
  case "$package" in
    deb) dpkg-query -W -f='${Package} ${Version}\n' atlas-duck ;;
    rpm) rpm -q atlas-duck ;;
    appimage) ls -l "$appimage_path" ;;
  esac
  export ATLAS_DUCK_INSTALL_TEST_INNER=1
  exec dbus-run-session -- xvfb-run -a -s "-screen 0 1280x1024x24" bash "$0" "$@"
fi

# --- inner phase ---------------------------------------------------------------------------------

[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] || die "no session bus"
[ -n "${DISPLAY:-}" ] || die "no display"
uid="$(id -u)"
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/install-test-work.XXXXXX")"
APP_OUT="$evidence/app-output.txt"
: >"$APP_OUT"
APP_PID=""
LOG=""

stop_apps() {
  pkill -TERM -u "$uid" -x atlas-duck-app 2>/dev/null || true
  local i
  for i in $(seq 1 40); do
    pgrep -u "$uid" -x atlas-duck-app >/dev/null 2>&1 || break
    sleep 0.5
  done
  pkill -KILL -u "$uid" -x atlas-duck-app 2>/dev/null || true
  pkill -KILL -u "$uid" -x atlas-duck-sand 2>/dev/null || true
}

cleanup() {
  local status=$?
  set +e
  stop_apps
  [ -n "$LOG" ] && [ -f "$LOG" ] && cp "$LOG" "$evidence/diag.log"
  pkill -u "$uid" -x gnome-keyring-d 2>/dev/null
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

case "$package" in
  deb | rpm)
    app_cmd=/usr/bin/atlas-duck-app
    cli=(/usr/bin/atlas-duck)
    ;;
  appimage)
    app_cmd="$appimage_path"
    cli=("$appimage_path" __cli)
    ;;
esac
runtime_versions

# The Secret Service (ci/keyring-ci.sh's setup).
if [ "$package" = rpm ]; then
  export XDG_DATA_HOME="${XDG_DATA_HOME:-/tmp/install-test-xdg}"
  mkdir -p "$XDG_DATA_HOME"
  passwd_home="$(getent passwd "$uid" | cut -d: -f6)"
  share="$passwd_home/.local/share"
  if [ ! -e "$share" ] && [ "$(stat -f -c %T "$passwd_home")" = overlayfs ]; then
    mkdir -p "$passwd_home/.local"
    ln -s "$XDG_DATA_HOME" "$share"
    info "linked $share -> $XDG_DATA_HOME (overlayfs home)"
  fi
fi
printf 'atlas-duck-ci' | gnome-keyring-daemon --components=secrets --daemonize --unlock >/dev/null
info "gnome-keyring-daemon started on $DBUS_SESSION_BUS_ADDRESS"

# The fixture binary (upload-artifact drops file modes; the container mounts the checkout read-only).
fixture_src="$(only_file "$fixture_dir" 'ci_fixture*')"
fixture="$work/ci_fixture"
cp "$fixture_src" "$fixture"
chmod +x "$fixture"

# run_fixture <test> <marker>: prints and returns the marker line.
run_fixture() {
  local out
  out="$work/fixture-$1.out"
  if ! timeout 180 "$fixture" --exact "$1" --ignored --nocapture --test-threads=1 >"$out" 2>&1; then
    cat "$out" >&2
    die "ci_fixture $1 failed"
  fi
  cat "$out" >&2
  grep -q '^test result: ok\. 1 passed' "$out" || die "ci_fixture $1 did not report exactly one passed test"
  # libtest prints a passing test's output right after "test <name> ... " on the same line.
  grep -oE "(^|[.][.][.] )$2 .*" "$out" | sed 's/^[.][.][.] //' | tail -n 1 | grep . || die "ci_fixture $1 printed no $2 line"
}

info "1. pinned fixture, store with the Secret Service, entries"
DATA_DIR="$("$here/pinned-fixture.sh")"
root="$(dirname "$DATA_DIR")"
CONFIG_DIR="$root/config"
ANCHOR_DIR="$root/anchors"
mkdir -p "$ANCHOR_DIR"
passwd_home="$(getent passwd "$uid" | cut -d: -f6)"
shopt -s nullglob
pins=("$passwd_home"/.config/atlas-duck/paths-*.toml)
shopt -u nullglob
[ "${#pins[@]}" -eq 1 ] || die "expected one pinned paths file, found ${#pins[@]}"
PINNED="${pins[0]}"
LOG="$DATA_DIR/logs/diag.log"
export ATLAS_DUCK_CI_FIXTURE_PINNED="$PINNED"
export ATLAS_DUCK_CI_FIXTURE_ANCHOR_DIR="$ANCHOR_DIR"
run_fixture ci_fixture_store CI_FIXTURE_STORE
e0="$(run_fixture ci_fixture_entries CI_FIXTURE_ENTRIES)"
info "E0: $e0"

# run_app <what>: start, wait for the core, then (with doctor=1) doctor, then SIGTERM and app_stop.
run_app() {
  local what="$1" with_doctor="$2" serving stops code
  serving="$(log_count "$LOG" "$PAT_SERVING")"
  stops="$(log_count "$LOG" "$PAT_STOP")"
  "$app_cmd" --background >>"$APP_OUT" 2>&1 &
  APP_PID=$!
  wait_log "$LOG" "$PAT_SERVING" "$serving" "$WAIT_SECONDS" "event=serve_started serve_state=core ($what)" "$APP_PID"
  info "ok: the installed app serves the core ($what; APP_START appended)"
  if [ "$with_doctor" = 1 ]; then
    set +e
    timeout 120 "${cli[@]}" --timeout 60 doctor >"$work/doctor.json" 2>"$work/doctor.err"
    code=$?
    set -e
    echo "DOCTOR $(tr '\n' ' ' <"$work/doctor.json")"
    [ "$code" -eq 0 ] || { cat "$work/doctor.err" >&2; die "atlas-duck doctor exited $code"; }
    python3 - "$work/doctor.json" <<'PY' || die "doctor did not answer from the core"
import json, sys
d = json.load(open(sys.argv[1]))
app = (d.get("data") or {}).get("app")
if not isinstance(app, dict):
    sys.exit("doctor has no data.app (the app did not answer)")
if "gate" in app:
    sys.exit("doctor answered from the gate: %r" % app["gate"])
if "instances" not in app:
    sys.exit("doctor data.app has no instances (not the core answer)")
PY
  fi
  info "quit: SIGTERM"
  pkill -TERM -u "$uid" -x atlas-duck-app || die "no atlas-duck-app process to quit"
  local i
  for i in $(seq 1 $((WAIT_SECONDS * 4))); do
    if ! pgrep -u "$uid" -x atlas-duck-app >/dev/null && ! kill -0 "$APP_PID" 2>/dev/null; then break; fi
    sleep 0.25
  done
  pgrep -u "$uid" -x atlas-duck-app >/dev/null && die "the app did not exit within $WAIT_SECONDS s of SIGTERM"
  wait "$APP_PID" 2>/dev/null || true
  APP_PID=""
  [ "$(log_count "$LOG" "$PAT_STOP")" -gt "$stops" ] || { dump_log "$LOG"; die "no event=app_stop line after SIGTERM ($what)"; }
  info "ok: $(grep -E "$PAT_STOP" "$LOG" | tail -n 1)"
}

info "2. start, doctor, quit"
run_app "first install" 1

info "3. uninstall: user data and keychain entries unchanged"
snapshot "$work/s0" "$DATA_DIR" "$CONFIG_DIR" "$ANCHOR_DIR" "$PINNED"
check_unchanged() {
  local e
  snapshot "$work/s" "$DATA_DIR" "$CONFIG_DIR" "$ANCHOR_DIR" "$PINNED"
  same_snapshot "$work/s0" "$work/s" "$1"
  e="$(run_fixture ci_fixture_entries CI_FIXTURE_ENTRIES)"
  [ "$e" = "$e0" ] || die "keychain entries changed by $1: before '$e0', after '$e'"
  info "ok: keychain entries unchanged by $1"
}
case "$package" in
  deb)
    $sudo_cmd apt-get remove -y atlas-duck >&2
    [ ! -e /usr/bin/atlas-duck-app ] || die "/usr/bin/atlas-duck-app is still there after apt-get remove"
    check_unchanged "apt-get remove"
    $sudo_cmd apt-get purge -y atlas-duck >&2
    check_unchanged "apt-get purge"
    ;;
  rpm)
    dnf -y remove atlas-duck >&2
    [ ! -e /usr/bin/atlas-duck-app ] || die "/usr/bin/atlas-duck-app is still there after dnf remove"
    check_unchanged "dnf remove"
    ;;
  appimage)
    rm -f "$appimage_path"
    check_unchanged "the AppImage file removal"
    ;;
esac

info "4. reinstall, start, quit"
install_package
snapshot "$work/s" "$DATA_DIR" "$CONFIG_DIR" "$ANCHOR_DIR" "$PINNED"
same_snapshot "$work/s0" "$work/s" "the reinstall"
run_app "reinstall" 0

info "5. ci_fixture_verify"
export ATLAS_DUCK_CI_FIXTURE_MIN_STARTS=2
run_fixture ci_fixture_verify CI_FIXTURE_VERIFY
echo "I45 OK package=$package uninstall/reinstall kept data dir, config dir, pinned file, anchor dir and keychain entries"

info "6. S-04 against the installed app (TAURI_WEBVIEW_AUTOMATION=true)"
stop_apps
pkill -f 'WebKit(Web|Network)Process' 2>/dev/null || true
bash "$here/s04-no-debug-port.sh" "$app_cmd" || die "S-04 on the installed $package failed"
runtime_versions
echo "OK: install-test $package"
