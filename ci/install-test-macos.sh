#!/bin/bash
# ci/install-test-macos.sh --release <dmg-dir> <arm64|x86_64>
# ci/install-test-macos.sh --debug-app <artifact-dir> <arm64|x86_64>
# ci/install-test-macos.sh --self-test
#
# --debug-app (M10 Task 27a, §13 I-45 macOS store half, PD-179): <artifact-dir> is the
# bundle-macos-e2e-<target> artifact of e2e-bundle.yml (app/*.tar.gz holding the debug
# scripted-approver "Atlas Duck.app", fixture/ci_fixture: app/src-tauri/tests/ci_fixture.rs). Every
# keychain access goes through the INSTALLED app (`__test-os-keystore`, the fixture's proxy), so
# the keychain items trust that app's cdhash. Flow: test home + pinned fixture (--home) -> install ->
# ci_fixture_store_macos -> ci_fixture_entries_macos (E0) -> start --background -> a new
# `event=serve_started serve_state=core` line (APP_START) -> SIGTERM -> app_stop -> `rm -rf` the
# .app -> data dir, config dir, pinned file and anchor dir hashes unchanged -> reinstall the same
# artifact (same cdhash) -> hashes unchanged, entries equal to E0 through the proxy -> start -> quit
# -> ci_fixture_verify_macos (Ready, full verification, APP_START/APP_STOP pairs, no incident).
# The app runs with a cleared environment (test home and PATH only): no ATLAS_DUCK_E2E_ALLOW_DRIVER.
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
# V32: RUNTIME_VERSIONS (macOS, WebKit framework version, the arch the app runs as); `lipo -archs`
# of the installed binary must equal the leg's arch. Last: S-04 (ci/s04-no-debug-port.sh, macOS
# branch) against the installed app.
set -euo pipefail
export LC_ALL=C

WAIT_SECONDS="${WAIT_SECONDS:-90}"
DUMMY_SERVICE="atlas-duck-ci-install-test"

info() { printf 'install-test-macos: %s\n' "$*" >&2; }
die() { printf 'install-test-macos: FAIL: %s\n' "$*" >&2; exit 1; }

PAT_PROBE='(^| )event=sandbox_probe( .*)? floor='
PAT_STOP='(^| )event=app_stop( |$)'
PAT_SERVING='(^| )event=serve_started( .*)? serve_state=core( |$)'

# run_bounded <seconds> <cmd>...: runs cmd, kills it after <seconds> (macOS has no timeout(1)).
run_bounded() {
  local seconds="$1" pid i=0 status=0
  shift
  "$@" &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$i" -ge $((seconds * 4)) ]; then
      kill -KILL "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      info "timed out after $seconds s: $1"
      return 124
    fi
    sleep 0.25
    i=$((i + 1))
  done
  wait "$pid" || status=$?
  return "$status"
}

log_count() {
  local n=""
  if [ -f "$1" ]; then n="$(grep -cE "$2" "$1" 2>/dev/null || true)"; fi
  echo "${n:-0}"
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
  printf '%s\n' '2026-10-25T10:00:02.000Z INFO atlas_duck_app_lib::serve src/serve.rs:1 event=serve_started serve_state=core dropped_fields=0' >>"$log"
  [ "$(log_count "$log" "$PAT_SERVING")" = 1 ] || die "self-test: serving count"
  run_bounded 5 true || die "self-test: run_bounded failed a quick command"
  if run_bounded 5 false; then die "self-test: run_bounded passed a failing command"; fi
  if run_bounded 1 sleep 10 2>/dev/null; then die "self-test: run_bounded passed a command past its bound"; fi
  rm -rf "$dir"
  echo "install-test-macos self-test ok"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

# ---- --debug-app (T27a) -----------------------------------------------------------------------
debug_app() {
  local art_dir="$1" arch="$2"
  case "$arch" in
    arm64 | x86_64) ;;
    *) die "the arch must be arm64 or x86_64, got '$arch'" ;;
  esac
  [ "${CI:-}" = true ] || die "CI only (CI=true): it installs into /Applications and writes keychain items"
  [ "$(uname -m)" = arm64 ] || die "this job expects an arm64 runner, uname -m is $(uname -m)"
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  evidence="${INSTALL_PROBE_EVIDENCE:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/install-test-evidence}"
  mkdir -p "$evidence"

  shopt -s nullglob
  local tars=("$art_dir"/app/*.tar.gz)
  shopt -u nullglob
  [ "${#tars[@]}" -eq 1 ] || die "expected one app/*.tar.gz in $art_dir, found ${#tars[@]}"
  [ -f "$art_dir/fixture/ci_fixture" ] || die "no fixture/ci_fixture in $art_dir"
  work="$(mktemp -d /tmp/atlas-duck-install-test-debug.XXXXXX)"
  APP_PID=""
  LOG=""
  dest="/Applications/Atlas Duck.app"
  # Before the trap: its cleanup removes $dest, which must be ours.
  [ ! -e "$dest" ] || die "$dest already exists; this job needs a fresh machine"
  trap debug_cleanup EXIT

  mkdir -p "$work/src"
  tar -xzf "${tars[0]}" -C "$work/src"
  src_app="$work/src/Atlas Duck.app"
  [ -d "$src_app" ] || die "the tarball holds no 'Atlas Duck.app'"
  app_exe="$dest/Contents/MacOS/atlas-duck-app"
  fixture="$work/ci_fixture"
  cp "$art_dir/fixture/ci_fixture" "$fixture"
  chmod +x "$fixture"
  [ "$(lipo -archs "$fixture")" = "$arch" ] || die "ci_fixture: lipo -archs is '$(lipo -archs "$fixture")', expected '$arch'"

  local webkit_version
  webkit_version="$(defaults read /System/Library/Frameworks/WebKit.framework/Resources/Info.plist CFBundleVersion 2>/dev/null || echo unknown)"
  echo "RUNTIME_VERSIONS macos=$(sw_vers -productVersion) build=$(sw_vers -buildVersion) webkit=$webkit_version app_arch=$arch runner=$(uname -m) build=debug-scripted-approver"

  info "1. test home, pinned fixture (--home), install"
  TEST_HOME="$(cd "$(mktemp -d "${RUNNER_TEMP:-/tmp}/atlas-duck-t27a.XXXXXX")" && pwd -P)"
  DATA_DIR="$("$here/pinned-fixture.sh" --home "$TEST_HOME" --data-dir "$TEST_HOME/data")"
  CONFIG_DIR="$TEST_HOME/config"
  ANCHOR_DIR="$TEST_HOME/anchors"
  mkdir -p "$ANCHOR_DIR"
  shopt -s nullglob
  local pins=("$TEST_HOME/Library/Application Support/atlas-duck"/paths-*.toml)
  shopt -u nullglob
  [ "${#pins[@]}" -eq 1 ] || die "expected one pinned paths file under the test home, found ${#pins[@]}"
  PINNED="${pins[0]}"
  LOG="$DATA_DIR/logs/diag.log"
  export ATLAS_DUCK_TEST_HOME="$TEST_HOME"
  export ATLAS_DUCK_CI_FIXTURE_APP="$app_exe"
  export ATLAS_DUCK_CI_FIXTURE_ANCHOR_DIR="$ANCHOR_DIR"

  debug_install
  local cd0
  cd0="$(cdhash_of)"
  echo "CDHASH first install: $cd0"

  info "2. ci_fixture_store_macos, ci_fixture_entries_macos (E0) through the installed app"
  run_fixture ci_fixture_store_macos CI_FIXTURE_STORE >/dev/null
  local e0 e1
  e0="$(run_fixture ci_fixture_entries_macos CI_FIXTURE_ENTRIES)"
  echo "E0 $e0"

  info "3. start, quit"
  debug_run_app "first install"

  info "4. rm -rf the .app: data dir, config dir, pinned file, anchor dir unchanged"
  snapshot "$work/s0" "$DATA_DIR" "$CONFIG_DIR" "$ANCHOR_DIR" "$PINNED"
  debug_remove
  snapshot "$work/s" "$DATA_DIR" "$CONFIG_DIR" "$ANCHOR_DIR" "$PINNED"
  same_snapshot "$work/s0" "$work/s" "rm -rf $dest"

  info "5. reinstall the same artifact: same cdhash, files unchanged, keychain entries through the proxy"
  debug_install
  local cd1
  cd1="$(cdhash_of)"
  echo "CDHASH reinstall: $cd1"
  [ -n "$cd0" ] && [ "$cd0" = "$cd1" ] || die "the reinstalled app's cdhash '$cd1' differs from '$cd0'"
  snapshot "$work/s" "$DATA_DIR" "$CONFIG_DIR" "$ANCHOR_DIR" "$PINNED"
  same_snapshot "$work/s0" "$work/s" "the reinstall"
  e1="$(run_fixture ci_fixture_entries_macos CI_FIXTURE_ENTRIES)"
  echo "E1 $e1"
  [ "$e1" = "$e0" ] || die "keychain entries changed by the removal and reinstall: before '$e0', after '$e1'"

  info "6. start, quit"
  debug_run_app "reinstall"

  info "7. ci_fixture_verify_macos"
  export ATLAS_DUCK_CI_FIXTURE_MIN_STARTS=2
  run_fixture ci_fixture_verify_macos CI_FIXTURE_VERIFY
  echo "I45 DEBUG-APP OK arch=$arch cdhash=$cd0: removal and reinstall kept data dir, config dir, pinned file, anchor dir and keychain entries"
  echo "OK: install-test macos debug-app $arch"
}

debug_stop_apps() {
  pkill -TERM -x atlas-duck-app 2>/dev/null || true
  local i
  for i in $(seq 1 40); do
    pgrep -x atlas-duck-app >/dev/null 2>&1 || break
    sleep 0.5
  done
  pkill -KILL -x atlas-duck-app 2>/dev/null || true
  pkill -KILL -f '/atlas-duck-sandbox( |$)' 2>/dev/null || true
}

debug_cleanup() {
  local status=$?
  set +e
  debug_stop_apps
  [ -n "$LOG" ] && [ -f "$LOG" ] && cp "$LOG" "$evidence/diag.log"
  if [ -w /Applications ]; then rm -rf "$dest"; else sudo rm -rf "$dest"; fi
  rm -rf "$work"
  exit "$status"
}

debug_install() {
  if [ -w /Applications ]; then ditto "$src_app" "$dest"; else sudo ditto "$src_app" "$dest"; fi
  [ -x "$app_exe" ] || die "no $app_exe after the install"
  local archs
  archs="$(lipo -archs "$app_exe")"
  [ "$archs" = "$arch" ] || die "$app_exe: lipo -archs is '$archs', expected '$arch'"
  codesign --verify --deep --strict "$dest" || die "codesign --verify failed on $dest"
}

debug_remove() {
  if [ -w /Applications ]; then rm -rf "$dest"; else sudo rm -rf "$dest"; fi
  [ ! -e "$dest" ] || die "$dest is still there after rm -rf"
}

cdhash_of() {
  codesign -dvvv "$dest" 2>&1 | sed -n 's/^CDHash=//p' | head -n 1
}

# run_fixture <test> <marker>: prints and returns the marker line (180 s bound).
run_fixture() {
  local out="$work/fixture-$1.out"
  if ! run_bounded 180 "$fixture" --exact "$1" --ignored --nocapture --test-threads=1 >"$out" 2>&1; then
    cat "$out" >&2
    die "ci_fixture $1 failed"
  fi
  cat "$out" >&2
  cp "$out" "$evidence/" 2>/dev/null || true
  grep -q '^test result: ok\. 1 passed' "$out" || die "ci_fixture $1 did not report exactly one passed test"
  # libtest prints a passing test's output right after "test <name> ... " on the same line.
  grep -oE "(^|[.][.][.] )$2 .*" "$out" | sed 's/^[.][.][.] //' | tail -n 1 | grep . || die "ci_fixture $1 printed no $2 line"
}

# debug_run_app <what>: start with a cleared environment, APP_START (serve_started core), SIGTERM,
# app_stop.
debug_run_app() {
  local what="$1" serving stops i
  serving="$(log_count "$LOG" "$PAT_SERVING")"
  stops="$(log_count "$LOG" "$PAT_STOP")"
  env -i ATLAS_DUCK_TEST_HOME="$TEST_HOME" PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    "$app_exe" --background >>"$evidence/app-output.txt" 2>&1 &
  APP_PID=$!
  wait_log "$LOG" "$PAT_SERVING" "$serving" "$WAIT_SECONDS" "event=serve_started serve_state=core ($what)" "$APP_PID"
  echo "SERVING_LINE $what: $(grep -E "$PAT_SERVING" "$LOG" | tail -n 1)"
  kill -TERM "$APP_PID"
  for i in $(seq 1 $((WAIT_SECONDS * 4))); do
    kill -0 "$APP_PID" 2>/dev/null || break
    sleep 0.25
  done
  kill -0 "$APP_PID" 2>/dev/null && die "the app did not exit within $WAIT_SECONDS s of SIGTERM ($what)"
  wait "$APP_PID" 2>/dev/null || true
  APP_PID=""
  [ "$(log_count "$LOG" "$PAT_STOP")" -gt "$stops" ] || { dump_log "$LOG"; die "no event=app_stop line after SIGTERM ($what)"; }
  echo "STOP_LINE $what: $(grep -E "$PAT_STOP" "$LOG" | tail -n 1)"
}

if [ "${1:-}" = "--debug-app" ]; then
  debug_app "${2:?usage: ci/install-test-macos.sh --debug-app <artifact-dir> <arm64|x86_64>}" \
    "${3:?usage: ci/install-test-macos.sh --debug-app <artifact-dir> <arm64|x86_64>}"
  exit 0
fi

[ "${1:-}" = "--release" ] || die "usage: ci/install-test-macos.sh --release <dmg-dir> <arm64|x86_64> | --debug-app <artifact-dir> <arm64|x86_64>"
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
  # V32: the installed binary is of the leg's arch (x86_64 runs translated by Rosetta 2).
  local archs
  archs="$(lipo -archs "$app_exe")"
  [ "$archs" = "$arch" ] || die "$app_exe: lipo -archs is '$archs', expected '$arch'"
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

# S-04 on the installed release .app (fix round 1; PD-179 keeps S-04 on the macOS release legs):
# the inspector variables and TAURI_WEBVIEW_AUTOMATION=true, no debug or automation port, all five
# scrubbed. It writes its own pinned file (first-run state: the Setup window is a real WKWebView)
# and removes it, so it runs last.
info "S-04 against the installed app (TAURI_WEBVIEW_AUTOMATION=true)"
stop_apps
/bin/bash "$here/s04-no-debug-port.sh" "$app_exe" || die "S-04 on the installed $arch .app failed"
echo "OK: install-test macos $arch"
