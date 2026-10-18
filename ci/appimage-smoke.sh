#!/usr/bin/env bash
# ci/appimage-smoke.sh <artifact-dir>
#
# M1 part of the §13 AppImage smoke job, on an ubuntu-22.04 runner with libfuse2 installed,
# using the downloaded bundle-x86_64-unknown-linux-gnu artifact (<artifact-dir>/deb/*.deb,
# <artifact-dir>/appimage/*.AppImage):
#   * `apt-get install` of the built deb succeeds: its Depends names resolve on Ubuntu 22.04 (§15 V32)
#   * the deb-installed `atlas-duck bogus` exits 2 with exactly one §4.2 usage envelope line
#   * `<AppImage> __cli bogus`, run through the real type-2 runtime (FUSE mount, no display),
#     reaches the cli crate (§12.1): same exit code and byte-identical stdout
#   * (§15 V14) `<AppImage> --autostart-probe` (T11, Linux, CI=true, ATLAS_DUCK_TEST_AUTOSTART_PROBE=1) with a throw-away HOME
#     enables autostart; the generated ~/.config/autostart/atlas-duck.desktop has
#     `Exec=<the AppImage path> --background`, never a /tmp/.mount_* path
#   * (M4 plan Task 26 step 5, CI-04, V14) the M4 section at the end: `<AppImage> __cli doctor`
#     cold-starts `<AppImage> --background` (the CLI's launch plan, never a /tmp/.mount_* path)
#     against a first-run fixture, `jira search` answers `not_configured {first_run}` (exit 9), and a
#     directly started `<AppImage> --background` answers `doctor` with the same gate
#   * (M6 plan Task 33, CI-04 M6 steps) `appimage-smoke.sh --m6 <e2e-artifact-dir>`: the driver-free
#     M6 section on the debug scripted-approver AppImage (see m6_inner below)
#   * (M8 plan Task 28, CI-04 script step) `appimage-smoke.sh --m8 <e2e-artifact-dir>`: one `script run`
#     survives the launching CLI's exit (see the M8 section below)
set -euo pipefail
export LC_ALL=C

# The M4 section runs in a child of this script (`--m4-inner`) inside one xvfb-run and one
# dbus-run-session: the CLI-launched app is a detached grandchild, and xvfb-run would take its
# display away the moment the first CLI call returned (the check of /proc and the second start
# need the app alive in the same session). Defined first so the dispatch below can call it.
m4_fail() { echo "FAIL: $*" >&2; exit 1; }

# m4_json_field <file> <dotted.path>: the value at the path of the CLI's one-line envelope.
m4_json_field() {
  python3 - "$1" "$2" <<'PY'
import json, sys
node = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    node = node[key]
print(node)
PY
}

# m4_stop_app <appimage>: SIGTERM the runtime process (command line `<AppImage> --background`) and
# the app inside the mount, then wait for both to go. M4 has no SIGTERM hook (M6), so the app dies
# by the default action and leaves its endpoint file behind: the caller deletes it.
m4_stop_app() {
  local appimage="$1" i
  pkill -TERM -f -x -- "$appimage --background" || true
  pkill -TERM -x atlas-duck-app || true
  for i in $(seq 1 100); do
    if ! pgrep -f -x -- "$appimage --background" >/dev/null && ! pgrep -x atlas-duck-app >/dev/null; then return 0; fi
    sleep 0.1
  done
  pkill -KILL -x atlas-duck-app || true
  pkill -KILL -f -x -- "$appimage --background" || true
  sleep 1
}

m4_inner() {
  local appimage="$1" data="$2" work="$3" code pid cmdline gate1 gate2 i
  unset APPIMAGE_EXTRACT_AND_RUN
  # Expanded now: the EXIT trap runs after this function returned, when the local is gone (set -u).
  trap "m4_stop_app \"$appimage\" || true" EXIT

  # (a) cold start through `__cli`: the CLI finds `$APPIMAGE` (set by the type-2 runtime), starts
  # `$APPIMAGE --background` detached and answers once the endpoint is up.
  set +e
  timeout 180 "$appimage" __cli --timeout 120 doctor >"$work/doctor1.json" 2>"$work/doctor1.err"
  code=$?
  set -e
  if [ "$code" -ne 0 ]; then
    cat "$work/doctor1.json" "$work/doctor1.err" >&2 || true
    m4_fail "<AppImage> __cli doctor (cold start) exited $code, expected 0"
  fi
  gate1="$(m4_json_field "$work/doctor1.json" data.app.gate)" || m4_fail "doctor 1 has no data.app.gate: $(cat "$work/doctor1.json")"
  [ "$gate1" = first_run ] || m4_fail "doctor 1 gate is '$gate1', expected first_run: $(cat "$work/doctor1.json")"
  echo "M4 cold start: doctor exit 0, gate=$gate1"

  # What the CLI launched: the runtime process, whose command line is the AppImage path plus
  # --background (§4.7), never a /tmp/.mount_* path.
  pid="$(pgrep -f -x -- "$appimage --background" | head -n 1 || true)"
  if [ -z "$pid" ]; then
    ps -eo pid,ppid,args | grep -i -E 'atlas|AppImage|mount_' >&2 || true
    m4_fail "no process with the command line '$appimage --background' after the cold start"
  fi
  cmdline="$(tr '\0' ' ' </proc/"$pid"/cmdline | sed 's/ $//')"
  echo "V14 launched=$cmdline"
  case "$cmdline" in
    /tmp/.mount_*) m4_fail "the launched command line points into the AppImage mount ($cmdline)" ;;
  esac
  [ "$cmdline" = "$appimage --background" ] || m4_fail "the launched command line is '$cmdline', expected '$appimage --background' (§4.7)"

  # (b) no store yet: every op is not_configured {first_run}, exit 9.
  set +e
  timeout 60 "$appimage" __cli jira search 'project=A' --timeout 20 >"$work/search.json" 2>"$work/search.err"
  code=$?
  set -e
  [ "$code" -eq 9 ] || m4_fail "<AppImage> __cli jira search exited $code, expected 9; stdout: $(cat "$work/search.json")"
  grep -qF '"code":"not_configured"' "$work/search.json" || m4_fail "jira search envelope lacks code not_configured: $(cat "$work/search.json")"
  grep -qF 'first_run' "$work/search.json" || m4_fail "jira search envelope lacks first_run: $(cat "$work/search.json")"
  echo "M4 jira search: exit 9 not_configured first_run"

  # (c) quit, then start the app DIRECTLY (what autostart and a user do) and talk to it.
  m4_stop_app "$appimage"
  rm -f "$data/endpoint"
  "$appimage" --background >"$work/app2.log" 2>&1 &
  for i in $(seq 1 600); do
    if [ -e "$data/endpoint" ]; then break; fi
    sleep 0.1
  done
  if [ ! -e "$data/endpoint" ]; then
    cat "$work/app2.log" >&2 || true
    m4_fail "the directly started app never wrote $data/endpoint within 60 s"
  fi
  set +e
  timeout 120 "$appimage" __cli --timeout 60 doctor >"$work/doctor2.json" 2>"$work/doctor2.err"
  code=$?
  set -e
  if [ "$code" -ne 0 ]; then
    cat "$work/doctor2.json" "$work/doctor2.err" "$work/app2.log" >&2 || true
    m4_fail "doctor against the directly started app exited $code, expected 0"
  fi
  gate2="$(m4_json_field "$work/doctor2.json" data.app.gate)" || m4_fail "doctor 2 has no data.app.gate: $(cat "$work/doctor2.json")"
  [ "$gate2" = "$gate1" ] || m4_fail "doctor 2 gate is '$gate2', expected $gate1"
  echo "M4 direct start: doctor exit 0, gate=$gate2"
}

# --- M6 section (CI-04 M6 steps, driver-free) ----------------------------------------------------
# Runs against the DEBUG `scripted-approver` AppImage of the bundle-linux-e2e artifact, which takes
# its base folders from ATLAS_DUCK_TEST_HOME (PD-01), so nothing here touches the runner's passwd home.
# No WebDriver (M6 CI ruling, task cifix6): WebKitWebDriver cannot drive the wizard on Linux, so the
# wizard, Install CLI to PATH and what depends on it (cli.toml app_path, the ~/.local/bin wrapper and
# its doctor cold start, the moved AppImage's exit 5) are rows of docs/release/linux-gui-checklist.md;
# ci/gui-no-driver.sh says why. What runs here, through the real type-2 runtime (FUSE mount) on a
# pinned data dir with no store: ci/gui-no-driver.sh (no tray host, a cold start that maps the Setup
# window, `<AppImage> __cli doctor`, forwarded no-argument and `--background` launches, SIGTERM, a
# clean next start). The M4 section above covers `__cli`'s cold start of `<AppImage> --background`.
m6_inner() {
  local appimage="$1" here="$2" work="$3"
  unset APPIMAGE_EXTRACT_AND_RUN
  trap "m4_stop_app \"$appimage\" || true; pkill -x gnome-keyring-d || true" EXIT
  # A file-backed Secret Service, unlocked as ci/keyring-ci.sh does: the host shape of a real install
  # (the scripted-approver build uses its own file keystore).
  if command -v gnome-keyring-daemon >/dev/null; then
    printf 'atlas-duck-ci' | gnome-keyring-daemon --components=secrets --daemonize --unlock >/dev/null || echo "M6: keyring daemon did not start (continuing)"
  fi
  bash "$here/gui-no-driver.sh" appimage-m6 "$work" "$appimage" "$appimage" __cli
}

# m6_save_diag <work>: copies the diag log, the app logs and the doctor answers to $E2E_DIAG_DIR (the
# workflow prints and uploads it) before the EXIT trap deletes <work>.
m6_save_diag() {
  local work="$1" f
  [ -n "${E2E_DIAG_DIR:-}" ] || return 0
  mkdir -p "$E2E_DIAG_DIR" 2>/dev/null || return 0
  while IFS= read -r f; do
    cp "$f" "$E2E_DIAG_DIR/$(echo "${f#"$work"/}" | tr / _)" 2>/dev/null || true
  done < <(find "$work" \( -name diag.log -o -name '*.log' -o -name 'doctor-*.json' -o -name 'doctor-*.err' -o -name doctor.json -o -name run.json -o -name run.err -o -name await.json -o -name await.err \) -type f 2>/dev/null)
}

# m8_save_home_diag <home>: the M8 section's provisioned test home lives outside <work> (the fixture
# makes it under /tmp) and holds the app's diag.log, data/logs and test-control files; copies them to
# $E2E_DIAG_DIR as home_* before the EXIT trap deletes the home. Never fails the trap.
m8_save_home_diag() {
  local home="$1" f
  [ -n "${E2E_DIAG_DIR:-}" ] && [ -n "$home" ] && [ -d "$home" ] || return 0
  mkdir -p "$E2E_DIAG_DIR" 2>/dev/null || return 0
  while IFS= read -r f; do
    cp "$f" "$E2E_DIAG_DIR/home_$(echo "${f#"$home"/}" | tr / _)" 2>/dev/null || true
  done < <(find "$home" \( -name diag.log -o -name '*.log' -o -path '*/logs/*' -o -path '*/test-control/*' \) -type f 2>/dev/null)
  return 0
}

# appimage-smoke.sh --m6 <e2e-artifact-dir>: the M6 section alone, CI only, on the downloaded
# bundle-linux-e2e artifact (appimage/*.AppImage) with libfuse2, xvfb, dbus-x11, x11-utils
# (xwininfo) and the host GL libraries the AppImage does not bundle (libEGL: the job installs
# libwebkit2gtk-4.1-0 for its Depends) installed. The workflow job `appimage-m6` (e2e-bundle.yml).
m6_outer() {
  local e2e_dist work m6_dir m6_code self_path
  e2e_dist="$(realpath "${1:?usage: appimage-smoke.sh --m6 <e2e-artifact-dir>}")"
  self_path="$(realpath "$0")"
  [ "${CI:-}" = true ] || m4_fail "the M6 AppImage section runs only with CI=true"
  command -v xwininfo >/dev/null || m4_fail "xwininfo missing (apt: x11-utils)"
  shopt -s nullglob
  local e2e_images=("$e2e_dist"/appimage/*.AppImage)
  shopt -u nullglob
  [ "${#e2e_images[@]}" -eq 1 ] || m4_fail "expected one AppImage in $e2e_dist/appimage, found ${#e2e_images[@]}"
  work="$(mktemp -d)"
  # Expanded now: the EXIT trap runs after this function returned, when the local is gone (set -u).
  trap "m6_save_diag \"$work\"; pkill -x atlas-duck-app || true; rm -rf \"$work\"" EXIT
  m6_dir="$work/m6"
  mkdir -p "$m6_dir/home" "$m6_dir/keys" "$m6_dir/out"
  cp "${e2e_images[0]}" "$m6_dir/atlas-duck-e2e.AppImage"
  chmod +x "$m6_dir/atlas-duck-e2e.AppImage"
  set +e
  env ATLAS_DUCK_TEST_HOME="$m6_dir/home" ATLAS_DUCK_TEST_KEYSTORE="$m6_dir/keys" \
    timeout 900 xvfb-run -a dbus-run-session -- bash "$self_path" --m6-inner "$m6_dir/atlas-duck-e2e.AppImage" "$(dirname "$self_path")" "$m6_dir/out"
  m6_code=$?
  set -e
  [ "$m6_code" -eq 0 ] || m4_fail "the M6 AppImage section failed (exit $m6_code)"
  echo "OK: M6 AppImage section (driver-free: no tray host, Setup window, __cli doctor, forwarded launches, SIGTERM, clean next start)"
}

# --- M8 section (CI-04 script step) --------------------------------------------------------------
# Runs against the same DEBUG `scripted-approver` AppImage as the M6 section (bundle-linux-e2e), in
# its own xvfb-run + dbus-run-session + keyring, on a test home of its own. What CI-04 asks of the
# script path: one `script run` succeeds AFTER the launching CLI has exited.
#   1. `<AppImage> __cli script run <file> --reason atlas-test:release --timeout 0` (pending, exit 4);
#   2. the CLI process is gone;
#   3. the scripted approver releases the finished run (the directive is in --reason);
#   4. `<AppImage> __cli await <id>` delivers `released`, exit 0;
#   5. the app's executable is not under the CLI's mount: after the CLI exited, exactly one AppImage
#      mount is left (the app's own, the command line of its runtime process names no /tmp/.mount_*
#      path) and the app is still alive. A run whose app lived in the CLI's mount would have been
#      cut off when the CLI's mount went away.
# Steps 1, 3 and 4 need a serving core: a store with one Jira instance, provisioned in the wizard's
# order. No shell step can do that (the wizard is unreachable without a driver, M6 CI ruling; the
# provisioning is in-process Rust), so the bundle job builds the test executable `script_fixture`
# (app/src-tauri/tests/script_fixture.rs) and ships it as <e2e-artifact-dir>/fixture/script_fixture.
# The section runs it once (under Xvfb: the harness wants a display), reads the `home=` and `keys=`
# lines it writes to ATLAS_DUCK_FIXTURE_OUT and starts the app on that test home. A missing fixture
# or a failed provisioning fails the section: it never skips.
# ATLAS_DUCK_M8_CI07=1 (the CI-07 step of e2e-bundle.yml, off until M10) adds the scripts-enabled
# matrix step (ci/script-matrix-step.sh debug).

# m8_mounts: the AppImage mount points that are live now, one per line.
m8_mounts() {
  awk '$2 ~ /^\/tmp\/\.mount_/ { print $2 }' /proc/mounts | sort -u
}

m8_inner() {
  local appimage="$1" here="$2" work="$3" code id status gate pid cmdline i mounts n
  unset APPIMAGE_EXTRACT_AND_RUN
  trap "m4_stop_app \"$appimage\" || true; pkill -x gnome-keyring-d || true" EXIT
  if command -v gnome-keyring-daemon >/dev/null; then
    printf 'atlas-duck-ci' | gnome-keyring-daemon --components=secrets --daemonize --unlock >/dev/null || echo "M8: keyring daemon did not start (continuing)"
  fi
  printf '%s\n' 'return {n: 1 + 1};' > "$work/m8.js"

  # Warm start: the CLI cold-starts `<AppImage> --background` (as the M4 section), so the
  # `--timeout 0` run below finds a serving app.
  set +e
  timeout 180 "$appimage" __cli --timeout 120 doctor >"$work/doctor.json" 2>"$work/doctor.err"
  code=$?
  set -e
  [ "$code" -eq 0 ] || { cat "$work/doctor.json" "$work/doctor.err" >&2 || true; m4_fail "<AppImage> __cli doctor (cold start) exited $code, expected 0"; }
  gate="$(m4_json_field "$work/doctor.json" data.app.gate)" || m4_fail "doctor has no data.app.gate: $(cat "$work/doctor.json")"
  echo "M8 cold start: doctor exit 0, gate=$gate"

  # (1) submit without waiting, through the AppImage's CLI.
  set +e
  timeout 180 "$appimage" __cli script run "$work/m8.js" --reason atlas-test:release --timeout 0 >"$work/run.json" 2>"$work/run.err"
  code=$?
  set -e

  # (2) the CLI is gone (the call above returned; no `__cli script` process is left either).
  if pgrep -f -- "$appimage __cli script" >/dev/null; then
    ps -eo pid,ppid,args | grep -F '__cli' >&2 || true
    m4_fail "a '__cli script' process is still running after script run returned"
  fi
  echo "M8 CLI exited: script run returned with exit $code"

  [ "$code" -eq 4 ] || m4_fail "script run --timeout 0 exited $code, expected 4 (pending); stdout: $(cat "$work/run.json")"
  status="$(m4_json_field "$work/run.json" status)" || m4_fail "script run printed no envelope: $(cat "$work/run.json")"
  [ "$status" = pending ] || m4_fail "script run status is '$status', expected pending: $(cat "$work/run.json")"
  id="$(m4_json_field "$work/run.json" request_id)" || m4_fail "script run has no request_id: $(cat "$work/run.json")"
  # (3, 4) the scripted approver releases the run on its own (the reason is the directive);
  # `await` from a fresh CLI process delivers it.
  set +e
  timeout 240 "$appimage" __cli await "$id" --timeout 180 >"$work/await.json" 2>"$work/await.err"
  code=$?
  set -e
  [ "$code" -eq 0 ] || { cat "$work/await.json" "$work/await.err" >&2 || true; m4_fail "await $id exited $code, expected 0"; }
  status="$(m4_json_field "$work/await.json" status)" || m4_fail "await printed no envelope: $(cat "$work/await.json")"
  [ "$status" = released ] || m4_fail "await status is '$status', expected released: $(cat "$work/await.json")"
  [ "$(m4_json_field "$work/await.json" data.result.n)" = 2 ] || m4_fail "await delivered another result than {n: 2}: $(cat "$work/await.json")"
  echo "M8 script run: submitted pending, released by the scripted approver, await delivered released (exit 0)"

  # (5) the app is not under the CLI's mount.
  pid="$(pgrep -f -x -- "$appimage --background" | head -n 1 || true)"
  [ -n "$pid" ] || m4_fail "no process with the command line '$appimage --background' after the CLI exited"
  cmdline="$(tr '\0' ' ' </proc/"$pid"/cmdline | sed 's/ $//')"
  case "$cmdline" in
    /tmp/.mount_*) m4_fail "the app's runtime command line points into an AppImage mount ($cmdline)" ;;
  esac
  pgrep -x atlas-duck-app >/dev/null || m4_fail "the app is gone after the CLI exited"
  # The CLI's own mounts go away with its processes: poll while they unmount.
  for i in $(seq 1 100); do
    mounts="$(m8_mounts)"
    n="$(printf '%s' "$mounts" | grep -c . || true)"
    [ "$n" -le 1 ] && break
    sleep 0.1
  done
  echo "M8 mounts after the CLI exited: $n (${mounts:-none})"
  [ "$n" -eq 1 ] || m4_fail "expected exactly one live AppImage mount (the app's) after the CLI exited, found $n: $mounts"
  pgrep -x atlas-duck-app >/dev/null || m4_fail "the app died when the CLI's mount went away"
  echo "M8 app executable is not under the CLI's mount: one mount ($mounts), app alive"

  if [ "${ATLAS_DUCK_M8_CI07:-}" = 1 ]; then
    bash "$here/script-matrix-step.sh" debug "$work/ci07" "$appimage" __cli
  fi
}

# appimage-smoke.sh --m8 <e2e-artifact-dir>: the M8 section alone, CI only, on the downloaded
# bundle-linux-e2e artifact, with the packages of the M6 job (`appimage-m6` of e2e-bundle.yml).
m8_outer() {
  local e2e_dist work m8_dir m8_code self_path home keys fixture_src fixture_code
  e2e_dist="$(realpath "${1:?usage: appimage-smoke.sh --m8 <e2e-artifact-dir>}")"
  self_path="$(realpath "$0")"
  [ "${CI:-}" = true ] || m4_fail "the M8 AppImage section runs only with CI=true"
  shopt -s nullglob
  local e2e_images=("$e2e_dist"/appimage/*.AppImage)
  shopt -u nullglob
  [ "${#e2e_images[@]}" -eq 1 ] || m4_fail "expected one AppImage in $e2e_dist/appimage, found ${#e2e_images[@]}"
  work="$(mktemp -d)"
  trap "m6_save_diag \"$work\"; pkill -x atlas-duck-app || true; rm -rf \"$work\"" EXIT
  m8_dir="$work/m8"
  mkdir -p "$m8_dir/out"
  cp "${e2e_images[0]}" "$m8_dir/atlas-duck-e2e.AppImage"
  chmod +x "$m8_dir/atlas-duck-e2e.AppImage"
  # The provisioned test home (a store with one Jira instance): the fixture test executable the
  # bundle job built, run once under Xvfb. Bounded, and a missing file or a failure fails the section.
  fixture_src="$e2e_dist/fixture/script_fixture"
  [ -f "$fixture_src" ] || m4_fail "$fixture_src is missing (the bundle-linux-e2e job builds and ships it)"
  cp "$fixture_src" "$m8_dir/script_fixture"
  chmod +x "$m8_dir/script_fixture"
  # The test executable links the whole app library (webkit2gtk, GTK, appindicator, xdo, ssl, dbus):
  # list every missing host library at once instead of the loader's first error.
  local missing
  missing="$(ldd "$m8_dir/script_fixture" 2>&1 | grep 'not found' || true)"
  if [ -n "$missing" ]; then
    echo "$missing"
    m4_fail "script_fixture has unresolved shared libraries (install the packages providing them on the appimage-m6 job):
$missing"
  fi
  set +e
  env ATLAS_DUCK_FIXTURE_OUT="$m8_dir/fixture.txt" \
    timeout 240 xvfb-run -a dbus-run-session -- "$m8_dir/script_fixture" --ignored --exact provision_script_fixture --nocapture --test-threads=1 >"$m8_dir/fixture.log" 2>&1
  fixture_code=$?
  set -e
  cat "$m8_dir/fixture.log"
  [ "$fixture_code" -eq 0 ] || m4_fail "script_fixture exited $fixture_code"
  grep -qE '^test result: ok\. 1 passed; 0 failed' "$m8_dir/fixture.log" || m4_fail "script_fixture did not run exactly once"
  home="$(sed -n 's/^home=//p' "$m8_dir/fixture.txt" | head -n 1)"
  keys="$(sed -n 's/^keys=//p' "$m8_dir/fixture.txt" | head -n 1)"
  [ -n "$home" ] && [ -d "$home" ] || m4_fail "the fixture's home '$home' is not a directory"
  [ -n "$keys" ] && [ -d "$keys" ] || m4_fail "the fixture's keystore '$keys' is not a directory"
  # The app is stopped first (its logs are final), then the logs of <work> and of the provisioned home
  # are saved, only then both are deleted (the home holds the app's diag.log).
  trap "pkill -x atlas-duck-app || true; m6_save_diag \"$work\"; m8_save_home_diag \"$home\"; rm -rf \"$work\" \"$home\"" EXIT
  set +e
  env ATLAS_DUCK_TEST_HOME="$home" ATLAS_DUCK_TEST_KEYSTORE="$keys" \
    timeout 900 xvfb-run -a dbus-run-session -- bash "$self_path" --m8-inner "$m8_dir/atlas-duck-e2e.AppImage" "$(dirname "$self_path")" "$m8_dir/out"
  m8_code=$?
  set -e
  [ "$m8_code" -eq 0 ] || m4_fail "the M8 AppImage section failed (exit $m8_code)"
  echo "OK: M8 AppImage section (script run after the CLI exited, release, await, app not under the CLI's mount)"
}

if [ "${1:-}" = --m6 ]; then
  m6_outer "${2:-}"
  exit 0
fi
if [ "${1:-}" = --m8 ]; then
  m8_outer "${2:-}"
  exit 0
fi
if [ "${1:-}" = --m8-inner ]; then
  [ "$#" -eq 4 ] || m4_fail "usage: appimage-smoke.sh --m8-inner <appimage> <ci-dir> <work-dir>"
  m8_inner "$2" "$3" "$4"
  exit 0
fi
if [ "${1:-}" = --m4-inner ]; then
  [ "$#" -eq 4 ] || m4_fail "usage: appimage-smoke.sh --m4-inner <appimage> <data-dir> <work-dir>"
  m4_inner "$2" "$3" "$4"
  exit 0
fi
if [ "${1:-}" = --m6-inner ]; then
  [ "$#" -eq 4 ] || m4_fail "usage: appimage-smoke.sh --m6-inner <appimage> <ci-dir> <work-dir>"
  m6_inner "$2" "$3" "$4"
  exit 0
fi
self="$(realpath "$0")"

dist="${1:?usage: ci/appimage-smoke.sh <artifact-dir>}"
sudo_cmd=""
if [ "$(id -u)" -ne 0 ]; then sudo_cmd="sudo"; fi

shopt -s nullglob
debs=("$dist"/deb/*.deb)
appimages=("$dist"/appimage/*.AppImage)
shopt -u nullglob
[ "${#debs[@]}" -eq 1 ] || { echo "FAIL: expected one deb in $dist/deb, found ${#debs[@]}" >&2; exit 1; }
[ "${#appimages[@]}" -eq 1 ] || { echo "FAIL: expected one AppImage in $dist/appimage, found ${#appimages[@]}" >&2; exit 1; }
deb="$(realpath "${debs[0]}")"
appimage="$(realpath "${appimages[0]}")"

$sudo_cmd apt-get update
$sudo_cmd apt-get install -y "$deb"
dpkg-query -W -f='${Package} ${Version}\nDepends: ${Depends}\n' atlas-duck

# assert_usage_envelope <label> <stdout-file> <exit-code>
assert_usage_envelope() {
  local label="$1" file="$2" code="$3" needle
  if [ "$code" -ne 2 ]; then
    echo "FAIL: $label exited $code, expected 2; stdout:" >&2
    cat "$file" >&2
    exit 1
  fi
  if [ "$(wc -l <"$file")" -ne 1 ] || [ -n "$(tail -c 1 "$file" | tr -d '\n')" ]; then
    echo "FAIL: $label printed $(wc -l <"$file") lines on stdout, expected exactly 1:" >&2
    cat "$file" >&2
    exit 1
  fi
  for needle in '"status":"failed"' '"code":"usage"' '"retryable":false' '"request_id":null'; do
    grep -qF "$needle" "$file" || { echo "FAIL: $label envelope lacks $needle: $(cat "$file")" >&2; exit 1; }
  done
  echo "$label: exit 2, envelope $(cat "$file")"
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

set +e
/usr/bin/atlas-duck bogus >"$work/deb.out"
deb_code=$?
set -e
assert_usage_envelope "deb-installed atlas-duck bogus" "$work/deb.out" "$deb_code"

# a copy: the artifact directory may be read-only, and upload-artifact dropped the mode bits
cp "$appimage" "$work/atlas-duck.AppImage"
appimage="$work/atlas-duck.AppImage"
chmod +x "$appimage"
set +e
(cd "$work" && env -u DISPLAY -u WAYLAND_DISPLAY -u APPIMAGE_EXTRACT_AND_RUN "$appimage" __cli bogus >"$work/appimage.out")
app_code=$?
set -e
assert_usage_envelope "AppImage __cli bogus" "$work/appimage.out" "$app_code"

if ! cmp -s "$work/deb.out" "$work/appimage.out"; then
  echo "FAIL: AppImage __cli output differs from the deb-installed atlas-duck output" >&2
  diff "$work/deb.out" "$work/appimage.out" >&2 || true
  exit 1
fi
echo "OK: <AppImage> __cli bogus and the deb-installed atlas-duck bogus print the same usage envelope (exit 2)"

# --- V14: what does tauri-plugin-autostart write for an AppImage? ---------------------------
# The GUI binary needs a display (xvfb-run) and a session bus (single-instance; dbus-run-session
# gives it a private one). HOME and XDG_CONFIG_HOME point into a throw-away directory, so the
# runner's real ~/.config is never touched and the entry is the only file the probe creates.
$sudo_cmd apt-get install -y --no-install-recommends xvfb xauth dbus-x11
probe_home="$work/probe-home"
mkdir -p "$probe_home"
set +e
(cd "$work" && env -u DISPLAY -u WAYLAND_DISPLAY -u APPIMAGE_EXTRACT_AND_RUN \
  HOME="$probe_home" XDG_CONFIG_HOME="$probe_home/.config" CI=true ATLAS_DUCK_TEST_AUTOSTART_PROBE=1 \
  timeout 120 xvfb-run -a dbus-run-session -- "$appimage" --autostart-probe >"$work/probe.out" 2>&1)
probe_code=$?
set -e
if [ "$probe_code" -ne 0 ]; then
  echo "FAIL: <AppImage> --autostart-probe exited $probe_code, expected 0; output:" >&2
  cat "$work/probe.out" >&2
  exit 1
fi

shopt -s nullglob
entries=("$probe_home"/.config/autostart/*.desktop)
shopt -u nullglob
if [ "${#entries[@]}" -ne 1 ]; then
  echo "FAIL: expected one autostart entry under $probe_home/.config/autostart, found ${#entries[@]}; tree:" >&2
  find "$probe_home" >&2
  exit 1
fi
entry="${entries[0]}"
exec_line="$(grep -m1 '^Exec=' "$entry" || true)"
exec_value="${exec_line#Exec=}"
# Evidence lines for T22 (§15 V14); printed before any assertion so a FAIL still leaves them.
echo "V14 autostart_entry=$(basename "$entry")"
echo "V14 autostart_exec=$exec_value"
echo "--- $entry"
cat "$entry"

[ "$(basename "$entry")" = "atlas-duck.desktop" ] || {
  echo "FAIL: the autostart entry is $(basename "$entry"), expected atlas-duck.desktop (Builder::app_name, T11)" >&2
  exit 1
}
case "$exec_value" in
  *"/tmp/.mount_"*)
    echo "FAIL: the autostart Exec points into the AppImage mount ($exec_value): tauri-plugin-autostart did not write \$APPIMAGE (§12.3, §15 V14)" >&2
    exit 1
    ;;
esac
case "$exec_value" in
  "$appimage --background" | "\"$appimage\" --background") ;;
  *)
    echo "FAIL: the autostart Exec is '$exec_value', expected '$appimage --background' (§2.5, §12.3)" >&2
    exit 1
    ;;
esac
echo "OK: <AppImage> --autostart-probe wrote atlas-duck.desktop with Exec=<the AppImage path> --background"

# --- M4 (CI-04, V14): the CLI cold-starts the AppImage ---------------------------------------
# CI only (the fixture below replaces this host's pinned paths file, see ci/pinned-fixture.sh):
# a release build has no test home, so the app reads the passwd home's pinned file, which
# pinned-fixture.sh points at a throw-away local data dir with no database (first-run gate).
if [ "${CI:-}" != "true" ]; then
  echo "SKIP: the M4 AppImage section replaces this host's pinned paths file and runs only with CI=true"
  exit 0
fi
m4_data="$(bash "$(dirname "$self")/pinned-fixture.sh" --data-dir "$work/m4/data")"
passwd_home="$(getent passwd "$(id -un)" | cut -d: -f6)"
trap 'rm -f "$passwd_home"/.config/atlas-duck/paths-*.toml; pkill -x atlas-duck-app || true; rm -rf "$work"' EXIT
mkdir -p "$work/m4-out"
set +e
timeout 600 xvfb-run -a dbus-run-session -- bash "$self" --m4-inner "$appimage" "$m4_data" "$work/m4-out"
m4_code=$?
set -e
[ "$m4_code" -eq 0 ] || m4_fail "the M4 AppImage section failed (exit $m4_code)"
echo "OK: <AppImage> __cli cold-started <AppImage> --background (doctor, first_run), and a direct start answers doctor"
