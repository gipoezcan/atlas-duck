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
#   * (M6 plan Task 33, CI-04 M6 steps) `appimage-smoke.sh --m6 <e2e-artifact-dir>`: the M6 section
#     on the debug scripted-approver AppImage (see m6_inner below for why it is not the release one)
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

# --- M6 section (CI-04 M6 steps) ------------------------------------------------------------------
# Runs against the DEBUG `scripted-approver` AppImage of the bundle-linux-e2e artifact: the release
# AppImage scrubs the WebDriver variables from its environment (§2.5, S-04) and tauri-driver cannot
# drive it, so "through tauri-driver" needs this build. The wrapper, `cli.toml` and `$APPIMAGE`
# logic is the same code in both builds. The scripted build needs ATLAS_DUCK_TEST_HOME and uses the
# file keystore (ATLAS_DUCK_TEST_KEYSTORE); the Secret Service below is unlocked as ci/keyring-ci.sh
# does and keeps the shape of a real install.
#   1. the wizard through tauri-driver (default data dir, passphrase twice, skip instances) and
#      "Install CLI to PATH" on its CLI step
#   2. `cli.toml` `app_path` is the AppImage file, never a /tmp/.mount_* path; the wrapper exists
#   3. `doctor` through the wrapper cold-starts `<AppImage> --background` (alive, not under the mount)
#   4. the AppImage moved: the wrapper exits 5 `not_running` with the re-install hint
# NOT covered here (needs a mock Jira, a configured instance and a token, which the Rust e2e target
# provides): releasing a request through the Approvals window and `await`; the Linux `e2e` job runs
# that flow (ui06) against the same drive code.
m6_inner() {
  local appimage="$1" tools="$2" here="$3" work="$4" passwd_home wrapper cli_toml app_path code line cmdline pid gate
  unset APPIMAGE_EXTRACT_AND_RUN
  trap "m4_stop_app \"$appimage\" || true; pkill -x gnome-keyring-d || true" EXIT
  passwd_home="$(getent passwd "$(id -un)" | cut -d: -f6)"
  if command -v gnome-keyring-daemon >/dev/null; then
    printf 'atlas-duck-ci' | gnome-keyring-daemon --components=secrets --daemonize --unlock >/dev/null || echo "M6: keyring daemon did not start (continuing)"
  fi

  python3 -I "$here/e2e-drive.py" wizard --app "$appimage" --driver "$tools/tauri-driver" \
    --driver-log "$work/wizard-driver.log" --cli-install || { tail -n 40 "$work/wizard-driver.log" >&2 || true; m4_fail "the wizard through tauri-driver failed"; }
  echo "M6 wizard: completed through tauri-driver, Install CLI to PATH pressed"

  # The wizard session ended the app; stop anything left before the wrapper cold-starts one.
  m4_stop_app "$appimage"

  cli_toml=""
  for d in "$ATLAS_DUCK_TEST_HOME" "$passwd_home/.config/atlas-duck"; do
    cli_toml="$(find "$d" -name 'cli*.toml' -type f 2>/dev/null | head -n 1 || true)"
    [ -n "$cli_toml" ] && break
  done
  [ -n "$cli_toml" ] || m4_fail "no cli.toml under $ATLAS_DUCK_TEST_HOME or $passwd_home/.config/atlas-duck after Install CLI to PATH"
  echo "--- $cli_toml"; cat "$cli_toml"
  app_path="$(sed -n "s/^app_path *= *['\"]\(.*\)['\"] *$/\1/p" "$cli_toml" | head -n 1)"
  echo "V14 cli_toml_app_path=$app_path"
  case "$app_path" in
    /tmp/.mount_*) m4_fail "cli.toml app_path points into the AppImage mount ($app_path)" ;;
  esac
  [ "$app_path" = "$appimage" ] || m4_fail "cli.toml app_path is '$app_path', expected '$appimage'"

  wrapper=""
  for d in "$ATLAS_DUCK_TEST_HOME" "$passwd_home"; do
    if [ -x "$d/.local/bin/atlas-duck" ]; then wrapper="$d/.local/bin/atlas-duck"; break; fi
  done
  [ -n "$wrapper" ] || m4_fail "no executable ~/.local/bin/atlas-duck wrapper after Install CLI to PATH"
  grep -qF '# atlas-duck-cli-wrapper v1' "$wrapper" || m4_fail "$wrapper has no wrapper marker"

  set +e
  timeout 180 "$wrapper" doctor --timeout 120 >"$work/m6-doctor.json" 2>"$work/m6-doctor.err"
  code=$?
  set -e
  if [ "$code" -ne 0 ]; then
    cat "$work/m6-doctor.json" "$work/m6-doctor.err" >&2 || true
    m4_fail "doctor through the wrapper exited $code, expected 0"
  fi
  gate="$(m4_json_field "$work/m6-doctor.json" data.app.gate)" || m4_fail "doctor through the wrapper has no data.app.gate: $(cat "$work/m6-doctor.json")"
  # After a completed wizard the gate is never first_run: the app the wrapper cold-started reads the
  # store the wizard created under the same data dir.
  [ -n "$gate" ] && [ "$gate" != first_run ] || m4_fail "doctor through the wrapper reports gate '$gate' after the wizard (the store was not seen)"
  echo "M6 wrapper: doctor exit 0, gate=$gate"

  pid="$(pgrep -f -x -- "$appimage --background" | head -n 1 || true)"
  [ -n "$pid" ] || m4_fail "no process '$appimage --background' after the wrapper's cold start"
  cmdline="$(tr '\0' ' ' </proc/"$pid"/cmdline | sed 's/ $//')"
  echo "V14 wrapper_launched=$cmdline"
  case "$cmdline" in
    /tmp/.mount_*) m4_fail "the wrapper-launched command line points into the AppImage mount ($cmdline)" ;;
  esac
  [ "$cmdline" = "$appimage --background" ] || m4_fail "the wrapper-launched command line is '$cmdline', expected '$appimage --background'"
  kill -0 "$pid" || m4_fail "the cold-started app is not alive"

  # The CLI that launched the app has exited: a second call through the wrapper must reach the same
  # instance (CI-04: the app outlives the CLI that started it).
  set +e
  timeout 120 "$wrapper" doctor --timeout 60 >"$work/m6-doctor2.json" 2>"$work/m6-doctor2.err"
  code=$?
  set -e
  if [ "$code" -ne 0 ]; then
    cat "$work/m6-doctor2.json" "$work/m6-doctor2.err" >&2 || true
    m4_fail "the second doctor through the wrapper (after the launching CLI exited) exited $code, expected 0"
  fi
  [ "$(pgrep -f -x -- "$appimage --background" | head -n 1 || true)" = "$pid" ] || m4_fail "the second doctor started another app instead of reaching pid $pid"
  echo "M6 wrapper: a second doctor after the launching CLI exited reached the same app, exit 0"

  # The AppImage moves: the wrapper exits 5 with the not_running envelope and the re-install hint.
  m4_stop_app "$appimage"
  mv "$appimage" "$appimage.moved"
  set +e
  "$wrapper" doctor >"$work/m6-moved.json" 2>"$work/m6-moved.err"
  code=$?
  set -e
  mv "$appimage.moved" "$appimage"
  [ "$code" -eq 5 ] || m4_fail "the wrapper with the AppImage moved exited $code, expected 5; stdout: $(cat "$work/m6-moved.json")"
  grep -qF '"reason":"not_running"' "$work/m6-moved.json" || m4_fail "moved-AppImage envelope lacks details.reason not_running: $(cat "$work/m6-moved.json")"
  grep -qF 're-run Install CLI to PATH' "$work/m6-moved.json" || m4_fail "moved-AppImage envelope lacks the re-install hint: $(cat "$work/m6-moved.json")"
  echo "M6 moved AppImage: exit 5 not_running with the re-install hint"
}

# m6_save_diag <work>: copies the diag log and the driver logs to $E2E_DIAG_DIR (the workflow prints and
# uploads it on failure) before the EXIT trap deletes <work>.
m6_save_diag() {
  local work="$1" f
  [ -n "${E2E_DIAG_DIR:-}" ] || return 0
  mkdir -p "$E2E_DIAG_DIR" 2>/dev/null || return 0
  while IFS= read -r f; do
    cp "$f" "$E2E_DIAG_DIR/$(echo "${f#"$work"/}" | tr / _)" 2>/dev/null || true
  done < <(find "$work" \( -name diag.log -o -name '*.log' -o -name 'm6-*.json' -o -name 'm6-*.err' \) -type f 2>/dev/null)
}

# appimage-smoke.sh --m6 <e2e-artifact-dir>: the M6 section alone, CI only, on the downloaded
# bundle-linux-e2e artifact (appimage/*.AppImage, tools/tauri-driver) with libfuse2, xvfb, dbus-x11 and
# webkit2gtk-driver (WebKitWebDriver) installed. The workflow job `appimage-m6` (e2e-bundle.yml).
m6_outer() {
  local e2e_dist work m6_dir m6_code self_path
  e2e_dist="$(realpath "${1:?usage: appimage-smoke.sh --m6 <e2e-artifact-dir>}")"
  self_path="$(realpath "$0")"
  [ "${CI:-}" = true ] || m4_fail "the M6 AppImage section runs only with CI=true"
  command -v WebKitWebDriver >/dev/null || m4_fail "WebKitWebDriver missing (apt: webkit2gtk-driver)"
  shopt -s nullglob
  local e2e_images=("$e2e_dist"/appimage/*.AppImage)
  shopt -u nullglob
  [ "${#e2e_images[@]}" -eq 1 ] || m4_fail "expected one AppImage in $e2e_dist/appimage, found ${#e2e_images[@]}"
  [ -f "$e2e_dist/tools/tauri-driver" ] || m4_fail "no tools/tauri-driver in $e2e_dist"
  chmod +x "$e2e_dist/tools/tauri-driver"
  work="$(mktemp -d)"
  # Expanded now: the EXIT trap runs after this function returned, when the local is gone (set -u).
  trap "m6_save_diag \"$work\"; pkill -x atlas-duck-app || true; rm -rf \"$work\"" EXIT
  m6_dir="$work/m6"
  mkdir -p "$m6_dir/home" "$m6_dir/keys" "$m6_dir/out"
  cp "${e2e_images[0]}" "$m6_dir/atlas-duck-e2e.AppImage"
  chmod +x "$m6_dir/atlas-duck-e2e.AppImage"
  # The host's WebKitWebDriver drives the WebKit the AppImage bundles: both versions are printed, as
  # "Failed to match capabilities" may be a mismatch between them.
  WebKitWebDriver --version || true
  dpkg-query -W webkit2gtk-driver libwebkit2gtk-4.1-0 || true
  (cd "$work" && "$m6_dir/atlas-duck-e2e.AppImage" --appimage-extract '*libwebkit2gtk*' >/dev/null 2>&1 &&
    find squashfs-root -name 'libwebkit2gtk*' -print && rm -rf squashfs-root) || echo "appimage-m6: could not list the bundled WebKit"
  set +e
  env ATLAS_DUCK_TEST_HOME="$m6_dir/home" ATLAS_DUCK_TEST_KEYSTORE="$m6_dir/keys" ATLAS_DUCK_E2E_ALLOW_DRIVER=1 \
    timeout 900 xvfb-run -a dbus-run-session -- bash "$self_path" --m6-inner "$m6_dir/atlas-duck-e2e.AppImage" "$e2e_dist/tools" "$(dirname "$self_path")" "$m6_dir/out"
  m6_code=$?
  set -e
  [ "$m6_code" -eq 0 ] || m4_fail "the M6 AppImage section failed (exit $m6_code)"
  echo "OK: M6 AppImage section (wizard and Install CLI to PATH through tauri-driver, cli.toml, wrapper doctor, moved AppImage exit 5)"
}

if [ "${1:-}" = --m6 ]; then
  m6_outer "${2:-}"
  exit 0
fi
if [ "${1:-}" = --m4-inner ]; then
  [ "$#" -eq 4 ] || m4_fail "usage: appimage-smoke.sh --m4-inner <appimage> <data-dir> <work-dir>"
  m4_inner "$2" "$3" "$4"
  exit 0
fi
if [ "${1:-}" = --m6-inner ]; then
  [ "$#" -eq 5 ] || m4_fail "usage: appimage-smoke.sh --m6-inner <appimage> <tools-dir> <ci-dir> <work-dir>"
  m6_inner "$2" "$3" "$4" "$5"
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
