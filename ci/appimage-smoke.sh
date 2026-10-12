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
  trap 'm4_stop_app "$appimage" || true' EXIT

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

if [ "${1:-}" = --m4-inner ]; then
  [ "$#" -eq 4 ] || m4_fail "usage: appimage-smoke.sh --m4-inner <appimage> <data-dir> <work-dir>"
  m4_inner "$2" "$3" "$4"
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
