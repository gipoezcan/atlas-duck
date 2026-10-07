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
#   * (§15 V14) `<AppImage> --autostart-probe` (T11, Linux, CI=true) with a throw-away HOME
#     enables autostart; the generated ~/.config/autostart/atlas-duck.desktop has
#     `Exec=<the AppImage path> --background`, never a /tmp/.mount_* path
set -euo pipefail
export LC_ALL=C

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
  HOME="$probe_home" XDG_CONFIG_HOME="$probe_home/.config" CI=true \
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
