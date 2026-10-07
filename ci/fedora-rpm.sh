#!/usr/bin/env bash
# ci/fedora-rpm.sh <artifact-dir>
#
# Runs as root inside the fedora:40 container (bundle.yml job `fedora-rpm`), on the downloaded
# bundle-x86_64-unknown-linux-gnu artifact (<artifact-dir>/rpm/*.rpm, <artifact-dir>/appimage/*.AppImage).
#   * `dnf install` of the built rpm succeeds: every rpm Requires name (webkit2gtk4.1,
#     libayatana-appindicator-gtk3 and the sonames tauri-cli adds) resolves on Fedora 40 (§12.2, §15 V32)
#   * the installed `atlas-duck bogus` exits 2 and prints exactly one §4.2 usage envelope line
#   * the AppImage runtime starts on Fedora 40 (extract-and-run: the container has no FUSE) and
#     `<AppImage> __cli bogus` prints the same bytes with the same exit code (§12.1, §15 V32)
set -euo pipefail
export LC_ALL=C

dist="${1:?usage: ci/fedora-rpm.sh <artifact-dir>}"

if ! grep -qx 'VERSION_ID=40' /etc/os-release; then
  echo "FAIL: this script expects Fedora 40:" >&2
  cat /etc/os-release >&2
  exit 1
fi

shopt -s nullglob
rpms=("$dist"/rpm/*.rpm)
appimages=("$dist"/appimage/*.AppImage)
shopt -u nullglob
[ "${#rpms[@]}" -eq 1 ] || { echo "FAIL: expected one rpm in $dist/rpm, found ${#rpms[@]}" >&2; exit 1; }
[ "${#appimages[@]}" -eq 1 ] || { echo "FAIL: expected one AppImage in $dist/appimage, found ${#appimages[@]}" >&2; exit 1; }
rpm_file="$(realpath "${rpms[0]}")"
appimage="$(realpath "${appimages[0]}")"

# Fedora 40 is past end of life; when its mirrors are gone, use the archive.
use_archive_repos() {
  echo "Fedora 40 mirrors unavailable; switching to archives.fedoraproject.org" >&2
  sed -i \
    -e 's|^metalink=|#metalink=|' \
    -e 's|^#baseurl=http://download.example/pub/fedora/linux|baseurl=https://archives.fedoraproject.org/pub/archive/fedora/linux|' \
    /etc/yum.repos.d/fedora.repo /etc/yum.repos.d/fedora-updates.repo
  if [ -f /etc/yum.repos.d/fedora-cisco-openh264.repo ]; then
    sed -i 's|^enabled=1|enabled=0|' /etc/yum.repos.d/fedora-cisco-openh264.repo
  fi
}
if ! dnf -y makecache; then
  use_archive_repos
  dnf -y makecache
fi
dnf -y install diffutils

echo "rpm requires:"
rpm -qp --requires "$rpm_file" | sed 's/^/  /'
if ! dnf -y install "$rpm_file"; then
  dnf repolist -v || true
  echo "FAIL: dnf could not install $rpm_file; an rpm Requires entry does not resolve on Fedora 40" >&2
  exit 1
fi
rpm -q atlas-duck

for b in atlas-duck-app atlas-duck atlas-duck-sandbox; do
  [ -x "/usr/bin/$b" ] || { echo "FAIL: /usr/bin/$b missing after install" >&2; exit 1; }
done
[ -f /usr/share/applications/atlas-duck.desktop ] ||
  { echo "FAIL: /usr/share/applications/atlas-duck.desktop missing after install" >&2; exit 1; }

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
/usr/bin/atlas-duck bogus >"$work/rpm.out"
rpm_code=$?
set -e
assert_usage_envelope "rpm-installed atlas-duck bogus" "$work/rpm.out" "$rpm_code"

# a copy: the artifact directory may be read-only, and upload-artifact dropped the mode bits
cp "$appimage" "$work/atlas-duck.AppImage"
appimage="$work/atlas-duck.AppImage"
chmod +x "$appimage"
set +e
(cd "$work" && env -u DISPLAY -u WAYLAND_DISPLAY APPIMAGE_EXTRACT_AND_RUN=1 "$appimage" __cli bogus >"$work/appimage.out")
app_code=$?
set -e
assert_usage_envelope "AppImage __cli bogus (Fedora 40, extract-and-run)" "$work/appimage.out" "$app_code"
if ! cmp -s "$work/rpm.out" "$work/appimage.out"; then
  echo "FAIL: AppImage __cli output differs from the rpm-installed atlas-duck output" >&2
  diff "$work/rpm.out" "$work/appimage.out" >&2 || true
  exit 1
fi

echo "OK: Fedora 40 installs the rpm, atlas-duck and the AppImage __cli path print the same usage envelope (exit 2)"
