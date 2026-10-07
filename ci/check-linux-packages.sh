#!/usr/bin/env bash
# ci/check-linux-packages.sh <bundle-dir>
#
# Checks the .deb, .rpm and AppImage that `cargo tauri build --bundles deb,rpm,appimage`
# wrote under <bundle-dir> (target/<triple>/release/bundle, or the downloaded
# bundle-x86_64-unknown-linux-gnu artifact with deb/, rpm/, appimage/) - spec §12.1, §12.2, §13:
#   * deb and rpm install exactly atlas-duck, atlas-duck-app, atlas-duck-sandbox in /usr/bin
#   * deb, rpm and AppImage ship exactly one launcher, /usr/share/applications/atlas-duck.desktop,
#     whose only Exec line is `Exec=atlas-duck-app` (no arguments), equal to the repository file
#   * the AppImage embeds that launcher (also at the AppDir root) and the three bins in usr/bin
# Run from the repository root. Needs dpkg-deb, rpm, rpm2cpio, cpio.
set -euo pipefail
export LC_ALL=C

bundle_dir="${1:?usage: ci/check-linux-packages.sh <bundle-dir>}"
template="app/src-tauri/linux/atlas-duck.desktop"
launcher="atlas-duck.desktop"
expected_exec="Exec=atlas-duck-app"
expected_bins=$'atlas-duck\natlas-duck-app\natlas-duck-sandbox'
expected_paths=(
  /usr/bin/atlas-duck-app
  /usr/bin/atlas-duck
  /usr/bin/atlas-duck-sandbox
  /usr/share/applications/atlas-duck.desktop
)

failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# only_file <dir> <glob>: prints the single match, exits 1 otherwise.
only_file() {
  local dir="$1" pattern="$2"
  local matches
  shopt -s nullglob
  # shellcheck disable=SC2206 # the pattern is a glob on purpose
  matches=("$dir"/$pattern)
  shopt -u nullglob
  if [ "${#matches[@]}" -ne 1 ]; then
    echo "FAIL: expected exactly one $pattern in $dir, found ${#matches[@]}" >&2
    exit 1
  fi
  realpath "${matches[0]}"
}

# check_desktop <file> <label>
check_desktop() {
  local file="$1" label="$2" execs
  if [ ! -f "$file" ]; then
    fail "$label: $file is missing"
    return
  fi
  [ "$(head -n 1 "$file")" = "[Desktop Entry]" ] || fail "$label: first line is not [Desktop Entry]"
  execs="$(grep -E '^Exec=' "$file" || true)"
  [ "$execs" = "$expected_exec" ] ||
    fail "$label: Exec line(s) '${execs//$'\n'/ | }', expected exactly '$expected_exec' (no arguments)"
  if grep -qE '^NoDisplay=true' "$file"; then
    fail "$label: the launcher is hidden (NoDisplay=true)"
  fi
  # linuxdeploy may add X-AppImage-* keys to the copy it embeds; nothing else may differ.
  if ! diff <(grep -v '^X-AppImage-' "$template") <(grep -v '^X-AppImage-' "$file") >&2; then
    fail "$label: launcher differs from $template"
  fi
}

# check_tree <root> <label> <exact|contains>
check_tree() {
  local root="$1" label="$2" mode="$3" bins apps b
  bins="$(ls -1A "$root/usr/bin" 2>/dev/null | sort || true)"
  echo "$label usr/bin: ${bins//$'\n'/ }"
  if [ "$mode" = exact ]; then
    [ "$bins" = "$expected_bins" ] ||
      fail "$label: usr/bin holds '${bins//$'\n'/ }', expected exactly '${expected_bins//$'\n'/ }'"
  else
    for b in atlas-duck atlas-duck-app atlas-duck-sandbox; do
      [ -x "$root/usr/bin/$b" ] || fail "$label: usr/bin/$b is missing or not executable"
    done
  fi
  apps="$(ls -1A "$root/usr/share/applications" 2>/dev/null | sort || true)"
  echo "$label usr/share/applications: ${apps//$'\n'/ }"
  [ "$apps" = "$launcher" ] ||
    fail "$label: usr/share/applications holds '${apps//$'\n'/ }', expected exactly $launcher"
  check_desktop "$root/usr/share/applications/$launcher" "$label"
}

# check_listing <label> <listing>: every expected path appears as a full line.
check_listing() {
  local label="$1" listing="$2" p
  for p in "${expected_paths[@]}"; do
    grep -qxF "$p" <<<"$listing" || fail "$label: package listing lacks $p"
  done
}

[ -f "$template" ] || { echo "FAIL: run from the repository root ($template not found)" >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- .deb ---------------------------------------------------------------------------
deb="$(only_file "$bundle_dir/deb" '*.deb')"
echo "deb: $deb"
dpkg-deb -f "$deb" Package Version Depends
# The tauri deb lists members without a leading "./"; normalise both spellings to "/path".
check_listing "deb" "$(dpkg-deb --fsys-tarfile "$deb" | tar -t | sed -E 's|^(\./)?/?|/|')"
mkdir "$work/deb"
dpkg-deb -x "$deb" "$work/deb"
check_tree "$work/deb" "deb" exact

# --- .rpm ---------------------------------------------------------------------------
rpm_file="$(only_file "$bundle_dir/rpm" '*.rpm')"
echo "rpm: $rpm_file"
rpm -qp --queryformat 'Name: %{NAME}\nVersion: %{VERSION}-%{RELEASE}\n' "$rpm_file"
echo "rpm requires:"
rpm -qp --requires "$rpm_file" | sed 's/^/  /'
check_listing "rpm" "$(rpm -qlp "$rpm_file")"
mkdir "$work/rpm"
# rpm2cpio of Ubuntu 22.04 exits 1 on this rpm although it writes the whole archive (tauri's
# rpm writer), so only cpio's status counts here; check_tree below proves the extraction.
if ! (cd "$work/rpm" && { rpm2cpio "$rpm_file" || true; } | cpio -idm --quiet --no-absolute-filenames); then
  echo "FAIL: rpm: could not extract $rpm_file with rpm2cpio | cpio" >&2
  exit 1
fi
check_tree "$work/rpm" "rpm" exact

# --- AppImage -----------------------------------------------------------------------
appimage="$(only_file "$bundle_dir/appimage" '*.AppImage')"
echo "AppImage: $appimage"
chmod +x "$appimage"
mkdir "$work/appimage"
if ! (cd "$work/appimage" && "$appimage" --appimage-extract >/dev/null); then
  echo "FAIL: AppImage: --appimage-extract failed" >&2
  exit 1
fi
appdir="$work/appimage/squashfs-root"
root_launchers="$(cd "$appdir" && ls -1A -- *.desktop 2>/dev/null | sort || true)"
[ "$root_launchers" = "$launcher" ] ||
  fail "AppImage: AppDir root launchers are '${root_launchers//$'\n'/ }', expected exactly $launcher"
check_desktop "$appdir/$launcher" "AppImage (AppDir root)"
check_tree "$appdir" "AppImage" contains

if [ "$failures" -ne 0 ]; then
  echo "check-linux-packages: $failures failure(s)" >&2
  exit 1
fi
echo "OK: deb, rpm and AppImage ship the three bins and exactly one atlas-duck.desktop with '$expected_exec'"
