#!/usr/bin/env bash
# ci/check-installers.sh <bundle-dir>
#
# CI-06 package inspection for the Linux packages (spec §12.5, §12.2, L35), run after
# `cargo tauri build --bundles deb,rpm,appimage` from the repository root:
#   * deb: `dpkg-deb -e` extracts the maintainer scripts; none may remove or purge anything under a
#     home, /var/lib, a config dir or the data/config folder name
#   * rpm: `rpm -qp --scripts` likewise
#   * the .desktop launcher is present in the deb, the rpm and the AppImage (--appimage-extract)
# The decision logic is ci/check-installers-lib.mjs (tested by ci/check-installers.test.mjs); this
# wrapper only extracts the package parts. Needs node, dpkg-deb, rpm; the AppImage is extracted, not run
# beyond its own --appimage-extract.
set -euo pipefail
export LC_ALL=C

bundle_dir="${1:?usage: ci/check-installers.sh <bundle-dir>}"
lib="ci/check-installers-lib.mjs"
paths_rs="crates/ipc/src/paths/mod.rs"
launcher="usr/share/applications/atlas-duck.desktop"

[ -f "$lib" ] || { echo "FAIL: run from the repository root ($lib not found)" >&2; exit 1; }

failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

only_file() {
  local dir="$1" pattern="$2" matches
  shopt -s nullglob
  # shellcheck disable=SC2206 # the pattern is a glob on purpose
  matches=("$dir"/$pattern)
  shopt -u nullglob
  if [ "${#matches[@]}" -ne 1 ]; then
    echo "FAIL: expected exactly one $pattern in $dir, found ${#matches[@]}" >&2
    exit 1
  fi
  echo "${matches[0]}"
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- .deb ---------------------------------------------------------------------------
deb="$(only_file "$bundle_dir/deb" '*.deb')"
echo "deb: $deb"
mkdir "$work/deb-control"
dpkg-deb -e "$deb" "$work/deb-control"
echo "deb control files: $(ls -1A "$work/deb-control" | tr '\n' ' ')"
scripts=()
for name in preinst postinst prerm postrm config; do
  [ -f "$work/deb-control/$name" ] && scripts+=("$work/deb-control/$name")
done
if [ "${#scripts[@]}" -gt 0 ]; then
  node "$lib" deb "$paths_rs" "${scripts[@]}" || fail "deb maintainer scripts"
else
  node "$lib" deb "$paths_rs" || fail "deb maintainer scripts"
fi
dpkg-deb --fsys-tarfile "$deb" | tar -t | sed -E 's|^(\./)?/?||' | grep -qxF "$launcher" ||
  fail "deb lacks /$launcher"

# --- .rpm ---------------------------------------------------------------------------
rpm_file="$(only_file "$bundle_dir/rpm" '*.rpm')"
echo "rpm: $rpm_file"
rpm -qp --scripts "$rpm_file" >"$work/rpm-scripts.txt"
echo "rpm --scripts output ($(wc -l <"$work/rpm-scripts.txt" | tr -d ' ') lines):"
sed 's/^/  /' "$work/rpm-scripts.txt"
node "$lib" rpm "$paths_rs" "$work/rpm-scripts.txt" || fail "rpm scriptlets"
rpm -qlp "$rpm_file" | grep -qxF "/$launcher" || fail "rpm lacks /$launcher"

# --- AppImage -----------------------------------------------------------------------
appimage="$(only_file "$bundle_dir/appimage" '*.AppImage')"
echo "AppImage: $appimage"
chmod +x "$appimage"
mkdir "$work/appimage"
if (cd "$work/appimage" && "$appimage" --appimage-extract >/dev/null); then
  [ -f "$work/appimage/squashfs-root/$launcher" ] || fail "AppImage lacks $launcher"
else
  fail "AppImage: --appimage-extract failed"
fi

if [ "$failures" -ne 0 ]; then
  echo "check-installers: $failures failure(s)" >&2
  exit 1
fi
echo "OK: no deb or rpm script removes user data; deb, rpm and AppImage ship atlas-duck.desktop"
