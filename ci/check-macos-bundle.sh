#!/usr/bin/env bash
# ci/check-macos-bundle.sh <dmg-dir> <arm64|x86_64>
#
# Checks the .dmg that `cargo tauri build --bundles app,dmg --target <triple>` wrote into
# <dmg-dir> (target/<triple>/release/bundle/dmg) - spec §12.1, §12.2, §2.5:
#   * the .app inside the dmg holds exactly atlas-duck-app, atlas-duck, atlas-duck-sandbox in
#     Contents/MacOS, and CFBundleExecutable is atlas-duck-app
#   * `lipo -archs` of each is exactly the target arch (separate arm64 and x86_64 builds)
#   * each is signed with the hardened runtime flag and without com.apple.security.get-task-allow
#   * the bundle signature verifies, and `atlas-duck bogus` exits 2 with the usage envelope
#     (for x86_64 on the arm64 runner this runs under Rosetta, which the job installs)
# Written for the bash 3.2 that ships with macOS.
set -euo pipefail
export LC_ALL=C

dmg_dir="${1:?usage: ci/check-macos-bundle.sh <dmg-dir> <arm64|x86_64>}"
arch="${2:?usage: ci/check-macos-bundle.sh <dmg-dir> <arm64|x86_64>}"
case "$arch" in
  arm64 | x86_64) ;;
  *) echo "usage: the arch must be arm64 or x86_64, got '$arch'" >&2; exit 2 ;;
esac
expected_bins=$'atlas-duck\natlas-duck-app\natlas-duck-sandbox'

failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

shopt -s nullglob
dmgs=("$dmg_dir"/*.dmg)
shopt -u nullglob
[ "${#dmgs[@]}" -eq 1 ] || { echo "FAIL: expected one .dmg in $dmg_dir, found ${#dmgs[@]}" >&2; exit 1; }
dmg="${dmgs[0]}"
echo "dmg: $dmg"

mnt="$(mktemp -d /tmp/atlas-duck-dmg.XXXXXX)"
hdiutil attach -nobrowse -readonly -noautoopen -mountpoint "$mnt" "$dmg" >/dev/null
trap 'hdiutil detach "$mnt" -force >/dev/null 2>&1 || true; rmdir "$mnt" 2>/dev/null || true' EXIT

shopt -s nullglob
apps=("$mnt"/*.app)
shopt -u nullglob
[ "${#apps[@]}" -eq 1 ] || { echo "FAIL: expected one .app in the dmg, found ${#apps[@]}" >&2; exit 1; }
app="${apps[0]}"
macos_dir="$app/Contents/MacOS"
echo "app: $app"

bins="$(ls -1A "$macos_dir" | sort)"
echo "Contents/MacOS: ${bins//$'\n'/ }"
[ "$bins" = "$expected_bins" ] ||
  fail "Contents/MacOS holds '${bins//$'\n'/ }', expected exactly '${expected_bins//$'\n'/ }'"

main_exe="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist")"
[ "$main_exe" = "atlas-duck-app" ] || fail "CFBundleExecutable is '$main_exe', expected atlas-duck-app"

for b in atlas-duck-app atlas-duck atlas-duck-sandbox; do
  f="$macos_dir/$b"
  if [ ! -f "$f" ]; then
    fail "$b is missing"
    continue
  fi
  archs="$(lipo -archs "$f")"
  echo "$b: lipo -archs = $archs"
  [ "$archs" = "$arch" ] || fail "$b: lipo -archs is '$archs', expected '$arch'"
  info="$(codesign -dv --verbose=4 "$f" 2>&1 || true)"
  grep -E '^(Identifier|CodeDirectory|Signature)' <<<"$info" | sed "s|^|$b: |" || true
  grep -Eq '^CodeDirectory .*flags=0x[0-9a-f]+\([^)]*runtime' <<<"$info" ||
    fail "$b: codesign -dv shows no runtime flag (hardened runtime missing)"
  ents="$(codesign -d --entitlements - --xml "$f" 2>/dev/null || true)"
  echo "$b: entitlements: ${ents:-<none>}"
  if grep -q 'get-task-allow' <<<"$ents"; then
    fail "$b: entitlements contain com.apple.security.get-task-allow"
  fi
done

codesign --verify --deep --strict --verbose=2 "$app" || fail "codesign --verify --deep --strict failed for $app"

out_file="$(mktemp /tmp/atlas-duck-cli.XXXXXX)"
set +e
"$macos_dir/atlas-duck" bogus >"$out_file"
code=$?
set -e
echo "atlas-duck bogus: exit $code, stdout $(cat "$out_file")"
[ "$code" -eq 2 ] || fail "atlas-duck bogus exited $code, expected 2"
[ "$(wc -l <"$out_file" | tr -d ' ')" = "1" ] || fail "atlas-duck bogus printed more or less than one line"
for needle in '"status":"failed"' '"code":"usage"' '"retryable":false' '"request_id":null'; do
  grep -qF "$needle" "$out_file" || fail "atlas-duck bogus envelope lacks $needle"
done
rm -f "$out_file"

if [ "$failures" -ne 0 ]; then
  echo "check-macos-bundle: $failures failure(s)" >&2
  exit 1
fi
echo "OK: $arch .app holds the three bins, hardened runtime without get-task-allow on each, CLI usage envelope exit 2"
