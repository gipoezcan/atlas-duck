#!/usr/bin/env bash
# ci/release-verify-macos.sh <dir-with-one-dmg> <arm64|x86_64>
#
# Release verification of a signed and notarized macOS package (M10 Task 26; spec §3.2, §2.5,
# §14 M10 exit). Runs in release.yml for both arches, on the dmg the signing job uploaded:
#   - codesign --verify --deep --strict --verbose=2 on the .app;
#   - every file in Contents/MacOS: the expected arch, a Developer ID signature with the hardened
#     runtime flag, and entitlements (codesign -d --entitlements :-) without get-task-allow;
#   - spctl --assess --type execute on the .app (Gatekeeper accepts it: Developer ID + notarized);
#   - spctl -a -t open --context context:primary-signature on the dmg;
#   - xcrun stapler validate on the .app (the notarization ticket is stapled).
set -euo pipefail
dir="${1:?usage: release-verify-macos.sh <dir-with-one-dmg> <arm64|x86_64>}"
arch="${2:?usage: release-verify-macos.sh <dir-with-one-dmg> <arm64|x86_64>}"
case "$arch" in arm64|x86_64) ;; *) echo "::error::arch must be arm64 or x86_64" >&2; exit 2 ;; esac

fail() { echo "::error::release-verify-macos ($arch): $*" >&2; exit 1; }

shopt -s nullglob
dmgs=("$dir"/*.dmg)
[ "${#dmgs[@]}" -eq 1 ] || fail "expected exactly one .dmg in $dir, found ${#dmgs[@]}"
dmg="${dmgs[0]}"

mnt="$(mktemp -d)"
hdiutil attach -nobrowse -readonly -noautoopen -mountpoint "$mnt" "$dmg" >/dev/null
trap 'hdiutil detach "$mnt" -force >/dev/null 2>&1 || true; rmdir "$mnt" 2>/dev/null || true' EXIT
apps=("$mnt"/*.app)
[ "${#apps[@]}" -eq 1 ] || fail "expected exactly one .app in $dmg, found ${#apps[@]}"
app="${apps[0]}"
echo "verifying $app from $(basename "$dmg")"

codesign --verify --deep --strict --verbose=2 "$app" || fail "codesign --verify --deep --strict failed on the .app"

count=0
for f in "$app/Contents/MacOS/"*; do
  [ -f "$f" ] || continue
  count=$((count+1))
  name="$(basename "$f")"
  archs="$(lipo -archs "$f")"
  [ "$archs" = "$arch" ] || fail "$name has arch '$archs', expected $arch"
  info="$(codesign -dv --verbose=4 "$f" 2>&1)"
  printf '%s\n' "$info" | grep -E '^(Authority|TeamIdentifier|Timestamp|CodeDirectory)' | sed "s/^/$name: /"
  printf '%s\n' "$info" | grep -qE '^CodeDirectory .*flags=0x[0-9a-f]*\(.*runtime.*\)' || fail "$name: no hardened runtime flag"
  printf '%s\n' "$info" | grep -q '^Authority=Developer ID Application' || fail "$name: not signed with a Developer ID Application certificate"
  printf '%s\n' "$info" | grep -q '^Signature=adhoc' && fail "$name: ad-hoc signature"
  printf '%s\n' "$info" | grep -q '^Timestamp=' || fail "$name: no secure timestamp"
  ent="$(codesign -d --entitlements :- "$f" 2>/dev/null || true)"
  [ -n "$ent" ] || fail "$name: no entitlements"
  if printf '%s' "$ent" | grep -q 'com.apple.security.get-task-allow'; then
    fail "$name: entitlements contain com.apple.security.get-task-allow"
  fi
  echo "$name: $arch, Developer ID, hardened runtime, timestamp, no get-task-allow"
done
[ "$count" -ge 3 ] || fail "Contents/MacOS has $count files, expected the three bins"

spctl --assess --type execute --verbose=4 "$app" || fail "spctl rejects the .app (not notarized or not Developer ID)"
spctl -a -t open --context context:primary-signature -v "$dmg" || fail "spctl rejects the dmg"
xcrun stapler validate "$app" || fail "no stapled notarization ticket on the .app"
echo "release-verify-macos: $(basename "$dmg") ($arch) is Developer ID signed, notarized and stapled"
