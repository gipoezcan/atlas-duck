#!/usr/bin/env bash
# Developer ID signs every binary that becomes Contents/MacOS (the three [[bin]]s: atlas-duck-app,
# atlas-duck, atlas-duck-sandbox) with the hardened runtime, the app's entitlements and a secure
# timestamp (spec §3.2, §2.5; M10 Task 26). Run as Tauri's build.beforeBundleCommand on release
# runs only, i.e. after the final cargo build and before the bundler copies the binaries into the
# .app; it replaces ci/sign-macos-bins-adhoc.sh there. Non-release runs keep the ad-hoc script.
#
# The identity comes from APPLE_SIGNING_IDENTITY (the keychain is set up by
# ci/import-macos-certificate.sh). The list of files is the target dir's executables named in
# [[bin]] sections of app/src-tauri/Cargo.toml, so a fourth [[bin]] is not skipped silently.
#
# usage: ci/sign-macos-bins.sh <target-triple>
set -euo pipefail
target="${1:?usage: sign-macos-bins.sh <target-triple>}"
: "${APPLE_SIGNING_IDENTITY:?APPLE_SIGNING_IDENTITY is empty: release signing needs a Developer ID identity}"
case "$APPLE_SIGNING_IDENTITY" in
  -) echo "sign-macos-bins: APPLE_SIGNING_IDENTITY is '-' (ad hoc); release runs need Developer ID" >&2; exit 1 ;;
esac
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
entitlements="$root/app/src-tauri/entitlements.plist"
test -f "$entitlements" || { echo "sign-macos-bins: $entitlements is missing" >&2; exit 1; }

bins="$(sed -nE '/^\[\[bin\]\]/,/^\[/{s/^name *= *"([^"]+)".*/\1/p;}' "$root/app/src-tauri/Cargo.toml" | sort -u)"
for need in atlas-duck-app atlas-duck atlas-duck-sandbox; do
  printf '%s\n' "$bins" | grep -qx "$need" || bins="$(printf '%s\n%s' "$bins" "$need")"
done

for bin in $bins; do
  f="$root/target/$target/release/$bin"
  test -f "$f" || { echo "sign-macos-bins: $f is missing" >&2; exit 1; }
  codesign --force --sign "$APPLE_SIGNING_IDENTITY" --options runtime --timestamp \
    --entitlements "$entitlements" "$f"
  codesign --verify --strict --verbose=2 "$f"
  codesign -dv "$f" 2>&1 | grep -E '^(Identifier|Authority|TeamIdentifier|Timestamp|CodeDirectory)'
done
