#!/usr/bin/env bash
# Ad-hoc signs the three release binaries with the hardened runtime and the app's
# entitlements. Run as Tauri's build.beforeBundleCommand, i.e. after the final
# cargo build and before the bundler copies the binaries into the .app.
#
# Why: Apple's linker signs (ad hoc) only the arm64 images it writes. The x86_64
# images cross-built on the arm64 runner are unsigned, and the bundler then fails
# sealing the .app ("code object is not signed at all", CI run 2).
#
# usage: ci/sign-macos-bins-adhoc.sh <target-triple>
set -euo pipefail
target="${1:?usage: sign-macos-bins-adhoc.sh <target-triple>}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for bin in atlas-duck-app atlas-duck atlas-duck-sandbox; do
  f="$root/target/$target/release/$bin"
  test -f "$f" || { echo "sign-macos-bins-adhoc: $f is missing" >&2; exit 1; }
  codesign --force --sign - --options runtime \
    --entitlements "$root/app/src-tauri/entitlements.plist" "$f"
  codesign -dv "$f"
done
