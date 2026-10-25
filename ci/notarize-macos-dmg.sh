#!/usr/bin/env bash
# ci/notarize-macos-dmg.sh <dir-with-one-dmg>
#
# Notarizes the Developer ID signed dmg with `xcrun notarytool submit --wait` and staples the
# ticket to it (M10 Task 26, fix I-1). Runs as its own step AFTER `cargo tauri build`, so the
# notarization credentials (APPLE_ID, APPLE_PASSWORD = app-specific password, APPLE_TEAM_ID) never
# enter the build (no build.rs or proc macro sees them). Notarizing the dmg also covers the .app
# inside it (Apple notarizes nested code); the ticket is stapled to the dmg, which is what ships.
set -euo pipefail
dir="${1:?usage: notarize-macos-dmg.sh <dir-with-one-dmg>}"
: "${APPLE_ID:?APPLE_ID is empty}"
: "${APPLE_PASSWORD:?APPLE_PASSWORD is empty}"
: "${APPLE_TEAM_ID:?APPLE_TEAM_ID is empty}"

shopt -s nullglob
dmgs=("$dir"/*.dmg)
[ "${#dmgs[@]}" -eq 1 ] || { echo "::error::expected exactly one .dmg in $dir, found ${#dmgs[@]}" >&2; exit 1; }
dmg="${dmgs[0]}"

codesign --verify --strict --verbose=2 "$dmg" || { echo "::error::the dmg is not signed; Tauri signs it with the release identity" >&2; exit 1; }

out="$(xcrun notarytool submit "$dmg" --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" \
  --team-id "$APPLE_TEAM_ID" --wait --timeout 60m --output-format json)"
echo "$out"
status="$(printf '%s' "$out" | /usr/bin/plutil -extract status raw -o - - 2>/dev/null || true)"
if [ "$status" != "Accepted" ]; then
  id="$(printf '%s' "$out" | /usr/bin/plutil -extract id raw -o - - 2>/dev/null || true)"
  if [ -n "$id" ]; then
    xcrun notarytool log "$id" --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID" || true
  fi
  echo "::error::notarization status is '${status:-unknown}', expected Accepted" >&2
  exit 1
fi
xcrun stapler staple "$dmg"
xcrun stapler validate "$dmg"
echo "notarize-macos-dmg: $(basename "$dmg") notarized and stapled"
