#!/usr/bin/env bash
# Imports the Developer ID Application certificate (APPLE_CERTIFICATE, base64 .p12, with
# APPLE_CERTIFICATE_PASSWORD) into a job keychain and puts it first in the search list, so
# ci/sign-macos-bins.sh (Tauri's beforeBundleCommand, which runs before Tauri's own keychain
# setup) can sign with APPLE_SIGNING_IDENTITY. Release signing jobs only (M10 Task 26).
set -euo pipefail
: "${APPLE_CERTIFICATE:?APPLE_CERTIFICATE is empty}"
: "${APPLE_CERTIFICATE_PASSWORD:?APPLE_CERTIFICATE_PASSWORD is empty}"
: "${APPLE_SIGNING_IDENTITY:?APPLE_SIGNING_IDENTITY is empty}"
: "${RUNNER_TEMP:?RUNNER_TEMP is not set}"

keychain="$RUNNER_TEMP/atlas-duck-release.keychain-db"
keychain_pw="$(openssl rand -base64 24)"
p12="$RUNNER_TEMP/atlas-duck-release.p12"
trap 'rm -f "$p12"' EXIT

printf '%s' "$APPLE_CERTIFICATE" | base64 --decode > "$p12"
security create-keychain -p "$keychain_pw" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$keychain_pw" "$keychain"
security import "$p12" -k "$keychain" -P "$APPLE_CERTIFICATE_PASSWORD" -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$keychain_pw" "$keychain" >/dev/null
# shellcheck disable=SC2046
security list-keychains -d user -s "$keychain" $(security list-keychains -d user | tr -d '"')
if ! security find-identity -v -p codesigning "$keychain" | grep -qF "$APPLE_SIGNING_IDENTITY"; then
  echo "::error::APPLE_SIGNING_IDENTITY is not a valid code-signing identity in the imported certificate"
  security find-identity -v -p codesigning "$keychain" | sed -E 's/[0-9A-F]{40}/<sha1>/'
  exit 1
fi
echo "import-macos-certificate: identity found in $keychain"
