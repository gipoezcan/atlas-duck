#!/usr/bin/env bash
# ci/check-release-identity.sh [--self-test]
#
# Release guard for the bundle identifier and the placeholder icons (PD-178, P15; spec §12.5).
# bundle.yml runs it only for release builds (`if: ${{ inputs.release }}`; T26 adds the
# `on: workflow_call` `release: boolean` input). It fails while a release would still ship:
#   a. the placeholder identifier dev.atlasduck.desktop in app/src-tauri/tauri.conf.json;
#   b. a placeholder icon: a file in app/src-tauri/icons/ whose SHA-256 is listed in
#      ci/placeholder-icons.sha256;
#   c. an identifier equal to the data-dir folder name, case-insensitively (spec §12.5: the bundle
#      identifier and the data folder must differ). The folder name is read from APP_DIR_NAME in
#      crates/ipc/src/paths/mod.rs, never hardcoded. NOT wizard.rs's NESTED_DATA_DIR: that is the
#      folder created inside a user-picked folder, not the per-OS data folder.
# Replacing the identifier or the icons is a later one-line change per file, once the lead
# provides them (human decision Q4).
#
# --self-test runs the same extraction and comparison over fixture strings and over the repo's own
# files. It spawns nothing beyond coreutils, sed, grep, tr and sha256sum or shasum.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

fail() { echo "::error::check-release-identity: $*" >&2; exit 1; }

placeholder_id="dev.atlasduck.desktop"
conf="app/src-tauri/tauri.conf.json"
paths_rs="crates/ipc/src/paths/mod.rs"
icons_dir="app/src-tauri/icons"
list="ci/placeholder-icons.sha256"

# Text helpers shared by both modes.
extract_identifier() { sed -n 's/^[[:space:]]*"identifier"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1; }
extract_folder() { sed -n 's/^pub const APP_DIR_NAME: &str = "\([^"]*\)";.*/\1/p' | head -n 1; }
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
is_placeholder_id() { [ "$1" = "$placeholder_id" ]; }
same_as_folder() { [ "$(lower "$1")" = "$(lower "$2")" ]; }
is_listed() { grep -qF -- "$1  " <<<"$2"; }
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d ' ' -f 1; else shasum -a 256 "$1" | cut -d ' ' -f 1; fi
}

if [ "${1:-}" = "--self-test" ]; then
  st_fail=0
  # expect <description> <0|1 expected status> <command...>
  expect() {
    local desc="$1" want="$2" got=0
    shift 2
    if "$@"; then got=0; else got=1; fi
    if [ "$got" = "$want" ]; then echo "  ok   $desc"; else echo "  FAIL $desc (want $want, got $got)" >&2; st_fail=1; fi
  }
  # expect_eq <description> <want> <got>
  expect_eq() {
    if [ "$2" = "$3" ]; then echo "  ok   $1"; else echo "  FAIL $1 (want '$2', got '$3')" >&2; st_fail=1; fi
  }
  all_entries_wellformed() { ! grep -qvE '^[0-9a-f]{64}  app/src-tauri/icons/[^ ]+$' "$list"; }

  echo "check-release-identity --self-test"
  expect_eq "identifier read from a tauri.conf.json line" "dev.atlasduck.desktop" \
    "$(printf '%s\n' '  "identifier": "dev.atlasduck.desktop",' | extract_identifier)"
  expect_eq "identifier read past other keys" "example.release.app" \
    "$(printf '%s\n' '  "productName": "Atlas Duck",' '  "identifier": "example.release.app",' | extract_identifier)"
  expect_eq "folder read from the APP_DIR_NAME constant" "atlas-duck" \
    "$(printf '%s\n' 'pub const APP_DIR_NAME: &str = "atlas-duck";' | extract_folder)"
  expect_eq "wizard NESTED_DATA_DIR is not read as the folder name" "" \
    "$(printf '%s\n' 'pub const NESTED_DATA_DIR: &str = "atlas-duck";' | extract_folder)"

  repo_id="$(extract_identifier < "$conf")"
  repo_folder="$(extract_folder < "$paths_rs")"
  expect "repo tauri.conf.json yields an identifier" 0 test -n "$repo_id"
  expect "repo paths/mod.rs yields the folder name" 0 test -n "$repo_folder"

  expect "placeholder identifier is flagged" 0 is_placeholder_id "dev.atlasduck.desktop"
  expect "a release identifier passes the placeholder check" 1 is_placeholder_id "example.release.app"
  expect "identifier equal to the folder name is flagged" 0 same_as_folder "atlas-duck" "atlas-duck"
  expect "identifier equal to the folder name in other case is flagged" 0 same_as_folder "Atlas-Duck" "atlas-duck"
  expect "identifier differing from the folder name passes" 1 same_as_folder "example.release.app" "atlas-duck"

  fixture_list='eddf0bebbd8ca62eebeb820e9f6d4c0c36b70afe150bb5e306e442e8dd59c2e5  app/src-tauri/icons/128x128.png'
  expect "listed icon hash is matched" 0 is_listed "eddf0bebbd8ca62eebeb820e9f6d4c0c36b70afe150bb5e306e442e8dd59c2e5" "$fixture_list"
  expect "unlisted icon hash passes" 1 is_listed "0000000000000000000000000000000000000000000000000000000000000000" "$fixture_list"
  expect "a truncated hash does not match" 1 is_listed "eddf0bebbd8ca62eebeb820e9f6d4c0c36b70afe" "$fixture_list"

  expect "placeholder list exists and is not empty" 0 test -s "$list"
  expect "every placeholder entry is '<64 hex>  app/src-tauri/icons/<name>'" 0 all_entries_wellformed

  if [ "$st_fail" -ne 0 ]; then fail "self-test failed"; fi
  echo "check-release-identity: self-test passed"
  exit 0
fi

[ "$#" -eq 0 ] || fail "usage: ci/check-release-identity.sh [--self-test]"

id="$(extract_identifier < "$conf")"
folder="$(extract_folder < "$paths_rs")"
[ -n "$id" ] || fail "no identifier in $conf"
[ -n "$folder" ] || fail "no APP_DIR_NAME constant in $paths_rs"

is_placeholder_id "$id" && fail "identifier is still the placeholder $placeholder_id in $conf"
same_as_folder "$id" "$folder" && fail "identifier '$id' equals the data-dir folder name '$folder' (case-insensitive); spec §12.5 requires them to differ"

listed="$(cat "$list")"
count=0
for f in "$icons_dir"/*; do
  [ -f "$f" ] || continue
  count=$((count + 1))
  h="$(sha256_of "$f")"
  is_listed "$h" "$listed" && fail "$f is a placeholder icon (SHA-256 $h is listed in $list)"
done
[ "$count" -gt 0 ] || fail "no icon files in $icons_dir"

echo "check-release-identity: identifier $id differs from the data-dir folder $folder and is not the placeholder; $count icon files, none a placeholder"
