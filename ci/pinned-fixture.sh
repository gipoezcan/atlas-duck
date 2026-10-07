#!/usr/bin/env bash
# CI-only (spec §7.7 "Machine-local files"): writes THIS host's pinned paths file
# (<passwd home>/.config/atlas-duck/paths-<host>.toml on Linux,
#  <passwd home>/Library/Application Support/atlas-duck/paths-<host>.toml on macOS)
# so that a started app finds a local, existing data directory instead of being
# "before first run". It stands in for the state the first-run wizard (M6) will produce.
# Never run it on a developer machine: it replaces this host's real pinned file.
#
# Needs no cargo and no built binary, so installed-package jobs can use it.
#
# Usage:  ci/pinned-fixture.sh [--data-dir DIR]
# Output: exactly one line on stdout, the data directory path. Diagnostics go to stderr.
#
# The <host> part must equal atlas_duck_ipc::paths::host_name(). This script mirrors the
# host source (Linux: first non-blank, non-comment line of /etc/hostname, else uname -n; macOS: LocalHostName,
# else the short uname -n) and the part of the sanitizer that is the identity (lower-case
# a-z, 0-9, '-', and inner single dots). Any other host name is refused, never guessed:
# set ATLAS_DUCK_FIXTURE_HOST to the value host_name() returns for it.
set -euo pipefail

info() { printf 'pinned-fixture: %s\n' "$*" >&2; }
die() { info "$*"; exit 2; }

data_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --data-dir) [ $# -ge 2 ] || die "--data-dir needs a value"; data_dir="$2"; shift 2 ;;
    *) die "usage: ci/pinned-fixture.sh [--data-dir DIR]" ;;
  esac
done

if [ "${CI:-}" != "true" ] && [ "${ATLAS_DUCK_FIXTURE_FORCE:-}" != "1" ]; then
  die "refusing to replace the pinned paths file outside CI (set ATLAS_DUCK_FIXTURE_FORCE=1 to override)"
fi

os="${ATLAS_DUCK_FIXTURE_OS:-$(uname -s)}"

# The passwd home directory, not $HOME: the app never reads per-session environment (§7.7).
passwd_home() {
  local user home=""
  user="$(id -un)"
  case "$os" in
    Darwin) home="$(dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | sed 's/^NFSHomeDirectory: //' || true)" ;;
    *) home="$(getent passwd "$user" 2>/dev/null | cut -d: -f6 || true)" ;;
  esac
  printf '%s' "${home:-$HOME}"
}

raw_host=""
case "$os" in
  Linux)
    home="$(passwd_home)"
    pinned_dir="$home/.config/atlas-duck"
    # T05's rule: first line of /etc/hostname that is non-blank and not a '#' comment, trimmed.
    if [ -r /etc/hostname ]; then
      raw_host="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' /etc/hostname | grep -v -E '^(#|$)' | head -n 1 || true)"
    fi
    [ -n "$raw_host" ] || raw_host="$(uname -n)"
    ;;
  Darwin)
    home="$(passwd_home)"
    pinned_dir="$home/Library/Application Support/atlas-duck"
    raw_host="$(scutil --get LocalHostName 2>/dev/null || true)"
    [ -n "$raw_host" ] || raw_host="$(uname -n | cut -d. -f1)"
    ;;
  *) die "unsupported OS '$os' (Windows uses ci/pinned-fixture.ps1)" ;;
esac

host="$(printf '%s' "${ATLAS_DUCK_FIXTURE_HOST:-$raw_host}" | tr '[:upper:]' '[:lower:]')"
case "$host" in
  ""|.*|*.|*..*|*[!a-z0-9.-]*)
    die "host name '$host' needs the escaping of atlas_duck_ipc::paths::sanitize_host_component; set ATLAS_DUCK_FIXTURE_HOST to the value host_name() returns" ;;
esac
[ "${#host}" -le 240 ] || die "host name is longer than 240 bytes; set ATLAS_DUCK_FIXTURE_HOST"

if [ -z "$data_dir" ]; then
  base="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
  root="$(mktemp -d "${base%/}/atlas-duck-fixture.XXXXXX")"
  data_dir="$root/data"
  config_dir="$root/config"
else
  config_dir="$(dirname "$data_dir")/config"
fi
mkdir -p "$data_dir" "$config_dir" "$pinned_dir"

case "$data_dir$config_dir" in
  *"'"*) die "path contains a single quote, which a TOML literal string cannot hold" ;;
esac

pinned_file="$pinned_dir/paths-$host.toml"
tmp_file="$pinned_file.tmp"
# TOML literal strings (single quotes) need no escaping.
printf "schema_version = 1\ndata_dir = '%s'\nconfig_dir = '%s'\n" "$data_dir" "$config_dir" > "$tmp_file"
mv -f "$tmp_file" "$pinned_file"

info "wrote $pinned_file (data_dir = $data_dir)"
printf '%s\n' "$data_dir"
