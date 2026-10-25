#!/usr/bin/env bash
# ci/check-release-secrets.sh windows|macos
# ci/check-release-secrets.sh --self-test
#
# The guard step of the release signing jobs (M10 Task 26, PD-182): a release run whose signing
# secrets or variables are empty fails here, before any build. It reads the job's env (the jobs map
# the `release` environment's secrets and variables into env) and never prints a value.
#   windows: WINDOWS_SIGN_COMMAND (variable) non-empty and containing %1, and either the pair
#            WINDOWS_CERTIFICATE + WINDOWS_CERTIFICATE_PASSWORD or SIGNPATH_API_TOKEN.
#            WINDOWS_CERT_THUMBPRINT and WINDOWS_TIMESTAMP_URL are optional.
#   macos:   APPLE_CERTIFICATE, APPLE_CERTIFICATE_PASSWORD, APPLE_SIGNING_IDENTITY, APPLE_ID,
#            APPLE_PASSWORD, APPLE_TEAM_ID all non-empty; the identity is not "-" (ad hoc).
set -euo pipefail

# Prints one line per problem; returns 1 when there is any.
check() {
  local platform="$1" problems=()
  case "$platform" in
    windows)
      if [ -z "${WINDOWS_SIGN_COMMAND:-}" ]; then
        problems+=("variable WINDOWS_SIGN_COMMAND is empty")
      else
        case "$WINDOWS_SIGN_COMMAND" in *%1*) ;; *) problems+=("WINDOWS_SIGN_COMMAND has no %1 (the file Tauri signs)") ;; esac
      fi
      if [ -n "${WINDOWS_CERTIFICATE:-}" ] && [ -z "${WINDOWS_CERTIFICATE_PASSWORD:-}" ]; then
        problems+=("secret WINDOWS_CERTIFICATE is set but WINDOWS_CERTIFICATE_PASSWORD is empty")
      elif [ -z "${WINDOWS_CERTIFICATE:-}" ] && [ -z "${SIGNPATH_API_TOKEN:-}" ]; then
        problems+=("neither the secrets WINDOWS_CERTIFICATE + WINDOWS_CERTIFICATE_PASSWORD nor SIGNPATH_API_TOKEN is set")
      fi
      ;;
    macos)
      local n
      for n in APPLE_CERTIFICATE APPLE_CERTIFICATE_PASSWORD APPLE_SIGNING_IDENTITY APPLE_ID APPLE_PASSWORD APPLE_TEAM_ID; do
        [ -n "${!n:-}" ] || problems+=("secret $n is empty")
      done
      [ "${APPLE_SIGNING_IDENTITY:-}" != "-" ] || problems+=("APPLE_SIGNING_IDENTITY is '-' (ad hoc)")
      ;;
    *) problems+=("unknown platform '$platform' (windows|macos)") ;;
  esac
  [ "${#problems[@]}" -eq 0 ] && return 0
  printf '%s\n' "${problems[@]}"
  return 1
}

self_test() {
  local n=0
  ok()  { n=$((n+1)); if ! ( unset_all; eval "$2"; check "$3" >/dev/null ); then echo "self-test FAIL (expected pass): $1" >&2; exit 1; fi; echo "ok $n - passes: $1"; }
  bad() { n=$((n+1)); if ( unset_all; eval "$2"; check "$3" >/dev/null ); then echo "self-test FAIL (expected failure): $1" >&2; exit 1; fi; echo "ok $n - fails: $1"; }
  unset_all() { unset WINDOWS_SIGN_COMMAND WINDOWS_CERTIFICATE WINDOWS_CERTIFICATE_PASSWORD SIGNPATH_API_TOKEN \
    APPLE_CERTIFICATE APPLE_CERTIFICATE_PASSWORD APPLE_SIGNING_IDENTITY APPLE_ID APPLE_PASSWORD APPLE_TEAM_ID; }
  local cmd='WINDOWS_SIGN_COMMAND="signtool sign /fd sha256 %1"'
  local mac='APPLE_CERTIFICATE=x APPLE_CERTIFICATE_PASSWORD=x APPLE_SIGNING_IDENTITY="Developer ID Application: X (T)" APPLE_ID=a APPLE_PASSWORD=p APPLE_TEAM_ID=T'
  ok  "windows: command + certificate pair" "$cmd WINDOWS_CERTIFICATE=c WINDOWS_CERTIFICATE_PASSWORD=p" windows
  ok  "windows: command + SignPath token" "$cmd SIGNPATH_API_TOKEN=t" windows
  bad "windows: nothing set" ":" windows
  bad "windows: empty command, certificate pair" "WINDOWS_SIGN_COMMAND= WINDOWS_CERTIFICATE=c WINDOWS_CERTIFICATE_PASSWORD=p" windows
  bad "windows: command without %1" "WINDOWS_SIGN_COMMAND=signtool SIGNPATH_API_TOKEN=t" windows
  bad "windows: command, no credential" "$cmd" windows
  bad "windows: certificate without password" "$cmd WINDOWS_CERTIFICATE=c" windows
  ok  "macos: all six" "$mac" macos
  local v
  for v in APPLE_CERTIFICATE APPLE_CERTIFICATE_PASSWORD APPLE_SIGNING_IDENTITY APPLE_ID APPLE_PASSWORD APPLE_TEAM_ID; do
    bad "macos: $v empty" "$mac $v=" macos
  done
  bad "macos: ad-hoc identity" "$mac APPLE_SIGNING_IDENTITY=-" macos
  bad "unknown platform" "$mac" linux
  echo "check-release-secrets self-test: $n checks passed"
}

case "${1:-}" in
  --self-test) self_test ;;
  windows|macos)
    if ! out="$(check "$1")"; then
      while IFS= read -r line; do echo "::error::check-release-secrets ($1): $line" >&2; done <<<"$out"
      echo "::error::a release run needs the signing secrets and variables of the 'release' environment (see docs/ and the M10 Task 26 report)" >&2
      exit 1
    fi
    echo "check-release-secrets: $1 signing values present"
    ;;
  *) echo "usage: ci/check-release-secrets.sh windows|macos|--self-test" >&2; exit 2 ;;
esac
