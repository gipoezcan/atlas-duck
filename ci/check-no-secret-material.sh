#!/bin/sh
# Secret-material and TLS-verification guard (M13 plan T12; SM-9.1, SM-9.2, PD-M13-7).
# POSIX sh + grep + awk (runs in the alpine image of `server:guards`).
#
# usage: ci/check-no-secret-material.sh [repo-root]
# Scans ci/, chart/, deployment/, .gitlab-ci.yml and crates/server/Dockerfile for:
#   a --build-arg other than GIT_SHA; an ENV naming a KEY/TOKEN/PASSWORD/SECRET; a PRIVATE KEY
#   block; *_TLS_REJECT_UNAUTHORIZED; insecureSkipVerify; --insecure; --skip-tls-verify;
#   tls-verify false; curl with -k; wget --no-check-certificate; GIT_SSL_NO_VERIFY; sslVerify false;
#   PYTHONHTTPSVERIFY=0; literal passwords/tokens in values files; ENV/ARG secrets in Dockerfiles
#   (continuations joined, any case); disabled certificate checks in crates/server/src.
# deployment/ca/*.pem may hold only CERTIFICATE blocks, comments and blank lines.
# The planted fixtures (ci/fixtures/secret-guard/) and this guard and its self-test are excluded.
# Exit 0 clean, 1 with every finding on stderr (file:line and the rule, never the line itself).
set -eu

root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$root"

files() {
  for t in ci chart deployment .gitlab-ci.yml crates/server/Dockerfile; do
    [ -e "$t" ] || continue
    find "$t" -type f
  done | grep -v -e '^ci/fixtures/secret-guard/' \
    -e '^ci/check-no-secret-material\.sh$' \
    -e '^ci/check-no-secret-material\.test\.sh$' | sort
}

status=0
finding() {
  echo "secret-guard: $1: $2" >&2
  status=1
}

# rule name | extended regex (matched per line)
check() {
  rule="$1"
  re="$2"
  files | while IFS= read -r f; do
    grep -nE -- "$re" "$f" 2> /dev/null | cut -d: -f1 | while IFS= read -r n; do
      echo "$f:$n|$rule"
    done
  done
}

# awk program over one file: prints "<line>|<rule>" per finding.
awk_check() {
  awk "$2" "$1" 2> /dev/null | while IFS= read -r hit; do echo "$1:$hit"; done
}

hits="$(
  {
    files | while IFS= read -r f; do
      # Only GIT_SHA may be a build argument: every --build-arg on a line is checked.
      awk_check "$f" '
        { for (i = 1; i < NF; i++) if ($i == "--build-arg") {
            v = $(i + 1); gsub(/^["\x27]/, "", v)
            if (v !~ /^GIT_SHA=/) print FNR "|build-arg other than GIT_SHA"
        } }'
      # curl -k: a curl line with a single-dash flag cluster containing k (not words in URLs).
      awk_check "$f" '
        /curl/ { for (i = 1; i <= NF; i++) if ($i ~ /^-[A-Za-z]*k[A-Za-z]*$/) { print FNR "|curl -k"; break } }'
      # A secret-like ENV or ARG in a Dockerfile, continuation lines joined, any case.
      case "$f" in
        (*Dockerfile*)
          awk_check "$f" '
            { line = (cont ? line " " : "") $0; start = cont ? start : FNR }
            /\\$/ { cont = 1; next }
            { cont = 0
              if (toupper(line) ~ /^[[:space:]]*(ENV|ARG)[[:space:]].*(KEY|TOKEN|PASSWORD|SECRET)/)
                print start "|ENV/ARG with a secret-like name"
              line = "" }'
          ;;
      esac
      # A literal password or token value in a values file.
      case "$f" in
        (chart/values*.yaml | chart/ci/*.yaml | chart/ci-fail/*.yaml | deployment/values*.yaml)
          awk_check "$f" '
            tolower($0) ~ /^[[:space:]]*-?[[:space:]]*[a-z_]*(password|passwd|token|apikey|api_key)[[:space:]]*:[[:space:]]*[^[:space:]"#]/ ||
            tolower($0) ~ /^[[:space:]]*-?[[:space:]]*[a-z_]*(password|passwd|token|apikey|api_key)[[:space:]]*:[[:space:]]*"[^"]/ {
              print FNR "|literal password or token in a values file" }'
          ;;
      esac
    done
    check 'ENV with a secret-like name' '^[[:space:]]*ENV[[:space:]].*(KEY|TOKEN|PASSWORD|SECRET)'
    check 'private key material' 'PRIVATE KEY'
    check 'TLS rejection disabled' '_TLS_REJECT_UNAUTHORIZED'
    check 'insecureSkipVerify' 'insecureSkipVerify'
    check '--insecure' '--insecure'
    check '--skip-tls-verify' '--skip-tls-verify'
    check 'tls-verify false' 'tls-verify(=|[[:space:]]+)false'
    check 'wget --no-check-certificate' '--no-check-certificate'
    check 'GIT_SSL_NO_VERIFY' 'GIT_SSL_NO_VERIFY'
    check 'git http.sslVerify false' '[sS][sS][lL][vV][eE][rR][iI][fF][yY]([[:space:]]*=[[:space:]]*|[[:space:]]+)([fF][aA][lL][sS][eE]|0)'
    check 'PYTHONHTTPSVERIFY=0' 'PYTHONHTTPSVERIFY=0'
    # Rust: certificate checks switched off in the server's own code.
    if [ -d crates/server/src ]; then
      find crates/server/src -type f -name '*.rs' | sort | while IFS= read -r f; do
        grep -nE 'danger_accept_invalid|accept_invalid_certs|accept_invalid_hostnames|dangerous\(\)' "$f" 2> /dev/null |
          cut -d: -f1 | while IFS= read -r n; do echo "$f:$n|TLS verification disabled in Rust"; done
      done
    fi
  } | sort -u
)"
if [ -n "$hits" ]; then
  printf '%s\n' "$hits" | while IFS='|' read -r where rule; do
    echo "secret-guard: $where: $rule" >&2
  done
  status=1
fi

# The CA bundle: public certificates only (PD-M13-7).
for pem in deployment/ca/*.pem; do
  [ -f "$pem" ] || continue
  bad="$(awk '
    /^-----BEGIN / { if ($0 != "-----BEGIN CERTIFICATE-----" || inside) { print NR; exit } inside = 1; next }
    /^-----END /   { if ($0 != "-----END CERTIFICATE-----" || !inside) { print NR; exit } inside = 0; next }
    inside { next }
    /^[[:space:]]*$/ || /^#/ { next }
    { print NR; exit }
    END { if (inside) print "end" }
  ' "$pem")"
  if [ -n "$bad" ]; then
    finding "$pem:$bad" "only CERTIFICATE blocks, comments and blank lines are allowed"
  fi
done

exit "$status"
