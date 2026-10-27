#!/bin/sh
# Secret-material and TLS-verification guard (M13 plan T12; SM-9.1, SM-9.2, PD-M13-7).
# POSIX sh + grep + awk (runs in the alpine image of `server:guards`).
#
# usage: ci/check-no-secret-material.sh [repo-root]
# Scans ci/, chart/, deployment/, .gitlab-ci.yml and crates/server/Dockerfile for:
#   a --build-arg other than GIT_SHA; an ENV naming a KEY/TOKEN/PASSWORD/SECRET; a PRIVATE KEY
#   block; *_TLS_REJECT_UNAUTHORIZED; insecureSkipVerify; --insecure; --skip-tls-verify;
#   tls-verify=false; curl with -k.
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

hits="$(
  {
    # Only GIT_SHA may be a build argument.
    files | while IFS= read -r f; do
      grep -nE -- '--build-arg' "$f" 2> /dev/null | grep -v 'GIT_SHA=' | cut -d: -f1 |
        while IFS= read -r n; do echo "$f:$n|build-arg other than GIT_SHA"; done
    done
    check 'ENV with a secret-like name' '^[[:space:]]*ENV[[:space:]].*(KEY|TOKEN|PASSWORD|SECRET)'
    check 'private key material' 'PRIVATE KEY'
    check 'TLS rejection disabled' '_TLS_REJECT_UNAUTHORIZED'
    check 'insecureSkipVerify' 'insecureSkipVerify'
    check '--insecure' '--insecure'
    check '--skip-tls-verify' '--skip-tls-verify'
    check 'tls-verify=false' 'tls-verify=false'
    check 'curl -k' 'curl([^|;&]*[[:space:]])?-[A-Za-z]*k'
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
