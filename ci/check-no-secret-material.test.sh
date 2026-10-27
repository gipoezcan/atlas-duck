#!/bin/sh
# Self-test of ci/check-no-secret-material.sh (M13 plan T12): a clean tree passes, and each
# planted fixture (ci/fixtures/secret-guard/) placed into a scanned path is refused.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
guard="$here/check-no-secret-material.sh"
fixtures="$here/fixtures/secret-guard"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

clean() {
  rm -rf "$work/tree"
  mkdir -p "$work/tree/ci" "$work/tree/chart" "$work/tree/deployment/ca" "$work/tree/crates/server"
  printf '%s\n' '# a clean pipeline' 'job:' '  script:' \
    '    - /kaniko/executor --build-arg "GIT_SHA=${CI_COMMIT_SHA}"' \
    '    - curl --cacert ca.pem -fsS https://example.test/healthz' > "$work/tree/.gitlab-ci.yml"
  printf '%s\n' 'FROM scratch' 'ENV RUSTUP_TOOLCHAIN=1.95.0' > "$work/tree/crates/server/Dockerfile"
  printf '%s\n' '# CA' '-----BEGIN CERTIFICATE-----' 'ZmFrZQ==' '-----END CERTIFICATE-----' '' \
    > "$work/tree/deployment/ca/org-ca.pem"
}

clean
sh "$guard" "$work/tree" || { echo "self-test: the clean tree was refused" >&2; exit 1; }

n=0
expect_refused() { # fixture destination-in-tree
  n=$((n + 1))
  clean
  mkdir -p "$(dirname "$work/tree/$2")"
  cp "$fixtures/$1" "$work/tree/$2"
  if sh "$guard" "$work/tree" 2> "$work/err"; then
    echo "self-test: $1 at $2 was not refused" >&2
    exit 1
  fi
  echo "self-test: $1 refused: $(head -n 1 "$work/err")"
}

expect_refused build-arg.gitlab-ci.yml .gitlab-ci.yml
expect_refused env-secret.Dockerfile crates/server/Dockerfile
expect_refused private-key.pem deployment/extra.pem
expect_refused tls-reject.yaml chart/templates/env.yaml
expect_refused skip-verify.yaml chart/templates/tls.yaml
expect_refused insecure-flag.sh ci/copy.sh
expect_refused skip-tls-verify.yml ci/build.yml
expect_refused tls-verify-false.sh ci/copy2.sh
expect_refused curl-k.sh ci/smoke.sh
expect_refused ca-with-key.pem deployment/ca/org-ca.pem

# A CA file with anything but comments and certificate blocks is refused too.
clean
printf '%s\n' 'not a certificate' > "$work/tree/deployment/ca/org-ca.pem"
if sh "$guard" "$work/tree" 2> /dev/null; then
  echo "self-test: stray text in the CA bundle was not refused" >&2
  exit 1
fi

echo "self-test: $((n + 1)) refusals as expected"
