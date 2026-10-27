#!/bin/sh
# Self-test of ci/check-chart-policy.sh (M13 plan T4): the good fixture passes, and each variant
# that breaks one rule fails. Runs in `chart:test` before the real check.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
check="$here/check-chart-policy.sh"
good="$here/fixtures/chart-policy/good.yaml"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

sh "$check" "$good" || { echo "self-test: the good fixture failed" >&2; exit 1; }

n=0
expect_fail() {
  n=$((n + 1))
  sed "$2" "$good" > "$work/bad-$n.yaml"
  if cmp -s "$good" "$work/bad-$n.yaml"; then
    echo "self-test: variant '$1' did not change the fixture" >&2
    exit 1
  fi
  if sh "$check" "$work/bad-$n.yaml" 2> "$work/err-$n.txt"; then
    echo "self-test: variant '$1' passed the policy" >&2
    exit 1
  fi
  echo "self-test: '$1' refused: $(head -n 1 "$work/err-$n.txt")"
}

expect_fail "two replicas" 's/^  replicas: 1$/  replicas: 2/'
expect_fail "rolling update" 's/type: Recreate/type: RollingUpdate/'
expect_fail "root allowed" 's/runAsNonRoot: true/runAsNonRoot: false/'
expect_fail "writable root" 's/readOnlyRootFilesystem: true/readOnlyRootFilesystem: false/'
expect_fail "privilege escalation" 's/allowPrivilegeEscalation: false/allowPrivilegeEscalation: true/'
expect_fail "capabilities kept" 's/- ALL/- NET_RAW/'
expect_fail "no seccomp" 's/type: RuntimeDefault/type: Unconfined/'
expect_fail "token mounted" 's/automountServiceAccountToken: false/automountServiceAccountToken: true/'
expect_fail "no limits" 's/^            limits:$/            limitz:/'
expect_fail "no readiness probe" 's/readinessProbe:/readinessProbo:/'
expect_fail "RWX volume" 's/- ReadWriteOnce/- ReadWriteMany/'
expect_fail "a Secret" 's/^kind: PersistentVolumeClaim$/kind: Secret/'
expect_fail "hostPath" 's/^            secretName: atlas-duck-master-key$/          hostPath: {path: \/x}/'
expect_fail "privileged" 's/privileged: false/privileged: true/'
expect_fail "a placeholder" 's/storageClassName: "ci-rwo"/storageClassName: "CHANGE-ME"/'
expect_fail "literal secret env" 's/name: ATLAS_DUCK_MASTER_KEY_FILE/name: ATLAS_DUCK_API_TOKEN/'

echo "self-test: $n refusals as expected"
