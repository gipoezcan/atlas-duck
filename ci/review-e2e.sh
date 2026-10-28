#!/bin/sh
# Review-environment e2e (M14 plan T23, PD-258, PD-261): the black-box suite built by
# `server:e2e-build` (artifact e2e-bin/e2e) against the review release through the ingress, with
# TLS verified against the system trust store, as review-smoke.sh: the ingress certificate comes from
# cert-manager's `letsencrypt` ClusterIssuer (chain to ISRG Root X1); INGRESS_CA_BUNDLE overrides it.
# deployment/ca/org-ca.pem is the directory's LDAPS root and is not used here. Like the smoke it first
# waits for /healthz to answer 200 three times in a row through the ingress (stale endpoints after a
# rollout answer 502). Jira is `none` there (its cases report skip, L258); the
# deactivation case is skipped (no kubectl in the rust image; `verify:review-ops-drill`
# deactivates a test user there). Writes e2e-summary.txt.
#
# env: REVIEW_URL (from deploy:review).
set -eu

: "${REVIEW_URL:?}"
[ -x e2e-bin/e2e ] || { echo "review e2e: no e2e-bin/e2e artifact" >&2; exit 1; }
BASE="${REVIEW_URL%/}"
if [ -n "${INGRESS_CA_BUNDLE:-}" ]; then
  export ATLAS_DUCK_E2E_CA_FILE="$INGRESS_CA_BUNDLE"
  CURL_CA="--cacert $INGRESS_CA_BUNDLE"
else
  CURL_CA=""
fi
streak=0
for i in $(seq 1 36); do
  # shellcheck disable=SC2086
  st="$(curl --silent --max-time 15 $CURL_CA -o /dev/null -w '%{http_code}' "$BASE/healthz" || true)"
  if [ "$st" = 200 ]; then streak=$((streak + 1)); else streak=0; fi
  echo "review e2e: /healthz through the ingress, try $i: ${st:-no answer} (${streak} in a row)"
  [ "$streak" -ge 3 ] && break
  sleep 5
done
[ "$streak" -ge 3 ] || { echo "review e2e: /healthz never steady through the ingress" >&2; exit 1; }
set +e
ATLAS_DUCK_E2E_BASE_URL="$BASE" \
  ATLAS_DUCK_E2E_USERS_FILE=deployment/testdir/users.json \
  ATLAS_DUCK_E2E_JIRA=none \
  ATLAS_DUCK_E2E_SCRIPTS=met \
  e2e-bin/e2e > e2e-output.txt 2>&1
code=$?
set -e
cat e2e-output.txt
grep -E '^(ok|fail|skip) ' e2e-output.txt > e2e-summary.txt || true
[ "$code" = 0 ] || { echo "review e2e: the suite exited $code" >&2; exit 1; }
echo "review e2e: ok"