#!/bin/sh
# Review-environment e2e (M14 plan T23, PD-258, PD-261): the black-box suite built by
# `server:e2e-build` (artifact e2e-bin/e2e) against the review release through the ingress, with
# TLS verified against the system trust store: the ingress certificate comes from cert-manager's
# `letsencrypt` ClusterIssuer, not from the org CA (deployment/ca/org-ca.pem is the directory's
# LDAPS root and is not used here; final review I1, pending M13's decision on an ingress CA). Jira is `none` there (its cases report skip, L258); the
# deactivation case is skipped (no kubectl in the rust image; `verify:review-ops-drill`
# deactivates a test user there). Writes e2e-summary.txt.
#
# env: REVIEW_URL (from deploy:review).
set -eu

: "${REVIEW_URL:?}"
[ -x e2e-bin/e2e ] || { echo "review e2e: no e2e-bin/e2e artifact" >&2; exit 1; }
set +e
ATLAS_DUCK_E2E_BASE_URL="${REVIEW_URL%/}" \
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