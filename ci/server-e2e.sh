#!/usr/bin/env bash
# M14 T23 (PD-260): the black-box e2e suite against the built image `atlas-duck-server:ci`. Starts
# the container with the PD-250 hardening flags (read-only root, no capability, no new
# privileges, tmpfs data dir, uid 65532) on the host network, the test directory users and a
# throwaway master key; waits for /readyz to leave `probing`; runs the e2e binary (crates/server-e2e)
# with the image's own verify-export as ATLAS_DUCK_E2E_VERIFY_EXEC; then greps the container log
# for the e2e canaries (the test passwords and full OAuth tokens). No Jira is reachable (the server
# accepts HTTPS instances only), so the Jira cases report skip.
#
# Writes $OUT/e2e-summary.txt and $OUT/container.log. Exit 1 on any failed case or canary hit.
set -euo pipefail

IMAGE="${IMAGE:-atlas-duck-server:ci}"
KEY_FILE="${RUNNER_TEMP:?}/atlas-duck-master-key"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURES="$ROOT/crates/server/fixtures"
USERS_FILE="$FIXTURES/test-directory.json"
OUT="${OUT:-$RUNNER_TEMP/server-e2e}"
NAME="atlas-duck-e2e"
BASE="http://127.0.0.1:8080"
mkdir -p "$OUT"

cleanup() {
  docker logs "$NAME" > "$OUT/container.log" 2>&1 || true
  docker rm -f "$NAME" > /dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  echo "::error::server e2e: $*"
  exit 1
}

docker run -d --name "$NAME" --network host --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /data:uid=65532,gid=65532,mode=0700 \
  -v "$KEY_FILE:/run/secrets/master-key:ro" \
  -v "$FIXTURES:/fixtures:ro" \
  -e ATLAS_DUCK_MODE=dev \
  -e ATLAS_DUCK_PUBLIC_URL="$BASE" \
  -e ATLAS_DUCK_LISTEN=127.0.0.1:8080 \
  -e ATLAS_DUCK_DATA_DIR=/data \
  -e ATLAS_DUCK_MASTER_KEY_FILE=/run/secrets/master-key \
  -e ATLAS_DUCK_TEST_DIRECTORY_FILE=/fixtures/test-directory.json \
  -e GROUP_USERS=cn=atlas-duck-users,ou=groups,dc=test \
  -e GROUP_ADMINS=cn=atlas-duck-admins,ou=groups,dc=test \
  -e GROUP_AUDITORS=cn=atlas-duck-auditors,ou=groups,dc=test \
  "$IMAGE" > /dev/null

# Ready, and the sandbox probe has answered.
state=""
for _ in $(seq 1 90); do
  state="$(curl --silent --max-time 5 "$BASE/readyz" 2> /dev/null \
    | sed -n 's/.*"scripts":"\([a-z_]*\)".*/\1/p')" || true
  if [[ -n "$state" && "$state" != probing ]]; then
    break
  fi
  sleep 1
done
[[ "$state" == met ]] || fail "/readyz scripts is '$state', not met"

set +e
ATLAS_DUCK_E2E_BASE_URL="$BASE" \
  ATLAS_DUCK_E2E_USERS_FILE="$USERS_FILE" \
  ATLAS_DUCK_E2E_JIRA=none \
  ATLAS_DUCK_E2E_SCRIPTS=met \
  ATLAS_DUCK_E2E_VERIFY_EXEC="bash $ROOT/ci/server-e2e-verify.sh" \
  cargo test -p atlas-duck-server-e2e --test e2e --locked 2>&1 | tee "$OUT/e2e-output.txt"
code=${PIPESTATUS[0]}
set -e
grep -E '^(ok|fail|skip) ' "$OUT/e2e-output.txt" > "$OUT/e2e-summary.txt" || true
{
  echo "### M14 server e2e"
  echo '```'
  cat "$OUT/e2e-summary.txt"
  echo '```'
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

# The canaries: no test password and no full OAuth token in the server's log.
docker logs "$NAME" > "$OUT/container.log" 2>&1 || true
passwords="$(sed -n 's/.*"password": *"\([^"]*\)".*/\1/p' "$USERS_FILE")"
[[ -n "$passwords" ]] || fail "no passwords read from $USERS_FILE"
while IFS= read -r pw; do
  if grep -qF -- "$pw" "$OUT/container.log"; then
    fail "a test password is in the container log"
  fi
done <<< "$passwords"
if grep -qE 'ado_(ac|at|rt)_[A-Za-z0-9_-]{43}' "$OUT/container.log"; then
  fail "an OAuth code or token is in the container log"
fi

[[ "$code" == 0 ]] || fail "the e2e suite exited $code"
grep -q '^ok ' "$OUT/e2e-summary.txt" || fail "no case ran"
echo "server e2e: ok"
