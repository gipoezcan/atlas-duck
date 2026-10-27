#!/usr/bin/env bash
# M12 T25: smoke test of the built image `atlas-duck-server:ci` (SM-1.3, SM-7.1, SM-9.5). Proves
# the image runs as uid 65532 with a read-only root, serves the pages with the CSP, signs in a
# test-directory user, creates an API key, answers MCP `initialize` + `tools/list` with it,
# answers the admin CLI over its socket (M13 T5), and refuses the test directory in production
# (exit 78). The Jira write flow itself is crates/server/tests/exit_flow.rs (in process).
set -euo pipefail

if [[ "${SMOKE_INNER:-}" != 1 ]]; then
  exec env SMOKE_INNER=1 timeout 300 bash "$0" "$@"
fi

IMAGE="${IMAGE:-atlas-duck-server:ci}"
KEY_FILE="${RUNNER_TEMP:?}/atlas-duck-master-key"
FIXTURES="$(cd "$(dirname "$0")/../crates/server/fixtures" && pwd)"
NAME="atlas-duck-smoke"
BASE="http://127.0.0.1:8080"
WORK="$(mktemp -d)"
JAR="$WORK/cookies.txt"
CURL=(curl --silent --show-error --max-time 10)

cleanup() {
  docker logs "$NAME" > "$WORK/container.log" 2>&1 || true
  docker rm -f "$NAME" > /dev/null 2>&1 || true
  echo "--- container log ---"
  cat "$WORK/container.log" || true
}
trap cleanup EXIT

fail() {
  echo "::error::server smoke: $*"
  exit 1
}

common_env=(
  -e ATLAS_DUCK_PUBLIC_URL="$BASE"
  -e ATLAS_DUCK_DATA_DIR=/data
  -e ATLAS_DUCK_MASTER_KEY_FILE=/run/secrets/master-key
  -e ATLAS_DUCK_TEST_DIRECTORY_FILE=/fixtures/test-directory.json
  -e GROUP_USERS=cn=atlas-duck-users,ou=groups,dc=test
  -e GROUP_ADMINS=cn=atlas-duck-admins,ou=groups,dc=test
  -e GROUP_AUDITORS=cn=atlas-duck-auditors,ou=groups,dc=test
)
mounts=(
  --tmpfs /data:uid=65532,gid=65532,mode=0700
  --tmpfs /run/atlas-duck:uid=65532,gid=65532,mode=0700
  --tmpfs /tmp:uid=65532,gid=65532,mode=1777
  -v "$KEY_FILE:/run/secrets/master-key:ro"
  -v "$FIXTURES:/fixtures:ro"
)

docker run -d --name "$NAME" -p 127.0.0.1:8080:8080 --read-only --cap-drop ALL \
  --security-opt no-new-privileges -e ATLAS_DUCK_MODE=dev "${common_env[@]}" "${mounts[@]}" \
  "$IMAGE" > /dev/null

ready=0
for _ in $(seq 1 60); do
  if "${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE/readyz" 2> /dev/null | grep -q '^200$'; then
    ready=1
    break
  fi
  sleep 1
done
[[ "$ready" == 1 ]] || fail "/readyz never answered 200"

user="$(docker inspect --format '{{.Config.User}}' "$NAME")"
[[ "$user" == "65532:65532" ]] || fail "container user is '$user', not 65532:65532"

# The admin CLI reaches the running server over its socket (M13 T5, Δ-M13-2).
set +e
docker exec "$NAME" /app/atlas-duck-server admin instances list > "$WORK/admin.out" 2>&1
code=$?
set -e
[[ "$code" == 0 ]] || fail "admin instances list exited $code: $(cat "$WORK/admin.out")"

login() { # user password jar
  "${CURL[@]}" -c "$3" -H "Origin: $BASE" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" "$BASE/api/login"
}
csrf_of() { sed -n 's/.*"csrf_token":"\([^"]*\)".*/\1/p'; }

# carol-admin adds an instance (no Jira call is made).
CAROL_JAR="$WORK/carol.txt"
carol_csrf="$(login carol-admin carol-test-password "$CAROL_JAR" | csrf_of)"
[[ -n "$carol_csrf" ]] || fail "carol-admin could not sign in"
status="$("${CURL[@]}" -o "$WORK/add.json" -w '%{http_code}' -b "$CAROL_JAR" -H "Origin: $BASE" \
  -H "X-CSRF-Token: $carol_csrf" -H 'Content-Type: application/json' \
  -d '{"alias":"work","product":"jira","base_url":"https://jira.example.test","is_default":true}' \
  "$BASE/api/admin/instances")"
[[ "$status" == 201 ]] || fail "admin add answered $status: $(cat "$WORK/add.json")"

# alice signs in, reads her session, creates an API key.
alice_csrf="$(login alice alice-test-password "$JAR" | csrf_of)"
[[ -n "$alice_csrf" ]] || fail "alice could not sign in"
"${CURL[@]}" -b "$JAR" "$BASE/api/session" | grep -q '"user":"alice"' || fail "GET /api/session"
key="$("${CURL[@]}" -b "$JAR" -H "Origin: $BASE" -H "X-CSRF-Token: $alice_csrf" \
  -H 'Content-Type: application/json' -d '{"name":"smoke","scopes":["read"]}' \
  "$BASE/api/me/api-keys" | sed -n 's/.*"key":"\(adk_[^"]*\)".*/\1/p')"
[[ -n "$key" ]] || fail "no API key created"

# MCP initialize + tools/list with the key.
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}'
"${CURL[@]}" -D "$WORK/init.headers" -o "$WORK/init.body" -H "Authorization: Bearer $key" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d "$init" "$BASE/mcp"
sid="$(sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d: *\([^[:space:]]*\).*/\1/p' "$WORK/init.headers" | tr -d '\r')"
[[ -n "$sid" ]] || fail "no MCP session id: $(cat "$WORK/init.headers")"
"${CURL[@]}" -o /dev/null -H "Authorization: Bearer $key" -H "Mcp-Session-Id: $sid" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$BASE/mcp"
"${CURL[@]}" -H "Authorization: Bearer $key" -H "Mcp-Session-Id: $sid" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' "$BASE/mcp" > "$WORK/tools.body"
# Exact tool names: the read tool jira_issue_editmeta contains the write tool's name as a prefix.
grep -q '"name":"jira_issue_get"' "$WORK/tools.body" || fail "tools/list lacks jira_issue_get"
grep -q '"name":"jira_issue_editmeta"' "$WORK/tools.body" || fail "tools/list lacks jira_issue_editmeta"
if grep -q '"name":"jira_issue_edit"' "$WORK/tools.body"; then fail "a read key lists a write tool"; fi
status="$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp")"
[[ "$status" == 401 ]] || fail "/mcp without a key answered $status"

# The approvals page carries the CSP.
"${CURL[@]}" -D "$WORK/page.headers" -o /dev/null "$BASE/approvals"
grep -qi "^content-security-policy: default-src 'self'" "$WORK/page.headers" || fail "no CSP on /approvals"

docker rm -f "$NAME" > /dev/null

# Production refuses the test directory: exit 78 within 10 s.
set +e
timeout 10 docker run --rm --read-only --cap-drop ALL -e ATLAS_DUCK_MODE=production \
  "${common_env[@]}" -e ATLAS_DUCK_PUBLIC_URL=https://duck.example.test "${mounts[@]}" "$IMAGE" \
  > "$WORK/prod.log" 2>&1
code=$?
set -e
[[ "$code" == 78 ]] || fail "production with the test directory exited $code, not 78: $(cat "$WORK/prod.log")"
grep -q 'config/test_directory_in_production' "$WORK/prod.log" || fail "production refused for another reason: $(cat "$WORK/prod.log")"

echo "server smoke: ok"
