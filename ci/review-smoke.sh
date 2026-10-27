#!/bin/sh
# Review-environment smoke test (M13 plan T14; master-plan exit criterion, SM-2, SM-3.2, SM-8.2).
# Runs in the `verify:review-smoke` job against the release `deploy:review` just applied, through
# the ingress with TLS verified against the organisation CA bundle (never -k, SM-9.2):
#   rollout done; /healthz 200; /readyz 200 with the test directory reported; /metrics not
#   reachable through the ingress; an instance via the admin socket (kubectl exec); login as a
#   test user (CSRF); an API key (scope read); MCP initialize + tools/list with it; the key
#   revoked -> 401; logout; helm test.
# The API key lives only in a shell variable and is never printed.
#
# env: REVIEW_URL, RELEASE_NAME (from deploy:review), KUBE_CONTEXT, KUBE_NAMESPACE.
set -eu
set +x

: "${REVIEW_URL:?}" "${RELEASE_NAME:?}" "${KUBE_CONTEXT:?}" "${KUBE_NAMESPACE:?}"
CA="${CA_BUNDLE:-deployment/ca/org-ca.pem}"
BASE="${REVIEW_URL%/}"
K="kubectl --context ${KUBE_CONTEXT} -n ${KUBE_NAMESPACE}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() {
  echo "review smoke: FAILED: $*" >&2
  exit 1
}
command -v curl > /dev/null || fail "no curl in this image"

c() { # curl with the CA bundle, bounded, quiet
  curl --silent --show-error --max-time 15 --cacert "$CA" "$@"
}
status_of() { # url [curl args...] -> HTTP status, body in $WORK/body
  url="$1"
  shift
  c -o "$WORK/body" -w '%{http_code}' "$@" "$url"
}

echo "review smoke: waiting for ${RELEASE_NAME}"
$K rollout status "deploy/${RELEASE_NAME}" --timeout=600s

ready=0
for _ in $(seq 1 60); do
  if [ "$(status_of "$BASE/readyz" || true)" = 200 ]; then
    ready=1
    break
  fi
  sleep 5
done
[ "$ready" = 1 ] || fail "/readyz never answered 200: $(cat "$WORK/body" 2> /dev/null || true)"
grep -q '"directory":"stub"' "$WORK/body" || fail "/readyz does not report the test directory"
grep -q '"ready":true' "$WORK/body" || fail "/readyz body: $(cat "$WORK/body")"

[ "$(status_of "$BASE/healthz")" = 200 ] || fail "/healthz"
# The ingress adds X-Forwarded-For, so the server never answers /metrics through it.
[ "$(status_of "$BASE/metrics")" = 404 ] || fail "/metrics is reachable through the ingress"

# An instance through the admin socket (idempotent across redeploys of the same branch).
ADMIN="$K exec deploy/${RELEASE_NAME} -- /app/atlas-duck-server admin"
if ! $ADMIN instances list | grep -q '"alias":"work"'; then
  $ADMIN instances add --alias work --product jira --url https://jira.example.test --default > /dev/null \
    || fail "admin instances add"
fi

# alice signs in (Origin + CSRF), reads her session, creates a read key.
JAR="$WORK/jar"
st="$(status_of "$BASE/api/login" -c "$JAR" -H "Origin: $BASE" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-test-password"}')"
[ "$st" = 200 ] || fail "login answered $st"
csrf="$(sed -n 's/.*"csrf_token":"\([^"]*\)".*/\1/p' "$WORK/body")"
[ -n "$csrf" ] || fail "no CSRF token"
[ "$(status_of "$BASE/api/session" -b "$JAR")" = 200 ] || fail "GET /api/session"
grep -q '"user":"alice"' "$WORK/body" || fail "session is not alice's"
st="$(status_of "$BASE/api/me/api-keys" -b "$JAR" -H "Origin: $BASE" -H "X-CSRF-Token: $csrf" \
  -H 'Content-Type: application/json' -d '{"name":"review-smoke","scopes":["read"]}')"
[ "$st" = 201 ] || [ "$st" = 200 ] || fail "API key creation answered $st"
key="$(sed -n 's/.*"key":"\(adk_[^"]*\)".*/\1/p' "$WORK/body")"
key_id="$(sed -n 's/.*"id":"\(key_[^"]*\)".*/\1/p' "$WORK/body")"
rm -f "$WORK/body"
[ -n "$key" ] && [ -n "$key_id" ] || fail "no API key in the answer"

# MCP initialize + tools/list with the key.
mcp() { # body [extra curl args] -> body in $WORK/mcp, headers in $WORK/mcp.h
  b="$1"
  shift
  c -D "$WORK/mcp.h" -o "$WORK/mcp" -w '%{http_code}' -H "Authorization: Bearer $key" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    "$@" -d "$b" "$BASE/mcp"
}
st="$(mcp '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"review-smoke","version":"1"}}}')"
[ "$st" = 200 ] || fail "MCP initialize answered $st"
sid="$(sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d: *\([^[:space:]]*\).*/\1/p' "$WORK/mcp.h" | tr -d '\r')"
[ -n "$sid" ] || fail "no MCP session id"
mcp '{"jsonrpc":"2.0","method":"notifications/initialized"}' -H "Mcp-Session-Id: $sid" > /dev/null
st="$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' -H "Mcp-Session-Id: $sid")"
[ "$st" = 200 ] || fail "tools/list answered $st"
grep -q 'jira_issue_get' "$WORK/mcp" || fail "tools/list lacks jira_issue_get"
if grep -q 'jira_issue_edit' "$WORK/mcp"; then fail "a read key lists a write tool"; fi

# Revoked: the key is refused at once.
st="$(status_of "$BASE/api/me/api-keys/$key_id" -X DELETE -b "$JAR" -H "Origin: $BASE" \
  -H "X-CSRF-Token: $csrf")"
case "$st" in 200 | 204) ;; *) fail "revocation answered $st" ;; esac
st="$(mcp '{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}' -H "Mcp-Session-Id: $sid")"
[ "$st" = 401 ] || fail "a revoked key answered $st, not 401"
key=""

# Logout ends the session.
st="$(status_of "$BASE/api/logout" -X POST -b "$JAR" -H "Origin: $BASE" -H "X-CSRF-Token: $csrf")"
case "$st" in 200 | 204) ;; *) fail "logout answered $st" ;; esac
[ "$(status_of "$BASE/api/session" -b "$JAR")" = 401 ] || fail "the session survived logout"

helm test "${RELEASE_NAME}" --namespace "${KUBE_NAMESPACE}" --kube-context "${KUBE_CONTEXT}" \
  --timeout 180s || fail "helm test"

echo "review smoke: ok (${BASE})"
