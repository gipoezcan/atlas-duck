#!/bin/sh
# Review-environment operations drill (M13 plan T15; master-plan exit criterion "master key
# rotation and backup/restore pass on it"). Runs on demand in `verify:review-ops-drill` against
# the release `deploy:review` applied, and changes it: afterwards the review environment runs on
# a new test key and alice is deactivated. Never point it at production.
#
#  1. seed: alice signs in, creates a read API key (one audit record at least)
#  2. admin backup (pre-rotation bundle) and admin anchor verify
#  3. a second test key into <release>-master-key-next (job-local tmpfs, never printed),
#     redeploy with masterKey.nextSecret, admin rotate-master-key
#  4. swap <release>-master-key to the new key, redeploy without nextSecret
#  5. login still works, the API key still works, anchor verify passes, /metrics shows the new
#     key id (port-forward: /metrics is never reachable through the ingress)
#  4b. admin master-key status must report rows_not_primary 0 before the Secret swap
#  6. post-rotation backup --stdout through kubectl exec; maintenance on; restoring the pre-rotation bundle is refused
#     (restore/unknown_master_key, expected); restore --stdin of the post-rotation stream passes;
#     anchor verify; maintenance off
#  7. admin users deactivate alice -> her API key answers 401; admin retention run --dry-run
#
# env: REVIEW_URL, RELEASE_NAME (deploy:review), KUBE_CONTEXT, KUBE_NAMESPACE, APP_NAME,
#      PROJECT_VERSION (the packaged chart ${APP_NAME}-${PROJECT_VERSION}.tgz is in the workdir).
set -eu
set +x

: "${REVIEW_URL:?}" "${RELEASE_NAME:?}" "${KUBE_CONTEXT:?}" "${KUBE_NAMESPACE:?}"
: "${APP_NAME:?}" "${PROJECT_VERSION:?}"
case "$RELEASE_NAME" in
  atlas-duck-*) ;;
  *) echo "ops drill: refusing release '$RELEASE_NAME' (review releases only)" >&2; exit 1 ;;
esac
CA="${CA_BUNDLE:-deployment/ca/org-ca.pem}"
BASE="${REVIEW_URL%/}"
CHART="${APP_NAME}-${PROJECT_VERSION}.tgz"
K="kubectl --context ${KUBE_CONTEXT} -n ${KUBE_NAMESPACE}"
H="helm --kube-context ${KUBE_CONTEXT} --namespace ${KUBE_NAMESPACE}"
MAIN_SECRET="${RELEASE_NAME}-master-key"
NEXT_SECRET="${RELEASE_NAME}-master-key-next"
BACKUPS=/var/lib/atlas-duck/backups

WORK="$(mktemp -d)"
KEY_DIR="$(mktemp -d /dev/shm/atlas-duck-drill.XXXXXX)"
chmod 700 "$KEY_DIR"
PF_PID=""
cleanup() {
  [ -n "$PF_PID" ] && kill "$PF_PID" 2> /dev/null || true
  rm -rf "$WORK" "$KEY_DIR"
}
trap cleanup EXIT

step() { echo "ops drill: $*"; }
fail() {
  echo "ops drill: FAILED: $*" >&2
  exit 1
}
c() { curl --silent --show-error --max-time 30 --cacert "$CA" "$@"; }
status_of() { # url [curl args...] -> status; body in $WORK/body
  url="$1"
  shift
  c -o "$WORK/body" -w '%{http_code}' "$@" "$url"
}
admin() { # admin CLI in the pod; output in $WORK/admin.out, exit code returned
  set +e
  $K exec "deploy/${RELEASE_NAME}" -- /app/atlas-duck-server admin "$@" > "$WORK/admin.out" 2>&1
  rc=$?
  set -e
  return "$rc"
}
rollout() { $K rollout status "deploy/${RELEASE_NAME}" --timeout=600s; }
login() { # -> csrf token (cookie jar $WORK/jar)
  st="$(status_of "$BASE/api/login" -c "$WORK/jar" -H "Origin: $BASE" \
    -H 'Content-Type: application/json' -d '{"username":"alice","password":"alice-test-password"}')"
  [ "$st" = 200 ] || fail "login answered $st"
  sed -n 's/.*"csrf_token":"\([^"]*\)".*/\1/p' "$WORK/body"
}
mcp_status() { # -> HTTP status of an MCP initialize with the drill key
  c -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"ops-drill","version":"1"}}}' \
    "$BASE/mcp"
}
bundle_of() { sed -n 's/.*"bundle":"\([^"]*\)".*/\1/p' "$WORK/admin.out"; }

rollout

# 1. Seed.
step "seed: alice signs in and creates a read API key"
csrf="$(login)"
[ -n "$csrf" ] || fail "no CSRF token"
st="$(status_of "$BASE/api/me/api-keys" -b "$WORK/jar" -H "Origin: $BASE" -H "X-CSRF-Token: $csrf" \
  -H 'Content-Type: application/json' -d '{"name":"ops-drill","scopes":["read"]}')"
[ "$st" = 201 ] || fail "API key creation answered $st"
KEY="$(sed -n 's/.*"key":"\(adk_[^"]*\)".*/\1/p' "$WORK/body")"
rm -f "$WORK/body"
[ -n "$KEY" ] || fail "no API key"
[ "$(mcp_status)" = 200 ] || fail "the new key is refused"

# 2. Pre-rotation backup and anchor verify.
step "backup (pre-rotation)"
admin backup "$BACKUPS" || fail "admin backup: $(cat "$WORK/admin.out")"
PRE_BUNDLE="$(bundle_of)"
[ -n "$PRE_BUNDLE" ] || fail "no bundle path in: $(cat "$WORK/admin.out")"
admin anchor verify || fail "anchor verify: $(cat "$WORK/admin.out")"

# 3. The next key, mounted alongside, then the rotation.
step "rotation: next key Secret ${NEXT_SECRET}"
NEW_ID="review-${CI_PIPELINE_ID:-drill}-next"
( umask 077
  printf 'atlas-duck-master-key/v1 %s %s\n' "$NEW_ID" \
    "$(head -c 32 /dev/urandom | base64 | tr -d '\n')" > "$KEY_DIR/next" )
$K delete secret "$NEXT_SECRET" --ignore-not-found > /dev/null
$K create secret generic "$NEXT_SECRET" --from-file=key="$KEY_DIR/next" > /dev/null
$H upgrade "$RELEASE_NAME" "$CHART" --reuse-values --set "masterKey.nextSecret=${NEXT_SECRET}" \
  --wait --timeout 600s > /dev/null
rollout
admin rotate-master-key --new-key-file /run/secrets/atlas-duck/master-key-next/key \
  || fail "rotate-master-key: $(cat "$WORK/admin.out")"
grep -q "\"new_key_id\":\"${NEW_ID}\"" "$WORK/admin.out" || fail "rotation output: $(cat "$WORK/admin.out")"
if grep -q "$(tail -c 20 "$KEY_DIR/next" | tr -d '\n')" "$WORK/admin.out"; then
  fail "the rotation output contains key material"
fi

# 4. The swap gate (master-key status), then swap the main Secret to the new key.
admin master-key status || fail "master-key status: $(cat "$WORK/admin.out")"
grep -q '"rows_not_primary":0' "$WORK/admin.out" || fail "rows still under the old key: $(cat "$WORK/admin.out")"
step "swap ${MAIN_SECRET} to ${NEW_ID}"
$K create secret generic "$MAIN_SECRET" --from-file=key="$KEY_DIR/next" --dry-run=client -o yaml \
  | $K apply -f - > /dev/null
$H upgrade "$RELEASE_NAME" "$CHART" --reuse-values --set "masterKey.nextSecret=" \
  --wait --timeout 600s > /dev/null
rollout
$K delete secret "$NEXT_SECRET" --ignore-not-found > /dev/null

# 5. Everything still works on the new key.
step "verify after rotation"
ready=0
for _ in $(seq 1 60); do
  if [ "$(status_of "$BASE/readyz" || true)" = 200 ]; then ready=1; break; fi
  sleep 5
done
[ "$ready" = 1 ] || fail "/readyz after the rotation: $(cat "$WORK/body" 2> /dev/null || true)"
csrf="$(login)"
[ -n "$csrf" ] || fail "login after the rotation"
[ "$(mcp_status)" = 200 ] || fail "the API key is refused after the rotation"
admin anchor verify || fail "anchor verify after the rotation: $(cat "$WORK/admin.out")"
$K port-forward "deploy/${RELEASE_NAME}" 18080:8080 > "$WORK/pf.log" 2>&1 &
PF_PID=$!
metrics=""
for _ in $(seq 1 30); do
  if metrics="$(curl --silent --max-time 5 http://127.0.0.1:18080/metrics)"; then break; fi
  sleep 1
done
kill "$PF_PID" 2> /dev/null || true
PF_PID=""
printf '%s\n' "$metrics" | grep -q "atlas_duck_master_key_info{key_id=\"${NEW_ID}\",role=\"primary\"} 1" \
  || fail "metrics do not show ${NEW_ID} as the primary key"
if printf '%s\n' "$metrics" | grep -q 'role="accepted"'; then
  fail "an old key is still loaded"
fi

# 6. Backup/restore across the rotation.
step "backup (post-rotation) streamed through kubectl exec"
set +e
$K exec "deploy/${RELEASE_NAME}" -- /app/atlas-duck-server admin backup --stdout \
  > "$WORK/post.tar" 2> "$WORK/post.err"
rc=$?
set -e
[ "$rc" = 0 ] || fail "backup --stdout exited $rc: $(cat "$WORK/post.err")"
[ -s "$WORK/post.tar" ] || fail "empty backup stream"
admin maintenance on || fail "maintenance on"
[ "$(status_of "$BASE/readyz")" = 503 ] || fail "/readyz not 503 in maintenance"
step "restore of the pre-rotation bundle must be refused (old key)"
if admin restore "$PRE_BUNDLE"; then
  fail "the pre-rotation bundle was restored without its key"
fi
grep -q 'restore/unknown_master_key' "$WORK/admin.out" || fail "refused for another reason: $(cat "$WORK/admin.out")"
step "restore of the post-rotation stream through kubectl exec -i"
set +e
$K exec -i "deploy/${RELEASE_NAME}" -- /app/atlas-duck-server admin restore --stdin \
  < "$WORK/post.tar" > "$WORK/admin.out" 2>&1
rc=$?
set -e
[ "$rc" = 0 ] || fail "restore --stdin exited $rc: $(cat "$WORK/admin.out")"
admin anchor verify || fail "anchor verify after the restore: $(cat "$WORK/admin.out")"
admin maintenance off || fail "maintenance off"
csrf="$(login)"
[ -n "$csrf" ] || fail "login after the restore"
[ "$(mcp_status)" = 200 ] || fail "the API key is refused after the restore"

# 7. Offboarding and retention.
step "deactivate alice"
admin users deactivate alice || fail "deactivate: $(cat "$WORK/admin.out")"
[ "$(mcp_status)" = 401 ] || fail "a deactivated user's API key is not refused"
st="$(status_of "$BASE/api/login" -H "Origin: $BASE" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-test-password"}')"
[ "$st" = 403 ] || fail "a deactivated user's login answered $st"
admin retention run --dry-run || fail "retention dry run: $(cat "$WORK/admin.out")"

# Kept bundles: the pre-rotation one and the pre-restore copy are listed and removed.
step "prune kept bundles"
admin backups list || fail "backups list: $(cat "$WORK/admin.out")"
for name in $(sed -n 's/.*"name":"\([^"]*\)".*/\1/p' "$WORK/admin.out"); do
  admin backups remove "$name" || fail "backups remove $name: $(cat "$WORK/admin.out")"
done
# restore --resume needs a crash mid-swap and is covered by the server's own tests
# (a_crash_mid_restore_keeps_maintenance_and_resume_finishes_it), not by this drill.
KEY=""

echo "ops drill: ok (rotated to ${NEW_ID}; pre-rotation restore refused; post-rotation restore passed)"
