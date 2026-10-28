#!/bin/sh
# Review-environment operations drill (M13 plan T15; master-plan exit criterion "master key
# rotation and backup/restore pass on it"). Runs on demand in `verify:review-ops-drill` against
# the release `deploy:review` applied, and changes it: afterwards the review environment runs on
# a new test key and the drill user (see below) is deactivated. Never point it at production.
#
#  1. seed: the drill user signs in, creates a read API key (one audit record at least)
#  2. admin backup (pre-rotation bundle) and admin anchor verify
#  3. a second test key into <release>-master-key-next (job-local tmpfs, never printed),
#     redeploy with masterKey.nextSecret, admin rotate-master-key
#  4. swap <release>-master-key to the new key, redeploy without nextSecret
#  5. login still works, the API key still works, anchor verify passes, /metrics shows the new
#     key id (port-forward to the Service's metrics port: the Ingress never routes it)
#  4b. admin master-key status must report rows_not_primary 0 before the Secret swap
#  6. post-rotation backup --stdout through kubectl exec; maintenance on; restoring the pre-rotation bundle is refused
#     (restore/unknown_master_key, expected); restore --stdin of the post-rotation stream passes;
#     anchor verify; maintenance off
#  7. admin users deactivate <drill user> -> the API key answers 401; admin retention run --dry-run
#
# Re-runnable: the drill user is the first of alice, bob, erin-leaver that can still sign in (each
# full run deactivates one; stop:review resets the environment). A run that finds
# <release>-master-key-next left by an interrupted drill resumes that rotation with the key in it
# (read into the job's tmpfs, never printed) instead of starting a new one; the pre-rotation
# backup and its refused restore are then skipped (the old key's state is unknown).
# kubectl never runs a client-side apply: the helmfile image's kubectl reads /openapi/v2, which
# this cluster answers 503. Secrets are replaced server-side.
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
# Ingress TLS: Let's Encrypt via cert-manager, verified against the system bundle (or
# INGRESS_CA_BUNDLE); deployment/ca/org-ca.pem is the AD root for LDAPS only.
INGRESS_CA="${INGRESS_CA_BUNDLE:-}"
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
c() {
  if [ -n "$INGRESS_CA" ]; then
    curl --silent --show-error --max-time 30 --cacert "$INGRESS_CA" "$@"
  else
    curl --silent --show-error --max-time 30 "$@"
  fi
}
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
login() { # -> csrf token (cookie jar $WORK/jar) of $USER_NAME
  st="$(status_of "$BASE/api/login" -c "$WORK/jar" -H "Origin: $BASE" \
    -H 'Content-Type: application/json' -d "{\"username\":\"$USER_NAME\",\"password\":\"$USER_PASS\"}")"
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
replace_secret() { # name keyfile: create or replace the Secret server-side (no client-side apply)
  $K create secret generic "$1" --from-file=key="$2" --dry-run=client -o yaml \
    | $K apply --server-side --force-conflicts --field-manager=atlas-duck-ops --validate=false -f - \
      > /dev/null
}
secret_key() { # name -> the Secret's key item, base64 (compared, never printed); empty if absent
  $K get secret "$1" -o jsonpath='{.data.key}' 2> /dev/null || true
}
# A drill interrupted after the swap left the same key in both Secrets, with the next one still
# mounted: the server refuses that pair, so unmount and delete the next key before anything else.
EARLY_NEXT="$(secret_key "$NEXT_SECRET")"
if [ -n "$EARLY_NEXT" ] && [ "$EARLY_NEXT" = "$(secret_key "$MAIN_SECRET")" ]; then
  step "an earlier drill already swapped ${MAIN_SECRET}: unmounting ${NEXT_SECRET}"
  $H upgrade "$RELEASE_NAME" "$CHART" --reuse-values --set "masterKey.nextSecret=" \
    --wait --timeout 600s > /dev/null
  $K delete secret "$NEXT_SECRET" --ignore-not-found > /dev/null
fi
EARLY_NEXT=""
rollout

# The drill user: the first test user that can still sign in.
USER_NAME=""
for cand in alice:alice-test-password bob:bob-test-password erin-leaver:erin-test-password; do
  n="${cand%%:*}"
  pw="${cand#*:}"
  st="$(status_of "$BASE/api/login" -H "Origin: $BASE" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$n\",\"password\":\"$pw\"}" || true)"
  if [ "$st" = 200 ]; then
    USER_NAME="$n"
    USER_PASS="$pw"
    break
  fi
done
rm -f "$WORK/body"
[ -n "$USER_NAME" ] || fail "no test user can sign in (all deactivated by earlier drills): run stop:review, then deploy:review"
step "drill user: $USER_NAME"

# An interrupted drill left the next key behind: resume that rotation.
RESUME=""
NEXT_DATA="$(secret_key "$NEXT_SECRET")"
if [ -n "$NEXT_DATA" ]; then
  RESUME=1
  ( umask 077; printf '%s' "$NEXT_DATA" | base64 -d > "$KEY_DIR/next" )
  NEW_ID="$(awk '{print $2}' "$KEY_DIR/next")"
  [ -n "$NEW_ID" ] || fail "${NEXT_SECRET} holds no key file"
  step "resuming the rotation to ${NEW_ID} left by an earlier drill"
fi
NEXT_DATA=""

# 1. Seed.
step "seed: $USER_NAME signs in and creates a read API key"
csrf="$(login)"[ -n "$csrf" ] || fail "no CSRF token"
st="$(status_of "$BASE/api/me/api-keys" -b "$WORK/jar" -H "Origin: $BASE" -H "X-CSRF-Token: $csrf" \
  -H 'Content-Type: application/json' -d '{"name":"ops-drill","scopes":["read"]}')"
[ "$st" = 201 ] || fail "API key creation answered $st"
KEY="$(sed -n 's/.*"key":"\(adk_[^"]*\)".*/\1/p' "$WORK/body")"
rm -f "$WORK/body"
[ -n "$KEY" ] || fail "no API key"
[ "$(mcp_status)" = 200 ] || fail "the new key is refused"

# 2. Pre-rotation backup and anchor verify (a resumed rotation has no pre-rotation state).
PRE_BUNDLE=""
if [ -z "$RESUME" ]; then
  step "backup (pre-rotation)"
  admin backup "$BACKUPS" || fail "admin backup: $(cat "$WORK/admin.out")"
  PRE_BUNDLE="$(bundle_of)"
  [ -n "$PRE_BUNDLE" ] || fail "no bundle path in: $(cat "$WORK/admin.out")"
fi
admin anchor verify || fail "anchor verify: $(cat "$WORK/admin.out")"

# 3. The next key, mounted alongside, then the rotation.
if [ -z "$RESUME" ]; then
  step "rotation: next key Secret ${NEXT_SECRET}"
  NEW_ID="review-${CI_PIPELINE_ID:-drill}-next"
  ( umask 077
    printf 'atlas-duck-master-key/v1 %s %s\n' "$NEW_ID" \
      "$(head -c 32 /dev/urandom | base64 | tr -d '\n')" > "$KEY_DIR/next" )
  replace_secret "$NEXT_SECRET" "$KEY_DIR/next"
fi
$H upgrade "$RELEASE_NAME" "$CHART" --reuse-values --set "masterKey.nextSecret=${NEXT_SECRET}" \
  --wait --timeout 600s > /dev/null
rollout
if admin rotate-master-key --new-key-file /run/secrets/atlas-duck/master-key-next/key; then
  grep -q "\"new_key_id\":\"${NEW_ID}\"" "$WORK/admin.out" || fail "rotation output: $(cat "$WORK/admin.out")"
elif [ -n "$RESUME" ] && grep -q 'rotate/same_key' "$WORK/admin.out"; then
  step "the earlier drill finished the re-wrap (rotate/same_key); the status gate decides"
else
  fail "rotate-master-key: $(cat "$WORK/admin.out")"
fi
if grep -q "$(tail -c 20 "$KEY_DIR/next" | tr -d '\n')" "$WORK/admin.out"; then
  fail "the rotation output contains key material"
fi

# 4. The swap gate (master-key status), then swap the main Secret to the new key.
admin master-key status || fail "master-key status: $(cat "$WORK/admin.out")"
grep -q '"rows_not_primary":0' "$WORK/admin.out" || fail "rows still under the old key: $(cat "$WORK/admin.out")"
step "swap ${MAIN_SECRET} to ${NEW_ID}"
replace_secret "$MAIN_SECRET" "$KEY_DIR/next"
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
# /metrics is on the Service's metrics port only (M13 T10).
$K port-forward "svc/${RELEASE_NAME}" 19090:metrics > "$WORK/pf.log" 2>&1 &
PF_PID=$!
metrics=""
for _ in $(seq 1 30); do
  if metrics="$(curl --silent --max-time 5 http://127.0.0.1:19090/metrics)"; then break; fi
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
if [ -n "$PRE_BUNDLE" ]; then
  step "restore of the pre-rotation bundle must be refused (old key)"
  if admin restore "$PRE_BUNDLE"; then
    fail "the pre-rotation bundle was restored without its key"
  fi
  grep -q 'restore/unknown_master_key' "$WORK/admin.out" || fail "refused for another reason: $(cat "$WORK/admin.out")"
fi
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
step "deactivate $USER_NAME"
admin users deactivate "$USER_NAME" || fail "deactivate: $(cat "$WORK/admin.out")"
[ "$(mcp_status)" = 401 ] || fail "a deactivated user's API key is not refused"
st="$(status_of "$BASE/api/login" -H "Origin: $BASE" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USER_NAME\",\"password\":\"$USER_PASS\"}")"
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
