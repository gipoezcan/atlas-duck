#!/bin/sh
# Review-environment sandbox check (M14 plan T15, PD-250): the sandbox floor inside the review pod
# under Kubernetes RuntimeDefault seccomp and the chart's securityContext. Runs `admin sandbox
# probe` through kubectl exec and asserts `met`; prints one evidence line (probe report, kernel
# and the node's container runtime). A `not_met` here blocks M14 (L247: the lead decides between a
# Localhost seccomp profile and scripts disabled in production).
#
# env: RELEASE_NAME (from deploy:review), KUBE_CONTEXT, KUBE_NAMESPACE.
set -eu

: "${RELEASE_NAME:?}" "${KUBE_CONTEXT:?}" "${KUBE_NAMESPACE:?}"
K="kubectl --context ${KUBE_CONTEXT} -n ${KUBE_NAMESPACE}"

fail() {
  echo "review sandbox: FAILED: $*" >&2
  exit 1
}

$K rollout status "deploy/${RELEASE_NAME}" --timeout=600s
out="$($K exec "deploy/${RELEASE_NAME}" -- /app/atlas-duck-server admin sandbox probe)" \
  || fail "admin sandbox probe: $out"
state="$(printf '%s' "$out" | sed -n 's/.*"state":"\([a-z_]*\)".*/\1/p')"
pod="$($K get pod -l "app.kubernetes.io/instance=${RELEASE_NAME}" -o jsonpath='{.items[0].metadata.name}')"
node="$($K get pod "$pod" -o jsonpath='{.spec.nodeName}')"
runtime="$($K get node "$node" -o jsonpath='{.status.nodeInfo.containerRuntimeVersion}' 2> /dev/null || echo unknown)"
kernel="$($K get node "$node" -o jsonpath='{.status.nodeInfo.kernelVersion}' 2> /dev/null || echo unknown)"
echo "evidence: review sandbox state=${state} runtime=${runtime} kernel=${kernel} report=$(printf '%s' "$out" | cut -c1-600)"
[ "$state" = met ] || fail "the sandbox floor is '${state}' under RuntimeDefault (L247)"
echo "review sandbox: ok"