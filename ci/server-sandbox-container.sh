#!/usr/bin/env bash
# M14 T14 (PD-250): proves the M8 Linux sandbox works inside the hardened server container with
# no capability and no user namespace, under the container runtime's DEFAULT seccomp profile.
#
# (a) `atlas-duck-server sandbox-probe --json` in the image under --read-only --tmpfs /tmp
#     --cap-drop ALL --security-opt no-new-privileges --user 65532:65532: exit 0 and the report
#     says floor met, every worker task `Seccomp: 2` and `NoNewPrivs: 1`.
# (b) No `--security-opt seccomp=...` is passed anywhere: Docker's default profile applies; the
#     Docker version and its security options are printed as evidence. (The cluster's Kubernetes
#     RuntimeDefault profile is checked separately in the review environment, T15.)
# (c) The M8 `confined_scripts` corpus (Dockerfile target `confined`, same distroless base) under
#     the same flags and --network none: exit 0, no case killed by SIGSYS.
#
# Failure handling (PD-250 decision path): `floor: not_met` fails the job and prints the probe's
# `failed` list; the lead then decides between a reviewed Localhost seccomp profile shipped with
# the chart and leaving scripts disabled in production (L247). Landlock is an extra layer:
# `landlock_abi` null or a number both pass and are recorded.
set -euo pipefail

if [[ "${SANDBOX_INNER:-}" != 1 ]]; then
  exec env SANDBOX_INNER=1 timeout 600 bash "$0" "$@"
fi

IMAGE="${IMAGE:-atlas-duck-server:ci}"
CONFINED_IMAGE="${CONFINED_IMAGE:-atlas-duck-confined:ci}"
WORK="$(mktemp -d)"

fail() {
  echo "::error::server sandbox container: $*"
  exit 1
}

hardening=(--read-only --tmpfs /tmp:size=64m --cap-drop ALL --security-opt no-new-privileges --user 65532:65532)

echo "evidence: docker $(docker version --format '{{.Server.Version}}') security_options=$(docker info --format '{{json .SecurityOptions}}')"

# (a) The probe in the server image.
set +e
timeout 180 docker run --rm "${hardening[@]}" -e ATLAS_DUCK_DATA_DIR=/tmp "$IMAGE" \
  sandbox-probe --json > "$WORK/probe.json" 2> "$WORK/probe.err"
code=$?
set -e
echo "--- sandbox-probe ---"
cat "$WORK/probe.json" || true
cat "$WORK/probe.err" || true
report="$(tr -d '[:space:]' < "$WORK/probe.json")"
field() { # key -> raw JSON value, jq-free
  grep -o "\"$1\":[^,}]*" <<< "$report" | head -n 1 | cut -d: -f2-
}
if [[ "$code" != 0 ]]; then
  fail "sandbox-probe exited $code; floor=$(field floor) failed=$(field failed)"
fi
[[ "$(field floor)" == '"met"' ]] || fail "floor is $(field floor), failed=$(field failed)"
[[ "$(field all_seccomp_2)" == true ]] || fail "not every worker task shows Seccomp: 2"
[[ "$(field all_no_new_privs_1)" == true ]] || fail "not every worker task shows NoNewPrivs: 1"
echo "evidence: floor=met landlock_abi=$(field landlock_abi) mechanism=$(field mechanism) thread_tasks=$(field thread_tasks) kernel=$(field kernel)"

# (c) The confined script corpus on the same base.
set +e
timeout 300 docker run --rm "${hardening[@]}" --network none "$CONFINED_IMAGE" \
  > "$WORK/confined.log" 2>&1
code=$?
set -e
echo "--- confined_scripts ---"
grep -E '^V11 |^V02 |^confined_scripts' "$WORK/confined.log" | cut -c1-400 || true
[[ "$code" == 0 ]] || { tail -n 50 "$WORK/confined.log"; fail "confined_scripts exited $code"; }
grep -qE '^V11 os=linux confined=true$' "$WORK/confined.log" || fail "the corpus did not run confined"
grep -qE '^V11 corpus=[0-9]+ passed=[0-9]+ killed_by_sigsys=0$' "$WORK/confined.log" \
  || fail "a case died by SIGSYS or failed"

echo "server sandbox container: ok"
