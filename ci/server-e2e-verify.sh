#!/usr/bin/env bash
# M14 T23: the image's own `verify-export` on an export the e2e suite downloaded and unpacked
# (ATLAS_DUCK_E2E_VERIFY_EXEC). Runs a throwaway container of the image with the export dir
# mounted read-only, pinned to the job's anchor head and the manifest SHA-256.
#
# usage: server-e2e-verify.sh <export dir> <excerpt file name> <seq>:<hash> <manifest sha256>
set -euo pipefail

IMAGE="${IMAGE:-atlas-duck-server:ci}"
[[ $# == 4 ]] || { echo "usage: $0 <dir> <excerpt> <seq>:<hash> <manifest sha256>" >&2; exit 2; }
dir="$1"
excerpt="$2"
head="$3"
manifest="$4"

# The files are the runner's, mode 0600; the container runs as uid 65532.
chmod -R a+rX "$dir"
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges --network none \
  -v "$dir:/export:ro" "$IMAGE" verify-export /export \
  --anchor-chain "/export/$excerpt" --anchor-chain-head "$head" --manifest-sha256 "$manifest"
