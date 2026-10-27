#!/usr/bin/env bash
# M12 T25: writes a throwaway master key file for the container smoke test into
# $RUNNER_TEMP/atlas-duck-master-key, mode 0400 and owned by the container's uid 65532 (as a
# Kubernetes secret would be), so the server's key-file mode check stays quiet. CI only.
set -euo pipefail

out="${RUNNER_TEMP:?RUNNER_TEMP is not set}/atlas-duck-master-key"
key="$(head -c 32 /dev/urandom | base64 -w0)"
printf 'atlas-duck-master-key/v1 ci-smoke %s\n' "$key" > "$out"
chmod 0400 "$out"
sudo chown 65532:65532 "$out"
echo "master key file: $out"
