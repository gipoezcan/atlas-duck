#!/usr/bin/env bash
# Runs INSIDE a fedora:40 container (glibc 2.39): the §9.4 Linux probes against
# binaries built on ubuntu-22.04 (glibc 2.35). This is the second glibc target
# of spec §15 V11.
#
# Usage (see the CI step "Fedora 40 probes (glibc 2.39)" in ci.yml):
#   docker run --rm -v "$PWD/fedora-probe:/probe:ro" fedora:40 \
#       bash /probe/fedora-probes.sh /probe
# <dir> holds `probes_linux` (the test executable of the atlas-duck-app package)
# and `atlas-duck-sandbox`. The container keeps Docker's default seccomp
# profile on purpose: the floor must hold under it, and if the profile blocks
# the seccomp(2) syscall itself, that is recorded, never worked around.
set -euo pipefail

dir="${1:?usage: fedora-probes.sh <dir with probes_linux and atlas-duck-sandbox>}"
for f in probes_linux atlas-duck-sandbox; do
  if [ ! -x "$dir/$f" ]; then
    echo "::error::$dir/$f is missing or not executable"
    exit 1
  fi
done

. /etc/os-release
echo "== $PRETTY_NAME, kernel $(uname -r)"
echo "== $(ldd --version | head -n 1)"
echo "== container seccomp state of this shell (Docker's profile):"
grep -E '^(Seccomp|Seccomp_filters|NoNewPrivs):' /proc/self/status || true

# The test executable lives in the app package and links WebKitGTK and the
# Ayatana indicator library through Tauri; the worker binary links neither.
dnf install -y webkit2gtk4.1 libayatana-appindicator-gtk3

if ldd "$dir/probes_linux" | grep 'not found'; then
  echo "::error::probes_linux has unresolved shared libraries on Fedora 40"
  exit 1
fi
export ATLAS_DUCK_SANDBOX_BIN="$dir/atlas-duck-sandbox"
export HOME="${HOME:-/root}"
if ! "$dir/probes_linux" --nocapture; then
  echo "::error::the Linux floor probes failed in fedora:40"
  echo "If the output above shows 'applied: false' with os_error 1 (EPERM) or 38 (ENOSYS),"
  echo "the container's seccomp profile blocks seccomp(2) itself. Record that for the"
  echo "go/no-go (docs/m1/go-no-go.md); do not loosen the floor."
  exit 1
fi
echo "== fedora:40 probes passed"
