#!/usr/bin/env bash
# Installs Rosetta 2 on the arm64 macOS runner and fails loudly if it does not work (§15 V32).
# Shared by the unsigned and the signing x86_64 bundle jobs (moved out of bundle.yml, M10 Task 26).
set -euo pipefail
machine="$(uname -m)"
if [ "$machine" != "arm64" ]; then
  echo "::error::runner hardware is $machine, expected arm64"
  exit 1
fi
if ! sudo softwareupdate --install-rosetta --agree-to-license; then
  echo "::error::softwareupdate could not install Rosetta 2"
  exit 1
fi
if ! arch -x86_64 /usr/bin/true; then
  echo "::error::Rosetta 2 is installed but cannot run x86_64 code"
  exit 1
fi
translated="$(arch -x86_64 /usr/sbin/sysctl -n sysctl.proc_translated)"
echo "sysctl.proc_translated under arch -x86_64: $translated"
if [ "$translated" != "1" ]; then
  echo "::error::x86_64 process is not translated by Rosetta"
  exit 1
fi
