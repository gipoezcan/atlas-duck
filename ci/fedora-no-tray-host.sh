#!/usr/bin/env bash
# ci/fedora-no-tray-host.sh <artifact-dir>
#
# CI-03 (spec §13 CI row, M6 plan Task 33, §15 V33): the no-tray-host GUI run, as root inside the
# fedora:40 container (e2e-bundle.yml job `fedora-no-tray-host`). <artifact-dir> is the downloaded
# `bundle-linux-e2e` artifact: rpm/*.rpm.
#
# The rpm is the DEBUG `scripted-approver` bundle (job bundle-linux-e2e): it refuses to start without
# ATLAS_DUCK_TEST_HOME, takes its base folders from it (so nothing here touches /root's own pinned
# file) and uses the file keystore from ATLAS_DUCK_TEST_KEYSTORE.
#
# Driver-free (M6 CI ruling, task cifix6): WebKitWebDriver cannot drive the wizard on Linux (see
# ci/gui-no-driver.sh), and without the wizard there is no store, so Approvals on a cold start,
# Settings from the header and header Quit are rows of docs/release/linux-gui-checklist.md. What runs:
# the rpm installs on Fedora 40 and its WebKit is the one the package depends on; then, under Xvfb on
# a session bus that has no org.kde.StatusNotifierWatcher, ci/gui-no-driver.sh on a pinned data dir
# with no store: a cold start maps the Setup window and logs tray_host=missing, `atlas-duck doctor`
# reports tray_host missing, a forwarded no-argument launch and a forwarded `--background` launch are
# logged and change no window, SIGTERM runs the shutdown path, and the next start comes up clean.
set -euo pipefail
export LC_ALL=C

fail() { echo "FAIL: $*" >&2; exit 1; }

if [ "${1:-}" = --inner ]; then
  # A file-backed Secret Service, unlocked as ci/keyring-ci.sh does (the scripted-approver build uses
  # its own file keystore; this keeps the host shape of a real install).
  if command -v gnome-keyring-daemon >/dev/null; then
    printf 'atlas-duck-ci' | gnome-keyring-daemon --components=secrets --daemonize --unlock >/dev/null || echo "fedora-no-tray-host: keyring daemon did not start (continuing)"
  fi
  # Diagnostics first: the logs are copied to /root/e2e-diag (the runner's bind mount; the workflow
  # prints and uploads it) before anything is stopped or cleaned up, on success and on failure.
  save_diag() {
    mkdir -p /root/e2e-diag
    find /root -path /root/e2e-diag -prune -o \( -name diag.log -o -name 'app-*.log' -o -name 'doctor-*.json' -o -name 'doctor-*.err' \) -type f -print 2>/dev/null |
      while read -r f; do cp "$f" "/root/e2e-diag/$(echo "${f#/}" | tr / _)" 2>/dev/null || true; done
    chmod -R a+rX /root/e2e-diag 2>/dev/null || true
  }
  trap 'save_diag; pkill -x atlas-duck-app || true; pkill -x gnome-keyring-d || true' EXIT
  here="$(cd "$(dirname "$0")" && pwd)"
  bash "$here/gui-no-driver.sh" fedora-no-tray-host /root/e2e-work /usr/bin/atlas-duck-app /usr/bin/atlas-duck
  echo "OK: Fedora 40 no-tray-host run (CI-03, driver-free)"
  # CI-07 (M8 plan Task 28, PD-150), `if: false` in e2e-bundle.yml until M10: the dry run and the
  # released real run through the rpm's CLI. The app must serve a configured core (M10 provisions it).
  if [ "${ATLAS_DUCK_M8_CI07:-}" = 1 ]; then
    bash "$here/script-matrix-step.sh" debug /root/e2e-work/ci07 /usr/bin/atlas-duck
  fi
  exit 0
fi

dist="${1:?usage: ci/fedora-no-tray-host.sh <artifact-dir>}"
dist="$(realpath "$dist")"

grep -qx 'VERSION_ID=40' /etc/os-release || fail "this script expects Fedora 40"
[ "${CI:-}" = true ] || fail "CI=true is not set (docker run --env CI): ci/pinned-fixture.sh runs only in CI"
shopt -s nullglob
rpms=("$dist"/rpm/*.rpm)
shopt -u nullglob
[ "${#rpms[@]}" -eq 1 ] || fail "expected one rpm in $dist/rpm, found ${#rpms[@]}"

# Fedora 40 is past end of life; when its mirrors are gone, use the archive (as ci/fedora-rpm.sh).
use_archive_repos() {
  echo "Fedora 40 mirrors unavailable; switching to archives.fedoraproject.org" >&2
  sed -i \
    -e 's|^metalink=|#metalink=|' \
    -e 's|^#baseurl=http://download.example/pub/fedora/linux|baseurl=https://archives.fedoraproject.org/pub/archive/fedora/linux|' \
    /etc/yum.repos.d/fedora.repo /etc/yum.repos.d/fedora-updates.repo
  if [ -f /etc/yum.repos.d/fedora-cisco-openh264.repo ]; then
    sed -i 's|^enabled=1|enabled=0|' /etc/yum.repos.d/fedora-cisco-openh264.repo
  fi
}
if ! dnf -y makecache; then
  use_archive_repos
  dnf -y makecache
fi

dnf -y install "${rpms[0]}"
rpm -q atlas-duck
# xwininfo (by its path: the package that ships it is a detail of the release) reads the mapped
# windows without a driver.
dnf -y install python3 xorg-x11-server-Xvfb xorg-x11-xauth dbus-daemon dbus-tools procps-ng gnome-keyring mesa-dri-drivers psmisc /usr/bin/xwininfo
rpm -q webkit2gtk4.1 || true
ldd /usr/bin/atlas-duck-app | grep -i -E 'webkit|javascriptcore' || true

# Locality: the container's /root is overlayfs and the app checks its data dir, so the workflow
# bind-mounts a runner directory over /root; the test home, the keystore and the temp dir live there.
[ "$(stat -f -c %T /root)" != overlayfs ] || fail "/root is an overlayfs: the workflow must bind-mount a runner dir over it"
export ATLAS_DUCK_TEST_HOME=/root/test-home
export ATLAS_DUCK_TEST_KEYSTORE=/root/test-keys
export TMPDIR=/root/tmp
mkdir -p "$ATLAS_DUCK_TEST_HOME" "$ATLAS_DUCK_TEST_KEYSTORE" "$TMPDIR" /root/e2e-work
# No bubblewrap sandbox in a container, software rendering.
export WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1
export WEBKIT_DISABLE_COMPOSITING_MODE=1
export LIBGL_ALWAYS_SOFTWARE=1

timeout 1500 xvfb-run -a dbus-run-session -- bash "$0" --inner "$dist"
