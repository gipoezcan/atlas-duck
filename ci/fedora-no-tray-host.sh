#!/usr/bin/env bash
# ci/fedora-no-tray-host.sh <artifact-dir>
#
# CI-03 (spec §13 CI row, M6 plan Task 33, §15 V33): the no-tray-host GUI run, as root inside the
# fedora:40 container (bundle.yml job `fedora-no-tray-host`). <artifact-dir> is the downloaded
# `bundle-linux-e2e` artifact: rpm/*.rpm and tools/tauri-driver.
#
# The rpm is the DEBUG `scripted-approver` bundle (job bundle-linux-e2e): a release build scrubs the
# WebDriver variables from its environment (§2.5, S-04) and tauri-driver cannot drive it. The
# scripted-approver build keeps them only under ATLAS_DUCK_E2E_ALLOW_DRIVER=1 and refuses to start
# without ATLAS_DUCK_TEST_HOME (and uses the file keystore from ATLAS_DUCK_TEST_KEYSTORE).
#
# What runs (ci/e2e-drive.py does the window steps): under Xvfb on a session bus that has no
# org.kde.StatusNotifierWatcher owner, the wizard is completed through the real windows; then a cold
# no-argument start opens Approvals, `doctor` reports tray_host missing, a forwarded no-argument
# launch and a forwarded `--background` launch are logged and open nothing new, Settings opens from
# the header, header Quit ends the process (the diag log has the line app_stop reason=quit among the
# lines written after the click, no quit_wait_expired or quit_core_lost, and the process is gone), and
# the next start comes up clean.
set -euo pipefail
export LC_ALL=C

fail() { echo "FAIL: $*" >&2; exit 1; }

if [ "${1:-}" = --inner ]; then
  dist="$2"
  # A file-backed Secret Service, unlocked as ci/keyring-ci.sh does (the scripted-approver build uses
  # its own file keystore; this keeps the host shape of a real install).
  if command -v gnome-keyring-daemon >/dev/null; then
    printf 'atlas-duck-ci' | gnome-keyring-daemon --components=secrets --daemonize --unlock >/dev/null || echo "fedora-no-tray-host: keyring daemon did not start (continuing)"
  fi
  # The session bus must not have a StatusNotifierWatcher.
  if dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
      org.freedesktop.DBus.NameHasOwner string:org.kde.StatusNotifierWatcher 2>/dev/null | grep -q 'boolean true'; then
    fail "the session bus has a StatusNotifierWatcher owner; this is not a no-tray-host run"
  fi
  echo "fedora-no-tray-host: no org.kde.StatusNotifierWatcher owner on the session bus"
  # Diagnostics first: the logs are copied to /root/e2e-diag (the runner's bind mount; the workflow
  # prints and uploads it) before anything is stopped or cleaned up, on success and on failure.
  save_diag() {
    mkdir -p /root/e2e-diag
    find /root -path /root/e2e-diag -prune -o \( -name diag.log -o -name '*-driver.log' \) -type f -print 2>/dev/null |
      while read -r f; do cp "$f" "/root/e2e-diag/$(echo "${f#/}" | tr / _)" 2>/dev/null || true; done
    chmod -R a+rX /root/e2e-diag 2>/dev/null || true
  }
  trap 'save_diag; pkill -x atlas-duck-app || true; pkill -x gnome-keyring-d || true; pkill -x tauri-driver || true; pkill -x WebKitWebDriver || true' EXIT
  here="$(cd "$(dirname "$0")" && pwd)"
  python3 -I "$here/e2e-drive.py" wizard --app /usr/bin/atlas-duck-app --driver "$dist/tools/tauri-driver" --driver-log "$ATLAS_DUCK_TEST_HOME/../wizard-driver.log"
  # The wizard session's DELETE ends the app, but not necessarily before the next session starts: a
  # new start would then be forwarded to the dying instance (single-instance plugin) and attach to
  # nothing. Stop it and wait, as ci/appimage-smoke.sh does between its sessions.
  pkill -TERM -x atlas-duck-app || true
  for _ in $(seq 1 60); do
    pgrep -x atlas-duck-app >/dev/null || break
    sleep 1
  done
  ! pgrep -x atlas-duck-app >/dev/null || fail "atlas-duck-app is still running after the wizard session"
  python3 -I "$here/e2e-drive.py" fedora --app /usr/bin/atlas-duck-app --cli /usr/bin/atlas-duck --driver "$dist/tools/tauri-driver" \
    --driver-log "$ATLAS_DUCK_TEST_HOME/../fedora-driver.log" --home "$ATLAS_DUCK_TEST_HOME"
  echo "OK: Fedora 40 no-tray-host run (CI-03)"
  exit 0
fi

dist="${1:?usage: ci/fedora-no-tray-host.sh <artifact-dir>}"
dist="$(realpath "$dist")"

grep -qx 'VERSION_ID=40' /etc/os-release || fail "this script expects Fedora 40"
shopt -s nullglob
rpms=("$dist"/rpm/*.rpm)
shopt -u nullglob
[ "${#rpms[@]}" -eq 1 ] || fail "expected one rpm in $dist/rpm, found ${#rpms[@]}"
[ -x "$dist/tools/tauri-driver" ] || chmod +x "$dist/tools/tauri-driver" || fail "no tauri-driver in $dist/tools"

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
dnf -y install python3 xorg-x11-server-Xvfb xorg-x11-xauth dbus-daemon dbus-tools procps-ng gnome-keyring mesa-dri-drivers psmisc

# WebKitWebDriver: tauri-driver looks it up on PATH. Which Fedora package ships it is checked at run
# time, so a failure here says what the repositories offer.
if ! command -v WebKitWebDriver >/dev/null; then
  found="$(find /usr/libexec /usr/lib64 /usr/bin -name WebKitWebDriver -type f 2>/dev/null | head -n 1 || true)"
  if [ -z "$found" ]; then
    dnf -y install '*/WebKitWebDriver' || true
    found="$(command -v WebKitWebDriver || find /usr/libexec /usr/lib64 /usr/bin -name WebKitWebDriver -type f 2>/dev/null | head -n 1 || true)"
  fi
  if [ -z "$found" ]; then
    dnf provides '*/WebKitWebDriver' || true
    fail "no WebKitWebDriver on this Fedora 40 image (see the dnf provides output above)"
  fi
  ln -sf "$found" /usr/local/bin/WebKitWebDriver
fi
echo "fedora-no-tray-host: WebKitWebDriver $(command -v WebKitWebDriver)"
# The driver comes from whichever package ships it (webkitgtk6.0 on Fedora 40) while the app links
# webkit2gtk-4.1: both versions are printed, as "Failed to match capabilities" may be a mismatch.
WebKitWebDriver --version || true
rpm -q webkit2gtk4.1 webkitgtk6.0 javascriptcoregtk4.1 || true
ldd /usr/bin/atlas-duck-app | grep -i -E 'webkit|javascriptcore' || true

# Locality: the container's /root is overlayfs and the app checks the passwd home, so the workflow
# bind-mounts a runner directory over /root; the test home, the keystore and the temp dir live there.
[ "$(stat -f -c %T /root)" != overlayfs ] || fail "/root is an overlayfs: the workflow must bind-mount a runner dir over it"
export ATLAS_DUCK_TEST_HOME=/root/test-home
export ATLAS_DUCK_TEST_KEYSTORE=/root/test-keys
export TMPDIR=/root/tmp
export XDG_DATA_HOME=/root/.local/share
mkdir -p "$ATLAS_DUCK_TEST_HOME" "$ATLAS_DUCK_TEST_KEYSTORE" "$TMPDIR" "$XDG_DATA_HOME"
# tauri-driver and the app it starts: the E2E opt-in (the scripted-approver build keeps the driver
# variables), no bubblewrap sandbox in a container, software rendering.
export ATLAS_DUCK_E2E_ALLOW_DRIVER=1
export WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1
export WEBKIT_DISABLE_COMPOSITING_MODE=1
export LIBGL_ALWAYS_SOFTWARE=1

timeout 1500 xvfb-run -a dbus-run-session -- bash "$0" --inner "$dist"
