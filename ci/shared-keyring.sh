#!/usr/bin/env bash
# I-43 / I-44 keyring phases (§8.6, §13, V29): two installs sharing one home and one Secret
# Service, a daemon restart between the two I-44 phases, and a keyring on an NFS mount.
# Needs ATLAS_DUCK_SHARED_STATE (a local directory), ATLAS_DUCK_TEST_NFS_DIR (an NFS mount the
# user can write) and the same GNOME Keyring packages as ci/keyring-ci.sh.
set -euo pipefail
command -v gnome-keyring-daemon >/dev/null || { echo "shared-keyring: gnome-keyring-daemon missing" >&2; exit 2; }
command -v dbus-run-session >/dev/null || { echo "shared-keyring: dbus-run-session missing" >&2; exit 2; }
: "${ATLAS_DUCK_SHARED_STATE:?shared-keyring: ATLAS_DUCK_SHARED_STATE is not set}"
: "${ATLAS_DUCK_TEST_NFS_DIR:?shared-keyring: ATLAS_DUCK_TEST_NFS_DIR is not set}"
export ATLAS_DUCK_SHARED_STATE
export ATLAS_DUCK_TEST_NFS_DIR
rm -rf "$ATLAS_DUCK_SHARED_STATE"
mkdir -p "$ATLAS_DUCK_SHARED_STATE"
# A local keyring home, never an overlayfs or network one (the locality check fails closed there).
export XDG_DATA_HOME="${XDG_DATA_HOME:-$ATLAS_DUCK_SHARED_STATE/xdg}"
rm -rf "$XDG_DATA_HOME"
mkdir -p "$XDG_DATA_HOME"
# Exact process name (Linux truncates comm to 15 characters); -f would also match wrapper
# shells whose command line contains the string.
daemon=gnome-keyring-d

stop_daemon() {
  pkill -u "$(id -u)" -x "$daemon" || true
  local _
  for _ in $(seq 1 50); do
    pgrep -u "$(id -u)" -x "$daemon" >/dev/null || return 0
    sleep 0.2
  done
  echo "shared-keyring: $daemon did not exit" >&2
  return 1
}
trap stop_daemon EXIT

test_cmd='cargo test -p atlas-duck-audit --test shared_keyring --locked -- --ignored --test-threads=1 --nocapture --exact'

# Phases A and B1: one session bus, one daemon.
dbus-run-session -- bash -euo pipefail -c '
  printf "atlas-duck-ci" | gnome-keyring-daemon --components=secrets --daemonize --unlock >/dev/null
  '"$test_cmd"' i43_shared_home_sequential
  echo "shared-keyring: A ok"
  '"$test_cmd"' i44_concurrent_phase1
  echo "shared-keyring: B1 ok"
'

# Restart the daemon: a new bus, a new process, the same on-disk keyring.
stop_daemon
dbus-run-session -- bash -euo pipefail -c '
  printf "atlas-duck-ci" | gnome-keyring-daemon --components=secrets --daemonize --unlock >/dev/null
  '"$test_cmd"' i44_concurrent_phase2
  echo "shared-keyring: B2 ok"
'
stop_daemon

# Phase C: the keyring dirs of the test process are on NFS. OsKeyStore::new still needs a
# Secret Service to talk to, so a daemon keeps its files on the local XDG_DATA_HOME; only the
# test process sees the NFS one. The test refuses on the path check, so nothing may touch it.
nfs_xdg="$ATLAS_DUCK_TEST_NFS_DIR/xdg"
rm -rf "$nfs_xdg"
mkdir -p "$nfs_xdg/keyrings"
echo "sentinel" > "$nfs_xdg/keyrings/sentinel.keyring"
dbus-run-session -- bash -euo pipefail -c '
  printf "atlas-duck-ci" | gnome-keyring-daemon --components=secrets --daemonize --unlock >/dev/null
  XDG_DATA_HOME="'"$nfs_xdg"'" '"$test_cmd"' i44_keyring_on_nfs_refused
  echo "shared-keyring: C ok"
'
stop_daemon
echo "shared-keyring: all phases ok"
