#!/usr/bin/env bash
# Linux OS-keychain tests against a file-backed Secret Service (GNOME Keyring) on a private
# session bus (§13, L39, V08). Extra args are passed to the test binary (e.g. a name filter).
set -euo pipefail
command -v gnome-keyring-daemon >/dev/null || { echo "keyring-ci: gnome-keyring-daemon missing" >&2; exit 2; }
command -v dbus-run-session >/dev/null || { echo "keyring-ci: dbus-run-session missing" >&2; exit 2; }
export XDG_DATA_HOME="${XDG_DATA_HOME:-$PWD/.ci-xdg}"   # never an overlayfs home: the locality check fails closed there
mkdir -p "$XDG_DATA_HOME"
exec dbus-run-session -- bash -euo pipefail -c '
  # The daemon outlives the bus it was started on; stop it when this shell ends.
  trap "pkill -u \"\$(id -u)\" -x gnome-keyring-d || true" EXIT
  printf "atlas-duck-ci" | gnome-keyring-daemon --components=secrets --daemonize --unlock >/dev/null
  echo "keyring-ci: keyring files: $(ls "$XDG_DATA_HOME/keyrings" 2>/dev/null | tr "\n" " ")"
  cargo test -p atlas-duck-audit --test os_keystore --locked -- --ignored --test-threads=1 --nocapture "$@"
  echo "keyring-ci: keyring files after: $(ls -l "$XDG_DATA_HOME/keyrings" || true)"
' keyring-ci "$@"
