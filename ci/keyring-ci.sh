#!/usr/bin/env bash
# Linux OS-keychain tests against a file-backed Secret Service (GNOME Keyring) on a private
# session bus (§13, L39, V08). Extra args are passed to the test binary (e.g. a name filter).
set -euo pipefail
command -v gnome-keyring-daemon >/dev/null || { echo "keyring-ci: gnome-keyring-daemon missing" >&2; exit 2; }
command -v dbus-run-session >/dev/null || { echo "keyring-ci: dbus-run-session missing" >&2; exit 2; }
export XDG_DATA_HOME="${XDG_DATA_HOME:-$PWD/.ci-xdg}"   # never an overlayfs home: the locality check fails closed there
mkdir -p "$XDG_DATA_HOME"
# OsKeyStore checks both $XDG_DATA_HOME/{keyrings,kwalletd} and the passwd home's .local/share/*
# (the locality check ignores $HOME). In a container that home is an overlayfs and the check
# fails closed, so point an absent <home>/.local/share at the project-local XDG dir.
passwd_home="$(getent passwd "$(id -u)" | cut -d: -f6)"
share="$passwd_home/.local/share"
echo "keyring-ci: passwd home $passwd_home ($(stat -f -c %T "$passwd_home" 2>&1)), XDG_DATA_HOME $XDG_DATA_HOME ($(stat -f -c %T "$XDG_DATA_HOME" 2>&1)), TMPDIR ${TMPDIR:-unset} ($(stat -f -c %T "${TMPDIR:-/tmp}" 2>&1))"
if [ ! -e "$share" ] && [ "$(stat -f -c %T "$passwd_home")" = overlayfs ]; then
  mkdir -p "$passwd_home/.local"
  ln -s "$XDG_DATA_HOME" "$share"
  echo "keyring-ci: linked $share -> $XDG_DATA_HOME (overlayfs home)"
fi
for d in keyrings kwalletd; do
  for base in "$XDG_DATA_HOME" "$share"; do
    probe="$base/$d"
    while [ ! -e "$probe" ] && [ "$probe" != / ]; do probe="$(dirname "$probe")"; done
    echo "keyring-ci: locality dir $base/$d -> $probe ($(stat -f -c %T "$probe" 2>&1))"
  done
done
exec dbus-run-session -- bash -euo pipefail -c '
  # The daemon outlives the bus it was started on; stop it when this shell ends.
  trap "pkill -u \"\$(id -u)\" -x gnome-keyring-d || true" EXIT
  printf "atlas-duck-ci" | gnome-keyring-daemon --components=secrets --daemonize --unlock >/dev/null
  echo "keyring-ci: keyring files: $(ls "$XDG_DATA_HOME/keyrings" 2>/dev/null | tr "\n" " ")"
  cargo test -p atlas-duck-audit --test os_keystore --locked -- --ignored --test-threads=1 --nocapture "$@"
  echo "keyring-ci: keyring files after: $(ls -l "$XDG_DATA_HOME/keyrings" || true)"
' keyring-ci "$@"
