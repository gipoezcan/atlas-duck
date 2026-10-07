#!/usr/bin/env bash
# §2.1: the CLI never touches keychain or DB; the sandbox links no HTTP client, keychain or DB code.
# Fails if `atlas-duck` or `atlas-duck-sandbox` dynamically links a webview, TLS, SQLite, secret-store
# or tray library. Prints every bin's full dependency list (the record Task 19 and Task 22 read).
# Usage: ci/check-bin-linkage.sh <dir containing the built bins>   (Linux: readelf, macOS: otool)
# Exit: 0 ok, 1 forbidden library linked, 2 usage error / missing binary / control failed.
set -euo pipefail

bin_dir="${1:-}"
if [ -z "$bin_dir" ]; then
  echo "usage: ci/check-bin-linkage.sh <bin-dir>" >&2
  exit 2
fi

pattern='webkit|gtk|gdk|soup|javascriptcore|ssl|crypto|sqlite|secret|WebView2Loader|ayatana'

case "$(uname -s)" in
  Linux)
    list_deps() { readelf -d "$1" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p'; }
    ;;
  Darwin)
    list_deps() { otool -L "$1" | tail -n +2 | awk '{ print $1 }'; }
    ;;
  *)
    echo "unsupported OS $(uname -s); use ci/check-bin-linkage.ps1 on Windows" >&2
    exit 2
    ;;
esac

for bin in atlas-duck-app atlas-duck atlas-duck-sandbox; do
  if [ ! -f "$bin_dir/$bin" ]; then
    echo "missing $bin_dir/$bin" >&2
    exit 2
  fi
done

status=0
for bin in atlas-duck atlas-duck-sandbox; do
  deps="$(list_deps "$bin_dir/$bin")"
  echo "== $bin dependencies =="
  echo "$deps"
  if [ -z "$deps" ]; then
    echo "CONTROL FAILED: no dependencies listed for $bin; the dependency listing is broken" >&2
    exit 2
  fi
  bad="$(printf '%s\n' "$deps" | grep -Ei "$pattern" || true)"
  if [ -n "$bad" ]; then
    echo "FAIL: $bin links forbidden libraries:" >&2
    echo "$bad" >&2
    status=1
  fi
done

# Control: the app itself links the webview, so the pattern provably matches on this OS.
app_deps="$(list_deps "$bin_dir/atlas-duck-app")"
echo "== atlas-duck-app dependencies (control) =="
echo "$app_deps"
if ! printf '%s\n' "$app_deps" | grep -Eiq "$pattern"; then
  echo "CONTROL FAILED: atlas-duck-app matches nothing; the pattern or the dependency listing is broken" >&2
  exit 2
fi

if [ "$status" -eq 0 ]; then
  echo "OK: atlas-duck and atlas-duck-sandbox link no webview/TLS/SQLite/secret-store/tray libraries"
fi
exit "$status"
