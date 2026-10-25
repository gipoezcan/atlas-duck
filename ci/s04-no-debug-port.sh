#!/usr/bin/env bash
# ci/s04-no-debug-port.sh <release atlas-duck-app>
#
# Spec §13 S-04 (Linux), M6 plan Task 33: a RELEASE build started with the WebKit inspector
# variables set (and the E2E opt-in, which a release build must ignore) opens no debug port while
# a real webview runs. CI only (it starts the app and leaves the passwd home to the app).
#
# The argument is any release app: target/release/atlas-duck-app (ci.yml), the installed
# /usr/bin/atlas-duck-app of the deb or rpm, or an AppImage file (M10 Task 27, install-probes.yml).
# For an AppImage the started process is the type-2 runtime and the app runs below it, so the
# webview is looked for among all DESCENDANTS of the started process, not only its children.
#
# M10 Task 27 (L216 (c), L217): TAURI_WEBVIEW_AUTOMATION=true is set next to the inspector
# variables (tauri-runtime-wry reads it in every build and lets WebKitGTK be automated); the
# release build must scrub it (`startup_env_scrubbed removed_var=TAURI_WEBVIEW_AUTOMATION`) and
# no driver/automation port may appear: no TCP listener exists after the check that did not exist
# before the app started (the app is non-dumpable, so `ss -p` cannot name its sockets; a diff of
# the listener table is the check), and none on the usual driver ports 4444, 4445 and 9515.
#
# Why no `--background`: a cold `--background` start opens no window, so no webview would exist and
# the check would pass vacuously. A no-argument start with no pinned paths file is "before first
# run" (here: a pinned data dir with no store, ci/pinned-fixture.sh) and opens the Setup window, a real WebKitGTK webview. The script requires a
# WebKitWebProcess (evidence the webview exists) and a listener on a control port it opened
# itself (evidence that the probe can see a listener).
#
# Checks: no listener on the inspector port; `startup_env_scrubbed` for each variable set in
# the app's diag log; a WebKitWebProcess that is a CHILD of the app is running (a process left over
# from an earlier step must neither satisfy the check nor go unnoticed: any WebKitWebProcess that
# exists before the app starts fails the script, and the CI job kills strays before this step).
set -euo pipefail
export LC_ALL=C

exe="${1:?usage: ci/s04-no-debug-port.sh <release atlas-duck-app>}"
[ "${CI:-}" = true ] || { echo "s04: refusing to run outside CI (CI=true)" >&2; exit 2; }
[ -x "$exe" ] || { echo "s04: $exe is not an executable" >&2; exit 2; }
command -v comm >/dev/null || { echo "s04: comm missing" >&2; exit 2; }
command -v xvfb-run >/dev/null || { echo "s04: xvfb-run missing" >&2; exit 2; }
command -v dbus-run-session >/dev/null || { echo "s04: dbus-run-session missing" >&2; exit 2; }
command -v ss >/dev/null || { echo "s04: ss missing" >&2; exit 2; }

if [ -z "${S04_INNER:-}" ]; then
  export S04_INNER=1
  exec xvfb-run -a dbus-run-session -- bash "$0" "$@"
fi

fail() { echo "FAIL: $*" >&2; exit 1; }

# listening <port>: whether a TCP listener holds the port (any address).
listening() { ss -H -ltn "sport = :$1" | grep -q .; }

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
PY
}

port="$(free_port)"
control="$(free_port)"
while [ "$control" = "$port" ]; do control="$(free_port)"; done

work="$(mktemp -d)"
holder=""
pid=""
cleanup() {
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  [ -n "$holder" ] && kill "$holder" 2>/dev/null || true
  pkill -x atlas-duck-app || true
  # the fixture's pinned paths file (CI only) and the throw-away data dir
  [ -n "${passwd_home:-}" ] && rm -f "$passwd_home"/.config/atlas-duck/paths-*.toml
  rm -rf "$work"
}
trap cleanup EXIT

# Positive control: the probe sees a listener that exists.
python3 - "$control" <<'PY' &
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(1)
time.sleep(600)
PY
holder=$!
for _ in $(seq 1 50); do listening "$control" && break; sleep 0.1; done
listening "$control" || fail "positive control: the probe does not see the listener on $control"
listening "$port" && fail "port $port is taken before the app starts"
echo "S04 control_port=$control seen, inspector_port=$port free"

# The diag log lives in <data dir>/logs, so the app needs a pinned data dir (ci/pinned-fixture.sh, as
# the Tray smoke step does). A pinned dir without a store is the first-run state: no-argument start
# opens the Setup window (a real webview, checked below). CI only: it replaces this host's pinned file.
data_dir="$(bash "$(dirname "$0")/pinned-fixture.sh" --data-dir "$work/data")"
passwd_home="$(getent passwd "$(id -un)" | cut -d: -f6)"
diag="$data_dir/logs/diag.log"
export WEBKIT_INSPECTOR_SERVER="127.0.0.1:$port"
export WEBKIT_INSPECTOR_HTTP_SERVER="127.0.0.1:$port"
export WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="--remote-debugging-port=$port"
export WEBVIEW2_USER_DATA_FOLDER="$work/wv2"
export ATLAS_DUCK_E2E_ALLOW_DRIVER=1
export TAURI_WEBVIEW_AUTOMATION=true
if pgrep -f WebKitWebProcess >/dev/null; then
  ps -eo pid,ppid,args | grep -F WebKitWebProcess >&2 || true
  fail "a WebKitWebProcess exists before the app starts (a stray from an earlier step)"
fi
# The listener table before the app starts (local address:port), for the automation-port diff.
listeners() { ss -H -ltn | awk '{print $4}' | sort -u; }
listeners >"$work/listeners.before"
"$exe" >"$work/app.out" 2>&1 &
pid=$!

# descendants <pid>: every process below <pid> (children, grandchildren, ...), one pid per line.
descendants() {
  local queue="$1" next p c
  while [ -n "$queue" ]; do
    next=""
    for p in $queue; do
      for c in $(pgrep -P "$p" 2>/dev/null || true); do
        echo "$c"
        next="$next $c"
      done
    done
    queue="${next# }"
  done
}

# webviews <pid>: the WebKitWebProcess processes below <pid> (15-character comm truncation, so
# the command line is matched).
webviews() {
  local d
  for d in $(descendants "$1"); do
    if tr '\0' ' ' <"/proc/$d/cmdline" 2>/dev/null | grep -q WebKitWebProcess; then echo "$d"; fi
  done
}

# A real webview: WebKitGTK's web process below the started process.
seen=""
for _ in $(seq 1 300); do
  if ! kill -0 "$pid" 2>/dev/null; then
    cat "$work/app.out" >&2 || true
    fail "the release app exited before a webview process appeared"
  fi
  if [ -n "$(webviews "$pid")" ]; then seen=1; break; fi
  sleep 0.2
done
[ -n "$seen" ] || { cat "$work/app.out" >&2 || true; fail "no WebKitWebProcess below the app within 60 s: no webview, the check would be vacuous"; }
echo "S04 webview_process=$(webviews "$pid" | head -n 1) (below started pid $pid)"

# Give the webview time to open a port, were one to be opened.
sleep 15
kill -0 "$pid" 2>/dev/null || { cat "$work/app.out" >&2 || true; fail "the release app died during the check"; }
if listening "$port"; then
  ss -ltnp >&2 || true
  fail "a debug port opened on $port with the inspector variables set (S-04)"
fi
ss -ltn | grep -F "127.0.0.1:$port" && fail "port $port appears in the socket table"
for p in 4444 4445 9515; do
  if listening "$p"; then
    ss -ltn >&2 || true
    fail "a listener on the driver port $p with TAURI_WEBVIEW_AUTOMATION=true (S-04)"
  fi
done
listeners >"$work/listeners.after"
new_listeners="$(comm -13 "$work/listeners.before" "$work/listeners.after" | grep -v -E ":$control\$" || true)"
if [ -n "$new_listeners" ]; then
  ss -ltn >&2 || true
  fail "new TCP listener(s) while the release app ran with TAURI_WEBVIEW_AUTOMATION=true (a driver/automation port, S-04): $(printf '%s' "$new_listeners" | tr '\n' ' ')"
fi
echo "S04 automation: TAURI_WEBVIEW_AUTOMATION=true set, no new TCP listener, none on 4444/4445/9515"

[ -f "$diag" ] || fail "no $diag"
echo "--- $diag"
cat "$diag" || true
for v in WEBKIT_INSPECTOR_SERVER WEBKIT_INSPECTOR_HTTP_SERVER WEBVIEW2_USER_DATA_FOLDER WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS TAURI_WEBVIEW_AUTOMATION; do
  grep -E "startup_env_scrubbed.*removed_var=$v( |$)" "$diag" >/dev/null || fail "no startup_env_scrubbed line for $v in $diag"
done
echo "S04 OK: no listener on $port and no automation port with the inspector variables and TAURI_WEBVIEW_AUTOMATION=true set; the release build scrubbed all five"
