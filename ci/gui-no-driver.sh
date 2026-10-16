#!/usr/bin/env bash
# ci/gui-no-driver.sh <label> <work-dir> <app> <cli> [<cli word>...]
#
# The driver-free GUI checks of a packaged Linux build of the DEBUG `scripted-approver` app
# (e2e-bundle.yml: `appimage-m6` through ci/appimage-smoke.sh --m6, `fedora-no-tray-host` through
# ci/fedora-no-tray-host.sh). <app> starts the GUI (the AppImage, /usr/bin/atlas-duck-app); <cli>
# and its words run the CLI (`<AppImage> __cli`, /usr/bin/atlas-duck).
#
# Why no WebDriver (M6 CI ruling, task cifix6, run 38885675593): the packaged runs started on an
# empty test home, where the Setup window is incognito (windows.rs: no data dir yet), and wry gives an
# incognito webview a fresh ephemeral WebKit context without automation, so WebKitWebDriver's session
# finds no "wry" browser and no webview ("Failed to match capabilities" / "failed to create a new
# browsing context"). With the paths pinned first the wizard goes to the passphrase step, whose
# credential window has its own web context (S-07), which WebKitWebDriver cannot reach on Linux
# (tests/e2e/flows.rs CREDENTIAL_NOT_ON_LINUX). The wizard, Install CLI to PATH and the store-backed
# windows are the manual rows of docs/release/linux-gui-checklist.md.
#
# Runs inside the caller's xvfb-run and session bus, with ATLAS_DUCK_TEST_HOME (an empty directory)
# and CI=true (ci/pinned-fixture.sh) set. What it checks, on a pinned data dir with no store (the
# first-run gate, as the plain e2e job's Setup flow):
#   1. the session bus has no org.kde.StatusNotifierWatcher (no tray host);
#   2. a cold no-argument start serves its endpoint, logs tray_host=missing and serve_state=first_run,
#      and maps a window titled "atlas-duck: Setup" (xwininfo, no driver);
#   3. `doctor` exits 0 with gate first_run and tray_host missing;
#   4. a forwarded no-argument launch and a forwarded `--background` launch (second processes) exit 0,
#      are logged as forwarded_launch and leave the set of mapped app windows unchanged;
#   5. SIGTERM runs the shutdown path: exit 0, os_end_session reason=sigterm, no quit_wait_expired or
#      quit_core_lost, no atlas-duck-app left;
#   6. the next start comes up clean (2 to 5 again: endpoint, Setup window, doctor, SIGTERM exit 0).
set -euo pipefail
export LC_ALL=C

[ "$#" -ge 4 ] || { echo "usage: ci/gui-no-driver.sh <label> <work-dir> <app> <cli> [<cli word>...]" >&2; exit 2; }
label="$1" work="$2" app="$3"
shift 3
cli=("$@")

# Seconds a forwarded launch gets to open (or not open) a window before the windows are compared.
SETTLE=4
TITLE_SETUP="atlas-duck: Setup"

say() { echo "$label: $*"; }
die() { echo "FAIL ($label): $*" >&2; exit 1; }

[ -n "${ATLAS_DUCK_TEST_HOME:-}" ] && [ -d "$ATLAS_DUCK_TEST_HOME" ] || die "ATLAS_DUCK_TEST_HOME is not an existing directory"
[ -n "${DISPLAY:-}" ] || die "no DISPLAY: run under xvfb-run"
[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] || die "no session bus: run under dbus-run-session"
for tool in xwininfo dbus-send python3 pgrep ps timeout; do
  command -v "$tool" >/dev/null || die "$tool missing"
done
[ -x "$app" ] || die "$app is not an executable"
! pgrep -x atlas-duck-app >/dev/null || die "an atlas-duck-app is running before the first start"

here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$work"
app_pid=""
cleanup() {
  [ -z "$app_pid" ] || kill -KILL "$app_pid" 2>/dev/null || true
  pkill -KILL -x atlas-duck-app 2>/dev/null || true
}
trap cleanup EXIT

# 1. No tray host.
if dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus.NameHasOwner string:org.kde.StatusNotifierWatcher 2>/dev/null | grep -q 'boolean true'; then
  die "the session bus has a StatusNotifierWatcher owner; this is not a no-tray-host run"
fi
say "no org.kde.StatusNotifierWatcher owner on the session bus"

# A pinned data dir with no store (the first-run gate): the diag log and the endpoint live in it.
data="$(bash "$here/pinned-fixture.sh" --home "$ATLAS_DUCK_TEST_HOME" --data-dir "$ATLAS_DUCK_TEST_HOME/data")"
diag="$data/logs/diag.log"
endpoint="$data/endpoint"

# ---- helpers ----------------------------------------------------------------------------------------

# alive <pid>: running and not a zombie (kill -0 succeeds on an unreaped child).
alive() {
  local s
  s="$(ps -o stat= -p "$1" 2>/dev/null)" || return 1
  case "$s" in Z*|"") return 1 ;; esac
}

# app_windows: the titles of the MAPPED top-level windows named "atlas-duck: <window>", sorted. A
# hidden window (unmapped) is not listed. Never fails (pipefail, set -e in the callers).
app_windows() {
  local id title
  { xwininfo -root -tree 2>/dev/null || true; } | sed -n 's/^[[:space:]]*\(0x[0-9a-fA-F]*\) "\(atlas-duck: [^"]*\)".*/\1 \2/p' |
    while read -r id title; do
      if xwininfo -id "$id" 2>/dev/null | grep -q 'Map State: IsViewable'; then printf '%s\n' "$title"; fi
    done | sort
}

# grep reads to the end (no -q): an early exit would SIGPIPE app_windows and fail the pipeline.
has_window() { app_windows | grep -xF "$1" >/dev/null; }

# diag_count <extended regex>: matching lines of the diag log (0 without a log).
diag_count() {
  [ -f "$diag" ] || { echo 0; return; }
  grep -c -E "$1" "$diag" || true
}

diag_count_over() { [ "$(diag_count "$1")" -gt "$2" ]; }

json_field() {
  python3 -I - "$1" "$2" <<'PY'
import json, sys
node = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    node = node[key]
print(node)
PY
}

# report <message>: fails with what the display, the app and its diag log show.
report() {
  {
    echo "--- windows (xwininfo -root -tree, atlas-duck only)"
    xwininfo -root -tree 2>/dev/null | grep -F '"atlas-duck' || echo "(none)"
    echo "--- processes"
    ps -eo pid,ppid,stat,args | grep -E 'atlas-duck|AppImage|WebKit' | grep -v grep || true
    for f in "$work"/app-*.log; do
      [ -f "$f" ] || continue
      echo "--- $f (end)"
      tail -n 40 "$f" || true
    done
    echo "--- $diag (end)"
    tail -n 60 "$diag" 2>/dev/null || echo "(no diag log)"
  } >&2
  die "$*"
}

# wait_for <seconds> <what> <command...>: until the command succeeds; fails early if the app died.
wait_for() {
  local secs="$1" what="$2" end
  shift 2
  end=$((SECONDS + secs))
  until "$@"; do
    if [ -n "$app_pid" ] && ! alive "$app_pid"; then report "the app (pid $app_pid) exited while waiting for $what"; fi
    [ "$SECONDS" -lt "$end" ] || report "timed out after ${secs}s waiting for $what"
    sleep 0.5
  done
}

# start_app <name>: a cold no-argument start (what the menu entry does), in the background.
start_app() {
  "$app" >"$work/app-$1.log" 2>&1 &
  app_pid=$!
  wait_for 90 "the endpoint file $endpoint" test -e "$endpoint"
  wait_for 90 "a mapped window titled '$TITLE_SETUP'" has_window "$TITLE_SETUP"
  say "$1: cold start pid $app_pid serves its endpoint and shows '$TITLE_SETUP'"
}

# doctor <name>: exit 0, gate first_run, tray_host missing.
doctor() {
  local code gate tray
  set +e
  timeout 180 "${cli[@]}" --timeout 120 doctor >"$work/doctor-$1.json" 2>"$work/doctor-$1.err"
  code=$?
  set -e
  if [ "$code" -ne 0 ]; then
    cat "$work/doctor-$1.json" "$work/doctor-$1.err" >&2 || true
    report "doctor ($1) exited $code, expected 0"
  fi
  gate="$(json_field "$work/doctor-$1.json" data.app.gate)" || report "doctor ($1) has no data.app.gate: $(cat "$work/doctor-$1.json")"
  [ "$gate" = first_run ] || report "doctor ($1) gate is '$gate', expected first_run"
  tray="$(json_field "$work/doctor-$1.json" data.tray_host)" || report "doctor ($1) has no data.tray_host: $(cat "$work/doctor-$1.json")"
  [ "$tray" = missing ] || report "doctor ($1) tray_host is '$tray', expected missing"
  say "$1: doctor exit 0, gate=first_run, tray_host=missing"
}

# forwarded <what> [<arg>...]: a second process forwards to the running instance and exits 0.
forwarded() {
  local what="$1" before windows code
  shift
  before="$(diag_count 'event=forwarded_launch')"
  windows="$(app_windows)"
  set +e
  timeout 60 "$app" "$@" >"$work/app-forward-$what.log" 2>&1
  code=$?
  set -e
  [ "$code" -eq 0 ] || report "the forwarded $what launch exited $code, expected 0"
  wait_for 30 "a forwarded_launch line for the $what launch" diag_count_over 'event=forwarded_launch' "$before"
  # tray.rs logs forwarded_launch before it acts on the launch: let a window a mistaken launch would
  # open appear before the windows are compared.
  sleep "$SETTLE"
  alive "$app_pid" || report "the first instance died after the forwarded $what launch"
  if [ "$(app_windows)" != "$windows" ]; then
    report "the forwarded $what launch changed the mapped windows: before [$(echo "$windows" | paste -sd,)] after [$(app_windows | paste -sd,)]"
  fi
  say "forwarded $what launch: exit 0, forwarded_launch logged, windows unchanged ($(echo "$windows" | paste -sd,))"
}

# stop_app <name>: SIGTERM runs the one shutdown path (os_hooks): exit 0 and the os_end_session line.
stop_app() {
  local offset code watchdog after i
  offset="$(stat -c %s "$diag")"
  kill -TERM "$app_pid"
  ( sleep 60; kill -KILL "$app_pid" 2>/dev/null ) &
  watchdog=$!
  set +e
  wait "$app_pid"
  code=$?
  set -e
  kill "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  [ "$code" -eq 0 ] || report "after SIGTERM ($1) the app exited $code, expected 0 (137: still running after 60 s)"
  after="$(tail -c +"$((offset + 1))" "$diag")"
  echo "$after" | grep -qE 'event=os_end_session reason=sigterm' || report "no os_end_session reason=sigterm line after SIGTERM ($1)"
  for bad in quit_wait_expired quit_core_lost; do
    ! grep -qF "$bad" "$diag" || report "the diag log shows $bad"
  done
  for i in $(seq 1 40); do
    pgrep -x atlas-duck-app >/dev/null || break
    sleep 0.25
  done
  ! pgrep -x atlas-duck-app >/dev/null || report "an atlas-duck-app is still running after SIGTERM ($1)"
  if [ -e "$endpoint" ]; then say "$1: (info) the endpoint file is still there after the stop"; fi
  app_pid=""
  say "$1: SIGTERM: exit 0, os_end_session reason=sigterm, no quit_wait_expired/quit_core_lost, no app left"
}

# ---- the run ---------------------------------------------------------------------------------------------

# 2. Cold start.
start_app cold
[ "$(diag_count 'event=tray_host_checked tray_host=missing')" -ge 1 ] || report "the diag log has no tray_host_checked tray_host=missing"
[ "$(diag_count 'event=serve_started serve_state=first_run')" -ge 1 ] || report "the diag log has no serve_started serve_state=first_run"
say "cold: the diag log has tray_host=missing and serve_state=first_run"
say "cold: mapped app windows: $(app_windows | paste -sd,)"

# 3. doctor.
doctor cold

# 4. Forwarded launches.
forwarded no-argument
forwarded --background --background

# 5. SIGTERM.
stop_app cold

# 6. The next start comes up clean. A file a stop left behind must not satisfy the endpoint wait.
rm -f "$endpoint"
start_app next
[ "$(diag_count 'event=serve_started serve_state=first_run')" -ge 2 ] || report "the next start logged no second serve_started serve_state=first_run"
doctor next
stop_app next

say "OK: no tray host, cold start (Setup window), doctor, forwarded launches, SIGTERM stop, clean next start"
