#!/usr/bin/env bash
# The M4 `cli_flows` integration tests on Linux (M4 plan Task 26 step 2): a private D-Bus session
# bus and a virtual display (the app links WebKitGTK and builds a tray). No real keychain and no
# Secret Service: the scripted-approver build uses the file keystore. Pure bash on purpose (the
# GitLab rust image has no Node).
#
#   bash ci/cli-flows-linux.sh            run every non-ignored flow and check the output
#   bash ci/cli-flows-linux.sh a b ...    extra test-binary arguments (e.g. `--ignored s02_`); the
#                                         pass-count minimum is not checked then, skip lines still are
set -euo pipefail

# A disposition inherited as "ignored" survives exec into the CLI under test and would hide the
# very signal paths X-08 exercises (SIGINT, SIGTERM, SIGHUP in turn); SIGPIPE too.
check_dispositions() {
  local ign sig bit
  ign="$(awk '/^SigIgn:/ {print $2}' /proc/$$/status)"
  for sig in HUP:1 INT:2 PIPE:13 TERM:15; do
    bit=$((1 << (${sig#*:} - 1)))
    if (( (0x$ign & bit) != 0 )); then
      echo "cli-flows-linux: SIG${sig%%:*} is ignored in this shell (SigIgn=$ign); the flows need the default disposition" >&2
      exit 2
    fi
  done
  echo "cli-flows-linux: SIGHUP/SIGINT/SIGPIPE/SIGTERM dispositions are default (SigIgn=$ign)"
}

if [ "${1:-}" != --inner ]; then
  command -v dbus-run-session >/dev/null || { echo "cli-flows-linux: dbus-run-session missing" >&2; exit 2; }
  command -v xvfb-run >/dev/null || { echo "cli-flows-linux: xvfb-run missing" >&2; exit 2; }
  check_dispositions
  # The runner's /tmp may be an overlayfs (GitLab containers): the data-dir locality check fails
  # closed there, so keep temp files on the project volume (see ci/keyring-ci.sh, core-suite-fedora).
  export TMPDIR="${TMPDIR:-$PWD/.ci-tmp}"
  mkdir -p "$TMPDIR"
  exec dbus-run-session -- xvfb-run -a bash "$0" --inner "$@"
fi
shift

check_dispositions  # again, inside dbus-run-session and xvfb-run
export ATLAS_DUCK_CLI_FLOWS=1
cargo_args=(test -p atlas-duck-app --features scripted-approver --locked --test cli_flows)
log="$TMPDIR/cli-flows.log"

# --test-threads=2: the flows start whole app instances (T22 handoff).
set +e
cargo "${cargo_args[@]}" -- --nocapture --test-threads=2 "$@" 2>&1 | tee "$log"
status="${PIPESTATUS[0]}"
set -e
if [ "$status" -ne 0 ]; then
  echo "::error::cli_flows failed (exit $status)"
  exit "$status"
fi

# A skipped flow prints a "skipped:" line and counts as passed: fail on any (T22 review).
if grep -E '(^|[[:space:]])skipped: ' "$log"; then
  echo "::error::cli_flows skipped tests (is ATLAS_DUCK_CLI_FLOWS set?)"
  exit 1
fi

if [ "$#" -eq 0 ]; then
  # Expected minimum: every listed test minus the #[ignore]d ones.
  total="$(cargo "${cargo_args[@]}" -- --list 2>/dev/null | grep -c ': test$' || true)"
  ignored="$(cargo "${cargo_args[@]}" -- --list --ignored 2>/dev/null | grep -c ': test$' || true)"
  expected=$((total - ignored))
  passed="$(sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' "$log" | awk '{s += $1} END {print s + 0}')"
  echo "cli-flows-linux: $passed passed, expected at least $expected ($total listed, $ignored ignored)"
  if [ "$expected" -eq 0 ] || [ "$passed" -lt "$expected" ]; then
    echo "::error::cli_flows passed $passed tests, expected at least $expected"
    exit 1
  fi
fi
