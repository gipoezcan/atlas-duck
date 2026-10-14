#!/usr/bin/env bash
# The M4 `cli_flows` integration tests on Linux (M4 plan Task 26 step 2): a private D-Bus session
# bus and a virtual display (the app links WebKitGTK and builds a tray). No real keychain and no
# Secret Service: the scripted-approver build uses the file keystore. Pure bash on purpose (the
# GitLab rust image has no Node).
#
#   bash ci/cli-flows-linux.sh            run every non-ignored flow and check the output
#   CLI_FLOWS_TEST=jira_flows bash ci/cli-flows-linux.sh
#                                         the same for another test target of the app (M5
#                                         jira_flows); the default is cli_flows
#   bash ci/cli-flows-linux.sh a b ...    extra test-binary arguments (e.g. `--ignored s02_`); the
#                                         pass-count minimum is not checked then, skip lines still are
set -euo pipefail

# A disposition inherited as "ignored" survives exec into the CLI under test and would hide the
# very signal paths X-08 exercises (SIGINT, SIGTERM, SIGHUP in turn). SIGPIPE is not checked: GitHub runners start the shell with it ignored, and the Rust runtime sets SIGPIPE to ignore in every binary at startup anyway.
check_dispositions() {
  local ign sig bit
  ign="$(awk '/^SigIgn:/ {print $2}' /proc/$$/status)"
  for sig in HUP:1 INT:2 TERM:15; do
    bit=$((1 << (${sig#*:} - 1)))
    if (( (0x$ign & bit) != 0 )); then
      echo "cli-flows-linux: SIG${sig%%:*} is ignored in this shell (SigIgn=$ign); the flows need the default disposition" >&2
      exit 2
    fi
  done
  echo "cli-flows-linux: SIGHUP/SIGINT/SIGTERM dispositions are default (SigIgn=$ign)"
}

if [ "${1:-}" != --inner ]; then
  command -v dbus-run-session >/dev/null || { echo "cli-flows-linux: dbus-run-session missing" >&2; exit 2; }
  command -v xvfb-run >/dev/null || { echo "cli-flows-linux: xvfb-run missing" >&2; exit 2; }
  # GitLab's runner starts the job shell with SIGINT ignored (SigIgn is inherited through exec):
  # re-exec once through perl, which can set the three dispositions back to default, then check.
  if [ -z "${CLI_FLOWS_SIG_RESET:-}" ]; then
    ign="$(awk '/^SigIgn:/ {print $2}' /proc/$$/status)"
    if (( (0x$ign & ((1 << 0) | (1 << 1) | (1 << 14))) != 0 )); then
      command -v perl >/dev/null || { echo "cli-flows-linux: HUP/INT/TERM are ignored (SigIgn=$ign) and perl is missing to reset them" >&2; exit 2; }
      export CLI_FLOWS_SIG_RESET=1
      exec perl -e '$SIG{HUP} = $SIG{INT} = $SIG{TERM} = "DEFAULT"; exec @ARGV or die "exec: $!"' bash "$0" "$@"
    fi
  fi
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
target="${CLI_FLOWS_TEST:-cli_flows}"
cargo_args=(test -p atlas-duck-app --features scripted-approver --locked --test "$target")
log="$TMPDIR/$target.log"

# --test-threads=2: the flows start whole app instances (T22 handoff).
set +e
cargo "${cargo_args[@]}" -- --nocapture --test-threads=2 "$@" 2>&1 | tee "$log"
status="${PIPESTATUS[0]}"
set -e
if [ "$status" -ne 0 ]; then
  echo "::error::$target failed (exit $status)"
  exit "$status"
fi

# A skipped flow prints a "skipped:" line and counts as passed: fail on any (T22 review).
if grep -E '(^|[[:space:]])skipped: ' "$log"; then
  echo "::error::$target skipped tests (is ATLAS_DUCK_CLI_FLOWS set?)"
  exit 1
fi

if [ "$#" -eq 0 ]; then
  # Expected minimum: every listed test minus the #[ignore]d ones.
  total="$(cargo "${cargo_args[@]}" -- --list 2>/dev/null | grep -c ': test$' || true)"
  ignored="$(cargo "${cargo_args[@]}" -- --list --ignored 2>/dev/null | grep -c ': test$' || true)"
  expected=$((total - ignored))
  passed="$(sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' "$log" | awk '{s += $1} END {print s + 0}')"
  echo "cli-flows-linux: $target: $passed passed, expected at least $expected ($total listed, $ignored ignored)"
  if [ "$expected" -eq 0 ] || [ "$passed" -lt "$expected" ]; then
    echo "::error::$target passed $passed tests, expected at least $expected"
    exit 1
  fi
fi
