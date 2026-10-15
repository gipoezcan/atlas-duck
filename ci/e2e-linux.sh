#!/usr/bin/env bash
# The M6 `e2e` integration tests on Linux (M6 plan Task 33, spec §13 UI End to end): the real
# debug `scripted-approver` app driven through `tauri-driver` and WebKitWebDriver, under Xvfb on a
# private D-Bus session bus. Pure bash on purpose (as ci/cli-flows-linux.sh).
#
# Environment:
#   ATLAS_DUCK_TAURI_DRIVER   the tauri-driver executable (default: `tauri-driver` on PATH)
#   ATLAS_DUCK_E2E_ARTIFACTS  where failure screenshots go (optional)
#   TMPDIR                    kept on the project volume (the data-dir locality check fails closed on overlayfs)
#
#   bash ci/e2e-linux.sh            run every non-ignored flow, then check the output
#   bash ci/e2e-linux.sh a b ...    extra test-binary arguments; the pass-count minimum is not checked
set -euo pipefail

if [ "${1:-}" != --inner ]; then
  command -v dbus-run-session >/dev/null || { echo "e2e-linux: dbus-run-session missing" >&2; exit 2; }
  command -v xvfb-run >/dev/null || { echo "e2e-linux: xvfb-run missing" >&2; exit 2; }
  command -v WebKitWebDriver >/dev/null || { echo "e2e-linux: WebKitWebDriver missing (apt: webkit2gtk-driver)" >&2; exit 2; }
  driver="${ATLAS_DUCK_TAURI_DRIVER:-$(command -v tauri-driver || true)}"
  [ -n "$driver" ] && [ -x "$driver" ] || { echo "e2e-linux: tauri-driver not found (ATLAS_DUCK_TAURI_DRIVER)" >&2; exit 2; }
  export ATLAS_DUCK_TAURI_DRIVER="$driver"
  "$driver" --help >/dev/null 2>&1 || echo "e2e-linux: warning: '$driver --help' failed" >&2
  export TMPDIR="${TMPDIR:-$PWD/.ci-tmp}"
  mkdir -p "$TMPDIR"
  exec dbus-run-session -- xvfb-run -a bash "$0" --inner "$@"
fi
shift

# CI opt-ins: the flows start apps (ATLAS_DUCK_CLI_FLOWS) and the scripted-approver build keeps the
# WebKit driver variables for the driver's own app (ATLAS_DUCK_E2E_ALLOW_DRIVER, T32; the driver
# also sets it for the app it starts).
export ATLAS_DUCK_CLI_FLOWS=1
export ATLAS_DUCK_E2E_ALLOW_DRIVER=1
log="$TMPDIR/e2e.log"
cargo_args=(test -p atlas-duck-app --features scripted-approver --locked --test e2e)

# --test-threads=1: every flow owns one app and one driver (T32).
set +e
cargo "${cargo_args[@]}" -- --nocapture --test-threads=1 "$@" 2>&1 | tee "$log"
status="${PIPESTATUS[0]}"
set -e
if [ "$status" -ne 0 ]; then
  echo "::error::e2e failed (exit $status)"
  exit "$status"
fi

# A skipped flow prints a "skipped:" line and counts as passed: fail on any, require the pass count
# of (listed - #[ignore]d) through ci/check-no-skips.mjs when no extra arguments narrowed the run.
if [ "$#" -eq 0 ]; then
  cargo "${cargo_args[@]}" -- --list 2>/dev/null > "$TMPDIR/e2e.list"
  cargo "${cargo_args[@]}" -- --list --ignored 2>/dev/null > "$TMPDIR/e2e.ignored"
  node ci/check-no-skips.mjs "$log" "$TMPDIR/e2e.list" "$TMPDIR/e2e.ignored" e2e
elif grep -E '(^|[[:space:]])skipped: ' "$log"; then
  echo "::error::e2e skipped tests (is ATLAS_DUCK_CLI_FLOWS set?)"
  exit 1
fi
grep -E '(^|[[:space:]])P01 ' "$log" || true
