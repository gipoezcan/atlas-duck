#!/usr/bin/env bash
# ci/check-release-build.sh <target>
#
# Runs in every bundle job right before `cargo tauri build` (M4 plan Task 26, T21 I-2, spec §13).
# The test-only features (`test-paths`, `test-env`, `testing`, `insecure-test-http`,
# `scripted-approver`) are locked out of release builds by compile_error! under
# `not(debug_assertions)`; a file scan of the manifests cannot see anything that turns debug
# assertions back on or enables a feature from outside. So this checks, for the build the job is
# about to run:
#   1. the environment: no RUSTFLAGS-style variable and no CARGO_PROFILE_*_DEBUG_ASSERTIONS enables
#      debug assertions (they would defeat the locks);
#   2. the `cargo tauri build` lines of bundle.yml: no `--debug`, no `--features`, no `--profile`,
#      no `--config` (either could select a profile or features from outside), no
#      `scripted-approver` (a debug-profile build is the one place the locks are open);
#   3. the dependency tree of the app with the bundle build's own flags (target, `--locked`, no
#      features): no workspace package shows a test-only feature in its `{f}` list. NOT the plan's
#      `cargo tree --release` (it has no such flag: the check was vacuous) and not `-e features`
#      (it hides root-enabled features); a second run with `--features scripted-approver` is the
#      positive control that proves the grep can see all five names.
set -euo pipefail

target="${1:?usage: ci/check-release-build.sh <target>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

fail() { echo "::error::check-release-build: $*" >&2; exit 1; }

# 1. environment
while IFS='=' read -r name value; do
  case "$name" in
    RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_TARGET_*_RUSTFLAGS|RUSTDOCFLAGS)
      if printf '%s' "$value" | grep -qiE 'debug[-_]assertions'; then
        fail "$name enables debug assertions: $value"
      fi
      ;;
    CARGO_PROFILE_*_DEBUG_ASSERTIONS)
      case "$value" in
        ""|false|0|no|off) ;;
        *) fail "$name=$value enables debug assertions" ;;
      esac
      ;;
  esac
done < <(env)

# 2. the bundle workflow's own tauri build command lines
# `--config` alone is legitimate (the macOS legs pass beforeBundleCommand); one that mentions a
# profile, debug assertions or features is not.
if grep -nE 'cargo tauri build.*(--debug|--features|--profile|scripted-approver)' .github/workflows/bundle.yml \
  || grep -nE 'cargo tauri build.*--config.*(profile|debug-assertions|features)' .github/workflows/bundle.yml; then
  fail "a bundle build uses --debug, --features, --profile, scripted-approver, or a --config that touches profiles or features"
fi

# 3. the feature tree with the build's flags
leak='\[[^]]*(testing|insecure-test-http|test-paths|test-env|scripted-approver)[^]]*\]'
tree() { cargo tree -p atlas-duck-app -e normal,build --target "$target" --locked --format '{p} [{f}]' --prefix none "$@"; }
out="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
tree > "$out/release-tree.txt"
[ -s "$out/release-tree.txt" ] || fail "cargo tree printed nothing"
if grep -E "$leak" "$out/release-tree.txt"; then
  fail "a test-only feature is enabled in the bundle build's dependency tree"
fi
tree --features scripted-approver > "$out/release-tree-control.txt"
for f in scripted-approver test-paths test-env testing insecure-test-http; do
  grep -qE "\[[^]]*$f[^]]*\]" "$out/release-tree-control.txt" || fail "positive control: $f is not visible with --features scripted-approver"
done
echo "check-release-build: no debug assertions forced, no test-only feature in the $target release tree ($(wc -l < "$out/release-tree.txt") packages)"
