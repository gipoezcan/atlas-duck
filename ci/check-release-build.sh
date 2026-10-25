#!/usr/bin/env bash
# ci/check-release-build.sh <target> [--config <json-or-file>]
# ci/check-release-build.sh --self-test
#
# Runs in every bundle job right before `cargo tauri build` (M4 plan Task 26, T21 I-2, spec §13;
# extended by M10 Task 26). The test-only features (`test-paths`, `test-env`, `testing`,
# `insecure-test-http`, `scripted-approver`) are locked out of release builds by compile_error!
# under `not(debug_assertions)`; a file scan of the manifests cannot see anything that turns debug
# assertions back on or enables a feature from outside. So this checks, for the build the job is
# about to run:
#   1. the environment: no RUSTFLAGS-style variable and no CARGO_PROFILE_*_DEBUG_ASSERTIONS enables
#      debug assertions (they would defeat the locks);
#   2. the `cargo tauri build` lines of the bundle workflows and the tauri-bundle composite action:
#      no `--debug`, no `--features`, no `--profile`, no `scripted-approver`; an inline `--config`
#      JSON written on such a line goes through the key check of 2b;
#   2b. the `--config` value the build is about to use (the `--config` argument of this script,
#      an inline JSON object or a path to a generated JSON file such as
#      ci/release-signing.windows.json): every key is in the allowed set, i.e. the signing keys
#      bundle.windows.{signCommand,certificateThumbprint,timestampUrl}, bundle.macOS.signingIdentity
#      and build.beforeBundleCommand; no string value mentions --debug, --features, --profile,
#      debug assertions or scripted-approver. Anything else (features, a profile, a runner, a
#      debug key) fails. The JSON is read with node (set up earlier in every bundle job);
#   3. the dependency tree of the app with the bundle build's own flags (target, `--locked`, no
#      features): no workspace package shows a test-only feature in its `{f}` list. NOT the plan's
#      `cargo tree --release` (it has no such flag: the check was vacuous) and not `-e features`
#      (it hides root-enabled features); a second run with `--features scripted-approver` is the
#      positive control that proves the grep can see all five names.
#
# --self-test drives 2 and 2b over fixtures (positive: a generated signing file, today's inline
# beforeBundleCommand value, the repo's own workflow files; negative: features, a profile, a debug
# key, a forbidden value, a forbidden flag on a build line, malformed JSON, a missing file). It
# runs no cargo.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

fail() { echo "::error::check-release-build: $*" >&2; exit 1; }

default_workflows=".github/workflows/bundle.yml .github/workflows/release.yml .github/actions/tauri-bundle/action.yml"

# 2b. prints nothing and returns 0 when the value is allowed; prints the reason and returns 1 when not.
config_check() {
  local value="$1"
  [ -z "$value" ] && return 0
  command -v node >/dev/null 2>&1 || { echo "node is needed to read the --config JSON"; return 1; }
  node -e '
    const fs = require("fs");
    let v = process.argv[1];
    let text;
    if (v.trimStart().startsWith("{")) { text = v; }
    else {
      if (!fs.existsSync(v)) { console.log("--config file " + v + " does not exist"); process.exit(1); }
      text = fs.readFileSync(v, "utf8");
    }
    let j;
    try { j = JSON.parse(text); } catch (e) { console.log("--config is not valid JSON: " + e.message); process.exit(1); }
    if (j === null || typeof j !== "object" || Array.isArray(j)) { console.log("--config is not a JSON object"); process.exit(1); }
    const allowed = ["build.beforeBundleCommand", "bundle.windows.signCommand",
      "bundle.windows.certificateThumbprint", "bundle.windows.timestampUrl", "bundle.macOS.signingIdentity"];
    const bad = /--debug|--features|--profile|debug[-_ ]?assertions|scripted-approver/i;
    const problems = [];
    const walk = (node, path) => {
      if (allowed.some(a => path === a || path.startsWith(a + "."))) {
        const scan = x => {
          if (typeof x === "string") { if (bad.test(x)) problems.push(path + " value mentions a profile, debug or features: " + x); }
          else if (x && typeof x === "object") Object.values(x).forEach(scan);
        };
        scan(node);
        return;
      }
      if (node !== null && typeof node === "object" && !Array.isArray(node)) {
        const keys = Object.keys(node);
        if (keys.length === 0 && path !== "") problems.push("empty object at " + path);
        for (const k of keys) {
          const p = path === "" ? k : path + "." + k;
          if (!allowed.some(a => a === p || a.startsWith(p + "."))) { problems.push("key " + p + " is not in the allowed set"); continue; }
          walk(node[k], p);
        }
        return;
      }
      problems.push("key " + path + " is not an object on the way to an allowed key");
    };
    walk(j, "");
    if (problems.length) { console.log(problems.join("; ")); process.exit(1); }
  ' "$value"
}

# 2. prints the offending lines and returns 1 when a build line is not allowed.
lines_check() {
  local files="$1" f line inline rc=0
  for f in $files; do
    [ -f "$f" ] || continue
    if grep -nE 'cargo tauri build.*(--debug|--features|--profile|scripted-approver)' "$f"; then
      echo "$f: a cargo tauri build line uses --debug, --features, --profile or scripted-approver"
      rc=1
    fi
    while IFS= read -r line; do
      case "$line" in *--config*) ;; *) continue ;; esac
      # Inline JSON written on the line: --config "{\"build\":...}" or --config '{"build":...}'.
      inline="$(printf '%s\n' "$line" | sed -nE "s/.*--config +\"(\{.*\})\".*/\1/p; s/.*--config +'(\{.*\})'.*/\1/p" | head -n1)"
      if [ -n "$inline" ]; then
        inline="${inline//\\\"/\"}"
        if ! config_check "$inline"; then echo "$f: $line"; rc=1; fi
      elif printf '%s\n' "$line" | grep -qE -- '--config.*(profile|debug-assertions|features)'; then
        echo "$f: $line"
        rc=1
      fi
      # A non-literal value ("$VAR", an array) is checked at run time through this script's --config.
    done < <(grep -E 'cargo tauri build' "$f" || true)
  done
  return "$rc"
}

self_test() {
  local tmp n=0
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  expect_ok() { n=$((n+1)); local out; if ! out="$(config_check "$2")"; then echo "self-test FAIL (expected pass): $1: $out" >&2; exit 1; fi; echo "ok $n - passes: $1"; }
  expect_bad() { n=$((n+1)); local out; if out="$(config_check "$2")"; then echo "self-test FAIL (expected rejection): $1" >&2; exit 1; fi; echo "ok $n - rejects: $1 ($out)"; }

  printf '%s' '{"bundle":{"windows":{"signCommand":"signtool sign /sha1 ABCDEF /fd sha256 /tr http://ts.example /td sha256 %1","certificateThumbprint":"ABCDEF","timestampUrl":"http://ts.example"}}}' > "$tmp/release-signing.windows.json"
  printf '%s' '{"bundle":{"windows":{"signCommand":{"cmd":"signpath-sign.cmd","args":["%1"]}}}}' > "$tmp/object-sign.json"
  printf '%s' '{"bundle":{"macOS":{"signingIdentity":"Developer ID Application: X (TEAMID)"}},"build":{"beforeBundleCommand":"bash /w/ci/sign-macos-bins.sh aarch64-apple-darwin"}}' > "$tmp/release-signing.macos.json"
  printf '%s' '{"build":{"features":["scripted-approver"]}}' > "$tmp/features.json"
  printf '%s' '{"bundle":{"windows":{"signCommand":"x %1"}},"profile":"debug"}' > "$tmp/profile.json"
  printf '%s' 'not json' > "$tmp/broken.json"

  expect_ok  "a generated ci/release-signing.windows.json" "$tmp/release-signing.windows.json"
  expect_ok  "a signCommand object {cmd,args}" "$tmp/object-sign.json"
  expect_ok  "a generated macOS release config" "$tmp/release-signing.macos.json"
  expect_ok  "today's inline beforeBundleCommand value (bundle.yml x86_64 leg)" '{"build":{"beforeBundleCommand":"bash $GITHUB_WORKSPACE/ci/sign-macos-bins-adhoc.sh $TARGET"}}'
  expect_ok  "no --config" ''
  expect_ok  "a Windows config with signCommand plus a beforeBundleCommand" '{"bundle":{"windows":{"signCommand":"signtool sign /fd sha256 %1"}},"build":{"beforeBundleCommand":"pwsh -File ci/x.ps1"}}'
  expect_ok  "an inline value with leading whitespace (same test as the action)" '  {"build":{"beforeBundleCommand":"x"}}'
  expect_bad "a file with features" "$tmp/features.json"
  expect_bad "a file with a profile" "$tmp/profile.json"
  expect_bad "an inline value with features" '{"build":{"features":["testing"]}}'
  expect_bad "an inline value with a profile key under build" '{"build":{"beforeBundleCommand":"x","profile":"dev"}}'
  expect_bad "an inline debug key" '{"build":{"beforeBundleCommand":"x"},"debug":true}'
  expect_bad "a debug build hidden in beforeBundleCommand" '{"build":{"beforeBundleCommand":"cargo build --features scripted-approver"}}'
  expect_bad "a debug-assertions value" '{"bundle":{"windows":{"signCommand":"RUSTFLAGS=-Cdebug-assertions=on x %1"}}}'
  expect_bad "a runner override" '{"build":{"runner":"cross"}}'
  expect_bad "a non-object value" '[1]'
  expect_bad "malformed JSON" "$tmp/broken.json"
  expect_bad "a missing file" "$tmp/does-not-exist.json"

  n=$((n+1))
  printf '%s\n' '        run: cargo tauri build --ci --target "$TARGET" --bundles nsis -- --locked' \
    '          cargo tauri build --ci --target "$TARGET" --bundles app,dmg             --config "{\"build\":{\"beforeBundleCommand\":\"bash $GITHUB_WORKSPACE/ci/sign-macos-bins-adhoc.sh $TARGET\"}}"             -- --locked' \
    '        cargo tauri build --ci --target "$TARGET" --bundles "$BUNDLES" ${config_args[@]+"${config_args[@]}"} -- --locked' > "$tmp/good.yml"
  lines_check "$tmp/good.yml" >/dev/null || { echo "self-test FAIL: allowed build lines rejected" >&2; lines_check "$tmp/good.yml" >&2 || true; exit 1; }
  echo "ok $n - passes: plain, inline-config and array-config build lines"
  for bad in 'cargo tauri build --debug' 'cargo tauri build --features testing' 'cargo tauri build --profile dev' \
    'cargo tauri build --config "{\"build\":{\"features\":[\"x\"]}}"' "cargo tauri build --config '{\"profile\":\"dev\"}'"; do
    n=$((n+1))
    printf '%s\n' "        run: $bad" > "$tmp/bad.yml"
    if lines_check "$tmp/bad.yml" >/dev/null; then echo "self-test FAIL: build line accepted: $bad" >&2; exit 1; fi
    echo "ok $n - rejects build line: $bad"
  done
  n=$((n+1))
  lines_check "$default_workflows" || { echo "self-test FAIL: the repo's own build lines are rejected" >&2; exit 1; }
  echo "ok $n - passes: the repo's own workflow and action build lines"
  echo "check-release-build self-test: $n checks passed"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

target="${1:?usage: ci/check-release-build.sh <target> [--config <json-or-file>] | --self-test}"
config=""
if [ "${2:-}" = "--config" ]; then
  config="${3-}"
elif [ -n "${2:-}" ]; then
  fail "unknown argument: $2"
fi

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

# 2. the build lines of the bundle workflows and the composite action
if ! lines_check "$default_workflows"; then
  fail "a bundle build uses --debug, --features, --profile, scripted-approver, or a --config outside the allowed keys"
fi

# 2b. the --config this build will use
if ! reason="$(config_check "$config")"; then
  fail "--config $config: $reason"
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
echo "check-release-build: no debug assertions forced, config keys allowed, no test-only feature in the $target release tree ($(wc -l < "$out/release-tree.txt") packages)"
