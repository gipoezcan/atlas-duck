#!/usr/bin/env bash
# The CI-07 step of the scripts-enabled matrix (spec §13 "Scripts-enabled matrix", PD-150, R6 option
# (a)); M8 plan Task 28. Written and wired in M8, switched on in M10 (`if: false` until then, see
# install-probes.yml and e2e-bundle.yml); its syntax and its parsing are checked on every ci.yml run
# by `--self-test`, which executes no package and no app.
#
#   ci/script-matrix-step.sh release <evidence-dir>
#       A RELEASE package job (install-probes.yml). A fresh release install is in the first-run state
#       and serves no core, so no `script run` happens here. The step reads the sandbox_probe line
#       the install-probe script saved (<evidence-dir>/probe-line.txt) and asserts what the matrix
#       asks of a release package: `floor=met failed=none`, and that the installed worker answered in
#       probe mode through the app's own spawner (the summary line carries the worker's version, which
#       only a worker that answered the probe handshake reports; `unknown` means it did not).
#
#   ci/script-matrix-step.sh debug <work-dir> <cli-word>...
#       The DEBUG scripted-approver bundle of the same commit (e2e-bundle.yml). The app must already
#       serve a configured core; <cli-word>... is the command that runs the CLI (`<AppImage> __cli`,
#       `/usr/bin/atlas-duck`). Runs `script run --dry-run=full` (status succeeded, exit 0) and a real
#       run that the scripted approver releases through the `atlas-test:release` reason and the CLI
#       delivers (status released, exit 0). Degraded confinement must be off: the step first
#       asserts the app's own sandbox_probe line (file named by ATLAS_DUCK_CI07_PROBE_LINE_FILE) shows
#       `floor=met failed=none` and this commit's worker_version, so the real run ran confined.
#
#   Both modes compare worker_version with the commit: ATLAS_DUCK_EXPECTED_COMMIT, default GITHUB_SHA
#   (the first 12 characters are the BUILD_ID suffix).
#
#   ci/script-matrix-step.sh --self-test
#       Parses canned probe lines and a canned envelope; starts nothing.
#
# Written for bash 3.2 (the macOS /bin/bash): no associative arrays, no mapfile, no ${var,,}.
set -euo pipefail
export LC_ALL=C

die() { echo "FAIL: script-matrix-step: $*" >&2; exit 1; }

# probe_field <line> <key>: the value of key=value, empty when absent.
probe_field() {
  printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n 1
}

# assert_release_line <line>: the release-package half of the matrix.
assert_release_line() {
  local line="$1" floor failed worker expected
  floor="$(probe_field "$line" floor)"
  failed="$(probe_field "$line" failed)"
  worker="$(probe_field "$line" worker_version)"
  [ "$floor" = met ] || die "floor=$floor (failed=$failed), expected floor=met: $line"
  [ "$failed" = none ] || die "failed=$failed although floor=met: $line"
  case "$worker" in
    '' | unknown) die "the sandbox_probe line has no worker_version ($worker): the installed worker did not answer in probe mode through the app's spawner: $line" ;;
  esac
  # Not only present: the worker is the one of this commit (BUILD_ID is `<version>+<commit12>`).
  expected="${ATLAS_DUCK_EXPECTED_COMMIT:-${GITHUB_SHA:-}}"
  [ -n "$expected" ] || die "no commit to compare worker_version with (set ATLAS_DUCK_EXPECTED_COMMIT; GITHUB_SHA is the default on CI)"
  expected="${expected:0:12}"
  case "$worker" in
    *"+$expected") ;;
    *) die "worker_version=$worker is not the build of commit $expected: $line" ;;
  esac
}

# json_field <file> <dotted.path>: the value at the path of the CLI's one-line envelope.
json_field() {
  local py=python3
  # Windows runners (Git Bash) have `python`, and their `python3` can be a Store stub that fails.
  "$py" -c 'import json' > /dev/null 2>&1 || py=python
  "$py" -I - "$1" "$2" <<'PY' | tr -d '\r'
import json, sys
node = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    node = node[key]
print(json.dumps(node) if isinstance(node, (dict, list)) else node)
PY
}

# assert_envelope <label> <file> <exit-code> <want-exit> <want-status>
assert_envelope() {
  local label="$1" file="$2" code="$3" want_code="$4" want_status="$5" status
  [ "$code" -eq "$want_code" ] || die "$label exited $code, expected $want_code: $(cat "$file")"
  status="$(json_field "$file" status)" || die "$label printed no envelope with a status: $(cat "$file")"
  [ "$status" = "$want_status" ] || die "$label status is '$status', expected $want_status: $(cat "$file")"
}

cmd_release() {
  local dir="${1:?usage: script-matrix-step.sh release <evidence-dir>}" file line
  file="$dir/probe-line.txt"
  [ -f "$file" ] || die "$file is missing (the install-probe script saves the sandbox_probe line there)"
  line="$(head -n 1 "$file")"
  [ -n "$line" ] || die "$file is empty"
  assert_release_line "$line"
  echo "CI07 mode=release floor=$(probe_field "$line" floor) failed=$(probe_field "$line" failed) worker_version=$(probe_field "$line" worker_version) engine_version=$(probe_field "$line" engine_version)"
}

cmd_debug() {
  local work="${1:?usage: script-matrix-step.sh debug <work-dir> <cli-word>...}" code probe_file probe_line
  shift
  [ "$#" -ge 1 ] || die "usage: script-matrix-step.sh debug <work-dir> <cli-word>..."
  mkdir -p "$work"
  # Degraded confinement is off (final review m-8). Neither the CLI nor doctor shows the setting or
  # a run's SCRIPT_STARTED.confinement, so the step asks for the sandbox_probe line of the app under
  # test: degraded confinement only applies under a floor that is not met, and a line with
  # `floor=met failed=none` and this commit's worker_version proves the run below is confined whatever
  # the setting holds. A missing line fails the step; it never passes unchecked.
  probe_file="${ATLAS_DUCK_CI07_PROBE_LINE_FILE:-}"
  [ -n "$probe_file" ] && [ -f "$probe_file" ] || die "ATLAS_DUCK_CI07_PROBE_LINE_FILE must name the file holding the app's sandbox_probe line (got '$probe_file')"
  probe_line="$(head -n 1 "$probe_file")"
  [ -n "$probe_line" ] || die "$probe_file is empty"
  assert_release_line "$probe_line"
  printf '%s\n' 'return {n: 1 + 1};' > "$work/matrix.js"

  set +e
  timeout 180 "$@" script run "$work/matrix.js" --dry-run=full --timeout 120 > "$work/dry.json" 2> "$work/dry.err"
  code=$?
  set -e
  assert_envelope "script run --dry-run=full" "$work/dry.json" "$code" 0 succeeded
  grep -qF 'dry_run' "$work/dry.json" || die "the dry run's envelope carries no dry_run marker: $(cat "$work/dry.json")"

  set +e
  timeout 180 "$@" script run "$work/matrix.js" --reason atlas-test:release --timeout 120 > "$work/real.json" 2> "$work/real.err"
  code=$?
  set -e
  assert_envelope "script run (released by the scripted approver)" "$work/real.json" "$code" 0 released
  [ "$(json_field "$work/real.json" data.result.n)" = 2 ] || die "the released run delivered another result than {n: 2}: $(cat "$work/real.json")"
  echo "CI07 mode=debug floor=$(probe_field "$probe_line" floor) worker_version=$(probe_field "$probe_line" worker_version) dry_run=succeeded real=released"
}

self_test() {
  local met notmet unknown stale w
  ATLAS_DUCK_EXPECTED_COMMIT=0123456789ab
  met='2026-10-07T10:00:00.123Z INFO atlas_duck_app_lib::sandbox_probe src/sandbox_probe.rs:301 event=sandbox_probe floor=met failed=none extra_layers=landlock:on engine_version=0.16.2 worker_version=0.1.0+0123456789ab ace=n/a dropped_fields=0'
  notmet="$(printf '%s' "$met" | sed 's/floor=met failed=none/floor=not_met failed=raw_clone/')"
  unknown="$(printf '%s' "$met" | sed 's/worker_version=[^ ]*/worker_version=unknown/')"
  ( assert_release_line "$met" ) || die "self-test: a floor=met failed=none line was refused"
  ( assert_release_line "$notmet" ) 2> /dev/null && die "self-test: a floor=not_met line was accepted"
  ( assert_release_line "$unknown" ) 2> /dev/null && die "self-test: a line without a worker version was accepted"
  [ "$(probe_field "$met" worker_version)" = '0.1.0+0123456789ab' ] || die "self-test: probe_field"
  stale="$(printf '%s' "$met" | sed 's/worker_version=[^ ]*/worker_version=0.1.0+ba9876543210/')"
  ( assert_release_line "$stale" ) 2> /dev/null && die "self-test: a worker of another commit was accepted"
  ( ATLAS_DUCK_EXPECTED_COMMIT=0123456789abcdef0123 assert_release_line "$met" ) || die "self-test: a full commit id was not cut to 12 characters"

  w="$(mktemp -d)"
  ( ATLAS_DUCK_CI07_PROBE_LINE_FILE='' cmd_debug "$w/d" true ) 2> /dev/null && die "self-test: the debug step ran without a probe line"
  printf '%s\n' "$notmet" > "$w/probe-notmet.txt"
  ( ATLAS_DUCK_CI07_PROBE_LINE_FILE="$w/probe-notmet.txt" cmd_debug "$w/d" true ) 2> /dev/null && die "self-test: the debug step ran on a floor that is not met"
  printf '%s\n' '{"status":"released","request_id":"req_1","data":{"result":{"n":2}}}' > "$w/ok.json"
  printf '%s\n' '{"status":"failed","request_id":null,"error":{"code":"not_configured"}}' > "$w/bad.json"
  [ "$(json_field "$w/ok.json" data.result.n)" = 2 ] || die "self-test: json_field"
  ( assert_envelope self-test "$w/ok.json" 0 0 released ) || die "self-test: a released envelope was refused"
  ( assert_envelope self-test "$w/bad.json" 9 0 released ) 2> /dev/null && die "self-test: a failed envelope was accepted"
  mkdir -p "$w/ev"
  printf '%s\n' "$met" > "$w/ev/probe-line.txt"
  cmd_release "$w/ev" > /dev/null
  rm -rf "$w"
  echo "OK: script-matrix-step self-test"
}

case "${1:-}" in
  release) shift; cmd_release "$@" ;;
  debug) shift; cmd_debug "$@" ;;
  --self-test) self_test ;;
  *) die "usage: script-matrix-step.sh release <evidence-dir> | debug <work-dir> <cli-word>... | --self-test" ;;
esac
