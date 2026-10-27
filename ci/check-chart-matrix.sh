#!/bin/sh
# Chart test matrix (M13 plan T4, PD-M13-10). Runs in the alpine/helm image of `chart:test`.
#
# Positive: every chart/ci/*.yaml lints with --strict and renders into rendered/<name>.yaml, which
# ci/check-chart-policy.sh then checks. Negative: every chart/ci-fail/*.yaml, layered on
# chart/ci/minimal.yaml, must fail to render with the text of its leading `# expect:` comment.
set -eu

chart=chart
out=rendered
mkdir -p "$out"

for f in "$chart"/ci/*.yaml; do
  name="$(basename "$f" .yaml)"
  echo "chart-matrix: lint + template $f"
  helm lint --strict "$chart" -f "$f"
  helm template "atlas-duck-$name" "$chart" --namespace team-dux -f "$f" > "$out/$name.yaml"
done

status=0
for f in "$chart"/ci-fail/*.yaml; do
  want="$(sed -n 's/^# expect: //p' "$f" | head -n 1)"
  if [ -z "$want" ]; then
    echo "chart-matrix: $f has no '# expect:' line" >&2
    status=1
    continue
  fi
  if helm template atlas-duck-fail "$chart" -f "$chart/ci/minimal.yaml" -f "$f" > /dev/null 2> "$out/fail.err"; then
    echo "chart-matrix: $f rendered, expected a failure" >&2
    status=1
  elif ! grep -qF -- "$want" "$out/fail.err"; then
    echo "chart-matrix: $f failed without '$want':" >&2
    cat "$out/fail.err" >&2
    status=1
  else
    echo "chart-matrix: $f refused as expected"
  fi
done
rm -f "$out/fail.err"

exit "$status"
