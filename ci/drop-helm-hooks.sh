#!/bin/sh
# Drops every document that carries a `helm.sh/hook` annotation (the `helm test` Pod) from a
# rendered manifest, for the server-side dry run of deploy:review / deploy:production. Hooks are
# not applied by `helm upgrade` either, and a test Pod left by an earlier `helm test` cannot be
# "updated" by an apply dry run (pod spec is immutable). POSIX sh + awk.
#
# usage: ci/drop-helm-hooks.sh rendered.yaml > rendered-no-hooks.yaml
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 rendered.yaml" >&2; exit 2; }

awk '
  function flush() {
    if (buf != "" && buf !~ /(^|\n) *helm\.sh\/hook: /) printf "---\n%s", buf
    buf = ""
  }
  /^---/ { flush(); next }
  { buf = buf $0 "\n" }
  END { flush() }
' "$1"
