#!/bin/sh
# Policy check over rendered chart YAML (M13 plan T4, PD-M13-10; SM-7.1, SM-9.1, SM-9.4, ADR 0003).
# POSIX sh + awk + grep only (runs in the alpine/helm image of `chart:test`).
#
# usage: ci/check-chart-policy.sh rendered/<name>.yaml...
# Exit 0 when every file passes, 1 otherwise (each finding on stderr).
set -eu

[ "$#" -gt 0 ] || { echo "usage: $0 rendered.yaml..." >&2; exit 2; }

status=0
finding() {
  echo "chart-policy: $1: $2" >&2
  status=1
}

# Prints every document of kind $2 in file $1 (documents split at lines starting with ---).
docs_of() {
  awk -v want="$2" '
    function flush() {
      if (buf ~ ("(^|\n)kind: " want "\n")) printf "%s", buf
      buf = ""
    }
    /^---/ { flush(); next }
    { buf = buf $0 "\n" }
    END { flush() }
  ' "$1"
}

has() {
  printf '%s\n' "$1" | grep -Eq -- "$2"
}

for f in "$@"; do
  [ -r "$f" ] || { finding "$f" "not readable"; continue; }

  dep="$(docs_of "$f" Deployment)"
  if [ -z "$dep" ]; then
    finding "$f" "no Deployment rendered"
  else
    # Each pattern is an extended regex that must match at least one line of the Deployment.
    for want in \
      '^  replicas: 1$' \
      '^    type: Recreate$' \
      'runAsNonRoot: true$' \
      'readOnlyRootFilesystem: true$' \
      'allowPrivilegeEscalation: false$' \
      'type: RuntimeDefault$' \
      'automountServiceAccountToken: false$' \
      '^ +limits:$' \
      '^ +requests:$' \
      '^ +livenessProbe:$' \
      '^ +readinessProbe:$' \
      '^ +startupProbe:$'; do
      has "$dep" "$want" || finding "$f" "Deployment lacks /$want/"
    done
    # `drop:` directly followed by `- ALL`.
    printf '%s\n' "$dep" | awk '
      prev ~ /^ +drop:$/ && $0 ~ /^ +- ALL$/ { ok = 1 }
      { prev = $0 }
      END { exit ok ? 0 : 1 }
    ' || finding "$f" "capabilities.drop is not [ALL]"
  fi

  pvc="$(docs_of "$f" PersistentVolumeClaim)"
  if [ -z "$pvc" ]; then
    finding "$f" "no PersistentVolumeClaim rendered"
  elif ! has "$pvc" '^ +- ReadWriteOnce$'; then
    finding "$f" "PVC is not ReadWriteOnce"
  fi
  if grep -Eq 'ReadWriteMany|ReadOnlyMany|ReadWriteOncePod' "$f"; then
    finding "$f" "an access mode other than ReadWriteOnce is rendered"
  fi

  if grep -q 'CHANGE-ME' "$f"; then
    finding "$f" "a CHANGE-ME placeholder is rendered"
  fi

  if grep -Eq '^kind: Secret$' "$f"; then
    finding "$f" "a Secret is rendered (Secrets are created out of band, PD-M13-5)"
  fi

  for banned in 'hostPath:' 'privileged: true' 'hostNetwork: true' 'hostPID: true' 'hostIPC: true'; do
    if grep -Fq -- "$banned" "$f"; then
      finding "$f" "contains '$banned'"
    fi
  done

  # An env entry whose name looks like a secret must not carry a literal value (SM-9.1);
  # `*_FILE` names hold paths.
  bad_env="$(awk '
    /^ *- name: / { name = $3; pending = 1; next }
    pending && /^ *value:/ {
      up = toupper(name)
      if (up ~ /(KEY|TOKEN|PASSWORD|SECRET)/ && up !~ /_FILE$/) print name
    }
    { pending = 0 }
  ' "$f")"
  if [ -n "$bad_env" ]; then
    finding "$f" "secret-like env with a literal value: $(printf '%s' "$bad_env" | tr '\n' ' ')"
  fi
done

exit "$status"
