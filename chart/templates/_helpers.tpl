{{/* Names and labels. */}}
{{- define "atlas-duck.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* The release name itself (`atlas-duck`, `atlas-duck-<slug>`), so runbooks can name `deploy/atlas-duck`. */}}
{{- define "atlas-duck.fullname" -}}
{{- default .Release.Name .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "atlas-duck.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "atlas-duck.selectorLabels" -}}
app.kubernetes.io/name: {{ include "atlas-duck.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "atlas-duck.labels" -}}
helm.sh/chart: {{ include "atlas-duck.chart" . }}
{{ include "atlas-duck.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "atlas-duck.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "atlas-duck.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "atlas-duck.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end }}

{{/*
Render-time guards (M13 plan T3). Each message starts with "atlas-duck:" so the chart test
matrix (chart/ci-fail/*.yaml, `# expect:`) can match it.
*/}}
{{- define "atlas-duck.validate" -}}
{{- if ne (.Values.persistence.accessMode | toString) "ReadWriteOnce" }}
{{- fail "atlas-duck: persistence.accessMode must be ReadWriteOnce (ADR 0003, SQLite)" }}
{{- end }}
{{- if not (has .Values.mode (list "production" "review")) }}
{{- fail "atlas-duck: mode must be production or review" }}
{{- end }}
{{- if and .Values.testDirectory.enabled (eq .Values.mode "production") }}
{{- fail "atlas-duck: testDirectory.enabled is not allowed with mode production (PD-M13-8)" }}
{{- end }}
{{- if and .Values.testDirectory.enabled (not .Values.testDirectory.usersJson) }}
{{- fail "atlas-duck: testDirectory.usersJson is required when testDirectory.enabled" }}
{{- end }}
{{- if not (contains "BEGIN CERTIFICATE" (.Values.caBundle.pem | toString)) }}
{{- fail "atlas-duck: caBundle.pem is required (PEM certificates, PD-M13-7)" }}
{{- end }}
{{- if not .Values.masterKey.existingSecret }}
{{- fail "atlas-duck: masterKey.existingSecret is required (PD-M13-5)" }}
{{- end }}
{{- if and (hasKey .Values "replicaCount") (ne (int .Values.replicaCount) 1) }}
{{- fail "atlas-duck: replicaCount must be 1 (ADR 0003)" }}
{{- end }}
{{- if and .Values.directory.serviceBind.existingSecret (not .Values.directory.serviceBind.dn) }}
{{- fail "atlas-duck: directory.serviceBind.dn is required with directory.serviceBind.existingSecret" }}
{{- end }}
{{- if and .Values.directory.serviceBind.dn (not .Values.directory.serviceBind.existingSecret) }}
{{- fail "atlas-duck: directory.serviceBind.existingSecret is required with directory.serviceBind.dn" }}
{{- end }}
{{- if and .Values.networkPolicy.enabled (not .Values.networkPolicy.ingressNamespaceSelectors) }}
{{- fail "atlas-duck: networkPolicy.ingressNamespaceSelectors is required when networkPolicy.enabled (Q2)" }}
{{- end }}
{{- if contains "CHANGE-ME" (toYaml .Values) }}
{{- fail "atlas-duck: a CHANGE-ME placeholder is left in the values (an open question, see deployment/README.md)" }}
{{- end }}
{{- range .Values.extraEnv }}
{{- if regexMatch "^(ATLAS_DUCK_|LDAP_|GROUP_)" .name }}
{{- fail (printf "atlas-duck: extraEnv %s is managed by the chart" .name) }}
{{- end }}
{{- if and (regexMatch "(?i)(KEY|TOKEN|PASSWORD|SECRET)" .name) (not (hasSuffix "_FILE" .name)) }}
{{- fail (printf "atlas-duck: extraEnv %s looks like a secret; mount a file instead (SM-9.1)" .name) }}
{{- end }}
{{- end }}
{{- end }}
