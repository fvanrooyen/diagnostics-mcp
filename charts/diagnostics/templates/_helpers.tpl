{{/* Common labels applied to every object's metadata. */}}
{{- define "diagnostics.labels" -}}
app.kubernetes.io/part-of: diagnostics
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{/* Fully-qualified container image reference. */}}
{{- define "diagnostics.image" -}}
{{- with .Values.image.repository -}}
{{ . }}:{{ $.Values.image.tag }}
{{- else -}}
{{ fail "image.repository is required (set it to the ECR repo URL)" }}
{{- end -}}
{{- end -}}

{{/* The OAuth AS issuer URL — must match what tokens are minted/verified against. */}}
{{- define "diagnostics.oauthIssuer" -}}
https://{{ .Values.oauth.subdomain }}.{{ required "domain is required" .Values.domain }}
{{- end -}}
