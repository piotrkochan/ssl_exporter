{{/*
Expand the name of the chart.
*/}}
{{- define "ssl-exporter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "ssl-exporter.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Namespace for namespaced resources.
*/}}
{{- define "ssl-exporter.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "ssl-exporter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Container image reference.
*/}}
{{- define "ssl-exporter.image" -}}
{{- $registry := default .Values.image.registry .Values.global.imageRegistry -}}
{{- $repository := .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- if $registry -}}
{{- printf "%s/%s@%s" $registry $repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s@%s" $repository .Values.image.digest -}}
{{- end -}}
{{- else -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry $repository $tag -}}
{{- else -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ssl-exporter.labels" -}}
helm.sh/chart: {{ include "ssl-exporter.chart" . }}
{{ include "ssl-exporter.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Values.commonLabels }}
{{ toYaml .Values.commonLabels }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ssl-exporter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ssl-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Name of the TLS Secret
*/}}
{{- define "ssl-exporter.tlsSecretName" -}}
{{- if .Values.tls.secretName }}
{{- .Values.tls.secretName }}
{{- else }}
{{- printf "%s-tls" (include "ssl-exporter.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Whether web-config.yaml should be mounted and passed to ssl_exporter.
*/}}
{{- define "ssl-exporter.webConfigEnabled" -}}
{{- if or .Values.webConfig.enabled .Values.webConfig.secretName .Values.tls.enabled -}}
true
{{- end -}}
{{- end }}

{{/*
Name of the web-config Secret
*/}}
{{- define "ssl-exporter.webConfigSecretName" -}}
{{- if .Values.webConfig.secretName }}
{{- .Values.webConfig.secretName }}
{{- else }}
{{- printf "%s-web-config" (include "ssl-exporter.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Validate TLS values that cannot produce a working deployment.
*/}}
{{- define "ssl-exporter.validateTLS" -}}
{{- if and .Values.tls.enabled (not .Values.tls.secretName) (not .Values.tls.certManager.enabled) -}}
{{- fail "tls.enabled requires tls.secretName or tls.certManager.enabled=true" -}}
{{- end -}}
{{- if and .Values.tls.enabled .Values.tls.certManager.enabled (not .Values.tls.certManager.issuerRef.name) -}}
{{- fail "tls.certManager.issuerRef.name is required when tls.certManager.enabled=true" -}}
{{- end -}}
{{- end }}

{{/*
Render a probe and switch HTTP probes to HTTPS when exporter TLS is enabled.
*/}}
{{- define "ssl-exporter.probe" -}}
{{- $probe := deepCopy .probe -}}
{{- if and .tlsEnabled (hasKey $probe "httpGet") -}}
{{- $_ := set $probe.httpGet "scheme" "HTTPS" -}}
{{- end -}}
{{- toYaml $probe -}}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "ssl-exporter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ssl-exporter.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
