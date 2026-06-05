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
Create chart name and version as used by the chart label.
*/}}
{{- define "ssl-exporter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
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
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ssl-exporter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ssl-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{/*
Name of the TLS Secret
*/}}
{{- define "ssl-exporter.tlsSecretName" -}}
{{- if .Values.tls.existingSecret }}
{{- .Values.tls.existingSecret }}
{{- else }}
{{- printf "%s-tls" (include "ssl-exporter.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Name of the web-config Secret
*/}}
{{- define "ssl-exporter.webConfigSecretName" -}}
{{- if .Values.webConfig.existingSecret }}
{{- .Values.webConfig.existingSecret }}
{{- else }}
{{- printf "%s-web-config" (include "ssl-exporter.fullname" .) }}
{{- end }}
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
