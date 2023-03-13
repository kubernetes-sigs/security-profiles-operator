{{/*
Expand the name of the chart.
*/}}
{{- define "security-profiles-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "security-profiles-operator.fullname" -}}
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
{{- define "security-profiles-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common annotations
*/}}
{{- define "security-profiles-operator.annotations" -}}
meta.helm.sh/release-name: {{ include "security-profiles-operator.name" . }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "security-profiles-operator.labels" -}}
helm.sh/chart: {{ include "security-profiles-operator.chart" . }}
{{ include "security-profiles-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "security-profiles-operator.selectorLabels" -}}
app: security-profiles-operator
name: security-profiles-operator
app.kubernetes.io/name: {{ include "security-profiles-operator.name" . }}
app.kubernetes.io/instance: {{ include "security-profiles-operator.name" . }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "security-profiles-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "security-profiles-operator.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
