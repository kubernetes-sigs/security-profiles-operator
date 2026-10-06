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
The reference of an image: by digest when one is set, by tag otherwise.
*/}}
{{- define "security-profiles-operator.image" -}}
{{- if .digest -}}
{{ .registry }}/{{ .repository }}@{{ .digest }}
{{- else -}}
{{ .registry }}/{{ .repository }}:{{ .tag }}
{{- end -}}
{{- end }}

{{/*
The spec of the SecurityProfilesOperatorDaemon as rendered from the dedicated
values, before spod.spec gets merged into it.
*/}}
{{- define "security-profiles-operator.spodSpec" -}}
{{- if or .Values.daemon.affinity .Values.daemon.tolerations }}
scheduling:
  {{- with .Values.daemon.affinity }}
  affinity:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.daemon.tolerations }}
  tolerations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}
daemonResourceRequirements:
  {{- toYaml .Values.daemon.resources | nindent 2 }}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
selinux:
  enable: {{ hasKey .Values.selinux "enable" | ternary .Values.selinux.enable .Values.enableSelinux }}
  enableRawSelinuxProfiles: {{ .Values.selinux.enableRawSelinuxProfiles }}
  typeTag: {{ .Values.selinux.typeTag | quote }}
  {{- with .Values.selinux.options }}
  options:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.selinux.customTemplatesConfigMap }}
  customTemplatesConfigMap: {{ . | quote }}
  {{- end }}
{{- if .Values.webhook.tolerations }}
webhook:
  tolerations:
    {{- toYaml .Values.webhook.tolerations | nindent 4 }}
{{- end }}
enricher:
  enableLogEnricher: {{ .Values.enableLogEnricher }}
  enableJsonEnricher: {{ .Values.enableJsonEnricher }}
  enableBpfRecorder: {{ .Values.enableBpfRecorder }}
enableAppArmor: {{ .Values.enableAppArmor }}
enableProfiling: {{ .Values.enableProfiling }}
verbosity: {{ .Values.verbosity }}
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
