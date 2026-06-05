{{/*
Common helpers for the Hopframe chart.
*/}}

{{- define "hopframe.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hopframe.controlPlane.name" -}}
{{- printf "%s-control-plane" (include "hopframe.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hopframe.mcpSensor.name" -}}
{{- printf "%s-mcp-sensor" (include "hopframe.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hopframe.imageRef" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "hopframe.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
