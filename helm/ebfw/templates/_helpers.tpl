{{/* Expand the name of the chart. */}}
{{- define "ebfw.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "ebfw.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "ebfw.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "ebfw.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end -}}

{{/* Operator name / SA / selector. */}}
{{- define "ebfw.operator.fullname" -}}{{ printf "%s-operator" (include "ebfw.fullname" .) }}{{- end -}}
{{- define "ebfw.operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ebfw.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: operator
{{- end -}}

{{/* Agent name / SA / selector. */}}
{{- define "ebfw.agent.fullname" -}}{{ printf "%s-agent" (include "ebfw.fullname" .) }}{{- end -}}
{{- define "ebfw.agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ebfw.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: agent
{{- end -}}

{{/* Image refs (tag defaults to appVersion). */}}
{{- define "ebfw.operator.image" -}}
{{- $tag := .Values.operator.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.operator.image.repository $tag -}}
{{- end -}}
{{- define "ebfw.agent.image" -}}
{{- $tag := .Values.agent.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.agent.image.repository $tag -}}
{{- end -}}
