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

{{/* Image refs. An empty tag defaults to "latest" — CI publishes :latest on the
     default branch on every push; the semver tags (:X.Y.Z) only exist once a
     vX.Y.Z release is tagged, so pin one of those for production. */}}
{{- define "ebfw.operator.image" -}}
{{- $tag := .Values.operator.image.tag | default "latest" -}}
{{- printf "%s:%s" .Values.operator.image.repository $tag -}}
{{- end -}}
{{- define "ebfw.agent.image" -}}
{{- $tag := .Values.agent.image.tag | default "latest" -}}
{{- printf "%s:%s" .Values.agent.image.repository $tag -}}
{{- end -}}

{{/* Pull policy. Honor an explicit pullPolicy; otherwise default to Always for
     the floating :latest tag (so nodes pick up new pushes) and IfNotPresent for
     a pinned tag (so a locally-imported image — k3d dev/e2e — is used instead of
     being re-pulled from a registry). */}}
{{- define "ebfw.operator.pullPolicy" -}}
{{- if .Values.operator.image.pullPolicy -}}
{{- .Values.operator.image.pullPolicy -}}
{{- else if or (not .Values.operator.image.tag) (eq .Values.operator.image.tag "latest") -}}
Always
{{- else -}}
IfNotPresent
{{- end -}}
{{- end -}}
{{- define "ebfw.agent.pullPolicy" -}}
{{- if .Values.agent.image.pullPolicy -}}
{{- .Values.agent.image.pullPolicy -}}
{{- else if or (not .Values.agent.image.tag) (eq .Values.agent.image.tag "latest") -}}
Always
{{- else -}}
IfNotPresent
{{- end -}}
{{- end -}}
