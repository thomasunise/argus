{{/*
Common helpers for the Sentinel chart.
*/}}

{{- define "sentinel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sentinel.fullname" -}}
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

{{- define "sentinel.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sentinel.labels" -}}
helm.sh/chart: {{ include "sentinel.chart" . }}
app.kubernetes.io/name: {{ include "sentinel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: sentinel
{{- end -}}

{{- define "sentinel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sentinel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "sentinel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "sentinel.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "sentinel.secretName" -}}
{{- if .Values.existingSecret -}}
{{- .Values.existingSecret -}}
{{- else -}}
{{- include "sentinel.fullname" . -}}
{{- end -}}
{{- end -}}

{{- define "sentinel.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/* Checksum of config + secret values so pods roll when they change. */}}
{{- define "sentinel.configChecksum" -}}
{{- print (toYaml .Values.config) (toYaml .Values.secrets) | sha256sum -}}
{{- end -}}

{{/* envFrom shared by api and worker */}}
{{- define "sentinel.envFrom" -}}
- configMapRef:
    name: {{ include "sentinel.fullname" . }}
- secretRef:
    name: {{ include "sentinel.secretName" . }}
{{- end -}}

{{/* Volumes shared by api and worker (tmp scratch, optional audit PVC, optional targets) */}}
{{- define "sentinel.volumes" -}}
- name: tmp
  emptyDir:
    sizeLimit: {{ .Values.tmpVolumeSizeLimit }}
- name: data
{{- if .Values.auditVolume.enabled }}
  persistentVolumeClaim:
    claimName: {{ default (printf "%s-audit" (include "sentinel.fullname" .)) .Values.auditVolume.existingClaim }}
{{- else }}
  emptyDir: {}
{{- end }}
{{- if .Values.worker.targets.enabled }}
- name: targets
  persistentVolumeClaim:
    claimName: {{ .Values.worker.targets.existingClaim }}
    readOnly: true
{{- end }}
{{- end -}}

{{- define "sentinel.volumeMounts" -}}
- name: tmp
  mountPath: /tmp
- name: data
  mountPath: /app/data
{{- if .Values.worker.targets.enabled }}
- name: targets
  mountPath: /app/targets
  readOnly: true
{{- end }}
{{- end -}}
