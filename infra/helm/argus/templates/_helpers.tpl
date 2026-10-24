{{/*
Common helpers for the Argus chart.
*/}}

{{- define "argus.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "argus.fullname" -}}
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

{{- define "argus.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "argus.labels" -}}
helm.sh/chart: {{ include "argus.chart" . }}
app.kubernetes.io/name: {{ include "argus.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: argus
{{- end -}}

{{- define "argus.selectorLabels" -}}
app.kubernetes.io/name: {{ include "argus.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "argus.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "argus.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "argus.secretName" -}}
{{- if .Values.existingSecret -}}
{{- .Values.existingSecret -}}
{{- else -}}
{{- include "argus.fullname" . -}}
{{- end -}}
{{- end -}}

{{- define "argus.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/* Checksum of config + secret values so pods roll when they change. */}}
{{- define "argus.configChecksum" -}}
{{- print (toYaml .Values.config) (toYaml .Values.secrets) | sha256sum -}}
{{- end -}}

{{/* envFrom shared by api and worker */}}
{{- define "argus.envFrom" -}}
- configMapRef:
    name: {{ include "argus.fullname" . }}
- secretRef:
    name: {{ include "argus.secretName" . }}
{{- end -}}

{{/* Volumes shared by api and worker (tmp scratch, optional audit PVC, optional targets) */}}
{{- define "argus.volumes" -}}
- name: tmp
  emptyDir:
    sizeLimit: {{ .Values.tmpVolumeSizeLimit }}
- name: data
{{- if .Values.auditVolume.enabled }}
  persistentVolumeClaim:
    claimName: {{ default (printf "%s-audit" (include "argus.fullname" .)) .Values.auditVolume.existingClaim }}
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

{{- define "argus.volumeMounts" -}}
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
