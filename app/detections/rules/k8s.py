"""Kubernetes rules."""
from __future__ import annotations

from ..engine import DetectionDraft, DetectionRule, RuleContext, registry
from ..util import deep_find_truthy, event_time, iso, meta, sample, window_bucket


class PrivilegedWorkload(DetectionRule):
    id = 'k8s.privileged_workload'
    name = 'Privileged Kubernetes workload'
    severity = 'high'
    category = 'k8s'
    description = ('A workload was created or admitted with privileged mode, host PID, host network or host IPC. Any of these lets a '
                   'container escape to the node.')
    remediation = 'Delete or redeploy the workload without host namespaces or privileged mode; enforce a restricted Pod Security admission level on the namespace.'
    default_params = {'flags': ['privileged', 'hostPID', 'hostNetwork', 'hostIPC'], 'actions': [], 'bucket_minutes': 60,
                      'ignore_namespaces': ['kube-system']}

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        flags = set(ctx.param('flags', []))
        wanted = {a.lower() for a in ctx.param('actions', []) or []}
        ignored = set(ctx.param('ignore_namespaces', []) or [])
        bucket_minutes = int(ctx.param('bucket_minutes', 60))
        drafts: list[DetectionDraft] = []
        for event in ctx.events(category='k8s'):
            if wanted and (event.action or '').lower() not in wanted:
                continue
            data = meta(event)
            raw_meta = data.get('metadata') if isinstance(data.get('metadata'), dict) else {}
            namespace = str(data.get('namespace') or raw_meta.get('namespace') or '')[:120]
            if namespace in ignored:
                continue
            found = deep_find_truthy(data, flags)
            if not found:
                continue
            when = event_time(event)
            workload = event.entity or data.get('name') or data.get('pod') or 'workload'
            severity = 'critical' if 'privileged' in found and len(found) > 1 else self.severity
            images = data.get('images') if isinstance(data.get('images'), list) else [data.get('image')] if data.get('image') else []
            drafts.append(DetectionDraft(
                rule_id=self.id, severity=severity, confidence=0.9, title=f'Privileged workload {workload} ({", ".join(found)})',
                description=f'`{event.actor or "unknown actor"}` admitted {workload} in namespace {namespace or "unknown"} with {", ".join(found)} enabled at {iso(when)}.',
                entity=str(workload), entity_kind='asset', asset_id=event.asset_id, fingerprint_parts=[str(workload), namespace],
                window_bucket=window_bucket(when, bucket_minutes), first_seen_at=when, last_seen_at=when,
                evidence={'workload': str(workload), 'namespace': namespace, 'flags': found, 'action': event.action, 'actor': event.actor,
                          'cluster': data.get('cluster') or '', 'images': sample(str(i) for i in images if i), 'event_ids': [event.id]}))
        return drafts


registry.register(PrivilegedWorkload())
