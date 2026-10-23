"""Falco runtime alerts (JSON output / falcosidekick payload)."""
from __future__ import annotations

from typing import Any

from ...core.findings import EventDraft
from . import registry
from ._common import ParseContext, Parser, event, first, hash_item, listify, snake

_K8S_FLAG_RULES = {'privileged': 'privileged', 'host network': 'hostNetwork', 'hostnetwork': 'hostNetwork', 'host pid': 'hostPID',
                   'hostpid': 'hostPID', 'host ipc': 'hostIPC', 'hostipc': 'hostIPC'}


class FalcoParser(Parser):
    name = 'falco'
    source = 'falco'
    description = 'Falco runtime security alerts (direct JSON output or falcosidekick).'
    kind = 'events'
    example = 'tests/fixtures/integrations/falco/alerts.json'
    correlate_alerts = True

    def items(self, payload: Any) -> list[Any]:
        if isinstance(payload, dict) and isinstance(payload.get('alerts'), list):
            return payload['alerts']
        return super().items(payload)

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        fields = item.get('output_fields') if isinstance(item.get('output_fields'), dict) else {}
        rule = str(item.get('rule') or 'Falco runtime alert')
        namespace = first(fields, 'k8s.ns.name', 'ka.target.namespace') or ''
        pod = first(fields, 'k8s.pod.name', 'ka.target.name') or ''
        container = first(fields, 'container.name', 'container.id') or ''
        hostname = item.get('hostname') or first(fields, 'evt.hostname') or ''
        falco_source = str(item.get('source') or 'syscall')
        is_k8s = bool(namespace or pod or falco_source == 'k8s_audit')
        actor = first(fields, 'user.name', 'ka.user.name', 'user.loginname') or ''
        entity = f'{namespace}/{pod}' if namespace and pod else pod or container or hostname
        category = 'k8s' if is_k8s else 'process'
        meta: dict[str, Any] = {
            'rule': rule, 'priority': item.get('priority') or '', 'host': hostname, 'namespace': namespace, 'pod': pod, 'container': container,
            'image': first(fields, 'container.image.repository', 'container.image') or '', 'process': first(fields, 'proc.name') or '',
            'parent_process': first(fields, 'proc.pname') or '', 'cmdline': first(fields, 'proc.cmdline') or '',
            'file': first(fields, 'fd.name') or '', 'syscall': first(fields, 'evt.type') or '', 'tags': [str(t) for t in listify(item.get('tags'))][:10],
            'falco_source': falco_source, 'ip': first(fields, 'fd.sip', 'fd.rip') or '', 'service': 'falco',
            'output': item.get('output') if isinstance(item.get('output'), str) else '',
        }
        lowered = rule.lower()
        for marker, flag in _K8S_FLAG_RULES.items():
            if marker in lowered:
                meta[flag] = True
                category = 'k8s'
        if first(fields, 'ka.req.pod.containers.privileged') in (True, 'true', ['true']):
            meta['privileged'] = True
            category = 'k8s'
        external_id = item.get('uuid') or item.get('event_id') or hash_item({'rule': rule, 'time': item.get('time'), 'host': hostname, 'output': item.get('output')})
        return [event(self.source, external_id, rule, severity=str(item.get('priority') or 'low'), category=category, actor=actor, entity=entity,
                      action=f'falco.{snake(rule)[:100]}', occurred_at=item.get('time'), metadata=meta)]


registry.register(FalcoParser())
