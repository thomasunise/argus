"""Kubernetes API server audit events (audit.k8s.io/v1 Event or EventList, webhook backend
batches). Actions are `k8s.<resource>.<verb>`; privileged pod specs are flagged for the
k8s.privileged_workload rule."""
from __future__ import annotations

from typing import Any

from ...core.findings import EventDraft
from . import registry
from ._common import ParseContext, Parser, dig, event, first, hash_item, listify

_FLAGS = ('privileged', 'hostPID', 'hostNetwork', 'hostIPC')
# Rules expect singular names for bindings but plural for most other resources.
_RESOURCE_NAMES = {'rolebindings': 'rolebinding', 'clusterrolebindings': 'clusterrolebinding', 'roles': 'role', 'clusterroles': 'clusterrole'}
_SENSITIVE_READS = {('secrets', 'get'), ('secrets', 'list'), ('secrets', 'watch'), ('configmaps', 'get'), ('serviceaccounts/token', 'create')}
_HIGH_WRITES = {'clusterrolebinding', 'rolebinding', 'clusterrole', 'mutatingwebhookconfigurations', 'validatingwebhookconfigurations',
                'daemonsets', 'nodes', 'persistentvolumes'}


def _find_flags(spec: Any, depth: int = 0, budget: list[int] | None = None) -> set[str]:
    budget = budget if budget is not None else [400]
    found: set[str] = set()
    if budget[0] <= 0 or depth > 8:
        return found
    budget[0] -= 1
    if isinstance(spec, dict):
        for key, value in spec.items():
            if key in _FLAGS and value is True:
                found.add(key)
            found |= _find_flags(value, depth + 1, budget)
    elif isinstance(spec, list):
        for item in spec[:50]:
            found |= _find_flags(item, depth + 1, budget)
    return found


def _images(spec: Any) -> list[str]:
    out: list[str] = []
    pod_spec = dig(spec, 'spec', 'template', 'spec') or dig(spec, 'spec') or {}
    for group in ('initContainers', 'containers', 'ephemeralContainers'):
        for container in listify(pod_spec.get(group) if isinstance(pod_spec, dict) else None):
            if isinstance(container, dict) and container.get('image'):
                out.append(str(container['image'])[:200])
    return out[:10]


class K8sAuditParser(Parser):
    name = 'k8s_audit'
    aliases = ('kubernetes_audit', 'k8s')
    source = 'k8s_audit'
    description = 'Kubernetes API audit events (audit.k8s.io/v1 Event or EventList).'
    kind = 'events'
    example = 'tests/fixtures/integrations/k8s_audit/events.json'

    def items(self, payload: Any) -> list[Any]:
        if isinstance(payload, dict):
            if str(payload.get('kind') or '') == 'EventList' and isinstance(payload.get('items'), list):
                return payload['items']
            if isinstance(payload.get('items'), list):
                return payload['items']
            return [payload]
        return payload

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        stage = str(item.get('stage') or 'ResponseComplete')
        if stage not in {'ResponseComplete', 'Panic'}:
            return []  # RequestReceived / ResponseStarted duplicate the completed record
        ref = item.get('objectRef') if isinstance(item.get('objectRef'), dict) else {}
        user = item.get('user') if isinstance(item.get('user'), dict) else {}
        verb = str(item.get('verb') or 'unknown').lower()
        resource_raw = str(ref.get('resource') or '').lower()
        subresource = str(ref.get('subresource') or '').lower()
        resource = _RESOURCE_NAMES.get(resource_raw, resource_raw) or 'unknown'
        action = f'k8s.{resource}.{subresource}' if subresource and verb in {'create', 'get'} and subresource in {'exec', 'attach', 'portforward', 'proxy', 'token', 'log'} \
            else f'k8s.{resource}.{verb}'
        namespace = str(ref.get('namespace') or '')
        name = str(ref.get('name') or '')
        entity = f'{namespace}/{name}' if namespace and name else name or f'{resource}' + (f'/{namespace}' if namespace else '')
        request_obj = item.get('requestObject') if isinstance(item.get('requestObject'), dict) else {}
        response_obj = item.get('responseObject') if isinstance(item.get('responseObject'), dict) else {}
        flags = _find_flags(request_obj or response_obj) if resource in {'pods', 'deployments', 'daemonsets', 'statefulsets', 'jobs', 'cronjobs', 'replicasets'} and verb in {'create', 'update', 'patch'} else set()
        code = dig(item, 'responseStatus', 'code')
        impersonated = dig(item, 'impersonatedUser', 'username') or ''  # the identity acted as; `user` is the real caller
        actual_user = user.get('username') or ''
        severity = 'informational' if verb in {'get', 'list', 'watch'} else 'low'
        category = 'k8s'
        if (resource_raw, verb) in _SENSITIVE_READS or (resource_raw == 'secrets' and verb in {'get', 'list'}):
            category, severity = 'data_access', 'low'
        if verb in {'create', 'update', 'patch', 'delete', 'deletecollection'} and resource in _HIGH_WRITES:
            severity = 'medium'
        if subresource in {'exec', 'attach', 'portforward'}:
            severity = 'medium'
        if flags:
            severity = 'critical' if 'privileged' in flags and len(flags) > 1 else 'high'
        if isinstance(code, int) and code >= 400:
            severity = 'low' if severity == 'informational' else severity
        meta: dict[str, Any] = {
            'verb': verb, 'resource': resource_raw, 'subresource': subresource, 'namespace': namespace, 'name': name, 'api_group': ref.get('apiGroup') or '',
            'api_version': ref.get('apiVersion') or '', 'ip': (listify(item.get('sourceIPs')) or [''])[0], 'user_agent': item.get('userAgent') or '',
            'groups': [str(g) for g in listify(user.get('groups'))][:8], 'uid': user.get('uid') or '', 'impersonated_user': impersonated,
            'response_code': code, 'response_reason': dig(item, 'responseStatus', 'reason') or '', 'stage': stage, 'level': item.get('level') or '',
            'audit_id': item.get('auditID') or '', 'request_uri': str(item.get('requestURI') or '')[:300], 'cluster': ctx.extra.get('cluster') or '',
            'service': 'k8s', 'authorization_reason': dig(item, 'annotations', 'authorization.k8s.io/reason') or '',
            'authorization_decision': dig(item, 'annotations', 'authorization.k8s.io/decision') or '',
            'pod_security': dig(item, 'annotations', 'pod-security.kubernetes.io/audit-violations') or '',
        }
        if flags:
            for flag in flags:
                meta[flag] = True
            meta['flags'] = sorted(flags)
            meta['images'] = _images(request_obj or response_obj)
            sa = dig(request_obj, 'spec', 'serviceAccountName') or dig(request_obj, 'spec', 'template', 'spec', 'serviceAccountName')
            if sa:
                meta['service_account'] = sa
        if resource in {'rolebinding', 'clusterrolebinding'} and verb in {'create', 'update', 'patch'}:
            meta['role_ref'] = dig(request_obj, 'roleRef', 'name') or ''
            meta['subjects'] = [f'{s.get("kind")}:{s.get("namespace", "")}/{s.get("name")}' for s in listify(request_obj.get('subjects')) if isinstance(s, dict)][:10]
        title = f'{verb} {resource_raw}{"/" + subresource if subresource else ""} {entity}'.strip()
        external_id = item.get('auditID') or hash_item(item)
        return [event(self.source, external_id, title, severity=severity, category=category, actor=actual_user, entity=entity, action=action,
                      occurred_at=first(item, 'stageTimestamp', 'requestReceivedTimestamp'), metadata=meta)]


registry.register(K8sAuditParser())
