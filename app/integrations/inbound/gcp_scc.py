"""Google Cloud: Security Command Center findings (finding JSON, Pub/Sub notification
`{finding, resource}`), and Cloud Audit Log entries (`protoPayload` AuditLog)."""
from __future__ import annotations

from typing import Any

from ...core.findings import EventDraft
from . import registry
from ._common import ParseContext, Parser, dig, event, first, hash_item, scan_markers, snake

# methodName (lower-case) -> dotted action the rules recognise.
_METHODS = {
    'storage.setiampermissions': 'storage.set_iam_policy',
    'storage.buckets.setiampolicy': 'storage.set_iam_policy',
    'storage.buckets.update': 'storage.buckets.update',
    'storage.objects.get': 'storage.objects.get',
    'storage.objects.list': 'storage.objects.list',
    'setiampolicy': 'gcp.set_iam_policy',
    'google.iam.admin.v1.setiampolicy': 'gcp.set_iam_policy',
    'google.cloud.resourcemanager.v3.projects.setiampolicy': 'gcp.set_iam_policy',
    'google.iam.credentials.v1.iamcredentials.generateaccesstoken': 'gcp.iam.impersonate',
    'google.iam.credentials.v1.iamcredentials.signjwt': 'gcp.iam.impersonate',
    'generateaccesstoken': 'gcp.iam.impersonate',
    'signjwt': 'gcp.iam.impersonate',
    'generateidtoken': 'gcp.iam.impersonate',
    'google.iam.admin.v1.createserviceaccountkey': 'gcp.iam.create_service_account_key',
    'v1.compute.firewalls.insert': 'compute.firewalls.insert',
    'v1.compute.firewalls.patch': 'compute.firewalls.patch',
    'beta.compute.firewalls.insert': 'compute.firewalls.insert',
    'jobservice.query': 'bigquery.query',
    'google.cloud.bigquery.v2.jobservice.query': 'bigquery.query',
    'google.cloud.bigquery.v2.jobservice.insertjob': 'bigquery.query',
    'google.cloud.secretmanager.v1.secretmanagerservice.accesssecretversion': 'secretmanager.access_secret_version',
}
_DATA_ACCESS = {'storage.objects.get', 'storage.objects.list', 'bigquery.query', 'secretmanager.access_secret_version'}
_IDENTITY = {'gcp.set_iam_policy', 'gcp.iam.impersonate', 'gcp.iam.create_service_account_key', 'storage.set_iam_policy'}
_EXPOSURE = {'storage.set_iam_policy', 'compute.firewalls.insert', 'compute.firewalls.patch', 'gcp.set_iam_policy'}
_SERVICE_SHORT = {'storage.googleapis.com': 'storage', 'compute.googleapis.com': 'compute', 'iam.googleapis.com': 'iam',
                  'cloudresourcemanager.googleapis.com': 'gcp', 'bigquery.googleapis.com': 'bigquery', 'iamcredentials.googleapis.com': 'gcp',
                  'secretmanager.googleapis.com': 'secretmanager', 'container.googleapis.com': 'gke', 'cloudsql.googleapis.com': 'cloudsql'}


def _audit_action(service_name: str, method: str) -> str:
    key = method.lower()
    if key in _METHODS:
        return _METHODS[key]
    short = _SERVICE_SHORT.get(service_name.lower(), service_name.split('.')[0].lower() or 'gcp')
    tail = method.split('.')
    # google.cloud.foo.v1.Service.Method -> service.method ; storage.objects.delete -> storage.objects.delete
    if key.startswith(('google.', 'v1.', 'beta.')):
        tail = tail[-2:]
    elif tail and tail[0].lower() == short:
        tail = tail[1:]
    return (short + '.' + '.'.join(snake(t) for t in tail if t))[:120]


def _severity(value: Any) -> str:
    return {'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}.get(str(value or '').upper(), 'medium')


class GcpSccParser(Parser):
    name = 'gcp_scc'
    aliases = ('scc', 'gcp', 'gcp_audit')
    source = 'gcp_scc'
    description = 'Security Command Center findings and Cloud Audit Log entries.'
    kind = 'events'
    example = 'tests/fixtures/integrations/gcp_scc/findings.json'
    correlate_alerts = True

    def items(self, payload: Any) -> list[Any]:
        if isinstance(payload, dict):
            if isinstance(payload.get('findings'), list):
                return payload['findings']
            if isinstance(payload.get('entries'), list):
                return payload['entries']
            return [payload]
        return payload

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        if isinstance(item.get('finding'), dict):
            return [self._finding(item['finding'], item.get('resource') if isinstance(item.get('resource'), dict) else {})]
        if isinstance(item.get('protoPayload'), dict):
            return [self._audit(item)]
        if 'category' in item and ('resourceName' in item or 'parent' in item):
            return [self._finding(item, {})]
        raise ValueError('not an SCC finding or audit log entry')

    def _finding(self, finding: dict, resource: dict) -> EventDraft:
        category = str(finding.get('category') or 'FINDING')
        access = finding.get('access') if isinstance(finding.get('access'), dict) else {}
        source_props = finding.get('sourceProperties') if isinstance(finding.get('sourceProperties'), dict) else {}
        name = str(finding.get('name') or '')
        resource_name = str(finding.get('resourceName') or resource.get('name') or '')
        parent_parts = [p for p in str(finding.get('parent') or '').split('/') if p]
        project = resource.get('projectDisplayName') or resource.get('project') or (dig(source_props, 'ProjectId') or '')
        meta: dict[str, Any] = {
            'finding_category': category, 'finding_name': name, 'state': finding.get('state') or '', 'finding_class': finding.get('findingClass') or '',
            'project': project, 'organization': parent_parts[1] if len(parent_parts) > 1 and parent_parts[0] == 'organizations' else '',
            'resource_type': resource.get('type') or dig(source_props, 'ResourceType') or '', 'service': 'scc', 'ip': access.get('callerIp') or '',
            'user_agent': access.get('userAgent') or access.get('userAgentFamily') or '',
            'geo': {'country': dig(access, 'callerIpGeo', 'regionCode') or ''}, 'method': access.get('methodName') or '',
            'external_uri': finding.get('externalUri') or '', 'mitre_techniques': [str(t) for t in (dig(finding, 'mitreAttack', 'primaryTechniques') or [])][:6],
            'explanation': str(source_props.get('Explanation') or finding.get('description') or '')[:600],
            'recommendation': str(source_props.get('Recommendation') or finding.get('nextSteps') or '')[:600],
            'markers': scan_markers(source_props) if category.upper() in {'PUBLIC_BUCKET_ACL', 'PUBLIC_IP_ADDRESS', 'OPEN_FIREWALL', 'PUBLIC_DATASET'} else [],
        }
        if category.upper().startswith('PUBLIC_') or category.upper() == 'OPEN_FIREWALL':
            meta['public'] = True
        actor = str(access.get('principalEmail') or access.get('principalSubject') or '')
        title = str(finding.get('description') or category.replace('_', ' ').title())
        external_id = name or hash_item(finding)
        return event(self.source, external_id, title, severity=_severity(finding.get('severity')), category='cloud', actor=actor, entity=resource_name,
                     action=f'scc.{snake(category)[:100]}', occurred_at=first(finding, 'eventTime', 'createTime'), metadata=meta)

    def _audit(self, entry: dict) -> EventDraft:
        proto = entry['protoPayload']
        service_name = str(proto.get('serviceName') or '')
        method = str(proto.get('methodName') or 'unknown')
        action = _audit_action(service_name, method)
        request_meta = proto.get('requestMetadata') if isinstance(proto.get('requestMetadata'), dict) else {}
        auth = proto.get('authenticationInfo') if isinstance(proto.get('authenticationInfo'), dict) else {}
        resource = entry.get('resource') if isinstance(entry.get('resource'), dict) else {}
        labels = resource.get('labels') if isinstance(resource.get('labels'), dict) else {}
        request = proto.get('request') if isinstance(proto.get('request'), dict) else {}
        markers = scan_markers(request) if action in _EXPOSURE else []
        actor = str(auth.get('principalEmail') or auth.get('principalSubject') or '')
        delegation = dig(auth, 'serviceAccountDelegationInfo')
        if isinstance(delegation, list) and delegation and isinstance(delegation[0], dict):
            actor = str(dig(delegation[0], 'firstPartyPrincipal', 'principalEmail') or actor)
        resource_name = str(proto.get('resourceName') or '')
        if action in _DATA_ACCESS:
            category, severity = 'data_access', 'low'
        elif action in _IDENTITY:
            category, severity = 'identity', 'medium'
        else:
            category = 'cloud_api'
            severity = 'medium' if any(w in action for w in ('.insert', '.delete', '.patch', '.update', '.create', '.set_')) else 'low'
        if markers and action in _EXPOSURE:
            severity = 'high'
        status = proto.get('status') if isinstance(proto.get('status'), dict) else {}
        meta: dict[str, Any] = {
            'ip': request_meta.get('callerIp') or '', 'user_agent': request_meta.get('callerSuppliedUserAgent') or '', 'service': _SERVICE_SHORT.get(service_name.lower(), service_name.split('.')[0]),
            'service_name': service_name, 'method': method, 'project': labels.get('project_id') or '', 'region': labels.get('location') or labels.get('zone') or '',
            'resource_type': resource.get('type') or '', 'resource_name': resource_name, 'insert_id': entry.get('insertId') or '', 'log_name': entry.get('logName') or '',
            'status_code': status.get('code'), 'status_message': status.get('message') or '', 'request': request, 'markers': markers,
            'principal_subject': auth.get('principalSubject') or '', 'impersonated': bool(delegation), 'severity_label': entry.get('severity') or '',
        }
        if markers:
            meta['public'] = True
        entity = resource_name.split('/')[-1] if resource_name else ''
        title = f'{method} on {entity}' if entity else method
        external_id = entry.get('insertId') or hash_item(entry)
        return event(self.source, external_id, title, severity=severity, category=category, actor=actor, entity=resource_name or entity, action=action,
                     occurred_at=first(entry, 'timestamp', 'receiveTimestamp'), metadata=meta)


registry.register(GcpSccParser())
