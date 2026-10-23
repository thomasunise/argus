"""ServiceNow Table API: create an incident per subject (correlation_id = sentinel subject id) and
update it (work notes, state) on later events."""
from __future__ import annotations

from typing import Any

from . import Channel, DeliveryResult, OutboundEvent, registry, request_with_retry, result_from_response, severity_label

# (impact, urgency) per severity; ServiceNow derives priority from these.
_IMPACT_URGENCY = {'critical': ('1', '1'), 'high': ('2', '1'), 'medium': ('2', '2'), 'low': ('3', '3'), 'informational': ('3', '3')}
STATE_RESOLVED = '6'


def correlation_id(event: OutboundEvent) -> str:
    return f'sentinel:{event.subject_kind or "event"}:{event.subject_id or event.delivery_id}'[:100]


def build_incident(event: OutboundEvent, config: dict[str, Any]) -> dict[str, Any]:
    impact, urgency = _IMPACT_URGENCY.get(event.severity, ('3', '3'))
    description = '\n'.join(x for x in [event.summary, f'Topic: {event.topic}', f'Severity: {severity_label(event.severity)}',
                                        f'Sentinel {event.subject_kind} id: {event.subject_id}', f'Link: {event.url}' if event.url else ''] if x)
    body: dict[str, Any] = {'short_description': f'[{severity_label(event.severity)}] {event.title}'[:160], 'description': description[:4000],
                            'impact': impact, 'urgency': urgency, 'correlation_id': correlation_id(event), 'category': str(config.get('category') or 'security')}
    for key in ('assignment_group', 'caller_id', 'business_service', 'cmdb_ci'):
        if config.get(key):
            body[key] = str(config[key])
    return body


class ServiceNowChannel(Channel):
    kind = 'servicenow'
    description = 'ServiceNow incidents via the Table API (create, then update by correlation id).'
    config_schema = {
        'type': 'object', 'additionalProperties': False, 'required': ['instance_url'],
        'properties': {
            'instance_url': {'type': 'string', 'pattern': '^https://', 'description': 'https://your-instance.service-now.com'},
            'table': {'type': 'string', 'default': 'incident'}, 'assignment_group': {'type': 'string'}, 'caller_id': {'type': 'string'},
            'business_service': {'type': 'string'}, 'cmdb_ci': {'type': 'string'}, 'category': {'type': 'string', 'default': 'security'},
            'timeout_seconds': {'type': 'number', 'minimum': 1, 'maximum': 60, 'default': 20},
        },
    }
    secret_fields = ['username', 'password', 'bearer_token']
    topics = ['finding.*', 'detection.*', 'action.*']
    default_topics = ['finding.created', 'finding.updated', 'finding.resolved']

    async def send(self, event: OutboundEvent, config: dict[str, Any], secrets: dict[str, str]) -> DeliveryResult:
        base = str(config.get('instance_url') or '').rstrip('/')
        table = str(config.get('table') or 'incident')
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        auth = None
        if secrets.get('bearer_token'):
            headers['Authorization'] = f'Bearer {secrets["bearer_token"]}'
        elif secrets.get('username'):
            auth = (secrets['username'], secrets.get('password') or '')
        if not base.startswith('https://') or (auth is None and 'Authorization' not in headers):
            return DeliveryResult(ok=False, error='servicenow needs https instance_url and username/password (or bearer_token) secrets')
        timeout = float(config.get('timeout_seconds') or 20)
        corr = correlation_id(event)
        lookup, error = await request_with_retry(lambda c: c.get(f'{base}/api/now/table/{table}', params={'sysparm_query': f'correlation_id={corr}', 'sysparm_limit': 1,
                                                                                                           'sysparm_fields': 'sys_id,number,state'}, headers=headers, auth=auth),
                                                 attempts=2, timeout=timeout)
        if lookup is None:
            return DeliveryResult(ok=False, error=f'servicenow lookup failed: {error}', retryable=True)
        if lookup.status_code != 200:
            return result_from_response(lookup, error)
        try:
            rows = lookup.json().get('result') or []
        except ValueError:
            rows = []
        if rows:
            sys_id, number = str(rows[0].get('sys_id') or ''), str(rows[0].get('number') or '')
            patch: dict[str, Any] = {'work_notes': f'Sentinel update ({event.topic}): {event.title}' + (f' - status {event.status}' if event.status else '')}
            if event.is_resolution:
                patch.update({'state': STATE_RESOLVED, 'close_code': 'Solved (Permanently)', 'close_notes': f'Resolved in Sentinel: {event.title}'[:4000]})
            response, error = await request_with_retry(lambda c: c.patch(f'{base}/api/now/table/{table}/{sys_id}', json=patch, headers=headers, auth=auth),
                                                       attempts=2, timeout=timeout)
            return result_from_response(response, error, external_ref=number or sys_id)
        if event.is_resolution:
            return DeliveryResult(ok=True, skipped=True, detail={'reason': 'no incident to resolve'})
        body = build_incident(event, config)
        response, error = await request_with_retry(lambda c: c.post(f'{base}/api/now/table/{table}', json=body, headers=headers, auth=auth), attempts=2, timeout=timeout)
        result = result_from_response(response, error, ok_codes=(200, 201))
        if result.ok and response is not None:
            try:
                created = response.json().get('result') or {}
                result.external_ref = str(created.get('number') or created.get('sys_id') or '')
            except ValueError:
                pass
        return result


registry.register(ServiceNowChannel())
