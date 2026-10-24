"""PagerDuty Events API v2: trigger on new findings/detections, resolve when the subject closes.
dedup_key is derived from the subject id so repeated events update one incident."""
from __future__ import annotations

from typing import Any

from . import Channel, DeliveryResult, OutboundEvent, registry, request_with_retry, result_from_response

EVENTS_URL = 'https://events.pagerduty.com/v2/enqueue'
_SEVERITY = {'critical': 'critical', 'high': 'error', 'medium': 'warning', 'low': 'info', 'informational': 'info'}


def dedup_key(event: OutboundEvent) -> str:
    return f'argus-{event.subject_kind or "event"}-{event.subject_id or event.delivery_id}'[:255]


def build_payload(event: OutboundEvent, routing_key: str, config: dict[str, Any]) -> dict[str, Any]:
    action = 'resolve' if event.is_resolution else 'trigger'
    body: dict[str, Any] = {'routing_key': routing_key, 'event_action': action, 'dedup_key': dedup_key(event)}
    if action == 'trigger':
        details = {k: v for k, v in (event.payload or {}).items() if isinstance(v, (str, int, float, bool))}
        details.update({'topic': event.topic, 'subject_kind': event.subject_kind, 'subject_id': event.subject_id, 'status': event.status})
        body['payload'] = {'summary': f'[{event.severity.upper()}] {event.title}'[:1024], 'severity': _SEVERITY.get(event.severity, 'warning'),
                           'source': str(config.get('source') or 'argus'), 'component': str(config.get('component') or event.subject_kind or 'argus'),
                           'group': str(config.get('group') or event.tenant_name or ''), 'class': event.topic, 'custom_details': details}
        if event.occurred_at:
            body['payload']['timestamp'] = event.occurred_at.isoformat()
        if event.url:
            body['links'] = [{'href': event.url, 'text': 'Open in Argus'}]
    return body


class PagerDutyChannel(Channel):
    kind = 'pagerduty'
    description = 'PagerDuty Events API v2 (trigger/resolve with a stable dedup key per subject).'
    config_schema = {
        'type': 'object', 'additionalProperties': False,
        'properties': {'source': {'type': 'string', 'default': 'argus'}, 'component': {'type': 'string'}, 'group': {'type': 'string'},
                       'timeout_seconds': {'type': 'number', 'minimum': 1, 'maximum': 60, 'default': 15}},
    }
    secret_fields = ['routing_key']
    topics = ['finding.*', 'detection.*', 'action.*', 'agent.*']
    default_topics = ['finding.created', 'finding.resolved', 'detection.created']

    async def send(self, event: OutboundEvent, config: dict[str, Any], secrets: dict[str, str]) -> DeliveryResult:
        routing_key = secrets.get('routing_key') or ''
        if not routing_key:
            return DeliveryResult(ok=False, error='routing_key secret missing')
        body = build_payload(event, routing_key, config)
        response, error = await request_with_retry(lambda client: client.post(EVENTS_URL, json=body), attempts=3, timeout=float(config.get('timeout_seconds') or 15))
        result = result_from_response(response, error, ok_codes=(200, 202))
        if result.ok and response is not None:
            try:
                result.external_ref = str(response.json().get('dedup_key') or body['dedup_key'])
            except ValueError:
                result.external_ref = body['dedup_key']
        return result


registry.register(PagerDutyChannel())
