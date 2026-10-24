"""Slack: incoming webhook or bot token (chat.postMessage) with a Block Kit summary."""
from __future__ import annotations

from typing import Any

from . import Channel, DeliveryResult, OutboundEvent, egress_error, excerpt, registry, request_with_retry, result_from_response, severity_label

POST_MESSAGE_URL = 'https://slack.com/api/chat.postMessage'


HIGH_RISKS = ('high', 'critical')
ROLLBACK_TOPICS = ('action.executed', 'action.autonomous')


def action_buttons(event: OutboundEvent, config: dict[str, Any] | None) -> dict[str, Any] | None:
    """Interactive buttons for action events when the integration has interactive=true. Clicks are
    handled by POST /api/v1/slack/interactions/{integration_id}, which re-checks everything."""
    config = config or {}
    if not config.get('interactive') or not event.topic.startswith('action.'):
        return None
    payload = event.payload if isinstance(event.payload, dict) else {}
    risk = str(payload.get('risk') or '')
    high_blocked = risk in HIGH_RISKS and not config.get('allow_high_risk')
    elements: list[dict[str, Any]] = []
    request_id = str(payload.get('request_id') or '')
    run_id = str(payload.get('run_id') or '')
    if event.topic == 'action.requested' and payload.get('status') == 'pending' and request_id and not high_blocked:
        elements.append({'type': 'button', 'action_id': 'argus_approve', 'style': 'primary', 'value': request_id,
                         'text': {'type': 'plain_text', 'text': 'Approve'}})
        elements.append({'type': 'button', 'action_id': 'argus_deny', 'style': 'danger', 'value': request_id,
                         'text': {'type': 'plain_text', 'text': 'Deny'}})
    elif event.topic in ROLLBACK_TOPICS and run_id and payload.get('reversible') is not False and not high_blocked:
        elements.append({'type': 'button', 'action_id': 'argus_rollback', 'style': 'danger', 'value': run_id,
                         'text': {'type': 'plain_text', 'text': 'Roll back'},
                         'confirm': {'title': {'type': 'plain_text', 'text': 'Roll back this action?'},
                                     'text': {'type': 'mrkdwn', 'text': f'Undo `{payload.get("action_type") or "the action"}` through the Argus broker.'},
                                     'confirm': {'type': 'plain_text', 'text': 'Roll back'}, 'deny': {'type': 'plain_text', 'text': 'Cancel'}}})
    if event.url:
        elements.append({'type': 'button', 'action_id': 'argus_open', 'url': event.url, 'text': {'type': 'plain_text', 'text': 'Open in Argus'}})
    if not elements:
        return None
    return {'type': 'actions', 'block_id': f'argus:{event.topic}'[:255], 'elements': elements}


def build_blocks(event: OutboundEvent, config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    fields = [{'type': 'mrkdwn', 'text': f'*Severity*\n{severity_label(event.severity)}'}, {'type': 'mrkdwn', 'text': f'*Topic*\n{event.topic}'}]
    if event.status:
        fields.append({'type': 'mrkdwn', 'text': f'*Status*\n{event.status}'})
    if event.subject_kind:
        fields.append({'type': 'mrkdwn', 'text': f'*Subject*\n{event.subject_kind} `{event.subject_id[:12]}`'})
    source = event.payload.get('source') if isinstance(event.payload, dict) else None
    if source:
        fields.append({'type': 'mrkdwn', 'text': f'*Source*\n{source}'})
    blocks: list[dict[str, Any]] = [
        {'type': 'header', 'text': {'type': 'plain_text', 'text': f'[{severity_label(event.severity)}] {event.title}'[:150], 'emoji': False}},
        {'type': 'section', 'fields': fields[:10]},
    ]
    if event.summary:
        blocks.append({'type': 'section', 'text': {'type': 'mrkdwn', 'text': event.summary[:2900]}})
    buttons = action_buttons(event, config)
    if buttons:
        blocks.append(buttons)
        payload = event.payload if isinstance(event.payload, dict) else {}
        if str(payload.get('risk') or '') in HIGH_RISKS and not (config or {}).get('allow_high_risk'):
            blocks.append({'type': 'context', 'elements': [{'type': 'mrkdwn', 'text': 'High-risk action: decide it in Argus (login and MFA required).'}]})
    context = [{'type': 'mrkdwn', 'text': f'Argus · {event.tenant_name or event.tenant_id[:8]}'}]
    if event.url:
        context.append({'type': 'mrkdwn', 'text': f'<{event.url}|Open in Argus>'})
    blocks.append({'type': 'context', 'elements': context})
    return blocks


class SlackChannel(Channel):
    kind = 'slack'
    description = 'Slack message via incoming webhook or bot token (chat.postMessage) with Block Kit formatting.'
    config_schema = {
        'type': 'object', 'additionalProperties': False,
        'properties': {
            'mode': {'type': 'string', 'enum': ['webhook', 'bot'], 'default': 'webhook'},
            'channel': {'type': 'string', 'description': 'Channel id or #name (bot mode)'},
            'username': {'type': 'string', 'default': 'Argus'},
            'timeout_seconds': {'type': 'number', 'minimum': 1, 'maximum': 60, 'default': 15},
            # interactive buttons (see docs/AUTONOMOUS-RESPONSE.md); needs the signing_secret secret
            'interactive': {'type': 'boolean', 'default': False},
            'user_map': {'type': 'object', 'description': 'Slack user id -> Argus user email', 'properties': {},
                         'additionalProperties': {'type': 'string', 'format': 'email', 'maxLength': 254}},
            'resolve_users_by_email': {'type': 'boolean', 'default': False},
            'allow_high_risk': {'type': 'boolean', 'default': False},
            'execute_on_approve': {'type': 'boolean', 'default': False},
            'team_id': {'type': 'string', 'maxLength': 32, 'description': 'only accept clicks from this Slack workspace'},
        },
    }
    secret_fields = ['webhook_url', 'bot_token', 'signing_secret']
    default_topics = ['finding.created', 'detection.created', 'action.executed']

    async def send(self, event: OutboundEvent, config: dict[str, Any], secrets: dict[str, str]) -> DeliveryResult:
        mode = str(config.get('mode') or ('bot' if secrets.get('bot_token') and not secrets.get('webhook_url') else 'webhook'))
        text = f'[{severity_label(event.severity)}] {event.title}'
        message: dict[str, Any] = {'text': text[:3000], 'blocks': build_blocks(event, config)}
        timeout = float(config.get('timeout_seconds') or 15)
        if mode == 'bot':
            token = secrets.get('bot_token') or ''
            channel = str(config.get('channel') or '')
            if not token or not channel:
                return DeliveryResult(ok=False, error='bot mode needs bot_token secret and channel')
            message['channel'] = channel
            if config.get('username'):
                message['username'] = str(config['username'])
            response, error = await request_with_retry(lambda client: client.post(POST_MESSAGE_URL, json=message, headers={'Authorization': f'Bearer {token}'}),
                                                       attempts=2, timeout=timeout)
            result = result_from_response(response, error)
            if result.ok and response is not None:
                try:
                    data = response.json()
                except ValueError:
                    data = {}
                if not data.get('ok', False):
                    return DeliveryResult(ok=False, status_code=response.status_code, error=f'slack: {data.get("error", "unknown error")}', retryable=data.get('error') in {'ratelimited', 'service_unavailable'})
                result.external_ref = str(data.get('ts') or '')
            return result
        url = secrets.get('webhook_url') or ''
        if not url.startswith('https://'):
            return DeliveryResult(ok=False, error='webhook_url secret missing or not https')
        denied = egress_error(url)
        if denied:
            return DeliveryResult(ok=False, error=f'webhook_url refused: {denied}')
        if config.get('username'):
            message['username'] = str(config['username'])
        response, error = await request_with_retry(lambda client: client.post(url, json=message), attempts=2, timeout=timeout)
        result = result_from_response(response, error)
        if result.ok and response is not None and excerpt(response).strip() not in {'ok', ''}:
            return DeliveryResult(ok=False, status_code=response.status_code, error=f'slack webhook: {excerpt(response)}')
        return result


registry.register(SlackChannel())
