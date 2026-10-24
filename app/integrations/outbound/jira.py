"""Jira Cloud REST v3: create one issue per finding (deduped by a `argus-finding-<id>` label),
comment on later events for the same finding, and transition to a done-like status on resolution."""
from __future__ import annotations

import base64
from typing import Any

from . import Channel, DeliveryResult, OutboundEvent, egress_error, excerpt, registry, request_with_retry, result_from_response, severity_label

_PRIORITY = {'critical': 'Highest', 'high': 'High', 'medium': 'Medium', 'low': 'Low', 'informational': 'Lowest'}
_DONE_NAMES = ('done', 'resolved', 'closed', 'complete', 'completed', 'fixed')


def adf(text: str) -> dict[str, Any]:
    paragraphs = [p for p in text.split('\n\n') if p.strip()] or ['']
    return {'type': 'doc', 'version': 1, 'content': [{'type': 'paragraph', 'content': [{'type': 'text', 'text': p[:5000]}]} for p in paragraphs[:20]]}


def label_for(event: OutboundEvent) -> str:
    return f'argus-{event.subject_kind or "event"}-{event.subject_id}'[:255].replace(' ', '-')


def build_issue(event: OutboundEvent, config: dict[str, Any]) -> dict[str, Any]:
    description = '\n\n'.join(x for x in [event.summary, f'Topic: {event.topic}', f'Severity: {severity_label(event.severity)}',
                                           f'Argus {event.subject_kind} id: {event.subject_id}', f'Link: {event.url}' if event.url else ''] if x)
    fields: dict[str, Any] = {
        'project': {'key': str(config.get('project_key'))}, 'issuetype': {'name': str(config.get('issue_type') or 'Task')},
        'summary': f'[{severity_label(event.severity)}] {event.title}'[:250], 'description': adf(description),
        'labels': [str(config.get('label_prefix') or 'argus'), label_for(event)],
    }
    if config.get('set_priority', True) is not False:
        fields['priority'] = {'name': _PRIORITY.get(event.severity, 'Medium')}
    if config.get('components'):
        fields['components'] = [{'name': str(c)} for c in config['components']]
    return {'fields': fields}


def _auth_header(secrets: dict[str, str]) -> dict[str, str]:
    if secrets.get('api_token') and secrets.get('email'):
        token = base64.b64encode(f'{secrets["email"]}:{secrets["api_token"]}'.encode()).decode()
        return {'Authorization': f'Basic {token}'}
    if secrets.get('bearer_token'):
        return {'Authorization': f'Bearer {secrets["bearer_token"]}'}
    return {}


class JiraChannel(Channel):
    kind = 'jira'
    description = 'Jira Cloud issues (REST v3) for findings; deduped by label, updated on status change.'
    config_schema = {
        'type': 'object', 'additionalProperties': False, 'required': ['base_url', 'project_key'],
        'properties': {
            'base_url': {'type': 'string', 'pattern': '^https://', 'description': 'https://your-site.atlassian.net'},
            'project_key': {'type': 'string', 'maxLength': 20}, 'issue_type': {'type': 'string', 'default': 'Task'},
            'label_prefix': {'type': 'string', 'default': 'argus'}, 'components': {'type': 'array', 'items': {'type': 'string'}},
            'set_priority': {'type': 'boolean', 'default': True}, 'transition_on_resolve': {'type': 'boolean', 'default': True},
            'timeout_seconds': {'type': 'number', 'minimum': 1, 'maximum': 60, 'default': 20},
        },
    }
    secret_fields = ['email', 'api_token', 'bearer_token']
    topics = ['finding.*', 'detection.*']
    default_topics = ['finding.created', 'finding.updated', 'finding.resolved']

    async def send(self, event: OutboundEvent, config: dict[str, Any], secrets: dict[str, str]) -> DeliveryResult:
        base = str(config.get('base_url') or '').rstrip('/')
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json', **_auth_header(secrets)}
        if not base.startswith('https://') or 'Authorization' not in headers or not config.get('project_key'):
            return DeliveryResult(ok=False, error='jira needs https base_url, project_key and email+api_token (or bearer_token) secrets')
        denied = egress_error(base)
        if denied:
            return DeliveryResult(ok=False, error=f'jira base_url refused: {denied}')
        timeout = float(config.get('timeout_seconds') or 20)
        label = label_for(event)
        jql = f'labels = "{label}" ORDER BY created DESC'
        search, error = await request_with_retry(lambda c: c.get(f'{base}/rest/api/3/search/jql', params={'jql': jql, 'maxResults': 1, 'fields': 'status,key'}, headers=headers),
                                                 attempts=2, timeout=timeout)
        if search is None:
            return DeliveryResult(ok=False, error=f'jira search failed: {error}', retryable=True)
        existing_key = ''
        if search.status_code == 200:
            try:
                issues = search.json().get('issues') or []
            except ValueError:
                issues = []
            if issues:
                existing_key = str(issues[0].get('key') or '')
        elif search.status_code not in (400, 404):
            return result_from_response(search, error)
        if existing_key:
            return await self._update(existing_key, event, config, headers, base, timeout)
        if event.is_resolution:
            return DeliveryResult(ok=True, skipped=True, detail={'reason': 'no issue to resolve'})
        body = build_issue(event, config)
        response, error = await request_with_retry(lambda c: c.post(f'{base}/rest/api/3/issue', json=body, headers=headers), attempts=2, timeout=timeout)
        result = result_from_response(response, error, ok_codes=(200, 201))
        if result.ok and response is not None:
            try:
                result.external_ref = str(response.json().get('key') or '')
            except ValueError:
                pass
        return result

    async def _update(self, key: str, event: OutboundEvent, config: dict[str, Any], headers: dict[str, str], base: str, timeout: float) -> DeliveryResult:
        comment = f'Argus update ({event.topic}): {event.title}' + (f'\n\nStatus: {event.status}' if event.status else '') + (f'\n\n{event.summary}' if event.summary else '')
        response, error = await request_with_retry(lambda c: c.post(f'{base}/rest/api/3/issue/{key}/comment', json={'body': adf(comment)}, headers=headers),
                                                   attempts=2, timeout=timeout)
        result = result_from_response(response, error, ok_codes=(200, 201), external_ref=key)
        if not result.ok or not event.is_resolution or config.get('transition_on_resolve', True) is False:
            return result
        transitions, _ = await request_with_retry(lambda c: c.get(f'{base}/rest/api/3/issue/{key}/transitions', headers=headers), attempts=1, timeout=timeout)
        if transitions is None or transitions.status_code != 200:
            result.detail['transition'] = 'unavailable'
            return result
        try:
            options = transitions.json().get('transitions') or []
        except ValueError:
            options = []
        chosen = next((t for t in options if str(t.get('name', '')).lower().startswith(_DONE_NAMES) or
                       str(((t.get('to') or {}).get('statusCategory') or {}).get('key', '')).lower() == 'done'), None)
        if chosen:
            done, _ = await request_with_retry(lambda c: c.post(f'{base}/rest/api/3/issue/{key}/transitions', json={'transition': {'id': str(chosen.get('id'))}}, headers=headers),
                                               attempts=1, timeout=timeout)
            result.detail['transition'] = chosen.get('name') if done is not None and done.status_code in (200, 204) else f'failed: {excerpt(done) if done is not None else "no response"}'
        return result


registry.register(JiraChannel())
