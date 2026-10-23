"""Okta System Log events (GET /api/v1/logs) and Okta Event Hook deliveries
(`{eventType: 'com.okta.event_hook', data: {events: [...]}}`). Supports the one-time
verification challenge (GET with X-Okta-Verification-Challenge) and the static Authorization
header Okta sends with event hooks."""
from __future__ import annotations

import hmac
from typing import Any

from ...core.findings import EventDraft
from . import registry
from ._common import ParseContext, Parser, dig, event, geo, hash_item

# Okta eventType -> (dotted action, category, base severity). Unlisted types become okta.<eventType>.
_EVENT_TYPES: dict[str, tuple[str, str, str]] = {
    'user.session.start': ('okta.user.session.start', 'auth', 'informational'),
    'user.session.end': ('okta.user.session.end', 'auth', 'informational'),
    'user.authentication.sso': ('okta.user.authentication.sso', 'auth', 'informational'),
    'user.authentication.auth_via_mfa': ('okta.user.authentication.auth_via_mfa', 'auth', 'informational'),
    'user.authentication.verify': ('okta.user.authentication.verify', 'auth', 'informational'),
    'user.mfa.factor.deactivate': ('okta.user.mfa.factor.deactivate', 'identity', 'medium'),
    'user.mfa.factor.reset_all': ('okta.user.mfa.factor.reset_all', 'identity', 'high'),
    'user.account.privilege.grant': ('permission_added', 'identity', 'high'),
    'user.account.privilege.revoke': ('okta.user.account.privilege.revoke', 'identity', 'low'),
    'group.user_membership.add': ('okta.group.user_membership.add', 'identity', 'low'),
    'group.privilege.grant': ('permission_added', 'identity', 'high'),
    'user.session.impersonation.initiate': ('role_assumed', 'identity', 'high'),
    'user.session.impersonation.grant': ('role_assumed', 'identity', 'medium'),
    'system.api_token.create': ('okta.system.api_token.create', 'identity', 'medium'),
    'application.user_membership.add': ('okta.application.user_membership.add', 'identity', 'low'),
    'policy.lifecycle.update': ('okta.policy.lifecycle.update', 'identity', 'medium'),
    'policy.rule.update': ('okta.policy.rule.update', 'identity', 'medium'),
    'security.request.blocked': ('okta.security.request.blocked', 'auth', 'medium'),
    'user.account.lock': ('okta.user.account.lock', 'auth', 'medium'),
    'user.account.reset_password': ('okta.user.account.reset_password', 'identity', 'low'),
    'user.account.update_password': ('okta.user.account.update_password', 'identity', 'low'),
    'system.idp.lifecycle.create': ('okta.system.idp.lifecycle.create', 'identity', 'high'),
    'app.oauth2.client.credentials.create': ('okta.app.oauth2.client.credentials.create', 'identity', 'medium'),
}
_ADMIN_GROUP_HINTS = ('admin', 'administrator', 'super')


class OktaParser(Parser):
    name = 'okta_logs'
    aliases = ('okta', 'okta_system_log', 'okta_event_hook')
    source = 'okta'
    description = 'Okta System Log events and Event Hook deliveries.'
    kind = 'events'
    example = 'tests/fixtures/integrations/okta_logs/system_log.json'
    supports_verify = True
    secret_fields = ['auth_header']
    config_schema = {'type': 'object', 'additionalProperties': False,
                     'properties': {'auth_header_name': {'type': 'string', 'default': 'Authorization', 'description': 'Header Okta sends the shared secret in'}}}

    def items(self, payload: Any) -> list[Any]:
        if isinstance(payload, dict):
            events = dig(payload, 'data', 'events')
            if isinstance(events, list):
                return events
            if isinstance(payload.get('events'), list):
                return payload['events']
            return [payload]
        return payload

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        event_type = str(item.get('eventType') or 'unknown')
        action, category, base_severity = _EVENT_TYPES.get(event_type, (f'okta.{event_type}'[:120], 'saas', 'informational'))
        actor_obj = item.get('actor') if isinstance(item.get('actor'), dict) else {}
        client = item.get('client') if isinstance(item.get('client'), dict) else {}
        geo_ctx = client.get('geographicalContext') if isinstance(client.get('geographicalContext'), dict) else {}
        geo_pt = geo_ctx.get('geolocation') if isinstance(geo_ctx.get('geolocation'), dict) else {}
        outcome = item.get('outcome') if isinstance(item.get('outcome'), dict) else {}
        targets = [t for t in (item.get('target') or []) if isinstance(t, dict)]
        debug = dig(item, 'debugContext', 'debugData') if isinstance(dig(item, 'debugContext', 'debugData'), dict) else {}
        auth_ctx = item.get('authenticationContext') if isinstance(item.get('authenticationContext'), dict) else {}
        security = item.get('securityContext') if isinstance(item.get('securityContext'), dict) else {}
        actor = str(actor_obj.get('alternateId') or actor_obj.get('displayName') or actor_obj.get('id') or '')
        primary_target = targets[0] if targets else {}
        entity = str(primary_target.get('alternateId') or primary_target.get('displayName') or primary_target.get('id') or '')
        severity = base_severity
        result = str(outcome.get('result') or '').upper()
        if event_type == 'group.user_membership.add':
            group = next((t for t in targets if str(t.get('type', '')).lower() == 'usergroup'), {})
            if any(h in str(group.get('displayName', '')).lower() for h in _ADMIN_GROUP_HINTS):
                action, severity = 'permission_added', 'high'
                entity = str(next((t.get('alternateId') for t in targets if str(t.get('type', '')).lower() == 'user'), entity))
        if result == 'FAILURE' and category == 'auth':
            severity = 'medium' if event_type == 'user.session.start' else 'low'
        if result == 'DENY' or event_type == 'security.request.blocked':
            severity = 'medium'
        okta_sev = str(item.get('severity') or '').upper()
        if okta_sev == 'ERROR' and severity in {'informational', 'low'}:
            severity = 'medium'
        meta: dict[str, Any] = {
            'event_type': event_type, 'display_message': item.get('displayMessage') or '', 'outcome': result, 'outcome_reason': outcome.get('reason') or '',
            'ip': client.get('ipAddress') or '', 'user_agent': dig(client, 'userAgent', 'rawUserAgent') or '', 'browser': dig(client, 'userAgent', 'browser') or '',
            'os': dig(client, 'userAgent', 'os') or '', 'device': client.get('device') or '', 'zone': client.get('zone') or '',
            'geo': geo(geo_pt.get('lat'), geo_pt.get('lon'), geo_ctx.get('country'), geo_ctx.get('city')), 'actor_type': actor_obj.get('type') or '',
            'actor_id': actor_obj.get('id') or '', 'targets': [{'type': t.get('type'), 'id': t.get('id'), 'name': t.get('alternateId') or t.get('displayName')} for t in targets][:6],
            'session_id': auth_ctx.get('externalSessionId') or '', 'auth_provider': auth_ctx.get('authenticationProvider') or '',
            'credential_type': auth_ctx.get('credentialType') or '', 'as_number': security.get('asNumber'), 'as_org': security.get('asOrg') or '',
            'isp': security.get('isp') or '', 'is_proxy': security.get('isProxy'), 'request_id': dig(debug, 'requestId') or '', 'threat_suspected': dig(debug, 'threatSuspected') or '',
            'risk_level': dig(debug, 'risk', 'level') or dig(debug, 'riskLevel') or '', 'behaviors': dig(debug, 'behaviors') or '', 'service': 'okta',
            'legacy_event_type': item.get('legacyEventType') or '', 'okta_severity': okta_sev,
        }
        title = str(item.get('displayMessage') or event_type)
        external_id = item.get('uuid') or hash_item(item)
        return [event(self.source, external_id, title, severity=severity, category=category, actor=actor, entity=entity, action=action,
                      occurred_at=item.get('published'), metadata=meta)]

    def verify(self, ctx: ParseContext, body: bytes, secret: str) -> bool:
        """Okta event hooks carry a static secret in a configured header (default Authorization)."""
        header_name = str(ctx.extra.get('auth_header_name') or 'Authorization')
        given = ctx.header(header_name)
        if not given or not secret:
            return False
        return hmac.compare_digest(given.strip().encode(), secret.strip().encode())

    @staticmethod
    def challenge(ctx: ParseContext) -> dict[str, str] | None:
        value = ctx.header('X-Okta-Verification-Challenge')
        return {'verification': value} if value else None


registry.register(OktaParser())
