"""Okta collector (httpx against the Okta management API, read-only). Inventories users with
their MFA enrolment, groups, apps and admin role assignments, and turns System Log entries
since the last run into security events.

API calls made (GET, paginated via Link rel="next"):
  GET /api/v1/users?limit=200
  GET /api/v1/users/{id}/factors
  GET /api/v1/groups?limit=200
  GET /api/v1/apps?limit=200
  GET /api/v1/iam/assignees/users          (users holding any admin role)
  GET /api/v1/users/{id}/roles             (per admin assignee)
  GET /api/v1/logs?since=<iso>&filter=<eventType filter>&limit=1000
Token: an API token (SSWS) for a Read-only Administrator, or an OAuth app with okta.users.read,
okta.groups.read, okta.apps.read, okta.roles.read and okta.logs.read.
"""
from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from .base import Collector, CollectorContext, CollectorResult, parse_time, registry

log = logging.getLogger('sentinel.collectors.okta')

LOG_EVENT_TYPES: dict[str, tuple[str, str, str]] = {  # eventType -> (action, severity, category)
    'user.session.start': ('sign_in', 'low', 'auth'),
    'user.authentication.auth_via_mfa': ('mfa_auth', 'low', 'auth'),
    'user.account.lock': ('account_locked', 'medium', 'auth'),
    'user.mfa.factor.deactivate': ('mfa_factor_reset', 'high', 'auth'),
    'user.mfa.factor.reset_all': ('mfa_factor_reset', 'high', 'auth'),
    'user.mfa.factor.update': ('mfa_factor_changed', 'medium', 'auth'),
    'user.account.privilege.grant': ('admin_privilege_granted', 'high', 'auth'),
    'user.account.privilege.revoke': ('admin_privilege_revoked', 'medium', 'auth'),
    'user.account.reset_password': ('password_reset', 'medium', 'auth'),
    'user.account.update_password': ('password_changed', 'low', 'auth'),
    'system.api_token.create': ('api_token_created', 'high', 'auth'),
    'application.user_membership.add': ('app_assigned', 'low', 'auth'),
    'policy.lifecycle.update': ('policy_changed', 'medium', 'auth'),
    'policy.rule.update': ('policy_changed', 'medium', 'auth'),
    'security.threat.detected': ('threat_detected', 'high', 'auth'),
    'user.session.impersonation.initiate': ('impersonation', 'high', 'auth'),
}
ADMIN_ROLE_TYPES = {'SUPER_ADMIN', 'ORG_ADMIN', 'APP_ADMIN', 'USER_ADMIN', 'GROUP_ADMIN', 'API_ACCESS_MANAGEMENT_ADMIN', 'MOBILE_ADMIN', 'READ_ONLY_ADMIN',
                    'HELP_DESK_ADMIN', 'REPORT_ADMIN', 'GROUP_MEMBERSHIP_ADMIN', 'CUSTOM'}


class OktaCollector(Collector):
    name = 'okta'
    kind = 'identity'
    description = 'Okta tenant inventory: users and MFA factors, groups, applications, admin roles, and System Log events (sign-in failures, MFA resets, privilege grants).'
    sdk_modules = ('httpx',)
    secret_fields = ['api_token']
    default_schedule_minutes = 30
    config_schema = {
        'type': 'object', 'additionalProperties': False, 'required': ['domain'],
        'properties': {
            'domain': {'type': 'string', 'pattern': r'^[a-z0-9.-]+\.(okta|oktapreview|okta-emea)\.com$', 'description': 'e.g. acme.okta.com'},
            'log_lookback_hours': {'type': 'integer', 'minimum': 1, 'maximum': 720, 'description': 'How far back to read logs on the first run; default 24'},
            'include_deprovisioned': {'type': 'boolean'},
        },
    }

    async def collect(self, ctx: CollectorContext) -> CollectorResult:
        raw = await _fetch(ctx)
        return self._normalize(raw)

    def _normalize(self, raw: dict[str, Any]) -> CollectorResult:
        r = CollectorResult()
        source = self.source
        domain = raw.get('domain') or 'okta'
        counts = {'users': 0, 'users_without_mfa': 0, 'groups': 0, 'apps': 0, 'admins': 0, 'log_events': 0}
        for warning in raw.get('warnings', []) or []:
            r.warn(str(warning))
        tenant = r.node('asset', f'okta:org:{domain}', {'provider': 'okta', 'type': 'identity_provider', 'domain': domain}, label=f'Okta {domain}', criticality='critical')
        admin_roles: dict[str, list[dict[str, Any]]] = raw.get('admin_roles') or {}
        for user in raw.get('users', []) or []:
            uid = user.get('id', '')
            profile = user.get('profile') or {}
            login = profile.get('login') or profile.get('email') or uid
            status = user.get('status', '')
            factors = [f for f in user.get('factors') or [] if f.get('status') == 'ACTIVE']
            factor_types = sorted({f"{f.get('provider', '')}:{f.get('factorType', '')}" for f in factors})
            strong = any(f.get('factorType') in ('webauthn', 'u2f', 'signed_nonce', 'token:hardware') or (f.get('factorType') == 'push') for f in factors)
            roles = admin_roles.get(uid) or []
            role_types = sorted({r_.get('type', '') for r_ in roles})
            is_admin = bool(role_types)
            counts['users'] += 1
            node = r.node('identity', f'okta:user:{uid}', {'provider': 'okta', 'type': 'user', 'login': login, 'status': status, 'mfa_enrolled': bool(factors),
                                                           'mfa_factors': factor_types, 'phishing_resistant_mfa': strong, 'admin_roles': role_types,
                                                           'last_login': user.get('lastLogin'), 'created': user.get('created'), 'department': profile.get('department')},
                          label=login, criticality='critical' if 'SUPER_ADMIN' in role_types else 'high' if is_admin else 'medium')
            r.edge(tenant, node, 'owns')
            for role in roles:
                rtype = role.get('type', '')
                perm = r.node('permission', f'okta:role:{domain}:{rtype}:{role.get("label") or rtype}', {'provider': 'okta', 'role': rtype, 'label': role.get('label'),
                                                                                                        'admin': rtype == 'SUPER_ADMIN', 'wildcard': rtype in ('SUPER_ADMIN', 'ORG_ADMIN')},
                              label=role.get('label') or rtype, criticality='critical' if rtype == 'SUPER_ADMIN' else 'high')
                r.edge(node, perm, 'has_permission', {'assignment_type': role.get('assignmentType')})
            if is_admin:
                counts['admins'] += 1
            if status == 'ACTIVE' and not factors:
                counts['users_without_mfa'] += 1
                r.event(source, f'okta:{domain}:no-mfa:{uid}', f'Okta user {login} has no active MFA factor', 'high' if is_admin else 'medium', 'auth',
                        actor=login, entity=node.key, action='mfa_missing', metadata={'domain': domain, 'admin': is_admin, 'status': status})
            if 'SUPER_ADMIN' in role_types and not strong:
                r.event(source, f'okta:{domain}:super-admin-weak-mfa:{uid}', f'Okta super admin {login} lacks phishing-resistant MFA', 'high', 'auth',
                        actor=login, entity=node.key, action='admin_weak_mfa', metadata={'domain': domain, 'factors': factor_types})
        for group in raw.get('groups', []) or []:
            gid = group.get('id', '')
            profile = group.get('profile') or {}
            counts['groups'] += 1
            node = r.node('role', f'okta:group:{gid}', {'provider': 'okta', 'type': group.get('type'), 'name': profile.get('name'), 'description': (profile.get('description') or '')[:200]},
                          label=profile.get('name') or gid, criticality='low')
            r.edge(tenant, node, 'owns')
        for app in raw.get('apps', []) or []:
            aid = app.get('id', '')
            counts['apps'] += 1
            sign_on = app.get('signOnMode', '')
            node = r.node('asset', f'okta:app:{aid}', {'provider': 'okta', 'type': 'saas_app', 'name': app.get('name'), 'label': app.get('label'), 'status': app.get('status'),
                                                       'sign_on_mode': sign_on, 'created': app.get('created')}, label=app.get('label') or app.get('name') or aid,
                          criticality='medium')
            r.edge(tenant, node, 'owns')
        for entry in raw.get('logs', []) or []:
            event_type = entry.get('eventType', '')
            outcome = (entry.get('outcome') or {}).get('result', '')
            spec = LOG_EVENT_TYPES.get(event_type)
            if spec is None:
                continue
            action, sev, category = spec
            if event_type == 'user.session.start':
                if outcome != 'FAILURE':
                    continue
                action, sev = 'sign_in_failure', 'medium'
            elif event_type == 'user.authentication.auth_via_mfa':
                if outcome != 'FAILURE':
                    continue
                action, sev = 'mfa_failure', 'medium'
            actor = entry.get('actor') or {}
            client = entry.get('client') or {}
            targets = entry.get('target') or []
            target_user = next((t for t in targets if t.get('type') == 'User'), targets[0] if targets else {})
            geo = (client.get('geographicalContext') or {})
            counts['log_events'] += 1
            r.event(source, f"okta:log:{entry.get('uuid')}", f"{entry.get('displayMessage') or event_type}: {actor.get('alternateId') or actor.get('displayName') or ''}".strip(': '),
                    sev, category, actor=actor.get('alternateId') or actor.get('displayName') or actor.get('id', ''),
                    entity=target_user.get('alternateId') or target_user.get('displayName') or target_user.get('id', ''), action=action,
                    occurred_at=parse_time(entry.get('published')),
                    metadata={'event_type': event_type, 'outcome': outcome, 'reason': (entry.get('outcome') or {}).get('reason'), 'ip': client.get('ipAddress'),
                              'user_agent': (client.get('userAgent') or {}).get('rawUserAgent'), 'country': geo.get('country'), 'city': geo.get('city'),
                              'targets': [{'type': t.get('type'), 'id': t.get('alternateId') or t.get('displayName')} for t in targets[:5]],
                              'severity_okta': entry.get('severity'), 'domain': domain})
        r.stats.update(counts)
        r.stats['domain'] = domain
        return r.finalize()


# ---------------------------------------------------------------- fetch


def _next_link(response: httpx.Response) -> str | None:
    for part in response.headers.get_list('link') if hasattr(response.headers, 'get_list') else [response.headers.get('link', '')]:
        match = re.search(r'<([^>]+)>;\s*rel="next"', part or '')
        if match:
            return match.group(1)
    return None


async def _get_all(client: httpx.AsyncClient, url: str, params: dict[str, Any] | None, warnings: list[str], label: str, max_pages: int = 100) -> list[Any]:
    items: list[Any] = []
    next_url: str | None = url
    next_params = dict(params or {})
    pages = 0
    while next_url and pages < max_pages:
        response = await client.get(next_url, params=next_params or None)
        next_params = {}
        if response.status_code in (401, 403, 404):
            warnings.append(f'{label}: HTTP {response.status_code}')
            return items
        response.raise_for_status()
        data = response.json()
        batch = data if isinstance(data, list) else [data]
        if not batch:
            break
        items.extend(batch)
        next_url = _next_link(response)
        pages += 1
    return items


async def _fetch(ctx: CollectorContext) -> dict[str, Any]:
    config = ctx.config
    domain = config['domain']
    base = f'https://{domain}'
    headers = {'Accept': 'application/json', 'User-Agent': 'sentinel-collector'}
    if config.get('api_token'):
        headers['Authorization'] = f"SSWS {config['api_token']}"
    warnings: list[str] = []
    raw: dict[str, Any] = {'domain': domain, 'users': [], 'groups': [], 'apps': [], 'admin_roles': {}, 'logs': [], 'warnings': warnings}
    since = ctx.since_or(int(config.get('log_lookback_hours') or 24)).strftime('%Y-%m-%dT%H:%M:%SZ')
    async with httpx.AsyncClient(headers=headers, timeout=httpx.Timeout(30.0)) as client:
        user_params = {'limit': 200}
        if not config.get('include_deprovisioned'):
            user_params['filter'] = 'status ne "DEPROVISIONED"'
        users = await _get_all(client, f'{base}/api/v1/users', user_params, warnings, 'users')
        for user in users:
            user['factors'] = await _get_all(client, f"{base}/api/v1/users/{user['id']}/factors", None, warnings, f"factors[{user['id']}]")
            await ctx.heartbeat()
        raw['users'] = users
        raw['groups'] = await _get_all(client, f'{base}/api/v1/groups', {'limit': 200}, warnings, 'groups')
        raw['apps'] = await _get_all(client, f'{base}/api/v1/apps', {'limit': 200}, warnings, 'apps')
        assignees = await _get_all(client, f'{base}/api/v1/iam/assignees/users', None, warnings, 'admin assignees')
        for assignee in assignees:
            uid = assignee.get('id')
            if uid:
                raw['admin_roles'][uid] = await _get_all(client, f'{base}/api/v1/users/{uid}/roles', None, warnings, f'roles[{uid}]')
        event_filter = ' or '.join(f'eventType eq "{t}"' for t in LOG_EVENT_TYPES)
        raw['logs'] = await _get_all(client, f'{base}/api/v1/logs', {'since': since, 'filter': event_filter, 'limit': 1000, 'sortOrder': 'ASCENDING'}, warnings, 'logs')
    return raw


registry.register(OktaCollector())
