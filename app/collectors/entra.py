"""Microsoft Entra ID collector (httpx against Microsoft Graph, client credentials, read-only).
Inventories users, groups, directory roles (Global Administrator members), service principals
with credentials and conditional access policies; turns risky sign-ins and directory audit
events since the last run into security events.

API calls made:
  POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token  (client_credentials, scope .default)
  GET /v1.0/users?$select=id,userPrincipalName,displayName,accountEnabled,userType,createdDateTime&$top=999
  GET /v1.0/groups?$select=id,displayName,securityEnabled,groupTypes,isAssignableToRole&$top=999
  GET /v1.0/directoryRoles
  GET /v1.0/directoryRoles/{id}/members?$select=id,userPrincipalName,displayName
  GET /v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,passwordCredentials,keyCredentials&$top=999
  GET /v1.0/identity/conditionalAccess/policies?$select=id,displayName,state
  GET /v1.0/auditLogs/signIns?$filter=createdDateTime ge <since> and riskLevelDuringSignIn ne 'none'&$top=500
  GET /v1.0/auditLogs/directoryAudits?$filter=activityDateTime ge <since>&$top=500
  (all paginated via @odata.nextLink)
App permissions (application type): User.Read.All, Group.Read.All, RoleManagement.Read.Directory,
Application.Read.All, Policy.Read.All, AuditLog.Read.All.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from .base import Collector, CollectorContext, CollectorResult, age_days, parse_time, registry

log = logging.getLogger('sentinel.collectors.entra')

PRIVILEGED_ROLES = {'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator', 'Security Administrator',
                    'Exchange Administrator', 'SharePoint Administrator', 'User Administrator', 'Application Administrator', 'Cloud Application Administrator',
                    'Authentication Administrator', 'Conditional Access Administrator', 'Hybrid Identity Administrator', 'Intune Administrator'}
AUDIT_ACTIVITIES: dict[str, tuple[str, str]] = {  # activityDisplayName -> (action, severity)
    'Add member to role': ('admin_privilege_granted', 'high'),
    'Add eligible member to role': ('admin_privilege_granted', 'medium'),
    'Remove member from role': ('admin_privilege_revoked', 'medium'),
    'Add service principal credentials': ('sp_credential_added', 'high'),
    'Update application – Certificates and secrets management ': ('app_credential_changed', 'high'),
    'Add application': ('app_registered', 'low'),
    'Consent to application': ('app_consent', 'medium'),
    'Add app role assignment to service principal': ('app_role_assigned', 'medium'),
    'Update conditional access policy': ('policy_changed', 'high'),
    'Delete conditional access policy': ('policy_deleted', 'critical'),
    'Add conditional access policy': ('policy_added', 'medium'),
    'Disable account': ('account_disabled', 'low'),
    'Reset password (by admin)': ('password_reset', 'medium'),
    'Change user password': ('password_changed', 'low'),
    'Disable Strong Authentication': ('mfa_disabled', 'high'),
    'Admin registered security info': ('mfa_factor_changed', 'medium'),
    'User registered security info': ('mfa_factor_changed', 'low'),
    'User deleted security info': ('mfa_factor_reset', 'medium'),
    'Add owner to application': ('app_owner_added', 'medium'),
    'Add owner to service principal': ('sp_owner_added', 'medium'),
}
RISK_SEVERITY = {'high': 'high', 'medium': 'medium', 'low': 'low', 'hidden': 'medium'}


class EntraCollector(Collector):
    name = 'entra'
    kind = 'identity'
    description = 'Microsoft Entra ID inventory: users, groups, directory roles and Global Administrators, service principals with credentials, conditional access policies, risky sign-ins and directory audit events.'
    sdk_modules = ('httpx',)
    secret_fields = ['client_secret']
    default_schedule_minutes = 30
    config_schema = {
        'type': 'object', 'additionalProperties': False, 'required': ['tenant_id', 'client_id'],
        'properties': {
            'tenant_id': {'type': 'string', 'maxLength': 64},
            'client_id': {'type': 'string', 'maxLength': 64},
            'graph_url': {'type': 'string', 'pattern': r'^https://', 'description': 'Default https://graph.microsoft.com'},
            'login_url': {'type': 'string', 'pattern': r'^https://', 'description': 'Default https://login.microsoftonline.com'},
            'log_lookback_hours': {'type': 'integer', 'minimum': 1, 'maximum': 720},
            'include_guests': {'type': 'boolean'},
        },
    }

    async def collect(self, ctx: CollectorContext) -> CollectorResult:
        raw = await _fetch(ctx)
        return self._normalize(raw)

    def _normalize(self, raw: dict[str, Any]) -> CollectorResult:
        r = CollectorResult()
        source = self.source
        tenant_id = raw.get('tenant_id') or 'entra'
        counts = {'users': 0, 'guests': 0, 'groups': 0, 'directory_roles': 0, 'global_admins': 0, 'service_principals': 0, 'sp_with_credentials': 0,
                  'conditional_access_policies': 0, 'risky_sign_ins': 0, 'audit_events': 0}
        for warning in raw.get('warnings', []) or []:
            r.warn(str(warning))
        tenant = r.node('asset', f'entra:tenant:{tenant_id}', {'provider': 'entra', 'type': 'identity_provider', 'tenant_id': tenant_id}, label=f'Entra tenant {tenant_id}',
                        criticality='critical')
        user_nodes: dict[str, Any] = {}
        for user in raw.get('users', []) or []:
            uid = user.get('id', '')
            upn = user.get('userPrincipalName') or uid
            guest = user.get('userType') == 'Guest'
            counts['users'] += 1
            counts['guests'] += int(guest)
            node = r.node('identity', f'entra:user:{uid}', {'provider': 'entra', 'type': 'user', 'upn': upn, 'display_name': user.get('displayName'),
                                                            'enabled': user.get('accountEnabled'), 'guest': guest, 'created': user.get('createdDateTime'),
                                                            'last_sign_in': (user.get('signInActivity') or {}).get('lastSignInDateTime')}, label=upn, criticality='medium')
            user_nodes[uid] = node
            r.edge(tenant, node, 'owns')
        for group in raw.get('groups', []) or []:
            gid = group.get('id', '')
            counts['groups'] += 1
            node = r.node('role', f'entra:group:{gid}', {'provider': 'entra', 'type': 'group', 'name': group.get('displayName'), 'security_enabled': group.get('securityEnabled'),
                                                         'group_types': group.get('groupTypes') or [], 'role_assignable': group.get('isAssignableToRole')},
                          label=group.get('displayName') or gid, criticality='high' if group.get('isAssignableToRole') else 'low')
            r.edge(tenant, node, 'owns')
        for role in raw.get('directory_roles', []) or []:
            name = role.get('displayName', '')
            counts['directory_roles'] += 1
            privileged = name in PRIVILEGED_ROLES
            perm = r.node('permission', f"entra:role:{tenant_id}:{role.get('roleTemplateId') or name}", {'provider': 'entra', 'role': name, 'admin': name == 'Global Administrator',
                                                                                                        'privileged': privileged, 'wildcard': name == 'Global Administrator',
                                                                                                        'template_id': role.get('roleTemplateId')},
                          label=name, criticality='critical' if name == 'Global Administrator' else 'high' if privileged else 'medium')
            for member in role.get('members') or []:
                mid = member.get('id', '')
                mtype = (member.get('@odata.type') or '').rsplit('.', 1)[-1]
                if mtype == 'group':
                    subj = r.node('role', f'entra:group:{mid}', {'provider': 'entra', 'type': 'group', 'name': member.get('displayName')}, label=member.get('displayName') or mid)
                elif mtype == 'servicePrincipal':
                    subj = r.node('identity', f'entra:sp:{mid}', {'provider': 'entra', 'type': 'service_principal', 'display_name': member.get('displayName')},
                                  label=member.get('displayName') or mid)
                else:
                    subj = user_nodes.get(mid) or r.node('identity', f'entra:user:{mid}', {'provider': 'entra', 'type': 'user', 'upn': member.get('userPrincipalName'),
                                                                                             'display_name': member.get('displayName')}, label=member.get('userPrincipalName') or mid)
                r.edge(subj, perm, 'has_permission', {'role': name})
                if privileged:
                    subj.criticality = 'critical' if name == 'Global Administrator' else 'high'
                    subj.props.setdefault('admin_roles', [])
                    if name not in subj.props['admin_roles']:
                        subj.props['admin_roles'].append(name)
                if name == 'Global Administrator':
                    counts['global_admins'] += 1
                    if mtype == 'servicePrincipal' or subj.props.get('guest'):
                        r.event(source, f'entra:{tenant_id}:ga-risky:{mid}', f"{member.get('displayName') or mid} ({mtype or 'user'}) is a Global Administrator", 'high', 'auth',
                                actor=member.get('userPrincipalName') or member.get('displayName') or mid, entity=perm.key, action='global_admin_risky_member',
                                metadata={'tenant_id': tenant_id, 'member_type': mtype, 'guest': bool(subj.props.get('guest'))})
        if counts['global_admins'] > 5:
            r.event(source, f"entra:{tenant_id}:too-many-global-admins:{counts['global_admins']}", f"Tenant has {counts['global_admins']} Global Administrators (recommended: 2-4)",
                    'medium', 'auth', entity=tenant.key, action='too_many_global_admins', metadata={'tenant_id': tenant_id, 'count': counts['global_admins']})
        for sp in raw.get('service_principals', []) or []:
            sid = sp.get('id', '')
            passwords = sp.get('passwordCredentials') or []
            keys = sp.get('keyCredentials') or []
            counts['service_principals'] += 1
            expiring = []
            for cred in passwords + keys:
                end = cred.get('endDateTime')
                remaining = age_days(end)
                if remaining is not None and remaining > 0:
                    expiring.append(cred.get('keyId'))
            node = r.node('identity', f'entra:sp:{sid}', {'provider': 'entra', 'type': 'service_principal', 'app_id': sp.get('appId'), 'display_name': sp.get('displayName'),
                                                          'sp_type': sp.get('servicePrincipalType'), 'enabled': sp.get('accountEnabled'), 'password_credentials': len(passwords),
                                                          'key_credentials': len(keys), 'expired_credentials': len(expiring)}, label=sp.get('displayName') or sid,
                          criticality='high' if passwords else 'medium')
            r.edge(tenant, node, 'owns')
            if passwords or keys:
                counts['sp_with_credentials'] += 1
            long_lived = [c for c in passwords if (age_days(c.get('startDateTime')) or 0) - (age_days(c.get('endDateTime')) or 0) > 730]
            if long_lived and sp.get('servicePrincipalType') == 'Application':
                r.event(source, f'entra:{tenant_id}:sp-long-secret:{sid}', f"Service principal {sp.get('displayName')} has a client secret valid for more than 2 years", 'medium', 'auth',
                        entity=node.key, action='sp_long_lived_secret', metadata={'tenant_id': tenant_id, 'app_id': sp.get('appId'), 'count': len(long_lived)})
        policies = raw.get('conditional_access_policies')
        if policies is not None:
            enabled = [p for p in policies if p.get('state') == 'enabled']
            counts['conditional_access_policies'] = len(policies)
            tenant.props['conditional_access_policies'] = len(policies)
            tenant.props['conditional_access_enabled'] = len(enabled)
            if not enabled:
                r.event(source, f'entra:{tenant_id}:no-conditional-access', 'Tenant has no enabled Conditional Access policy', 'high', 'auth', entity=tenant.key,
                        action='conditional_access_missing', metadata={'tenant_id': tenant_id, 'total_policies': len(policies)})
        for signin in raw.get('risky_sign_ins', []) or []:
            level = str(signin.get('riskLevelDuringSignIn') or signin.get('riskLevelAggregated') or 'low').lower()
            if level == 'none':
                continue
            counts['risky_sign_ins'] += 1
            status = signin.get('status') or {}
            loc = signin.get('location') or {}
            upn = signin.get('userPrincipalName', '')
            r.event(source, f"entra:signin:{signin.get('id')}", f"Risky sign-in ({level}) for {upn} to {signin.get('appDisplayName') or 'unknown app'}", RISK_SEVERITY.get(level, 'medium'),
                    'auth', actor=upn, entity=signin.get('appDisplayName') or signin.get('resourceDisplayName', ''), action='risky_sign_in',
                    occurred_at=parse_time(signin.get('createdDateTime')),
                    metadata={'tenant_id': tenant_id, 'risk_level': level, 'risk_state': signin.get('riskState'), 'risk_detail': signin.get('riskDetail'),
                              'risk_event_types': signin.get('riskEventTypes_v2') or signin.get('riskEventTypes') or [], 'ip': signin.get('ipAddress'),
                              'user_agent': signin.get('userAgent') or (signin.get('deviceDetail') or {}).get('browser'), 'country': loc.get('countryOrRegion'), 'city': loc.get('city'),
                              'status_code': status.get('errorCode'), 'failure_reason': status.get('failureReason'), 'client_app': signin.get('clientAppUsed'),
                              'conditional_access': signin.get('conditionalAccessStatus')})
        for audit in raw.get('audit_logs', []) or []:
            activity = audit.get('activityDisplayName', '')
            spec = AUDIT_ACTIVITIES.get(activity) or AUDIT_ACTIVITIES.get(activity.strip())
            if spec is None:
                continue
            action, sev = spec
            if audit.get('result') not in (None, 'success'):
                continue
            initiated = audit.get('initiatedBy') or {}
            actor = (initiated.get('user') or {}).get('userPrincipalName') or (initiated.get('app') or {}).get('displayName') or ''
            targets = audit.get('targetResources') or []
            target = targets[0] if targets else {}
            modified = [m for m in target.get('modifiedProperties') or [] if m.get('displayName') in ('Role.DisplayName', 'Role.TemplateId', 'ConditionalAccessPolicy')]
            role_name = next((str(m.get('newValue') or '').strip('"') for m in modified if m.get('displayName') == 'Role.DisplayName'), '')
            if action == 'admin_privilege_granted' and role_name and role_name not in PRIVILEGED_ROLES:
                sev = 'medium'
            counts['audit_events'] += 1
            r.event(source, f"entra:audit:{audit.get('id')}", f"{activity}: {target.get('userPrincipalName') or target.get('displayName') or ''}{(' -> ' + role_name) if role_name else ''}".strip(': '),
                    sev, 'auth', actor=actor, entity=target.get('userPrincipalName') or target.get('displayName') or target.get('id', ''), action=action,
                    occurred_at=parse_time(audit.get('activityDateTime')),
                    metadata={'tenant_id': tenant_id, 'activity': activity, 'category': audit.get('category'), 'result': audit.get('result'), 'role': role_name,
                              'ip': (initiated.get('user') or {}).get('ipAddress'), 'target_type': target.get('type'), 'correlation_id': audit.get('correlationId')})
        r.stats.update(counts)
        r.stats['tenant_id'] = tenant_id
        return r.finalize()


# ---------------------------------------------------------------- fetch


async def _token(client: httpx.AsyncClient, login_url: str, tenant_id: str, client_id: str, client_secret: str, graph_url: str) -> str:
    response = await client.post(f'{login_url}/{tenant_id}/oauth2/v2.0/token',
                                 data={'grant_type': 'client_credentials', 'client_id': client_id, 'client_secret': client_secret, 'scope': f'{graph_url}/.default'})
    response.raise_for_status()
    return response.json()['access_token']


async def _get_all(client: httpx.AsyncClient, url: str, params: dict[str, Any] | None, warnings: list[str], label: str, max_pages: int = 100,
                   extra_headers: dict[str, str] | None = None) -> list[Any] | None:
    """Follow @odata.nextLink. Returns None when Graph denies the call (missing permission or licence)."""
    items: list[Any] = []
    next_url: str | None = url
    next_params = dict(params or {})
    pages = 0
    while next_url and pages < max_pages:
        response = await client.get(next_url, params=next_params or None, headers=extra_headers)
        next_params = {}
        if response.status_code in (401, 403, 404):
            warnings.append(f'{label}: HTTP {response.status_code}')
            return None if pages == 0 else items
        if response.status_code == 400 and pages == 0:
            warnings.append(f'{label}: HTTP 400 (unsupported filter or licence)')
            return None
        response.raise_for_status()
        data = response.json()
        items.extend(data.get('value', []) if isinstance(data, dict) else [])
        next_url = data.get('@odata.nextLink') if isinstance(data, dict) else None
        pages += 1
    return items


async def _fetch(ctx: CollectorContext) -> dict[str, Any]:
    config = ctx.config
    tenant_id, client_id = config['tenant_id'], config['client_id']
    graph = (config.get('graph_url') or 'https://graph.microsoft.com').rstrip('/')
    login = (config.get('login_url') or 'https://login.microsoftonline.com').rstrip('/')
    warnings: list[str] = []
    raw: dict[str, Any] = {'tenant_id': tenant_id, 'users': [], 'groups': [], 'directory_roles': [], 'service_principals': [], 'conditional_access_policies': None,
                           'risky_sign_ins': [], 'audit_logs': [], 'warnings': warnings}
    since = ctx.since_or(int(config.get('log_lookback_hours') or 24)).strftime('%Y-%m-%dT%H:%M:%SZ')
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0), headers={'User-Agent': 'sentinel-collector'}) as client:
        token = await _token(client, login, tenant_id, client_id, config.get('client_secret', ''), graph)
        client.headers['Authorization'] = f'Bearer {token}'
        client.headers['ConsistencyLevel'] = 'eventual'
        v1 = f'{graph}/v1.0'
        user_params: dict[str, Any] = {'$select': 'id,userPrincipalName,displayName,accountEnabled,userType,createdDateTime', '$top': 999}
        if not config.get('include_guests', True):
            user_params['$filter'] = "userType eq 'Member'"
        raw['users'] = await _get_all(client, f'{v1}/users', user_params, warnings, 'users') or []
        await ctx.heartbeat()
        raw['groups'] = await _get_all(client, f'{v1}/groups', {'$select': 'id,displayName,securityEnabled,groupTypes,isAssignableToRole', '$top': 999}, warnings, 'groups') or []
        roles = await _get_all(client, f'{v1}/directoryRoles', None, warnings, 'directoryRoles') or []
        for role in roles:
            role['members'] = await _get_all(client, f"{v1}/directoryRoles/{role['id']}/members", {'$select': 'id,userPrincipalName,displayName,userType'}, warnings,
                                             f"role members[{role.get('displayName')}]") or []
        raw['directory_roles'] = roles
        await ctx.heartbeat()
        raw['service_principals'] = await _get_all(client, f'{v1}/servicePrincipals',
                                                   {'$select': 'id,appId,displayName,servicePrincipalType,accountEnabled,passwordCredentials,keyCredentials', '$top': 999},
                                                   warnings, 'servicePrincipals') or []
        raw['conditional_access_policies'] = await _get_all(client, f'{v1}/identity/conditionalAccess/policies', {'$select': 'id,displayName,state'}, warnings,
                                                            'conditionalAccess policies')
        raw['risky_sign_ins'] = await _get_all(client, f'{v1}/auditLogs/signIns',
                                               {'$filter': f"createdDateTime ge {since} and riskLevelDuringSignIn ne 'none'", '$top': 500}, warnings, 'signIns') or []
        raw['audit_logs'] = await _get_all(client, f'{v1}/auditLogs/directoryAudits', {'$filter': f'activityDateTime ge {since}', '$top': 500}, warnings, 'directoryAudits') or []
    return raw


registry.register(EntraCollector())
