from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Role(StrEnum):
    viewer = 'viewer'
    analyst = 'analyst'
    approver = 'approver'
    operator = 'operator'
    user_admin = 'user_admin'
    admin = 'admin'
    owner = 'owner'


ROLE_ORDER = [Role.viewer, Role.analyst, Role.approver, Role.operator, Role.user_admin, Role.admin, Role.owner]

_VIEWER = {
    'assets:read', 'findings:read', 'events:read', 'graph:read', 'detections:read', 'collectors:read',
    'agents:read', 'tests:read', 'actions:read', 'integrations:read', 'audit:read', 'reports:read',
    'investigations:read', 'approvals:read', 'canaries:read', 'scans:read', 'evals:read',
    'autoresponse:read', 'ai:read', 'exploit:read',
}
_ANALYST = _VIEWER | {
    'findings:write', 'investigations:write', 'agents:run', 'detections:write', 'canaries:write',
    'approvals:write', 'evals:run',
    'ai_gateway:use', 'exploit:run',
}
# Dedicated separation-of-duty roles:
# - approver: can approve actions/exploits, but cannot administer users or API keys or request/execute actions
# - user_admin: can administer users and API keys, but cannot request, approve, or execute actions
_APPROVER = _ANALYST | {
    'actions:approve', 'exploit:approve',
}
_USER_ADMIN = _ANALYST | {
    'admin:users', 'admin:api_keys', 'admin:settings',
}
_OPERATOR = _ANALYST | {
    'assets:write', 'assets:authorize', 'tests:run', 'tests:write', 'scans:run', 'collectors:run',
    'actions:request', 'actions:approve', 'actions:execute', 'actions:rollback', 'detections:run',
    'exploit:approve',
}
_ADMIN = _OPERATOR | {
    'admin:users', 'admin:api_keys', 'admin:settings', 'collectors:write', 'integrations:write',
    'actions:kill_switch', 'tests:scopes', 'autoresponse:write', 'ai:write',
}
_OWNER = _ADMIN | {'admin:tenant', 'actions:approve_critical'}

PERMISSIONS: dict[Role, set[str]] = {
    Role.viewer: _VIEWER,
    Role.analyst: _ANALYST,
    Role.approver: _APPROVER,
    Role.operator: _OPERATOR,
    Role.user_admin: _USER_ADMIN,
    Role.admin: _ADMIN,
    Role.owner: _OWNER,
}

ALL_PERMISSIONS: set[str] = _OWNER


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    role: Role
    auth: str = 'session'  # session, api_key, system
    user_id: str | None = None
    email: str = ''
    scopes: frozenset[str] = field(default_factory=frozenset)
    api_key_id: str | None = None
    request_id: str = ''
    custom_permissions: frozenset[str] = field(default_factory=frozenset)

    @property
    def actor(self) -> str:
        if self.auth == 'api_key':
            return f'api_key:{self.api_key_id}'
        if self.auth == 'system':
            return 'system'
        return self.email or (self.user_id or 'unknown')

    def can(self, perm: str) -> bool:
        return has(self, perm)


def has(principal: Principal, perm: str) -> bool:
    if principal.auth == 'system':
        return True
    if principal.scopes:
        # Scoped API keys are limited to their scopes, intersected with their role (or custom_permissions).
        if perm not in principal.scopes and not any(perm.startswith(s.rstrip('*')) for s in principal.scopes if s.endswith('*')):
            return False
    allowed = PERMISSIONS.get(principal.role, set()) | set(principal.custom_permissions)
    if f'-{perm}' in principal.custom_permissions:
        return False
    return perm in allowed


def role_at_least(role: Role, minimum: Role) -> bool:
    return ROLE_ORDER.index(role) >= ROLE_ORDER.index(minimum)


def system_principal(tenant_id: str) -> Principal:
    return Principal(tenant_id=tenant_id, role=Role.owner, auth='system', email='system')
