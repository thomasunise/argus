"""Administration: tenants, users (via memberships), roles and tenant settings.

Invariants enforced here:
  - a tenant always keeps at least one active owner (no demotion, deactivation or removal of the last one)
  - nobody grants a role above their own; only owners grant or change owner
  - passwords are never written to the audit log; temporary passwords are returned exactly once
  - settings are a whitelist; secrets are stored as references (env:/file:/secrets:), never inline
"""
from __future__ import annotations

import re
import secrets
from typing import Any

from fastapi import APIRouter, Body, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.config import AI_PROVIDERS, Settings
from ..core.errors import Conflict, Forbidden, NotFound
from ..core.findings import SEVERITIES
from ..core.rbac import ROLE_ORDER, Principal, Role, role_at_least
from ..core.security import hash_password
from ..models import ApiKey, Asset, AuditEntry, Finding, Membership, SecurityEvent, Tenant, User, dumps, loads, utcnow
from ._common import BadRequest, like
from .deps import Page, get_db, get_settings, require

router = APIRouter(prefix='/api/v1/admin', tags=['admin'])

SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9\-]{1,62}$')
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
SETTING_KEY_RE = re.compile(r'^[a-z][a-z0-9_]{0,63}$')
SECRET_REF_PREFIXES = ('env:', 'file:', 'secrets:')
MIN_PASSWORD = 14
SETTINGS_WHITELIST = {'ai_provider', 'actions_enabled', 'default_min_severity_for_notifications', 'retention_days', 'action_credentials'}
OWNER_ONLY_SETTINGS = {'actions_enabled'}
RETENTION_RANGE = (7, 3650)


class TenantBody(BaseModel):
    slug: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=2, max_length=120)


class TenantPatch(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    is_active: bool | None = None
    actions_enabled: bool | None = None


class UserBody(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    display_name: str = Field(default='', max_length=120)
    role: Role = Role.viewer
    password: str | None = Field(default=None, min_length=MIN_PASSWORD, max_length=512)
    invite: bool = False


class UserPatch(BaseModel):
    display_name: str | None = Field(default=None, max_length=120)
    is_active: bool | None = None


class ResetBody(BaseModel):
    password: str | None = Field(default=None, min_length=MIN_PASSWORD, max_length=512)


class MembershipBody(BaseModel):
    user_id: str = Field(min_length=1, max_length=36)
    role: Role


# ---------------------------------------------------------------- helpers


def _tenant_dict(t: Tenant, role: str | None = None) -> dict:
    data = {'id': t.id, 'slug': t.slug, 'name': t.name, 'is_active': t.is_active, 'actions_enabled': t.actions_enabled, 'created_at': t.created_at}
    if role is not None:
        data['role'] = role
    return data


def _member_dict(user: User, membership: Membership) -> dict:
    return {'id': user.id, 'email': user.email, 'display_name': user.display_name, 'is_active': user.is_active, 'totp_enabled': user.totp_enabled,
            'has_password': bool(user.password_hash), 'role': membership.role, 'membership_id': membership.id, 'member_since': membership.created_at,
            'created_at': user.created_at, 'last_login_at': user.last_login_at}


def _membership(db: Session, tenant_id: str, user_id: str) -> Membership | None:
    return db.execute(select(Membership).where(Membership.tenant_id == tenant_id, Membership.user_id == user_id)).scalar_one_or_none()


def _assert_home_tenant(db: Session, tenant_id: str, user_id: str) -> None:
    """Password and active-flag are global user state: only a tenant the user belongs to exclusively may change them."""
    others = db.execute(select(func.count()).select_from(Membership).where(Membership.user_id == user_id, Membership.tenant_id != tenant_id)).scalar_one()
    if others:
        raise Forbidden('This user also belongs to other tenants; their password and active state cannot be changed from here')


def _active_owner_ids(db: Session, tenant_id: str) -> set[str]:
    rows = db.execute(select(Membership.user_id).join(User, User.id == Membership.user_id)
                      .where(Membership.tenant_id == tenant_id, Membership.role == Role.owner.value, User.is_active.is_(True))).scalars().all()
    return set(rows)


def _assert_not_last_owner(db: Session, tenant_id: str, user_id: str) -> None:
    owners = _active_owner_ids(db, tenant_id)
    if user_id in owners and len(owners) <= 1:
        raise Conflict('This user is the last active owner of the tenant; promote another owner first', code='last_owner')


def _assert_can_assign(principal: Principal, role: Role, current: str | None = None) -> None:
    if role == Role.owner and principal.role != Role.owner:
        raise Forbidden('Only owners can grant the owner role')
    if current == Role.owner.value and principal.role != Role.owner:
        raise Forbidden('Only owners can change the role of an owner')
    if ROLE_ORDER.index(role) > ROLE_ORDER.index(principal.role):
        raise Forbidden('Cannot grant a role above your own')


def _temp_password() -> str:
    return secrets.token_urlsafe(18)


# ---------------------------------------------------------------- tenants (owner only)


@router.get('/tenants')
def list_tenants(db: Session = Depends(get_db), principal: Principal = Depends(require('admin:tenant'))):
    if principal.user_id:
        rows = db.execute(select(Tenant, Membership.role).join(Membership, Membership.tenant_id == Tenant.id)
                          .where(Membership.user_id == principal.user_id).order_by(Tenant.created_at.asc())).all()
        return {'items': [_tenant_dict(t, role) for t, role in rows], 'next_cursor': None}
    tenant = db.get(Tenant, principal.tenant_id)
    return {'items': [_tenant_dict(tenant, principal.role.value)] if tenant else [], 'next_cursor': None}


@router.post('/tenants', status_code=201)
def create_tenant(body: TenantBody, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:tenant'))):
    if not principal.user_id:
        raise Forbidden('Tenant creation requires an interactive user session (the creator becomes the owner)')
    slug = body.slug.strip().lower()
    if not SLUG_RE.match(slug):
        raise BadRequest('slug must be 2-64 lowercase letters, digits or hyphens', code='invalid_slug')
    if db.execute(select(Tenant).where(Tenant.slug == slug)).scalar_one_or_none():
        raise Conflict('A tenant with this slug already exists')
    tenant = Tenant(slug=slug, name=body.name.strip())
    db.add(tenant)
    db.flush()
    db.add(Membership(user_id=principal.user_id, tenant_id=tenant.id, role=Role.owner.value))
    record_audit(db, principal, 'admin.tenant_created', tenant.id, {'slug': slug, 'name': tenant.name, 'owner': principal.user_id}, tenant_id=tenant.id)
    record_audit(db, principal, 'admin.tenant_created', tenant.id, {'slug': slug, 'name': tenant.name})
    return _tenant_dict(tenant, Role.owner.value)


@router.patch('/tenants/{tenant_id}')
def patch_tenant(tenant_id: str, body: TenantPatch, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:tenant'))):
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise NotFound('Tenant not found')
    if tenant_id != principal.tenant_id:
        membership = _membership(db, tenant_id, principal.user_id or '')
        if membership is None or membership.role != Role.owner.value:
            raise NotFound('Tenant not found')
    changes: dict[str, Any] = {}
    if body.name is not None and body.name.strip() != tenant.name:
        changes['name'] = {'from': tenant.name, 'to': body.name.strip()}
        tenant.name = body.name.strip()
    if body.is_active is not None and body.is_active != tenant.is_active:
        if not body.is_active and tenant_id == principal.tenant_id:
            raise Conflict('Switch to another tenant before deactivating this one')
        changes['is_active'] = {'from': tenant.is_active, 'to': body.is_active}
        tenant.is_active = body.is_active
    if body.actions_enabled is not None and body.actions_enabled != tenant.actions_enabled:
        changes['actions_enabled'] = {'from': tenant.actions_enabled, 'to': body.actions_enabled}
        tenant.actions_enabled = body.actions_enabled
    if changes:
        record_audit(db, principal, 'admin.tenant_updated', tenant.id, {'changes': changes}, tenant_id=tenant.id)
    return _tenant_dict(tenant)


# ---------------------------------------------------------------- users


@router.get('/users')
def list_users(search: str | None = None, role: str | None = None, page: Page = Depends(Page), db: Session = Depends(get_db),
               principal: Principal = Depends(require('admin:users'))):
    stmt = select(User, Membership).join(Membership, Membership.user_id == User.id).where(Membership.tenant_id == principal.tenant_id)
    if role:
        stmt = stmt.where(Membership.role == role)
    if search:
        pattern = like(search.strip())
        stmt = stmt.where(User.email.ilike(pattern, escape='\\') | User.display_name.ilike(pattern, escape='\\'))
    rows = db.execute(page.apply(stmt.order_by(User.email.asc()))).all()
    return page.wrap(rows, lambda pair: _member_dict(pair[0], pair[1]))


@router.post('/users', status_code=201)
def create_user(body: UserBody, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:users'))):
    email = body.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise BadRequest('email is not valid', code='invalid_email')
    _assert_can_assign(principal, body.role)
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    response: dict[str, Any] = {}
    if user is not None:
        # An account that exists in another tenant is never attached from here: a membership would let this
        # tenant's admins reset its password or deactivate it (global user state). The message is the same
        # in both cases so the endpoint does not reveal which tenants an address belongs to.
        raise Conflict('A user with this email already exists')
    else:
        temporary = None
        if body.invite:
            password_hash = ''  # sign in through OIDC or after an admin password reset
        else:
            temporary = body.password or _temp_password()
            password_hash = hash_password(temporary)
        user = User(email=email, display_name=body.display_name.strip() or email.split('@')[0], password_hash=password_hash)
        db.add(user)
        db.flush()
        created = True
        if temporary and not body.password:
            response['temporary_password'] = temporary
        record_audit(db, principal, 'admin.user_created', user.id, {'email': email, 'invite': body.invite, 'password_set': bool(password_hash)})
    membership = Membership(user_id=user.id, tenant_id=principal.tenant_id, role=body.role.value)
    db.add(membership)
    db.flush()
    record_audit(db, principal, 'admin.membership_created', user.id, {'email': email, 'role': body.role.value, 'new_user': created})
    return {**_member_dict(user, membership), 'created': created, 'invited': body.invite and created, **response}


@router.patch('/users/{user_id}')
def patch_user(user_id: str, body: UserPatch, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:users'))):
    membership = _membership(db, principal.tenant_id, user_id)
    user = db.get(User, user_id) if membership else None
    if membership is None or user is None:
        raise NotFound('User not found in this tenant')
    if membership.role == Role.owner.value and principal.role != Role.owner:
        raise Forbidden('Only owners can modify an owner')
    if body.is_active is not None:
        _assert_home_tenant(db, principal.tenant_id, user_id)
    changes: dict[str, Any] = {}
    if body.display_name is not None and body.display_name.strip() != user.display_name:
        changes['display_name'] = {'from': user.display_name, 'to': body.display_name.strip()}
        user.display_name = body.display_name.strip()
    if body.is_active is not None and body.is_active != user.is_active:
        if not body.is_active:
            if user_id == principal.user_id:
                raise Conflict('You cannot deactivate your own account')
            _assert_not_last_owner(db, principal.tenant_id, user_id)
        changes['is_active'] = {'from': user.is_active, 'to': body.is_active}
        user.is_active = body.is_active
    if changes:
        record_audit(db, principal, 'admin.user_updated', user.id, {'email': user.email, 'changes': changes})
    return _member_dict(user, membership)


@router.post('/users/{user_id}/reset-password')
def reset_password(user_id: str, body: ResetBody | None = None, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:users'))):
    membership = _membership(db, principal.tenant_id, user_id)
    user = db.get(User, user_id) if membership else None
    if membership is None or user is None:
        raise NotFound('User not found in this tenant')
    if membership.role == Role.owner.value and principal.role != Role.owner and user_id != principal.user_id:
        raise Forbidden('Only owners can reset an owner password')
    _assert_home_tenant(db, principal.tenant_id, user_id)
    supplied = body.password if body else None
    temporary = supplied or _temp_password()
    user.password_hash = hash_password(temporary)
    record_audit(db, principal, 'admin.password_reset', user.id, {'email': user.email, 'generated': supplied is None})
    out: dict[str, Any] = {'ok': True, 'user_id': user.id}
    if supplied is None:
        out['temporary_password'] = temporary
    return out


@router.delete('/users/{user_id}')
def remove_member(user_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:users'))):
    membership = _membership(db, principal.tenant_id, user_id)
    if membership is None:
        raise NotFound('User not found in this tenant')
    if membership.role == Role.owner.value and principal.role != Role.owner:
        raise Forbidden('Only owners can remove an owner')
    _assert_not_last_owner(db, principal.tenant_id, user_id)
    user = db.get(User, user_id)
    db.delete(membership)
    record_audit(db, principal, 'admin.membership_removed', user_id, {'email': user.email if user else '', 'role': membership.role})
    return {'ok': True}


# ---------------------------------------------------------------- memberships


@router.post('/memberships')
def set_role(body: MembershipBody, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:users'))):
    user = db.get(User, body.user_id)
    if user is None:
        raise NotFound('User not found')
    membership = _membership(db, principal.tenant_id, user.id)
    if membership is None:
        raise NotFound('User not found in this tenant')  # memberships are created through POST /admin/users only
    _assert_can_assign(principal, body.role, membership.role)
    if membership.role == body.role.value:
        return _member_dict(user, membership)
    if membership.role == Role.owner.value:
        _assert_not_last_owner(db, principal.tenant_id, user.id)
    previous = membership.role
    membership.role = body.role.value
    record_audit(db, principal, 'admin.role_changed', user.id, {'email': user.email, 'from': previous, 'to': body.role.value})
    return _member_dict(user, membership)


# ---------------------------------------------------------------- settings


def _settings_view(tenant: Tenant, settings: Settings) -> dict[str, Any]:
    stored = loads(tenant.settings_json)
    return {'ai_provider': stored.get('ai_provider'), 'effective_ai_provider': stored.get('ai_provider') or settings.ai_provider,
            'actions_enabled': bool(tenant.actions_enabled), 'default_min_severity_for_notifications': stored.get('default_min_severity_for_notifications', 'high'),
            'retention_days': stored.get('retention_days'), 'action_credentials': stored.get('action_credentials', {}),
            'available_providers': sorted(AI_PROVIDERS), 'kill_switch': settings.actions_kill_switch}


def _validate_setting(key: str, value: Any) -> Any:
    if key == 'ai_provider':
        if value in (None, ''):
            return None
        if not isinstance(value, str) or value.lower() not in AI_PROVIDERS:
            raise BadRequest(f'ai_provider must be one of {sorted(AI_PROVIDERS)} or null', code='invalid_setting')
        return value.lower()
    if key == 'actions_enabled':
        if not isinstance(value, bool):
            raise BadRequest('actions_enabled must be a boolean', code='invalid_setting')
        return value
    if key == 'default_min_severity_for_notifications':
        if value not in SEVERITIES:
            raise BadRequest(f'default_min_severity_for_notifications must be one of {list(SEVERITIES)}', code='invalid_setting')
        return value
    if key == 'retention_days':
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or not (RETENTION_RANGE[0] <= value <= RETENTION_RANGE[1]):
            raise BadRequest(f'retention_days must be an integer between {RETENTION_RANGE[0]} and {RETENTION_RANGE[1]}', code='invalid_setting')
        return value
    if key == 'action_credentials':
        if not isinstance(value, dict) or len(value) > 50:
            raise BadRequest('action_credentials must be an object of at most 50 entries', code='invalid_setting')
        cleaned: dict[str, str] = {}
        for name, ref in value.items():
            if not isinstance(name, str) or not SETTING_KEY_RE.match(name):
                raise BadRequest(f'action_credentials key {name!r} is not a valid identifier', code='invalid_setting')
            if not isinstance(ref, str) or not ref.startswith(SECRET_REF_PREFIXES):
                raise BadRequest(f'action_credentials[{name}] must be a secret reference starting with one of {SECRET_REF_PREFIXES}; '
                                 'inline secrets are not stored', code='inline_secret')
            cleaned[name] = ref
        return cleaned
    raise BadRequest(f'Unknown setting {key!r}', code='unknown_setting')


@router.get('/settings')
def get_tenant_settings(db: Session = Depends(get_db), settings: Settings = Depends(get_settings), principal: Principal = Depends(require('admin:settings'))):
    tenant = db.get(Tenant, principal.tenant_id)
    if tenant is None:
        raise NotFound('Tenant not found')
    return _settings_view(tenant, settings)


@router.patch('/settings')
def patch_tenant_settings(body: dict[str, Any] = Body(...), db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                          principal: Principal = Depends(require('admin:settings'))):
    tenant = db.get(Tenant, principal.tenant_id)
    if tenant is None:
        raise NotFound('Tenant not found')
    unknown = sorted(set(body) - SETTINGS_WHITELIST)
    if unknown:
        raise BadRequest(f'Unknown settings {unknown}; allowed: {sorted(SETTINGS_WHITELIST)}', code='unknown_setting')
    if (set(body) & OWNER_ONLY_SETTINGS) and not role_at_least(principal.role, Role.owner):
        raise Forbidden('Only owners can change actions_enabled')
    stored = loads(tenant.settings_json)
    changes: dict[str, Any] = {}
    for key, raw in body.items():
        value = _validate_setting(key, raw)
        if key == 'actions_enabled':
            if value != tenant.actions_enabled:
                changes[key] = {'from': tenant.actions_enabled, 'to': value}
                tenant.actions_enabled = value
            continue
        if stored.get(key) != value:
            changes[key] = {'from': stored.get(key), 'to': value}
            if value is None:
                stored.pop(key, None)
            else:
                stored[key] = value
    if changes:
        tenant.settings_json = dumps(stored)
        record_audit(db, principal, 'admin.settings_changed', tenant.id, {'changes': changes})
    return _settings_view(tenant, settings)


# ---------------------------------------------------------------- overview


@router.get('/overview')
def overview(db: Session = Depends(get_db), principal: Principal = Depends(require('admin:users'))):
    tenant_id = principal.tenant_id
    tenant = db.get(Tenant, tenant_id)
    roles = {r: int(n) for r, n in db.execute(select(Membership.role, func.count()).where(Membership.tenant_id == tenant_id).group_by(Membership.role)).all()}

    def count(model, *where) -> int:
        return int(db.scalar(select(func.count()).select_from(model).where(*where)) or 0)

    return {'tenant': _tenant_dict(tenant) if tenant else None, 'members': {'total': sum(roles.values()), 'by_role': roles,
                                                                           'active_owners': len(_active_owner_ids(db, tenant_id))},
            'api_keys': {'active': count(ApiKey, ApiKey.tenant_id == tenant_id, ApiKey.revoked_at.is_(None)),
                         'revoked': count(ApiKey, ApiKey.tenant_id == tenant_id, ApiKey.revoked_at.is_not(None))},
            'assets': count(Asset, Asset.tenant_id == tenant_id),
            'findings_open': count(Finding, Finding.tenant_id == tenant_id, Finding.status.in_(['open', 'investigating'])),
            'events': count(SecurityEvent, SecurityEvent.tenant_id == tenant_id),
            'audit_entries': count(AuditEntry, AuditEntry.tenant_id == tenant_id),
            'settings_keys': sorted(loads(tenant.settings_json)) if tenant else [], 'generated_at': utcnow()}
