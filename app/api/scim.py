"""SCIM 2.0 user provisioning and deprovisioning (/api/v1/scim/v2/Users).

Deprovisioning (DELETE or PATCH active=false) immediately invalidates browser sessions,
deactivates the user, removes/disables their membership, and revokes all of their API keys.
"""
from __future__ import annotations

import hmac
from typing import Any

from fastapi import APIRouter, Depends, Header, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.config import Settings
from ..core.db import set_tenant_context
from ..core.errors import Conflict, Forbidden, NotFound, Unauthorized
from ..core.rbac import Principal, Role, has
from ..models import ApiKey, Membership, Tenant, User, utcnow
from .deps import current_principal, get_db, get_settings

router = APIRouter(prefix='/api/v1/scim/v2', tags=['scim'])
SCIM_SCHEMA_USER = 'urn:ietf:params:scim:schemas:core:2.0:User'
SCIM_SCHEMA_LIST = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'


class ScimCreateUserBody(BaseModel):
    userName: str = Field(min_length=3, max_length=254)
    displayName: str = Field(default='', max_length=120)
    active: bool = True
    roles: list[dict[str, Any]] = []


class ScimPatchBody(BaseModel):
    Operations: list[dict[str, Any]] = []
    active: bool | None = None


def _scim_principal(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                    authorization: str = Header(default='')) -> Principal:
    token = authorization[7:].strip() if authorization.lower().startswith('bearer ') else ''
    expected = (settings.scim_bearer_token or '').strip()
    if expected and token and hmac.compare_digest(token.encode(), expected.encode()):
        tenant = db.execute(select(Tenant).where(Tenant.slug == settings.default_tenant_slug)).scalar_one()
        set_tenant_context(db, tenant.id)
        return Principal(tenant_id=tenant.id, role=Role.admin, auth='system', email='scim-provisioner')
    principal = current_principal(request, db, settings)
    if principal is not None:
        if not has(principal, 'admin:users'):
            raise Forbidden('Missing permission admin:users for SCIM')
        return principal
    raise Unauthorized('Valid SCIM authentication required')


def _scim_resource(user: User, membership: Membership | None) -> dict[str, Any]:
    return {
        'schemas': [SCIM_SCHEMA_USER],
        'id': user.id,
        'userName': user.email,
        'displayName': user.display_name or user.email,
        'active': bool(user.is_active and membership is not None),
        'roles': [{'value': membership.role}] if membership else [],
    }


def _deprovision_user(db: Session, tenant_id: str, user: User) -> int:
    user.is_active = False
    user.sessions_invalidated_at = utcnow()
    keys = db.execute(select(ApiKey).where(ApiKey.tenant_id == tenant_id, ApiKey.created_by == user.id,
                                           ApiKey.revoked_at.is_(None))).scalars().all()
    now = utcnow()
    for k in keys:
        k.revoked_at = now
    membership = db.execute(select(Membership).where(Membership.tenant_id == tenant_id,
                                                     Membership.user_id == user.id)).scalar_one_or_none()
    if membership is not None:
        db.delete(membership)
    return len(keys)


@router.get('/Users')
def list_scim_users(db: Session = Depends(get_db), principal: Principal = Depends(_scim_principal)):
    rows = db.execute(
        select(User, Membership)
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.tenant_id == principal.tenant_id)
        .order_by(User.email.asc())
    ).all()
    resources = [_scim_resource(u, m) for u, m in rows]
    return {'schemas': [SCIM_SCHEMA_LIST], 'totalResults': len(resources), 'Resources': resources}


@router.post('/Users', status_code=201)
def create_scim_user(body: ScimCreateUserBody, db: Session = Depends(get_db),
                     principal: Principal = Depends(_scim_principal)):
    email = body.userName.strip().lower()
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        raise Conflict('SCIM user already exists')
    role_val = 'viewer'
    if body.roles and isinstance(body.roles[0], dict):
        candidate = str(body.roles[0].get('value') or 'viewer')
        if candidate in {r.value for r in Role if r != Role.owner}:
            role_val = candidate
    user = User(email=email, display_name=body.displayName or email.split('@')[0], is_active=body.active,
                created_by=(principal.user_id or principal.actor)[:36])
    db.add(user)
    db.flush()
    membership = Membership(user_id=user.id, tenant_id=principal.tenant_id, role=role_val,
                            created_by=(principal.user_id or principal.actor)[:36])
    db.add(membership)
    db.flush()
    record_audit(db, principal, 'scim.user_provisioned', user.id, {'email': email, 'role': role_val})
    return _scim_resource(user, membership)


@router.patch('/Users/{user_id}')
def patch_scim_user(user_id: str, body: ScimPatchBody, db: Session = Depends(get_db),
                    principal: Principal = Depends(_scim_principal)):
    membership = db.execute(select(Membership).where(Membership.tenant_id == principal.tenant_id,
                                                     Membership.user_id == user_id)).scalar_one_or_none()
    user = db.get(User, user_id) if membership else None
    if user is None or membership is None:
        raise NotFound('SCIM user not found')
    active = body.active
    for op in body.Operations or []:
        if str(op.get('op') or '').lower() == 'replace':
            val = op.get('value')
            if isinstance(val, dict) and 'active' in val:
                active = bool(val['active'])
            elif str(op.get('path') or '').lower() == 'active':
                active = bool(val)
    if active is False:
        revoked = _deprovision_user(db, principal.tenant_id, user)
        record_audit(db, principal, 'scim.user_deprovisioned', user.id, {'email': user.email, 'revoked_api_keys': revoked})
        return _scim_resource(user, None)
    if active is True:
        user.is_active = True
    return _scim_resource(user, membership)


@router.delete('/Users/{user_id}', status_code=204)
def delete_scim_user(user_id: str, db: Session = Depends(get_db), principal: Principal = Depends(_scim_principal)):
    membership = db.execute(select(Membership).where(Membership.tenant_id == principal.tenant_id,
                                                     Membership.user_id == user_id)).scalar_one_or_none()
    user = db.get(User, user_id) if membership else None
    if user is None or membership is None:
        raise NotFound('SCIM user not found')
    revoked = _deprovision_user(db, principal.tenant_id, user)
    record_audit(db, principal, 'scim.user_deleted', user.id, {'email': user.email, 'revoked_api_keys': revoked})
    return Response(status_code=204)
