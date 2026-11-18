"""SCIM 2.0 user provisioning and deprovisioning (/api/v1/scim/v2/Users).

Deprovisioning (DELETE or PATCH active=false) immediately invalidates browser sessions,
deactivates the user, removes/disables their membership, and revokes all of their API keys.
"""
from __future__ import annotations

import hmac
import re
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.config import Settings
from ..core.db import set_tenant_context
from ..core.errors import Conflict, NotFound, Unauthorized
from ..core.rbac import Principal, Role
from ..models import ApiKey, Membership, Tenant, User, utcnow
from ._common import BadRequest
from .deps import get_db, get_settings

router = APIRouter(prefix='/api/v1/scim/v2', tags=['scim'])
SCIM_SCHEMA_USER = 'urn:ietf:params:scim:schemas:core:2.0:User'
SCIM_SCHEMA_LIST = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'
SCIM_MAX_PAGE = 200


class ScimCreateUserBody(BaseModel):
    userName: str = Field(min_length=3, max_length=254)
    displayName: str = Field(default='', max_length=120)
    active: bool = True
    roles: list[dict[str, Any]] = []


class ScimPatchBody(BaseModel):
    Operations: list[dict[str, Any]] = []
    active: bool | None = None


def _scim_principal(db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                    authorization: str = Header(default='')) -> Principal:
    """SCIM is the identity provider's interface, so it authenticates with the provisioning token and nothing else.
    People administer users through /admin/users, where role and permission ceilings apply to them."""
    expected = (settings.scim_bearer_token or '').strip()
    if not expected:
        raise NotFound('SCIM is not configured')
    token = authorization[7:].strip() if authorization.lower().startswith('bearer ') else ''
    if not token or not hmac.compare_digest(token.encode(), expected.encode()):
        raise Unauthorized('Valid SCIM authentication required')
    tenant = db.execute(select(Tenant).where(Tenant.slug == settings.default_tenant_slug)).scalar_one()
    set_tenant_context(db, tenant.id)
    return Principal(tenant_id=tenant.id, role=Role.admin, auth='system', email='scim-provisioner')


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
    membership = db.execute(select(Membership).where(Membership.tenant_id == tenant_id,
                                                     Membership.user_id == user.id)).scalar_one_or_none()
    if membership is not None and membership.role == Role.owner.value:
        other_owners = db.execute(select(func.count()).select_from(Membership).where(
            Membership.tenant_id == tenant_id, Membership.role == Role.owner.value, Membership.user_id != user.id)).scalar_one()
        if not other_owners:
            raise Conflict('Refusing to deprovision the last owner of the tenant')
    elsewhere = db.execute(select(func.count()).select_from(Membership).where(
        Membership.user_id == user.id, Membership.tenant_id != tenant_id)).scalar_one()
    if not elsewhere:
        user.is_active = False  # the account is global; only switch it off when no other tenant still relies on it
    user.sessions_invalidated_at = utcnow()
    keys = db.execute(select(ApiKey).where(ApiKey.tenant_id == tenant_id, ApiKey.created_by == user.id,
                                           ApiKey.revoked_at.is_(None))).scalars().all()
    now = utcnow()
    for k in keys:
        k.revoked_at = now
    if membership is not None:
        db.delete(membership)
    return len(keys)


_FILTER_RE = re.compile(r'^\s*userName\s+eq\s+"([^"]{1,254})"\s*$', re.IGNORECASE)


@router.get('/ServiceProviderConfig')
def service_provider_config(principal: Principal = Depends(_scim_principal)):
    off = {'supported': False}
    return {'schemas': ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'], 'patch': {'supported': True},
            'bulk': {**off, 'maxOperations': 0, 'maxPayloadSize': 0}, 'filter': {'supported': True, 'maxResults': SCIM_MAX_PAGE},
            'changePassword': off, 'sort': off, 'etag': off,
            'authenticationSchemes': [{'type': 'oauthbearertoken', 'name': 'Bearer token', 'description': 'SCIM provisioning token'}]}


@router.get('/Users')
def list_scim_users(filter: str = Query(default='', max_length=400), startIndex: int = Query(default=1, ge=1),  # noqa: A002, N803
                    count: int = Query(default=100, ge=0, le=SCIM_MAX_PAGE),
                    db: Session = Depends(get_db), principal: Principal = Depends(_scim_principal)):
    """Identity providers look a user up with `filter=userName eq "..."` before every create or update."""
    stmt = (select(User, Membership).join(Membership, Membership.user_id == User.id)
            .where(Membership.tenant_id == principal.tenant_id))
    if filter:
        match = _FILTER_RE.match(filter)
        if not match:
            raise BadRequest('Only the filter `userName eq "value"` is supported', code='invalidFilter')
        stmt = stmt.where(User.email == match.group(1).strip().lower())
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(User.email.asc()).offset(startIndex - 1).limit(count)).all()
    resources = [_scim_resource(u, m) for u, m in rows]
    return {'schemas': [SCIM_SCHEMA_LIST], 'totalResults': total, 'startIndex': startIndex, 'itemsPerPage': len(resources),
            'Resources': resources}


@router.get('/Users/{user_id}')
def get_scim_user(user_id: str, db: Session = Depends(get_db), principal: Principal = Depends(_scim_principal)):
    membership = db.execute(select(Membership).where(Membership.tenant_id == principal.tenant_id,
                                                     Membership.user_id == user_id)).scalar_one_or_none()
    user = db.get(User, user_id) if membership else None
    if user is None or membership is None:
        raise NotFound('SCIM user not found')
    return _scim_resource(user, membership)


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
    if active is True and not user.is_active:
        elsewhere = db.execute(select(func.count()).select_from(Membership).where(
            Membership.user_id == user.id, Membership.tenant_id != principal.tenant_id)).scalar_one()
        if elsewhere:
            raise Conflict('This account was disabled outside this tenant and cannot be re-enabled from here')
        user.is_active = True
        record_audit(db, principal, 'scim.user_reactivated', user.id, {'email': user.email})
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
