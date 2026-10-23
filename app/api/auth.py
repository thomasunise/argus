from __future__ import annotations

import secrets
import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.config import Settings
from ..core.errors import Conflict, Forbidden, NotFound, RateLimited, Unauthorized
from ..core.rbac import ALL_PERMISSIONS, Principal, Role
from ..core.security import (generate_api_key, oidc_authorize_url, oidc_discover, oidc_exchange_code, pkce_pair,
                             totp_generate_secret, totp_provisioning_uri, totp_verify, verify_password)
from ..models import ApiKey, Membership, OidcIdentity, Tenant, User, utcnow
from .deps import current_principal, get_db, get_settings, require

router = APIRouter(prefix='/api/v1/auth', tags=['auth'])


class LoginBody(BaseModel):
    email: str = ''
    password: str = Field(min_length=1, max_length=512)
    totp: str = ''
    tenant: str = ''  # slug; optional when the user belongs to one tenant


class TotpVerifyBody(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class ApiKeyBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    role: Role = Role.viewer
    scopes: list[str] = []


class SwitchTenantBody(BaseModel):
    tenant: str


def _throttle(request: Request, settings: Settings) -> None:
    attempts: dict = request.app.state.login_attempts
    client_id = request.client.host if request.client else 'unknown'
    now = time.monotonic()
    recent = [t for t in attempts.get(client_id, []) if now - t < settings.login_window_seconds]
    attempts[client_id] = recent
    if len(recent) >= settings.login_max_attempts:
        raise RateLimited('Too many attempts, try again later')


def _record_failure(request: Request) -> None:
    client_id = request.client.host if request.client else 'unknown'
    request.app.state.login_attempts.setdefault(client_id, []).append(time.monotonic())


def _memberships(db: Session, user_id: str) -> list[tuple[Membership, Tenant]]:
    rows = db.execute(select(Membership, Tenant).join(Tenant, Tenant.id == Membership.tenant_id)
                      .where(Membership.user_id == user_id, Tenant.is_active.is_(True)).order_by(Membership.created_at.asc(), Tenant.slug.asc())).all()
    return [(m, t) for m, t in rows]


def _establish_session(request: Request, user: User, tenant_id: str, mfa: bool) -> dict:
    request.session.clear()
    request.session.update({'authed': True, 'user_id': user.id, 'tenant_id': tenant_id, 'csrf': secrets.token_urlsafe(32), 'mfa': mfa})
    return {'authenticated': True, 'csrf': request.session['csrf'], 'tenant_id': tenant_id, 'mfa': mfa}


def _session_payload(request: Request, db: Session, principal: Principal | None, settings: Settings) -> dict:
    if principal is None:
        pending = request.session.get('pending_mfa_user')
        return {'authenticated': False, 'csrf': None, 'mfa_required': bool(pending), 'oidc_enabled': bool(settings.oidc_issuer)}
    user = db.get(User, principal.user_id) if principal.user_id else None
    tenants = [{'id': t.id, 'slug': t.slug, 'name': t.name, 'role': m.role} for m, t in _memberships(db, principal.user_id)] if principal.user_id else []
    tenant = db.get(Tenant, principal.tenant_id)
    return {'authenticated': True, 'csrf': request.session.get('csrf') if principal.auth == 'session' else None,
            'user': {'id': principal.user_id, 'email': principal.email, 'display_name': user.display_name if user else '',
                     'totp_enabled': bool(user and user.totp_enabled)},
            'tenant': {'id': principal.tenant_id, 'slug': tenant.slug if tenant else '', 'name': tenant.name if tenant else '',
                       'actions_enabled': bool(tenant and tenant.actions_enabled)},
            'role': principal.role, 'auth': principal.auth, 'tenants': tenants, 'oidc_enabled': bool(settings.oidc_issuer)}


@router.get('/session')
def session(request: Request, db: Session = Depends(get_db), principal: Principal | None = Depends(current_principal),
            settings: Settings = Depends(get_settings)):
    return _session_payload(request, db, principal, settings)


@router.post('/login')
def login(body: LoginBody, request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    _throttle(request, settings)
    email = (body.email or settings.admin_email).strip().lower()
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user or not user.is_active or not user.password_hash or not verify_password(body.password, user.password_hash):
        _record_failure(request)
        raise Unauthorized('Invalid credentials')
    memberships = _memberships(db, user.id)
    if not memberships:
        raise Forbidden('User has no tenant membership')
    if body.tenant:
        chosen = next((t for _, t in memberships if t.slug == body.tenant), None)
        if not chosen:
            raise Forbidden('Not a member of that tenant')
    else:
        chosen = memberships[0][1]
    mfa_ok = True
    if user.totp_enabled:
        if not body.totp or not totp_verify(user.totp_secret, body.totp):
            _record_failure(request)
            raise Unauthorized('TOTP code required or invalid')
    elif settings.totp_required:
        mfa_ok = False
    request.app.state.login_attempts.pop(request.client.host if request.client else 'unknown', None)
    user.last_login_at = utcnow()
    payload = _establish_session(request, user, chosen.id, mfa_ok)
    record_audit(db, Principal(tenant_id=chosen.id, role=Role(memberships[0][0].role), user_id=user.id, email=user.email),
                 'auth.login', user.id, {'method': 'password', 'mfa': mfa_ok})
    if not mfa_ok:
        payload['mfa_required'] = True
        payload['enroll_uri'] = None
    return payload


@router.post('/logout')
def logout(request: Request, db: Session = Depends(get_db), principal: Principal | None = Depends(current_principal)):
    if principal and principal.auth == 'session':
        record_audit(db, principal, 'auth.logout', principal.user_id or '')
    request.session.clear()
    return {'ok': True}


@router.post('/switch-tenant')
def switch_tenant(body: SwitchTenantBody, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require())):
    if principal.auth != 'session':
        raise Forbidden('Only interactive sessions can switch tenants')
    target = next((t for _, t in _memberships(db, principal.user_id) if t.slug == body.tenant or t.id == body.tenant), None)
    if not target:
        raise NotFound('Tenant not found')
    request.session['tenant_id'] = target.id
    request.session['csrf'] = secrets.token_urlsafe(32)
    record_audit(db, principal, 'auth.switch_tenant', target.id, tenant_id=target.id)
    return {'ok': True, 'tenant_id': target.id, 'csrf': request.session['csrf']}


# ---------------------------------------------------------------- TOTP


@router.post('/totp/enroll')
def totp_enroll(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                principal: Principal | None = Depends(current_principal)):
    user_id = principal.user_id if principal else request.session.get('user_id')
    if not user_id:
        raise Unauthorized('Authentication required')
    user = db.get(User, user_id)
    if not user:
        raise Unauthorized('Authentication required')
    if user.totp_enabled:
        raise Conflict('TOTP already enabled')
    secret = totp_generate_secret()
    request.session['pending_totp_secret'] = secret
    return {'secret': secret, 'uri': totp_provisioning_uri(secret, user.email, settings.app_name)}


@router.post('/totp/verify')
def totp_confirm(body: TotpVerifyBody, request: Request, db: Session = Depends(get_db), principal: Principal | None = Depends(current_principal)):
    user_id = principal.user_id if principal else request.session.get('user_id')
    user = db.get(User, user_id) if user_id else None
    if not user:
        raise Unauthorized('Authentication required')
    secret = request.session.get('pending_totp_secret') or user.totp_secret
    if not secret or not totp_verify(secret, body.code):
        raise Unauthorized('Invalid code')
    if not user.totp_enabled:
        user.totp_secret, user.totp_enabled = secret, True
    request.session.pop('pending_totp_secret', None)
    request.session['mfa'] = True
    request.session['csrf'] = request.session.get('csrf') or secrets.token_urlsafe(32)
    tenant_id = request.session.get('tenant_id', '')
    record_audit(db, Principal(tenant_id=tenant_id, role=Role.viewer, user_id=user.id, email=user.email), 'auth.totp_verified', user.id)
    return {'ok': True, 'csrf': request.session['csrf']}


# ---------------------------------------------------------------- OIDC


@router.get('/oidc/start')
async def oidc_start(request: Request, settings: Settings = Depends(get_settings)):
    if not settings.oidc_issuer or not settings.oidc_client_id:
        raise NotFound('OIDC is not configured')
    doc = await oidc_discover(settings.oidc_issuer)
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    verifier, challenge = pkce_pair()
    request.session.update({'oidc_state': state, 'oidc_nonce': nonce, 'oidc_verifier': verifier})
    return RedirectResponse(oidc_authorize_url(doc, settings, state, nonce, challenge), status_code=302)


@router.get('/oidc/callback')
async def oidc_callback(request: Request, code: str = '', state: str = '', db: Session = Depends(get_db),
                        settings: Settings = Depends(get_settings)):
    if not code or not state or state != request.session.get('oidc_state'):
        raise Unauthorized('Invalid OIDC state')
    doc = await oidc_discover(settings.oidc_issuer)
    claims = await oidc_exchange_code(doc, settings, code, request.session.get('oidc_verifier', ''), request.session.get('oidc_nonce', ''))
    email = (claims.get('email') or '').lower()
    if not email:
        raise Unauthorized('OIDC token has no email claim')
    allowed = [d.strip().lower() for d in settings.oidc_allowed_domains.split(',') if d.strip()]
    if allowed and email.split('@')[-1] not in allowed:
        raise Forbidden('Email domain is not allowed')
    identity = db.execute(select(OidcIdentity).where(OidcIdentity.issuer == doc.issuer, OidcIdentity.subject == claims['sub'])).scalar_one_or_none()
    user = db.get(User, identity.user_id) if identity else db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user:
        if not settings.oidc_auto_provision:
            raise Forbidden('User is not provisioned')
        user = User(email=email, display_name=claims.get('name', ''))
        db.add(user)
        db.flush()
        tenant = db.execute(select(Tenant).where(Tenant.slug == settings.default_tenant_slug)).scalar_one()
        db.add(Membership(user_id=user.id, tenant_id=tenant.id, role=settings.oidc_default_role))
    if not identity:
        db.add(OidcIdentity(user_id=user.id, issuer=doc.issuer, subject=claims['sub']))
    memberships = _memberships(db, user.id)
    if not memberships:
        raise Forbidden('User has no tenant membership')
    user.last_login_at = utcnow()
    _establish_session(request, user, memberships[0][1].id, True)
    record_audit(db, Principal(tenant_id=memberships[0][1].id, role=Role(memberships[0][0].role), user_id=user.id, email=user.email),
                 'auth.login', user.id, {'method': 'oidc', 'issuer': doc.issuer})
    return RedirectResponse('/', status_code=302)


# ---------------------------------------------------------------- API keys


def _key_dict(key: ApiKey) -> dict:
    return {'id': key.id, 'name': key.name, 'prefix': key.prefix, 'role': key.role, 'scopes': [s for s in key.scopes.split(',') if s],
            'created_at': key.created_at, 'last_used_at': key.last_used_at, 'revoked_at': key.revoked_at}


@router.get('/api-keys')
def list_api_keys(db: Session = Depends(get_db), principal: Principal = Depends(require('admin:api_keys'))):
    rows = db.execute(select(ApiKey).where(ApiKey.tenant_id == principal.tenant_id).order_by(ApiKey.created_at.desc())).scalars().all()
    return {'items': [_key_dict(k) for k in rows]}


@router.post('/api-keys', status_code=201)
def create_api_key(body: ApiKeyBody, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:api_keys'))):
    if body.role in {Role.admin, Role.owner} and principal.role != Role.owner:
        raise Forbidden('Only owners can mint admin keys')
    valid_domains = {p.split(':')[0] for p in ALL_PERMISSIONS}
    for scope in body.scopes:
        ok = scope == 'ingest' or scope in ALL_PERMISSIONS or (scope.endswith(':*') and scope[:-2] in valid_domains)
        if not ok:
            from ..core.errors import SentinelError

            raise SentinelError(f'Unknown scope {scope!r}', code='invalid_scope', status=400)
    if len(body.scopes) > 32:
        from ..core.errors import SentinelError

        raise SentinelError('Too many scopes', code='invalid_scope', status=400)
    plaintext, prefix, key_hash = generate_api_key()
    key = ApiKey(tenant_id=principal.tenant_id, name=body.name, prefix=prefix, key_hash=key_hash, role=body.role,
                 scopes=','.join(sorted(set(body.scopes))), created_by=principal.user_id or '')
    db.add(key)
    db.flush()
    record_audit(db, principal, 'auth.api_key_created', key.id, {'name': body.name, 'role': body.role, 'scopes': body.scopes})
    return {**_key_dict(key), 'key': plaintext}


@router.delete('/api-keys/{key_id}')
def revoke_api_key(key_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:api_keys'))):
    key = db.execute(select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == principal.tenant_id)).scalar_one_or_none()
    if not key:
        raise NotFound('API key not found')
    key.revoked_at = utcnow()
    record_audit(db, principal, 'auth.api_key_revoked', key.id, {'name': key.name})
    return {'ok': True}
