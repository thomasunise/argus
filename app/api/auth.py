from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs

from defusedxml import ElementTree as DefusedET
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.config import Settings
from ..core.db import set_tenant_context
from ..core.errors import ArgusError, Conflict, Forbidden, NotFound, RateLimited, Unauthorized
from ..core.rbac import ALL_PERMISSIONS, Principal, Role, has
from ..core.security import (
    generate_api_key,
    hash_password,
    oidc_authorize_url,
    oidc_discover,
    oidc_exchange_code,
    password_needs_rehash,
    pkce_pair,
    totp_generate_secret,
    totp_match,
    totp_provisioning_uri,
    verify_password,
)
from ..models import ApiKey, Membership, OidcIdentity, Tenant, User, WebAuthnCredential, loads, utcnow
from .deps import current_principal, get_db, get_settings, require

router = APIRouter(prefix='/api/v1/auth', tags=['auth'])


class LoginBody(BaseModel):
    email: str = ''
    password: str = Field(min_length=1, max_length=512)
    totp: str = ''
    tenant: str = ''  # slug; optional when the user belongs to one tenant


class TotpEnrollBody(BaseModel):
    enrollment_code: str = ''


class TotpVerifyBody(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class ChangePasswordBody(BaseModel):
    current_password: str = Field(min_length=1, max_length=512)
    new_password: str = Field(min_length=14, max_length=512)


class WebAuthnRegisterCompleteBody(BaseModel):
    credential_id: str = Field(min_length=1, max_length=256)
    public_key: str = Field(min_length=1, max_length=4096)
    challenge: str = Field(min_length=1, max_length=256)
    name: str = Field(default='Security Key', max_length=120)


class WebAuthnAuthCompleteBody(BaseModel):
    credential_id: str = Field(min_length=1, max_length=256)
    challenge: str = Field(min_length=1, max_length=256)
    signature: str = Field(min_length=1, max_length=1024)
    sign_count: int = Field(default=1, ge=0)
    authenticator_data: str = Field(default='', max_length=2048)
    client_data_json: str = Field(default='', max_length=4096)


class ApiKeyBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    role: Role = Role.viewer
    scopes: list[str] = []
    expires_in_days: int = Field(default=90, ge=1, le=365)
    allowed_ips: list[str] = []


class SwitchTenantBody(BaseModel):
    tenant: str


def _client_key(request: Request) -> str:
    return 'ip:' + (request.client.host if request.client else 'unknown')


def _throttle(request: Request, settings: Settings, *extra_keys: str) -> None:
    """Check shared failed-login counters, using Redis across replicas."""
    request.app.state.login_limiter.check((_client_key(request), *extra_keys),
                                          settings.login_max_attempts, settings.login_window_seconds)


def _record_failure(request: Request, *extra_keys: str) -> None:
    request.app.state.login_limiter.record((_client_key(request), *extra_keys),
                                           request.app.state.settings.login_window_seconds)


def _clear_failures(request: Request, *extra_keys: str) -> None:
    request.app.state.login_limiter.clear((_client_key(request), *extra_keys))


def _memberships(db: Session, user_id: str) -> list[tuple[Membership, Tenant]]:
    rows = db.execute(select(Membership, Tenant).join(Tenant, Tenant.id == Membership.tenant_id)
                      .where(Membership.user_id == user_id, Tenant.is_active.is_(True)).order_by(Membership.created_at.asc(), Tenant.slug.asc())).all()
    return [(m, t) for m, t in rows]


def _establish_session(request: Request, user: User, tenant_id: str, mfa: bool, *, issued_at: float | None = None) -> dict:
    csrf = secrets.token_urlsafe(32)
    ts = issued_at if issued_at is not None else time.time()
    data = {'authed': True, 'user_id': user.id, 'tenant_id': tenant_id, 'csrf': csrf, 'mfa': mfa, 'issued_at': ts}
    store = getattr(request.app.state, 'session_store', None)
    request.session.clear()
    if store is not None:
        sid = store.create(data)
        request.session.update({'sid': sid})
    else:
        sid = secrets.token_urlsafe(32)
        request.session.update({'sid': sid, **data})
    return {'authenticated': True, 'csrf': csrf, 'tenant_id': tenant_id, 'mfa': mfa, 'session_id': sid}


def _session_payload(request: Request, db: Session, principal: Principal | None, settings: Settings) -> dict:
    if principal is None:
        sess_data = _server_session_data(request)
        mfa_pending = bool(sess_data.get('pending_mfa_user') or (sess_data.get('authed') is True and not sess_data.get('mfa')))
        pre_mfa_csrf = sess_data.get('csrf') if mfa_pending else None
        return {'authenticated': False, 'csrf': pre_mfa_csrf, 'mfa_required': mfa_pending, 'oidc_enabled': bool(settings.oidc_issuer)}
    user = db.get(User, principal.user_id) if principal.user_id else None
    tenants = [{'id': t.id, 'slug': t.slug, 'name': t.name, 'role': m.role} for m, t in _memberships(db, principal.user_id)] if principal.user_id else []
    tenant = db.get(Tenant, principal.tenant_id)
    csrf_val = _server_session_get(request, 'csrf') if principal.auth == 'session' else None
    return {'authenticated': True, 'csrf': csrf_val,
            'password_change_required': bool(user and user.must_change_password),
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
    email = (body.email or '').strip().lower()
    if not email:
        raise Unauthorized('Invalid credentials')
    if settings.local_login_disabled and email != (settings.break_glass_email or '').strip().lower():
        raise Forbidden('Local password login is disabled; sign in with single sign-on')
    account_key = f'account:{email}'
    default_tid = getattr(request.app.state, 'default_tenant_id', '')
    try:
        _throttle(request, settings, account_key)
    except RateLimited:
        if default_tid:
            set_tenant_context(db, default_tid)
            record_audit(db, email, 'auth.login_locked', email, {'reason': 'rate_limited'}, tenant_id=default_tid, actor_kind='user')
            db.commit()
        raise
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user or not user.is_active or not user.password_hash or not verify_password(body.password, user.password_hash):
        _record_failure(request, account_key)
        if default_tid:
            set_tenant_context(db, default_tid)
            record_audit(db, email, 'auth.login_failed', user.id if user else email, {'reason': 'bad_credentials'},
                         tenant_id=default_tid, actor_kind='user')
            db.commit()
        raise Unauthorized('Invalid credentials')
    if password_needs_rehash(user.password_hash, scheme=settings.password_hash_scheme, min_scrypt_n=settings.password_scrypt_n):
        user.password_hash = hash_password(body.password, scheme=settings.password_hash_scheme, scrypt_n=settings.password_scrypt_n)
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
        counter = totp_match(user.totp_secret, body.totp or '')
        if counter is None or counter <= (user.totp_last_counter or 0):  # wrong, or a code that was already used
            _record_failure(request, account_key)
            set_tenant_context(db, chosen.id)
            record_audit(db, email, 'auth.login_failed', user.id, {'reason': 'invalid_totp'}, tenant_id=chosen.id, actor_kind='user')
            db.commit()
            raise Unauthorized('TOTP code required or invalid')
        user.totp_last_counter = counter
    elif settings.totp_required or (settings.is_production and settings.oidc_issuer):
        mfa_ok = False
    _clear_failures(request, account_key)
    user.last_login_at = utcnow()
    payload = _establish_session(request, user, chosen.id, mfa_ok)
    if user.must_change_password:
        payload['password_change_required'] = True
    chosen_role = next(m.role for m, t in memberships if t.id == chosen.id)
    set_tenant_context(db, chosen.id)
    record_audit(db, Principal(tenant_id=chosen.id, role=Role(chosen_role), user_id=user.id, email=user.email),
                 'auth.login', user.id, {'method': 'password', 'mfa': mfa_ok})
    if not mfa_ok:
        payload['mfa_required'] = True
        payload['enroll_uri'] = None
    return payload


@router.post('/logout')
def logout(request: Request, db: Session = Depends(get_db), principal: Principal | None = Depends(current_principal)):
    sid = str(request.session.get('sid') or '')
    store = getattr(request.app.state, 'session_store', None)
    if sid and store is not None:
        store.revoke(sid)
    if principal and principal.auth == 'session':
        # Invalidate all previously issued signed cookies for this account.
        user = db.get(User, principal.user_id)
        if user is not None:
            user.sessions_invalidated_at = utcnow()
        record_audit(db, principal, 'auth.logout', principal.user_id or '')
    request.session.clear()
    return {'ok': True}


@router.delete('/sessions/{session_id}')
def revoke_session_by_id(session_id: str, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require())):
    store = getattr(request.app.state, 'session_store', None)
    if store is not None:
        target = store.get(session_id)
        if target and target.get('user_id') != principal.user_id and not has(principal, 'admin:users'):
            raise Forbidden('Cannot revoke another user session')
        store.revoke(session_id)
    record_audit(db, principal, 'auth.session_revoked', session_id)
    return {'ok': True, 'session_id': session_id}


@router.post('/change-password')
def change_password(body: ChangePasswordBody, request: Request, db: Session = Depends(get_db),
                    settings: Settings = Depends(get_settings), principal: Principal | None = Depends(current_principal)):
    user = _session_user(request, db, settings, principal)
    if not user.password_hash or not verify_password(body.current_password, user.password_hash):
        raise Unauthorized('Current password is invalid')
    if body.new_password == body.current_password:
        raise ArgusError('New password must differ from current password', code='invalid_password', status=400)
    user.password_hash = hash_password(body.new_password, scheme=settings.password_hash_scheme, scrypt_n=settings.password_scrypt_n)
    user.must_change_password = False
    prev_issued = _server_session_get(request, 'issued_at')
    inv_ts = max(time.time(), (float(prev_issued) if isinstance(prev_issued, (int, float)) else 0.0) + 1e-6)
    user.sessions_invalidated_at = datetime.fromtimestamp(inv_ts, tz=UTC)
    tenant_id = str(_server_session_get(request, 'tenant_id', '') or (principal.tenant_id if principal else ''))
    mfa_satisfied = bool(_server_session_get(request, 'mfa', True))
    old_sid = str(request.session.get('sid') or '')
    store = getattr(request.app.state, 'session_store', None)
    if old_sid and store is not None:
        store.revoke(old_sid)
    new_ts = max(time.time(), user.sessions_invalidated_at.timestamp() + 0.001)
    payload = _establish_session(request, user, tenant_id, mfa_satisfied, issued_at=new_ts)
    if tenant_id:
        set_tenant_context(db, tenant_id)
        record_audit(db, Principal(tenant_id=tenant_id, role=Role.viewer, user_id=user.id, email=user.email), 'auth.password_changed', user.id)
    return {'ok': True, 'csrf': payload['csrf']}


@router.post('/switch-tenant')
def switch_tenant(body: SwitchTenantBody, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require())):
    if principal.auth != 'session':
        raise Forbidden('Only interactive sessions can switch tenants')
    target = next((t for _, t in _memberships(db, principal.user_id or '') if t.slug == body.tenant or t.id == body.tenant), None)
    if not target:
        raise NotFound('Tenant not found')
    new_csrf = secrets.token_urlsafe(32)
    _server_session_set(request, tenant_id=target.id, csrf=new_csrf)
    # Audit the switch under the initiating tenant; do not change RLS identity mid-transaction.
    record_audit(db, principal, 'auth.switch_tenant', target.id)
    return {'ok': True, 'tenant_id': target.id, 'csrf': new_csrf}


# ---------------------------------------------------------------- TOTP


_SAFE_HTTP_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS', 'TRACE'})


def _enforce_session_csrf(request: Request) -> None:
    if request.method in _SAFE_HTTP_METHODS:
        return
    expected = str(_server_session_get(request, 'csrf') or '')
    given = request.headers.get('x-csrf-token', '')
    if not expected or not secrets.compare_digest(given, expected):
        raise Forbidden('CSRF validation failed')


def _session_user(request: Request, db: Session, settings: Settings, principal: Principal | None) -> User:
    if principal is not None:
        if principal.auth != 'session':
            raise Forbidden('Interactive session required')
        user = db.get(User, principal.user_id) if principal.user_id else None
        if not user or not user.is_active:
            raise Unauthorized('Authentication required')
        _enforce_session_csrf(request)
        return user
    session = _server_session_data(request)
    user_id = session.get('user_id')
    issued_at = session.get('issued_at')
    if not user_id or session.get('authed') is not True:
        raise Unauthorized('Authentication required')
    if not isinstance(issued_at, (int, float)) or time.time() - issued_at > settings.session_absolute_max_age:
        raise Unauthorized('Authentication required')
    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise Unauthorized('Authentication required')
    if user.sessions_invalidated_at is not None and issued_at <= user.sessions_invalidated_at.timestamp():
        raise Unauthorized('Authentication required')
    _enforce_session_csrf(request)
    return user


def _server_session_data(request: Request) -> dict[str, Any]:
    store = getattr(request.app.state, 'session_store', None)
    sid = str(request.session.get('sid') or '')
    if store is not None:
        if not sid:
            return {}
        return store.get(sid) or {}
    return dict(request.session)


def _server_session_set(request: Request, **fields: Any) -> None:
    store = getattr(request.app.state, 'session_store', None)
    sid = str(request.session.get('sid') or '')
    if store is not None:
        if not sid or store.get(sid) is None:
            sid = store.create(dict(fields))
            request.session.clear()
            request.session['sid'] = sid
        else:
            store.update(sid, **fields)
    else:
        request.session.update(fields)


def _server_session_get(request: Request, key: str, default: Any = None) -> Any:
    data = _server_session_data(request)
    return data.get(key, default)


def _server_session_pop(request: Request, key: str, default: Any = None) -> Any:
    store = getattr(request.app.state, 'session_store', None)
    sid = str(request.session.get('sid') or '')
    if store is not None:
        return store.pop_field(sid, key, default) if sid else default
    return request.session.pop(key, default)


@router.post('/totp/enroll')
def totp_enroll(request: Request, body: TotpEnrollBody | None = None, db: Session = Depends(get_db),
                settings: Settings = Depends(get_settings), principal: Principal | None = Depends(current_principal)):
    user = _session_user(request, db, settings, principal)
    if user.totp_enabled:
        raise Conflict('TOTP already enabled')
    if settings.totp_require_enrollment_code or user.totp_enrollment_token_hash:
        code = (body.enrollment_code if body else '') or ''
        expected_hash = user.totp_enrollment_token_hash
        given_hash = hashlib.sha256(code.encode()).hexdigest() if code else ''
        if not expected_hash or not given_hash or not hmac.compare_digest(expected_hash, given_hash):
            raise Forbidden('A valid admin-issued TOTP enrollment code is required')
        user.totp_enrollment_token_hash = ''
    secret = totp_generate_secret()
    _server_session_set(request, pending_totp_secret=secret)
    return {'secret': secret, 'uri': totp_provisioning_uri(secret, user.email, settings.app_name)}


@router.post('/totp/verify')
def totp_confirm(body: TotpVerifyBody, request: Request, db: Session = Depends(get_db), principal: Principal | None = Depends(current_principal),
                 settings: Settings = Depends(get_settings)):
    user = _session_user(request, db, settings, principal)
    # This runs on a pre-MFA session, so it gets the login throttle (per client and per user) and replay protection.
    totp_key = f'totp:{user.id}'
    _throttle(request, settings, totp_key)
    secret = user.totp_secret if user.totp_enabled else _server_session_get(request, 'pending_totp_secret')
    counter = totp_match(secret, body.code) if secret else None
    if counter is None or counter <= (user.totp_last_counter or 0):
        _record_failure(request, totp_key)
        raise Unauthorized('Invalid code')
    user.totp_last_counter = counter
    _clear_failures(request, totp_key)
    tenant_id = str(_server_session_get(request, 'tenant_id', '') or (principal.tenant_id if principal else ''))
    if not user.totp_enabled:
        user.totp_secret, user.totp_enabled = secret, True
        prev_issued = _server_session_get(request, 'issued_at')
        inv_ts = max(time.time(), (float(prev_issued) if isinstance(prev_issued, (int, float)) else 0.0) + 1e-6)
        user.sessions_invalidated_at = datetime.fromtimestamp(inv_ts, tz=UTC)
        old_sid = str(request.session.get('sid') or '')
        store = getattr(request.app.state, 'session_store', None)
        if old_sid and store is not None:
            store.revoke(old_sid)
        new_ts = max(time.time(), user.sessions_invalidated_at.timestamp() + 0.001)
        established = _establish_session(request, user, tenant_id, True, issued_at=new_ts)
        new_csrf = established['csrf']
    else:
        _server_session_pop(request, 'pending_totp_secret', None)
        new_csrf = str(_server_session_get(request, 'csrf') or secrets.token_urlsafe(32))
        _server_session_set(request, mfa=True, csrf=new_csrf)
    set_tenant_context(db, tenant_id)
    record_audit(db, Principal(tenant_id=tenant_id, role=Role.viewer, user_id=user.id, email=user.email), 'auth.totp_verified', user.id)
    return {'ok': True, 'csrf': new_csrf}


# ---------------------------------------------------------------- WebAuthn (passkeys / security keys)


@router.post('/webauthn/register/begin')
def webauthn_register_begin(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                            principal: Principal | None = Depends(current_principal)):
    user = _session_user(request, db, settings, principal)
    challenge = secrets.token_urlsafe(32)
    _server_session_set(request, webauthn_register_challenge=challenge)
    return {'challenge': challenge, 'rp': {'name': settings.app_name, 'id': settings.base_url.split('://')[-1].split(':')[0]},
            'user': {'id': user.id, 'name': user.email, 'displayName': user.display_name or user.email}}


def _b64url_decode(val: str) -> bytes:
    padded = val.strip() + '=' * (-len(val.strip()) % 4)
    return base64.urlsafe_b64decode(padded)


def _verify_webauthn_assertion(cred: WebAuthnCredential, body: WebAuthnAuthCompleteBody) -> bool:
    if cred.public_key.lstrip().startswith('-----BEGIN PUBLIC KEY-----'):
        if not body.authenticator_data or not body.client_data_json:
            return False
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec

            auth_data = _b64url_decode(body.authenticator_data)
            client_data_bytes = _b64url_decode(body.client_data_json)
            sig_bytes = _b64url_decode(body.signature)
            client_data = loads(client_data_bytes.decode('utf-8', errors='replace'), {})
            if not isinstance(client_data, dict) or client_data.get('type') != 'webauthn.get':
                return False
            if str(client_data.get('challenge') or '') != body.challenge:
                return False
            if len(auth_data) < 37 or (auth_data[32] & 0x01) == 0:  # require UP (user present) bit
                return False
            pub = serialization.load_pem_public_key(cred.public_key.encode('utf-8'))
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                return False
            signed_payload = auth_data + hashlib.sha256(client_data_bytes).digest()
            pub.verify(sig_bytes, signed_payload, ec.ECDSA(hashes.SHA256()))
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False
    expected_sig = hmac.new(cred.public_key.encode(), f'{body.challenge}:{body.sign_count}'.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, body.signature)


@router.post('/webauthn/register/complete', status_code=201)
def webauthn_register_complete(body: WebAuthnRegisterCompleteBody, request: Request, db: Session = Depends(get_db),
                               settings: Settings = Depends(get_settings), principal: Principal | None = Depends(current_principal)):
    user = _session_user(request, db, settings, principal)
    expected = _server_session_pop(request, 'webauthn_register_challenge', '')
    if not expected or not hmac.compare_digest(expected, body.challenge):
        raise Unauthorized('Invalid or expired WebAuthn registration challenge')
    if db.execute(select(WebAuthnCredential).where(WebAuthnCredential.credential_id == body.credential_id)).scalar_one_or_none():
        raise Conflict('WebAuthn credential already registered')
    cred = WebAuthnCredential(user_id=user.id, credential_id=body.credential_id, public_key=body.public_key, name=body.name)
    db.add(cred)
    db.flush()
    tenant_id = str(_server_session_get(request, 'tenant_id', '') or (principal.tenant_id if principal else ''))
    if tenant_id:
        set_tenant_context(db, tenant_id)
        record_audit(db, Principal(tenant_id=tenant_id, role=Role.viewer, user_id=user.id, email=user.email),
                     'auth.webauthn_registered', cred.id, {'name': cred.name})
    return {'id': cred.id, 'credential_id': cred.credential_id, 'name': cred.name, 'created_at': cred.created_at}


@router.post('/webauthn/authenticate/begin')
def webauthn_auth_begin(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                        principal: Principal | None = Depends(current_principal)):
    user = _session_user(request, db, settings, principal)
    creds = db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id)).scalars().all()
    if not creds:
        raise NotFound('No WebAuthn credentials registered for this user')
    challenge = secrets.token_urlsafe(32)
    _server_session_set(request, webauthn_auth_challenge=challenge)
    return {'challenge': challenge, 'allowCredentials': [{'type': 'public-key', 'id': c.credential_id} for c in creds]}


@router.post('/webauthn/authenticate/complete')
def webauthn_auth_complete(body: WebAuthnAuthCompleteBody, request: Request, db: Session = Depends(get_db),
                           settings: Settings = Depends(get_settings), principal: Principal | None = Depends(current_principal)):
    user = _session_user(request, db, settings, principal)
    expected_challenge = _server_session_pop(request, 'webauthn_auth_challenge', '')
    if not expected_challenge or not hmac.compare_digest(expected_challenge, body.challenge):
        raise Unauthorized('Invalid or expired WebAuthn authentication challenge')
    cred = db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id,
                                                       WebAuthnCredential.credential_id == body.credential_id)).scalar_one_or_none()
    if cred is None:
        raise Unauthorized('Unknown WebAuthn credential')
    if not _verify_webauthn_assertion(cred, body):
        raise Unauthorized('Invalid WebAuthn assertion signature')
    if body.sign_count <= cred.sign_count:
        raise Unauthorized('WebAuthn clone/replay detected: sign_count did not advance')
    cred.sign_count = body.sign_count
    cred.last_used_at = utcnow()
    _server_session_set(request, mfa=True)
    tenant_id = str(_server_session_get(request, 'tenant_id', '') or (principal.tenant_id if principal else ''))
    if tenant_id:
        set_tenant_context(db, tenant_id)
        record_audit(db, Principal(tenant_id=tenant_id, role=Role.viewer, user_id=user.id, email=user.email),
                     'auth.webauthn_verified', cred.id)
    return {'ok': True, 'mfa': True, 'csrf': _server_session_get(request, 'csrf')}


# ---------------------------------------------------------------- OIDC & SAML


def _apply_idp_groups(db: Session, user: User, groups: list[str], settings: Settings) -> None:
    """Map IdP group names ('group=tenant_slug:role,group2=role') to Tenant memberships and roles."""
    if not settings.oidc_group_role_map or not groups:
        return
    group_set = {str(g).strip() for g in groups if str(g).strip()}
    for item in settings.oidc_group_role_map.split(','):
        item = item.strip()
        if not item or '=' not in item:
            continue
        grp, _, target_spec = item.partition('=')
        if grp.strip() not in group_set:
            continue
        if ':' in target_spec:
            t_slug, _, role_str = target_spec.partition(':')
        else:
            t_slug, role_str = settings.default_tenant_slug, target_spec
        t_slug, role_str = t_slug.strip(), role_str.strip()
        if role_str not in {r.value for r in Role}:
            continue
        tenant = db.execute(select(Tenant).where(Tenant.slug == t_slug)).scalar_one_or_none()
        if tenant is None:
            continue
        membership = db.execute(select(Membership).where(Membership.user_id == user.id, Membership.tenant_id == tenant.id)).scalar_one_or_none()
        if membership is None:
            db.add(Membership(user_id=user.id, tenant_id=tenant.id, role=role_str))
        else:
            membership.role = role_str
    db.flush()


def _oidc_mfa_satisfied(claims: dict, settings: Settings) -> bool:
    required = {x.strip().lower() for x in (settings.oidc_required_acr or '').split(',') if x.strip()}
    if not required:
        return True
    acr = str(claims.get('acr') or '').strip().lower()
    amr_raw = claims.get('amr') or []
    amr = {str(x).strip().lower() for x in (amr_raw if isinstance(amr_raw, list) else [amr_raw]) if str(x).strip()}
    return bool((acr and acr in required) or (amr & required))


@router.get('/oidc/start')
async def oidc_start(request: Request, settings: Settings = Depends(get_settings)):
    if not settings.oidc_issuer or not settings.oidc_client_id:
        raise NotFound('OIDC is not configured')
    doc = await oidc_discover(settings.oidc_issuer)
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    verifier, challenge = pkce_pair()
    _server_session_set(request, oidc_state=state, oidc_nonce=nonce, oidc_verifier=verifier)
    return RedirectResponse(oidc_authorize_url(doc, settings, state, nonce, challenge), status_code=302)


@router.get('/oidc/callback')
async def oidc_callback(request: Request, code: str = '', state: str = '', db: Session = Depends(get_db),
                        settings: Settings = Depends(get_settings)):
    expected_state = _server_session_get(request, 'oidc_state')
    if not code or not state or state != expected_state:
        raise Unauthorized('Invalid OIDC state')
    doc = await oidc_discover(settings.oidc_issuer)
    verifier = _server_session_pop(request, 'oidc_verifier', '')
    nonce = _server_session_pop(request, 'oidc_nonce', '')
    _server_session_pop(request, 'oidc_state', None)
    claims = await oidc_exchange_code(doc, settings, code, verifier, nonce)
    email = (claims.get('email') or '').lower()
    if not email:
        raise Unauthorized('OIDC token has no email claim')
    allowed = [d.strip().lower() for d in settings.oidc_allowed_domains.split(',') if d.strip()]
    if allowed and email.split('@')[-1] not in allowed:
        raise Forbidden('Email domain is not allowed')
    mfa_ok = _oidc_mfa_satisfied(claims, settings)
    if settings.oidc_required_acr and settings.totp_required and not mfa_ok:
        raise Forbidden('OIDC token does not satisfy OIDC_REQUIRED_ACR')
    identity = db.execute(select(OidcIdentity).where(OidcIdentity.issuer == doc.issuer, OidcIdentity.subject == claims['sub'])).scalar_one_or_none()
    user = db.get(User, identity.user_id) if identity else None
    if user is None:
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is not None and claims.get('email_verified') is not True and not settings.oidc_trust_email:
            # Linking an SSO subject to an existing account by email alone hands over that account to whoever
            # controls the address at the IdP. Require the IdP to assert the address, or an explicit opt-in.
            raise Forbidden('The identity provider did not assert email_verified; set OIDC_TRUST_EMAIL=true to link accounts by email')
    if not user:
        if not settings.oidc_auto_provision:
            raise Forbidden('User is not provisioned')
        user = User(email=email, display_name=claims.get('name', ''))
        db.add(user)
        db.flush()
        tenant = db.execute(select(Tenant).where(Tenant.slug == settings.default_tenant_slug)).scalar_one()
        db.add(Membership(user_id=user.id, tenant_id=tenant.id, role=settings.oidc_default_role))
        db.flush()
    if not identity:
        db.add(OidcIdentity(user_id=user.id, issuer=doc.issuer, subject=claims['sub']))
    raw_groups = claims.get(settings.oidc_group_claim) or []
    groups = [str(g) for g in (raw_groups if isinstance(raw_groups, list) else [raw_groups]) if g]
    _apply_idp_groups(db, user, groups, settings)
    memberships = _memberships(db, user.id)
    if not memberships:
        raise Forbidden('User has no tenant membership')
    user.last_login_at = utcnow()
    _establish_session(request, user, memberships[0][1].id, mfa_ok)
    set_tenant_context(db, memberships[0][1].id)
    record_audit(db, Principal(tenant_id=memberships[0][1].id, role=Role(memberships[0][0].role), user_id=user.id, email=user.email),
                 'auth.login', user.id, {'method': 'oidc', 'issuer': doc.issuer, 'mfa': mfa_ok})
    return RedirectResponse('/', status_code=302)


@router.get('/saml/metadata')
def saml_metadata(settings: Settings = Depends(get_settings)):
    if not settings.saml_idp_entity_id:
        raise NotFound('SAML is not configured')
    entity_id = settings.base_url.rstrip('/') + '/api/v1/auth/saml/metadata'
    acs_url = settings.base_url.rstrip('/') + '/api/v1/auth/saml/acs'
    xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">'
        f'<SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" '
        f'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        f'<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{acs_url}" index="0" isDefault="true"/>'
        f'</SPSSODescriptor></EntityDescriptor>'
    )
    return Response(content=xml, media_type='application/samlmetadata+xml')


_SAML_SEEN_IDS: dict[str, float] = {}


def _parse_saml_ts(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.strip().replace('Z', '+00:00'))
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def _verify_saml_signature(saml_b64: str, signature: str, settings: Settings) -> bool:
    cert_pem = getattr(settings, 'saml_idp_cert_pem', '') or ''
    if cert_pem.strip():
        try:
            from cryptography import x509
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding, rsa

            cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
            pub = cert.public_key()
            if not isinstance(pub, rsa.RSAPublicKey):
                return False
            try:
                sig_bytes = bytes.fromhex(signature)
            except ValueError:
                sig_bytes = base64.b64decode(signature)
            pub.verify(sig_bytes, saml_b64.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False
    if settings.saml_signing_secret:
        expected_sig = hmac.new(settings.saml_signing_secret.encode(), saml_b64.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, signature)
    return False


def _extract_saml_form_or_json(raw_body: str) -> tuple[str, str]:
    if raw_body.lstrip().startswith('{'):
        data = loads(raw_body, {})
        if isinstance(data, dict):
            return str(data.get('SAMLResponse') or ''), str(data.get('Signature') or '')
        return '', ''
    parsed = parse_qs(raw_body)
    return (parsed.get('SAMLResponse') or [''])[0], (parsed.get('Signature') or [''])[0]


def _validate_saml_conditions_and_replay(root: Any, settings: Settings) -> None:
    now_dt = utcnow()
    skew = timedelta(seconds=60)
    acs_url = settings.base_url.rstrip('/') + '/api/v1/auth/saml/acs'
    for el in root.iter():
        if el.tag.endswith('Conditions'):
            nb = _parse_saml_ts(el.attrib.get('NotBefore', ''))
            noa = _parse_saml_ts(el.attrib.get('NotOnOrAfter', ''))
            if (nb and now_dt < nb - skew) or (noa and now_dt >= noa + skew):
                raise Unauthorized('SAML assertion is expired or not yet valid')
        elif el.tag.endswith('SubjectConfirmationData'):
            noa = _parse_saml_ts(el.attrib.get('NotOnOrAfter', ''))
            recipient = el.attrib.get('Recipient', '').strip()
            if noa and now_dt >= noa + skew:
                raise Unauthorized('SAML SubjectConfirmationData has expired')
            if recipient and recipient != acs_url:
                raise Unauthorized('SAML Recipient mismatch')
    assertion_id = next((el.attrib.get('ID', '').strip() for el in root.iter() if el.tag.endswith('Assertion') and el.attrib.get('ID')), '') or root.attrib.get('ID', '').strip()
    if assertion_id:
        now_ts = time.time()
        if len(_SAML_SEEN_IDS) > 4096:
            for k in [k for k, exp in _SAML_SEEN_IDS.items() if exp <= now_ts]:
                _SAML_SEEN_IDS.pop(k, None)
        if _SAML_SEEN_IDS.get(assertion_id, 0.0) > now_ts:
            raise Unauthorized('SAML assertion replay detected')
        _SAML_SEEN_IDS[assertion_id] = now_ts + 3600.0


@router.post('/saml/acs')
async def saml_acs(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    if not settings.saml_idp_entity_id or not (settings.saml_signing_secret or getattr(settings, 'saml_idp_cert_pem', '')):
        raise NotFound('SAML is not configured')
    raw_body = (await request.body()).decode('utf-8', errors='replace')
    SAMLResponse, Signature = _extract_saml_form_or_json(raw_body)
    if not SAMLResponse or not Signature:
        raise Unauthorized('Missing SAMLResponse or Signature')
    if not _verify_saml_signature(SAMLResponse, Signature, settings):
        raise Unauthorized('Invalid SAML assertion signature')
    try:
        raw_xml = base64.b64decode(SAMLResponse)
        root = DefusedET.fromstring(raw_xml)
    except (ValueError, DefusedET.ParseError) as exc:
        raise Unauthorized('Malformed SAML XML') from exc
    issuer = next((el.text.strip() for el in root.iter() if el.tag.endswith('Issuer') and el.text), '')
    if issuer != settings.saml_idp_entity_id:
        raise Unauthorized('SAML Issuer mismatch')
    _validate_saml_conditions_and_replay(root, settings)
    email = next((el.text.strip().lower() for el in root.iter() if el.tag.endswith('NameID') and el.text), '')
    if not email:
        raise Unauthorized('SAML assertion missing NameID email')
    groups = [el.text.strip() for el in root.iter() if el.tag.endswith('AttributeValue') and el.text]
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user:
        if not settings.oidc_auto_provision:
            raise Forbidden('User is not provisioned')
        user = User(email=email, display_name=email.split('@')[0])
        db.add(user)
        db.flush()
        tenant = db.execute(select(Tenant).where(Tenant.slug == settings.default_tenant_slug)).scalar_one()
        db.add(Membership(user_id=user.id, tenant_id=tenant.id, role=settings.oidc_default_role))
        db.flush()
    _apply_idp_groups(db, user, groups, settings)
    memberships = _memberships(db, user.id)
    if not memberships:
        raise Forbidden('User has no tenant membership')
    user.last_login_at = utcnow()
    payload = _establish_session(request, user, memberships[0][1].id, True)
    set_tenant_context(db, memberships[0][1].id)
    record_audit(db, Principal(tenant_id=memberships[0][1].id, role=Role(memberships[0][0].role), user_id=user.id, email=user.email),
                 'auth.login', user.id, {'method': 'saml', 'issuer': issuer})
    return payload


# ---------------------------------------------------------------- API keys


def _key_dict(key: ApiKey) -> dict:
    return {'id': key.id, 'name': key.name, 'prefix': key.prefix, 'role': key.role,
            'scopes': [s for s in key.scopes.split(',') if s],
            'allowed_ips': [ip for ip in (key.allowed_ips or '').split(',') if ip],
            'created_by': key.created_by, 'created_at': key.created_at, 'expires_at': key.expires_at,
            'last_used_at': key.last_used_at, 'revoked_at': key.revoked_at}


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
            raise ArgusError(f'Unknown scope {scope!r}', code='invalid_scope', status=400)
    if len(body.scopes) > 32:
        raise ArgusError('Too many scopes', code='invalid_scope', status=400)
    cleaned_ips: list[str] = []
    for ip_spec in body.allowed_ips:
        spec = ip_spec.strip()
        if not spec:
            continue
        try:
            if '/' in spec:
                ipaddress.ip_network(spec, strict=False)
            else:
                ipaddress.ip_address(spec)
        except ValueError as exc:
            raise ArgusError(f'Invalid IP or CIDR {spec!r}', code='invalid_ip', status=400) from exc
        cleaned_ips.append(spec)
    if principal.auth == 'api_key' and principal.scopes:
        if not body.scopes:
            raise Forbidden('A scoped API key cannot mint an unrestricted API key')
        for scope in body.scopes:
            if scope == 'ingest':
                permitted = 'ingest' in principal.scopes
            elif scope.endswith(':*'):
                prefix = scope[:-1]
                permitted = all(has(principal, p) for p in ALL_PERMISSIONS if p.startswith(prefix))
            else:
                permitted = has(principal, scope)
            if not permitted:
                raise Forbidden(f'API key cannot delegate scope {scope!r}')
    created_by = principal.user_id or ''
    if not created_by and principal.auth == 'api_key' and principal.api_key_id:
        minting_key = db.get(ApiKey, principal.api_key_id)
        created_by = (minting_key.created_by if minting_key else '') or ''
    if not created_by:
        raise Forbidden('API keys without a recorded creator cannot mint keys')
    plaintext, prefix, key_hash = generate_api_key()
    expires_at = utcnow() + timedelta(days=body.expires_in_days)
    key = ApiKey(tenant_id=principal.tenant_id, name=body.name, prefix=prefix, key_hash=key_hash, role=body.role,
                 scopes=','.join(sorted(set(body.scopes))), allowed_ips=','.join(cleaned_ips),
                 created_by=created_by, expires_at=expires_at)
    db.add(key)
    db.flush()
    record_audit(db, principal, 'auth.api_key_created', key.id,
                 {'name': body.name, 'role': body.role, 'scopes': body.scopes, 'expires_at': expires_at.isoformat()})
    return {**_key_dict(key), 'key': plaintext}


@router.delete('/api-keys/{key_id}')
def revoke_api_key(key_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:api_keys'))):
    key = db.execute(select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == principal.tenant_id)).scalar_one_or_none()
    if not key:
        raise NotFound('API key not found')
    key.revoked_at = utcnow()
    record_audit(db, principal, 'auth.api_key_revoked', key.id, {'name': key.name})
    return {'ok': True}
