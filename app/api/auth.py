from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlparse

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

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
from ..models import ApiKey, Membership, OidcIdentity, Tenant, User, WebAuthnCredential, utcnow
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


WEBAUTHN_CEREMONY_SECONDS = 300
EMAIL_RE = re.compile(r'^[^@\s]{1,64}@[^@\s]{1,190}$')


class WebAuthnRegisterBeginBody(BaseModel):
    enrollment_code: str = Field(default='', max_length=128)


class WebAuthnRegisterCompleteBody(BaseModel):
    """`credential` is the browser's PublicKeyCredential from navigator.credentials.create(), serialized as JSON."""
    credential: dict[str, Any]
    name: str = Field(default='Security Key', max_length=120)


class WebAuthnAuthCompleteBody(BaseModel):
    """`credential` is the browser's PublicKeyCredential from navigator.credentials.get(), serialized as JSON."""
    credential: dict[str, Any]


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
    elif settings.totp_required or (settings.is_production and settings.oidc_issuer) or _webauthn_credentials(db, user.id):
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
    if _webauthn_credentials(db, user.id):
        if not _server_session_get(request, 'mfa'):
            raise Forbidden('Complete multi-factor sign-in before adding an authenticator')
    else:
        _consume_enrollment_code(user, (body.enrollment_code if body else '') or '', settings.totp_require_enrollment_code)
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
#
# The ceremonies are verified by the `webauthn` library (py_webauthn): attestation parsing, origin and RP ID binding,
# user verification, signature checks and the signature counter. Nothing here trusts a value the browser could invent.


def _webauthn_rp(settings: Settings) -> tuple[str, str]:
    """(rp_id, origin) from BASE_URL. WebAuthn binds every credential to this origin, which is what makes it
    phishing-resistant: an assertion produced for another site's origin never verifies here."""
    parsed = urlparse(settings.base_url)
    origin = f'{parsed.scheme}://{parsed.netloc}'
    return (parsed.hostname or 'localhost'), origin


def _webauthn_credentials(db: Session, user_id: str) -> list[WebAuthnCredential]:
    return list(db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user_id)).scalars().all())


def _consume_enrollment_code(user: User, code: str, required: bool) -> None:
    """First-factor enrolment gate shared by TOTP and WebAuthn: when an administrator issued a one-time code (or the
    deployment requires one), a password alone is not enough to attach an authenticator to the account."""
    if not (required or user.totp_enrollment_token_hash):
        return
    expected = user.totp_enrollment_token_hash or ''
    given = hashlib.sha256(code.encode()).hexdigest() if code else ''
    if not expected or not given or not hmac.compare_digest(expected, given):
        raise Forbidden('Enrollment requires a valid one-time code issued by an administrator')
    user.totp_enrollment_token_hash = ''


@router.post('/webauthn/register/begin')
def webauthn_register_begin(request: Request, body: WebAuthnRegisterBeginBody | None = None, db: Session = Depends(get_db),
                            settings: Settings = Depends(get_settings),
                            principal: Principal | None = Depends(current_principal)):
    user = _session_user(request, db, settings, principal)
    existing = _webauthn_credentials(db, user.id)
    has_factor = bool(user.totp_enabled or existing)
    if has_factor and not _server_session_get(request, 'mfa'):
        # Adding an authenticator is itself a privileged act: it needs the factor the account already has.
        raise Forbidden('Complete multi-factor sign-in before adding an authenticator')
    if not has_factor:
        _consume_enrollment_code(user, (body.enrollment_code if body else '') or '', settings.totp_require_enrollment_code)
    rp_id, _ = _webauthn_rp(settings)
    options = generate_registration_options(
        rp_id=rp_id, rp_name='Argus', user_name=user.email, user_id=user.id.encode(),
        user_display_name=user.display_name or user.email,
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id)) for c in existing],
        authenticator_selection=AuthenticatorSelectionCriteria(user_verification=UserVerificationRequirement.REQUIRED),
    )
    _server_session_set(request, pending_webauthn_reg=bytes_to_base64url(options.challenge), pending_webauthn_reg_at=time.time())
    return json.loads(options_to_json(options))


@router.post('/webauthn/register/complete', status_code=201)
def webauthn_register_complete(body: WebAuthnRegisterCompleteBody, request: Request, db: Session = Depends(get_db),
                               settings: Settings = Depends(get_settings),
                               principal: Principal | None = Depends(current_principal)):
    user = _session_user(request, db, settings, principal)
    challenge = _server_session_pop(request, 'pending_webauthn_reg', None)
    started = _server_session_pop(request, 'pending_webauthn_reg_at', 0) or 0
    if not challenge or time.time() - float(started) > WEBAUTHN_CEREMONY_SECONDS:
        raise Unauthorized('No registration in progress; start again')
    existing = _webauthn_credentials(db, user.id)
    had_factor = bool(user.totp_enabled or existing)
    if had_factor and not _server_session_get(request, 'mfa'):
        raise Forbidden('Complete multi-factor sign-in before adding an authenticator')
    rp_id, origin = _webauthn_rp(settings)
    try:
        verified = verify_registration_response(
            credential=body.credential, expected_challenge=base64url_to_bytes(str(challenge)),
            expected_rp_id=rp_id, expected_origin=origin, require_user_verification=True)
    except Exception as exc:  # noqa: BLE001 - the library raises several types; every one of them means "not verified"
        raise Unauthorized('WebAuthn registration could not be verified') from exc
    credential_id = bytes_to_base64url(verified.credential_id)
    if db.execute(select(WebAuthnCredential.id).where(WebAuthnCredential.credential_id == credential_id)).first():
        raise Conflict('Credential already registered')
    cred = WebAuthnCredential(user_id=user.id, credential_id=credential_id,
                              public_key=bytes_to_base64url(verified.credential_public_key),
                              sign_count=int(verified.sign_count), name=body.name.strip() or 'Security Key')
    db.add(cred)
    db.flush()
    tenant_id = str(_server_session_get(request, 'tenant_id', '') or (principal.tenant_id if principal else ''))
    csrf = str(_server_session_get(request, 'csrf') or '')
    if not had_factor:
        # First authenticator on the account: every other session predates it, so end them and re-issue this one
        # as MFA-satisfied (the user just proved possession and user verification).
        prev_issued = _server_session_get(request, 'issued_at')
        inv_ts = max(time.time(), (float(prev_issued) if isinstance(prev_issued, (int, float)) else 0.0) + 1e-6)
        user.sessions_invalidated_at = datetime.fromtimestamp(inv_ts, tz=UTC)
        old_sid = str(request.session.get('sid') or '')
        store = getattr(request.app.state, 'session_store', None)
        if old_sid and store is not None:
            store.revoke(old_sid)
        csrf = _establish_session(request, user, tenant_id, True, issued_at=max(time.time(), inv_ts + 0.001))['csrf']
    set_tenant_context(db, tenant_id)
    record_audit(db, Principal(tenant_id=tenant_id, role=Role.viewer, user_id=user.id, email=user.email),
                 'auth.webauthn_registered', user.id, {'credential': credential_id[:16], 'name': cred.name})
    return {'ok': True, 'id': cred.id, 'credential_id': credential_id, 'csrf': csrf}


@router.post('/webauthn/authenticate/begin')
def webauthn_auth_begin(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                        principal: Principal | None = Depends(current_principal)):
    user = _session_user(request, db, settings, principal)
    creds = _webauthn_credentials(db, user.id)
    if not creds:
        raise Conflict('No WebAuthn credentials registered')
    rp_id, _ = _webauthn_rp(settings)
    options = generate_authentication_options(
        rp_id=rp_id, user_verification=UserVerificationRequirement.REQUIRED,
        allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id)) for c in creds])
    _server_session_set(request, pending_webauthn_auth=bytes_to_base64url(options.challenge), pending_webauthn_auth_at=time.time())
    return json.loads(options_to_json(options))


@router.post('/webauthn/authenticate/complete')
def webauthn_auth_complete(body: WebAuthnAuthCompleteBody, request: Request, db: Session = Depends(get_db),
                           settings: Settings = Depends(get_settings),
                           principal: Principal | None = Depends(current_principal)):
    user = _session_user(request, db, settings, principal)
    key = f'webauthn:{user.id}'
    _throttle(request, settings, key)
    challenge = _server_session_pop(request, 'pending_webauthn_auth', None)
    started = _server_session_pop(request, 'pending_webauthn_auth_at', 0) or 0
    if not challenge or time.time() - float(started) > WEBAUTHN_CEREMONY_SECONDS:
        raise Unauthorized('No authentication in progress; start again')
    raw_id = str(body.credential.get('id') or '')
    cred = db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id,
                                                       WebAuthnCredential.credential_id == raw_id)).scalar_one_or_none()
    rp_id, origin = _webauthn_rp(settings)
    try:
        if cred is None:
            raise ValueError('unknown credential')
        verified = verify_authentication_response(
            credential=body.credential, expected_challenge=base64url_to_bytes(str(challenge)),
            expected_rp_id=rp_id, expected_origin=origin, credential_public_key=base64url_to_bytes(cred.public_key),
            credential_current_sign_count=int(cred.sign_count or 0), require_user_verification=True)
    except Exception as exc:  # noqa: BLE001 - see registration: any library error means "not verified"
        _record_failure(request, key)
        raise Unauthorized('WebAuthn assertion could not be verified') from exc
    _clear_failures(request, key)
    cred.sign_count = int(verified.new_sign_count)
    cred.last_used_at = utcnow()
    new_csrf = str(_server_session_get(request, 'csrf') or secrets.token_urlsafe(32))
    _server_session_set(request, mfa=True, csrf=new_csrf)
    tenant_id = str(_server_session_get(request, 'tenant_id', '') or (principal.tenant_id if principal else ''))
    set_tenant_context(db, tenant_id)
    record_audit(db, Principal(tenant_id=tenant_id, role=Role.viewer, user_id=user.id, email=user.email),
                 'auth.webauthn_verified', user.id, {'credential': cred.credential_id[:16]})
    return {'ok': True, 'csrf': new_csrf}


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
    if settings.oidc_required_acr and not mfa_ok:
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


# SAML 2.0 is handled by python3-saml (the OneLogin toolkit): XML signature verification against the pinned IdP
# certificate, Destination/Recipient/Audience/time-window checks and InResponseTo matching all happen in the library,
# in strict mode. Argus adds only what the toolkit leaves to the application: one-time AuthnRequest IDs (which also
# makes a captured response unreplayable) and the mapping from the verified assertion to an Argus account.

_SAML_PENDING: dict[str, tuple[str, float]] = {}  # fallback when no shared session store is configured
SAML_REQUEST_TTL = 600


def _saml_configured(settings: Settings) -> bool:
    return bool(settings.saml_idp_entity_id and settings.saml_idp_sso_url and settings.saml_idp_cert_pem)


def _saml_toolkit_settings(settings: Settings) -> dict[str, Any]:
    base = settings.base_url.rstrip('/')
    return {
        'strict': True,
        'debug': False,
        'sp': {
            'entityId': f'{base}/api/v1/auth/saml/metadata',
            'assertionConsumerService': {'url': f'{base}/api/v1/auth/saml/acs',
                                         'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'},
            'NameIDFormat': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        },
        'idp': {
            'entityId': settings.saml_idp_entity_id,
            'singleSignOnService': {'url': settings.saml_idp_sso_url,
                                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'},
            'x509cert': settings.saml_idp_cert_pem,
        },
        'security': {
            'wantAssertionsSigned': True,      # an unsigned assertion is never accepted
            'wantNameId': True,
            'wantAttributeStatement': False,   # an IdP that sends no attributes is still a valid sign-in
            'rejectDeprecatedAlgorithm': True,  # no SHA-1 signatures or digests
            'requestedAuthnContext': False,
            'allowRepeatAttributeName': False,
        },
    }


def _saml_auth(settings: Settings, request: Request, post: dict[str, str] | None = None) -> OneLogin_Saml2_Auth:
    # Host and scheme come from BASE_URL, never from request headers, so Destination and Recipient are checked
    # against the address the operator configured rather than one the caller supplied.
    parsed = urlparse(settings.base_url)
    req = {'https': 'on' if parsed.scheme == 'https' else 'off', 'http_host': parsed.netloc,
           'script_name': request.url.path, 'get_data': dict(request.query_params), 'post_data': post or {}}
    return OneLogin_Saml2_Auth(req, old_settings=_saml_toolkit_settings(settings))


def _saml_remember_request(request: Request, request_id: str) -> str:
    """Record an issued AuthnRequest ID and return the RelayState handle that finds it again. The IdP posts the
    response cross-site, where the session cookie is not sent, so the handle travels in RelayState instead."""
    store = getattr(request.app.state, 'session_store', None)
    if store is not None:
        return str(store.create({'saml_request_id': request_id}, ttl=SAML_REQUEST_TTL))
    now = time.time()
    for key in [k for k, (_, exp) in _SAML_PENDING.items() if exp <= now]:
        _SAML_PENDING.pop(key, None)
    handle = secrets.token_urlsafe(24)
    _SAML_PENDING[handle] = (request_id, now + SAML_REQUEST_TTL)
    return handle


def _saml_take_request(request: Request, handle: str) -> str:
    """One-time lookup: the request ID is consumed, so a response can be accepted at most once."""
    if not handle:
        return ''
    store = getattr(request.app.state, 'session_store', None)
    if store is not None:
        data = store.get(handle) or {}
        store.revoke(handle)
        return str(data.get('saml_request_id') or '')
    request_id, exp = _SAML_PENDING.pop(handle, ('', 0.0))
    return request_id if exp > time.time() else ''


@router.get('/saml/metadata')
def saml_metadata(settings: Settings = Depends(get_settings)):
    if not _saml_configured(settings):
        raise NotFound('SAML is not configured')
    sp = OneLogin_Saml2_Settings(_saml_toolkit_settings(settings), sp_validation_only=True)
    return Response(content=sp.get_sp_metadata(), media_type='application/samlmetadata+xml')


@router.get('/saml/login')
def saml_login(request: Request, settings: Settings = Depends(get_settings)):
    if not _saml_configured(settings):
        raise NotFound('SAML is not configured')
    auth = _saml_auth(settings, request)
    # The toolkit builds the redirect; RelayState is replaced with our one-time handle for the request it just made.
    url = auth.login(return_to='pending')
    handle = _saml_remember_request(request, auth.get_last_request_id())
    return RedirectResponse(url.replace('RelayState=pending', f'RelayState={handle}'), status_code=302)


@router.post('/saml/acs')
async def saml_acs(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    if not _saml_configured(settings):
        raise NotFound('SAML is not configured')
    form = parse_qs((await request.body()).decode('utf-8', 'replace'))
    post = {k: v[0] for k, v in form.items() if v}
    request_id = _saml_take_request(request, post.get('RelayState', ''))
    if not post.get('SAMLResponse') or not request_id:
        # No matching sign-in started here: IdP-initiated and replayed responses both end up on this branch.
        raise Unauthorized('SAML response does not match a sign-in started from Argus')
    auth = _saml_auth(settings, request, post)
    try:
        auth.process_response(request_id=request_id)
    except Exception as exc:  # noqa: BLE001 - malformed input surfaces as several toolkit and XML error types
        raise Unauthorized('SAML response could not be verified') from exc
    if auth.get_errors() or not auth.is_authenticated():
        raise Unauthorized('SAML response could not be verified')
    required_ctx = {x.strip() for x in (settings.saml_required_authn_context or '').split(',') if x.strip()}
    if required_ctx and not (required_ctx & set(auth.get_last_authn_contexts() or [])):
        raise Forbidden('The identity provider did not report the required authentication strength')
    subject = str(auth.get_nameid() or '').strip()
    email = subject.lower()
    if not EMAIL_RE.match(email):
        raise Unauthorized('SAML assertion did not carry an email NameID')
    issuer = settings.saml_idp_entity_id
    identity = db.execute(select(OidcIdentity).where(OidcIdentity.issuer == issuer, OidcIdentity.subject == subject)).scalar_one_or_none()
    user = db.get(User, identity.user_id) if identity else None
    if user is None:
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is None:
        if not settings.oidc_auto_provision:
            raise Forbidden('User is not provisioned')
        user = User(email=email, display_name=email.split('@')[0])
        db.add(user)
        db.flush()
        tenant = db.execute(select(Tenant).where(Tenant.slug == settings.default_tenant_slug)).scalar_one()
        db.add(Membership(user_id=user.id, tenant_id=tenant.id, role=settings.oidc_default_role))
        db.flush()
    if not user.is_active:
        raise Forbidden('Account is disabled')
    if identity is None:
        db.add(OidcIdentity(user_id=user.id, issuer=issuer, subject=subject))
    # Only the configured group attribute is read; other attribute values never grant a role.
    groups = [str(g) for g in (auth.get_attributes() or {}).get(settings.saml_group_attribute, []) if g]
    _apply_idp_groups(db, user, groups, settings)
    memberships = _memberships(db, user.id)
    if not memberships:
        raise Forbidden('User has no tenant membership')
    user.last_login_at = utcnow()
    _establish_session(request, user, memberships[0][1].id, True)
    set_tenant_context(db, memberships[0][1].id)
    record_audit(db, Principal(tenant_id=memberships[0][1].id, role=Role(memberships[0][0].role), user_id=user.id, email=user.email),
                 'auth.login', user.id, {'method': 'saml', 'issuer': issuer})
    return RedirectResponse('/', status_code=303)


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
