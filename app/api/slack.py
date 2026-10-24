"""Slack interactivity: Approve / Deny / Roll back buttons on action messages.

POST /api/v1/slack/interactions/{integration_id} is public (Slack calls it) and authenticated by the
Slack request signature (v0 HMAC-SHA256 over 'v0:{timestamp}:{body}' with the integration's
signing_secret), a 5-minute timestamp window and a replay cache. The clicking Slack user is mapped
to an Argus user with a membership in the integration's tenant; the broker then applies the same
permission, separation-of-duty and policy checks as the web UI. A click does not pass Argus login
or MFA, so high and critical actions are refused from Slack unless the integration sets
allow_high_risk=true.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from urllib.parse import parse_qs, urlsplit

import httpx
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..actions import broker
from ..core.audit import record_audit
from ..core.db import get_scoped
from ..core.errors import ArgusError, Unauthorized
from ..core.rbac import Principal, Role
from ..core.security import redact
from ..integrations.delivery import resolve_secrets
from ..models import Membership, Tenant, User, loads
from ..models.actions import ActionRequest, ActionRun
from ..models.integrations import IntegrationConfig
from .deps import RateLimiter, get_db

router = APIRouter(prefix='/api/v1/slack', tags=['slack'])
log = logging.getLogger('argus.integrations.slack')

MAX_BODY = 64 * 1024
MAX_SKEW_SECONDS = 300
HIGH_RISKS = ('high', 'critical')
USERS_INFO_URL = 'https://slack.com/api/users.info'
RESPONSE_HOSTS = {'hooks.slack.com'}
ACTIONS = {'argus_approve': 'approve', 'argus_deny': 'reject', 'argus_rollback': 'rollback'}


def _reject() -> Unauthorized:
    # One answer for every authentication failure so callers cannot tell a missing integration from a bad signature.
    return Unauthorized('invalid Slack request')


def _seen(app, signature: str, now: float) -> bool:
    cache: dict[str, float] | None = getattr(app.state, 'slack_replay_cache', None)
    if cache is None:
        cache = {}
        app.state.slack_replay_cache = cache
    for key in [k for k, t in cache.items() if now - t > MAX_SKEW_SECONDS * 2]:
        del cache[key]
    if signature in cache:
        return True
    cache[signature] = now
    return False


def verify(secret: str, timestamp: str, body: bytes, signature: str, now: float | None = None) -> bool:
    if not secret or not timestamp or not signature or not timestamp.isdigit():
        return False
    if abs((now if now is not None else time.time()) - int(timestamp)) > MAX_SKEW_SECONDS:
        return False
    base = b'v0:' + timestamp.encode() + b':' + body
    expected = 'v0=' + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """Signature Slack would send (used by tests and by operators debugging their app)."""
    return 'v0=' + hmac.new(secret.encode(), b'v0:' + timestamp.encode() + b':' + body, hashlib.sha256).hexdigest()


async def _read(request: Request) -> bytes:
    declared = request.headers.get('content-length', '')
    if declared.isdigit() and int(declared) > MAX_BODY:
        raise _reject()
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY:
            raise _reject()
        chunks.append(chunk)
    return b''.join(chunks)


async def _email_from_slack(token: str, slack_user: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            response = await client.get(USERS_INFO_URL, params={'user': slack_user}, headers={'Authorization': f'Bearer {token}'})
        data = response.json() if response.status_code == 200 else {}
    except (httpx.HTTPError, ValueError):
        return ''
    if not data.get('ok'):
        return ''
    return str(((data.get('user') or {}).get('profile') or {}).get('email') or '')


async def _principal(db: Session, row: IntegrationConfig, config: dict, secrets: dict, slack_user: str) -> tuple[Principal | None, str]:
    """(principal, reason). The Slack user must map to an active Argus user with a membership in the tenant."""
    email = ''
    user_map = config.get('user_map') if isinstance(config.get('user_map'), dict) else {}
    if slack_user in user_map:
        email = str(user_map[slack_user])
    elif config.get('resolve_users_by_email') and secrets.get('bot_token'):
        email = await _email_from_slack(secrets['bot_token'], slack_user)
    if not email:
        return None, 'Your Slack account is not linked to an Argus user. Ask an admin to add it to the integration user_map.'
    user = db.execute(select(User).where(func.lower(User.email) == email.lower())).scalar_one_or_none()
    if user is None or not user.is_active:
        return None, 'The Argus user linked to your Slack account does not exist or is disabled.'
    membership = db.execute(select(Membership).where(Membership.user_id == user.id, Membership.tenant_id == row.tenant_id)).scalar_one_or_none()
    if membership is None:
        return None, 'The Argus user linked to your Slack account has no access to this tenant.'
    return Principal(tenant_id=row.tenant_id, role=Role(membership.role), auth='slack', user_id=user.id, email=user.email), ''


async def _reply(response_url: str, text: str) -> None:
    parts = urlsplit(response_url or '')
    if parts.scheme != 'https' or parts.hostname not in RESPONSE_HOSTS:
        return
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            await client.post(response_url, json={'response_type': 'ephemeral', 'replace_original': False, 'text': text[:2900]})
    except httpx.HTTPError:
        log.warning('slack response_url post failed')


async def _act(request: Request, db: Session, row: IntegrationConfig, config: dict, principal: Principal, kind: str, value: str) -> str:
    """Perform the click through the broker; returns the message for the user."""
    allow_high = bool(config.get('allow_high_risk'))
    if kind in {'approve', 'reject'}:
        req = get_scoped(db, ActionRequest, row.tenant_id, value)
        if req is None:
            return 'That action request no longer exists.'
        if req.risk in HIGH_RISKS and not allow_high:
            return f'`{req.action_type}` is {req.risk} risk. Decide it in Argus, where login and MFA apply.'
        req = broker.approve(db, principal, req.id, kind, comment='via Slack')
        if req.status == 'approved' and config.get('execute_on_approve'):
            db.commit()
            run = await broker.execute(request.app, principal, req.id, db=db)
            return f'Approved and queued `{req.action_type}` for execution (run {run.id[:8]}).'
        if req.status == 'approved':
            return f'Approved `{req.action_type}`. It is ready to execute in Argus.'
        if req.status == 'rejected':
            return f'Denied `{req.action_type}`.'
        return f'Approval recorded for `{req.action_type}`; it still needs {req.required_approvals} approval(s) in total.'
    run = get_scoped(db, ActionRun, row.tenant_id, value)
    req = get_scoped(db, ActionRequest, row.tenant_id, run.request_id) if run is not None else None
    if run is None or req is None:
        return 'That action run no longer exists.'
    if req.risk in HIGH_RISKS and not allow_high:
        return f'`{req.action_type}` is {req.risk} risk. Roll it back in Argus, where login and MFA apply.'
    await broker.rollback(request.app, principal, run.id, db=db)
    return f'Rollback of `{req.action_type}` queued.'


@router.post('/interactions/{integration_id}', include_in_schema=True)
async def interactions(integration_id: str, request: Request, db: Session = Depends(get_db)):
    limiter: RateLimiter = request.app.state.rate_limiter
    ip = (request.client.host if request.client else '')[:64]
    limiter.check(f'slack-ip:{ip}', 120, 60.0)
    limiter.check(f'slack-int:{integration_id[:64]}', 120, 60.0)
    body = await _read(request)
    timestamp = request.headers.get('x-slack-request-timestamp', '')
    signature = request.headers.get('x-slack-signature', '')
    if not timestamp or not signature:
        raise _reject()
    row = db.get(IntegrationConfig, integration_id)
    config = loads(row.config_json, {}) if row is not None else {}
    if row is None or row.kind != 'slack' or not row.enabled or not config.get('interactive'):
        raise _reject()
    tenant = db.get(Tenant, row.tenant_id)
    if tenant is None or not tenant.is_active:
        raise _reject()
    secrets = resolve_secrets(loads(row.secret_refs_json, {}), request.app.state.settings)
    now = time.time()
    if not verify(secrets.get('signing_secret', ''), timestamp, body, signature, now) or _seen(request.app, signature, now):
        raise _reject()

    try:
        payload = json.loads((parse_qs(body.decode('utf-8', errors='replace')).get('payload') or ['{}'])[0])
    except ValueError:
        payload = {}
    if not isinstance(payload, dict) or payload.get('type') != 'block_actions':
        return Response(status_code=200)
    if config.get('team_id') and str((payload.get('team') or {}).get('id') or '') != config['team_id']:
        raise _reject()
    slack_user = str((payload.get('user') or {}).get('id') or '')[:32]
    response_url = str(payload.get('response_url') or '')
    clicked = next((a for a in payload.get('actions') or [] if isinstance(a, dict) and a.get('action_id') in ACTIONS), None)
    if clicked is None:
        return Response(status_code=200)  # 'Open in Argus' link buttons also post here; nothing to do
    kind, value = ACTIONS[clicked['action_id']], str(clicked.get('value') or '')[:36]

    principal, reason = await _principal(db, row, config, secrets, slack_user)
    detail = {'via': 'slack', 'slack_user': slack_user, 'integration_id': row.id, 'action': kind, 'subject': value}
    if principal is None:
        record_audit(db, f'slack:{slack_user}', 'slack.interaction_refused', value, detail | {'reason': reason}, tenant_id=row.tenant_id,
                     actor_kind='user')
        db.commit()
        await _reply(response_url, reason)
        return Response(status_code=200)
    try:
        message = await _act(request, db, row, config, principal, kind, value)
        outcome = 'ok'
    except ArgusError as exc:  # broker refusal: permissions, separation of duty, state, kill switch
        db.rollback()
        message, outcome = f'Argus refused: {exc.message}', 'refused'
    record_audit(db, principal, 'slack.interaction', value, detail | {'outcome': outcome, 'message': redact(message)[:300]})
    db.commit()
    await _reply(response_url, message)
    return Response(status_code=200)


__all__ = ['router', 'verify', 'sign']
