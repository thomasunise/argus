"""AI gateway API.

Proxy endpoints (API key with ai_gateway:use; point an SDK's base_url at them):
  POST /api/v1/ai-gateway/openai/v1/chat/completions
  POST /api/v1/ai-gateway/openai/v1/embeddings
  GET  /api/v1/ai-gateway/openai/v1/models
  POST /api/v1/ai-gateway/anthropic/v1/messages
  GET  /api/v1/ai-gateway/anthropic/v1/models

Management (session or API key): GET/PUT /policy, GET /requests, GET /stats, GET /status.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import timedelta

import httpx
from fastapi import APIRouter, Body, Depends, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..ai import gateway as gw
from ..ai.catalog import BY_KEY
from ..ai.discovery import upsert_service
from ..core.audit import record_audit
from ..core.config import Settings
from ..core.db import scoped, session_scope
from ..core.errors import Forbidden, NotFound, RateLimited, Unauthorized
from ..core.rbac import Principal, has
from ..models import ApiKey, Tenant, dumps, loads, utcnow
from ..models.ai import AIGatewayRequest
from ._common import BadRequest
from .deps import Page, RateLimiter, current_principal, get_db, get_settings, require

log = logging.getLogger('argus.ai.gateway')

router = APIRouter(prefix='/api/v1/ai-gateway', tags=['ai-gateway'])

SERVICE_FOR = {'openai': 'openai.api', 'anthropic': 'anthropic.api'}


def gateway_principal(request: Request, principal: Principal | None = Depends(current_principal),
                      settings: Settings = Depends(get_settings)) -> Principal:
    if not settings.ai_gateway_enabled:
        raise NotFound('The AI gateway is disabled (AI_GATEWAY_ENABLED)')
    if principal is None or principal.auth != 'api_key':
        raise Unauthorized('An Argus API key is required (Authorization: Bearer or x-api-key)')
    if not has(principal, 'ai_gateway:use'):
        raise Forbidden('Missing permission ai_gateway:use')
    return principal


def _page(limit: int = 50, cursor: str | None = None) -> Page:
    return Page(limit, cursor)


# ---------------------------------------------------------------- proxy


class _Call:
    """State for one proxied call: the record row and helpers to finish it."""

    def __init__(self, db: Session, principal: Principal, provider: str, endpoint: str):
        self.db = db
        self.principal = principal
        self.provider = provider
        self.started = time.monotonic()
        key = db.get(ApiKey, principal.api_key_id) if principal.api_key_id else None
        self.row = AIGatewayRequest(tenant_id=principal.tenant_id, api_key_id=principal.api_key_id or '', user_id=(key.created_by if key else '') or '',
                                    actor=principal.actor[:200], provider=provider, endpoint=endpoint, status='allowed')

    def elapsed_ms(self) -> int:
        return int((time.monotonic() - self.started) * 1000)

    def reject(self, status: int, reason: str, *, kind: str = 'argus_policy', state: str = 'blocked') -> JSONResponse:
        self.row.status, self.row.block_reason, self.row.latency_ms = state, reason[:300], self.elapsed_ms()
        self.db.add(self.row)
        self.db.flush()
        if state == 'blocked':
            record_audit(self.db, self.principal, 'ai_gateway.blocked', self.row.id,
                         {'provider': self.provider, 'endpoint': self.row.endpoint, 'model': self.row.model, 'reason': reason[:300],
                          'dlp_hits': loads(self.row.dlp_hits_json, {})})
        self.db.commit()  # the record must survive: an error response is not committed by the middleware
        return JSONResponse(gw.error_body(self.provider, status, reason, kind), status_code=status,
                            headers={'x-argus-gateway-request-id': self.row.id})


def _upstream_headers(request: Request, provider: str, key: str) -> dict[str, str]:
    headers = {'content-type': 'application/json', 'accept': request.headers.get('accept') or 'application/json'}
    for name in gw.FORWARD_HEADERS.get(provider, ()):
        value = request.headers.get(name)
        if value:
            headers[name] = value[:300]
    if provider == 'anthropic':
        headers.setdefault('anthropic-version', gw.DEFAULT_ANTHROPIC_VERSION)
        headers['x-api-key'] = key
    else:
        headers['authorization'] = f'Bearer {key}'
    return headers


async def _read_limited(request: Request, limit: int) -> bytes | None:
    declared = request.headers.get('content-length', '')
    if declared.isdigit() and int(declared) > limit:
        return None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b''.join(chunks)


def _sanction(db: Session, principal: Principal, provider: str) -> None:
    service = BY_KEY.get(SERVICE_FOR[provider])
    if service is not None:
        upsert_service(db, principal.tenant_id, service, 'gateway', principal.actor, evidence='Argus AI gateway', status='sanctioned')


async def _proxy(request: Request, db: Session, settings: Settings, principal: Principal, provider: str, endpoint: str):
    call = _Call(db, principal, provider, endpoint)
    tenant = db.get(Tenant, principal.tenant_id)
    policy = gw.tenant_policy(tenant)
    if not policy.enabled:
        return call.reject(403, 'the AI gateway is disabled for this tenant')
    if policy.allowed_providers and provider not in policy.allowed_providers:
        return call.reject(403, f'provider {provider} is not allowed by tenant policy')
    key = gw.provider_key(settings, provider)
    if not key:
        return call.reject(503, f'provider {provider} is not configured on this gateway', kind='argus_unavailable', state='error')
    limiter: RateLimiter = request.app.state.rate_limiter
    rpm = policy.requests_per_minute or settings.ai_gateway_requests_per_minute
    try:
        limiter.check(f'ai-gateway:{principal.api_key_id}', max(1, int(rpm)), 60.0)
    except RateLimited:
        return call.reject(429, f'rate limit of {rpm} requests per minute exceeded', kind='rate_limit_error')
    limit = policy.max_request_bytes or settings.ai_gateway_max_request_bytes
    raw = await _read_limited(request, limit)
    if raw is None:
        return call.reject(413, f'request body exceeds {limit} bytes', kind='request_too_large')
    call.row.request_bytes = len(raw)
    try:
        body = json.loads(raw or b'null')
    except ValueError:
        body = None
    if not isinstance(body, dict):
        return call.reject(400, 'request body must be a JSON object', kind='invalid_request_error', state='error')
    model = str(body.get('model') or '')
    call.row.model = model[:120]
    if not model:
        return call.reject(400, 'model is required', kind='invalid_request_error', state='error')
    if not gw.model_allowed(policy, model):
        return call.reject(403, f'model {model} is not allowed by tenant policy')
    if policy.monthly_budget_usd is not None:
        spent = gw.month_spend(db, principal.tenant_id)
        if spent >= policy.monthly_budget_usd:
            return call.reject(429, f'monthly AI budget of ${policy.monthly_budget_usd:.2f} is exhausted (spent ${spent:.2f})', kind='insufficient_quota')
    inspection = gw.inspect(provider, endpoint, body, policy)
    call.row.stream = inspection.stream
    call.row.dlp_hits_json = dumps(inspection.dlp_hits)
    call.row.dlp_action = inspection.dlp_action
    call.row.prompt_injection = inspection.prompt_injection
    if inspection.block_reason:
        return call.reject(403, inspection.block_reason)

    url = gw.provider_base(settings, provider) + gw.ENDPOINTS[(provider, endpoint)]
    headers = _upstream_headers(request, provider, key)
    content = json.dumps(inspection.body).encode()
    timeout = httpx.Timeout(float(settings.ai_gateway_timeout_seconds), connect=10.0)
    if inspection.stream:
        return await _stream(request, call, settings, url, headers, content, timeout)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.post(url, content=content, headers=headers)
    except httpx.HTTPError as exc:
        return call.reject(502, f'upstream {provider} unreachable ({type(exc).__name__})', kind='api_error', state='error')
    try:
        parsed = response.json()
    except ValueError:
        parsed = None
    call.row.input_tokens, call.row.output_tokens = gw.usage_from_body(provider, parsed)
    call.row.cost_usd = gw.cost(settings, model, call.row.input_tokens, call.row.output_tokens)
    call.row.upstream_status = response.status_code
    call.row.status = 'allowed' if response.status_code < 400 else 'error'
    if response.status_code >= 400:
        call.row.block_reason = f'upstream returned {response.status_code}'
    call.row.latency_ms = call.elapsed_ms()
    db.add(call.row)
    if response.status_code < 400:
        _sanction(db, principal, provider)
    db.flush()
    return Response(content=response.content, status_code=response.status_code,
                    media_type=response.headers.get('content-type', 'application/json'), headers={'x-argus-gateway-request-id': call.row.id})


async def _stream(request: Request, call: _Call, settings: Settings, url: str, headers: dict, content: bytes, timeout: httpx.Timeout):
    client = httpx.AsyncClient(timeout=timeout, follow_redirects=False)
    try:
        upstream = await client.send(client.build_request('POST', url, content=content, headers=headers), stream=True)
    except httpx.HTTPError as exc:
        await client.aclose()
        return call.reject(502, f'upstream {call.provider} unreachable ({type(exc).__name__})', kind='api_error', state='error')
    if upstream.status_code >= 400:
        body = await upstream.aread()
        await upstream.aclose()
        await client.aclose()
        call.row.upstream_status, call.row.status = upstream.status_code, 'error'
        call.row.block_reason, call.row.latency_ms = f'upstream returned {upstream.status_code}', call.elapsed_ms()
        call.db.add(call.row)
        call.db.flush()
        return Response(content=body, status_code=upstream.status_code, media_type=upstream.headers.get('content-type', 'application/json'),
                        headers={'x-argus-gateway-request-id': call.row.id})
    call.row.upstream_status = upstream.status_code
    call.db.add(call.row)
    _sanction(call.db, call.principal, call.provider)
    call.db.flush()
    row_id, tenant_id, model, provider = call.row.id, call.row.tenant_id, call.row.model, call.provider
    factory = request.app.state.db_factory
    usage = gw.SSEUsage(provider)

    def _finish(error: str) -> None:
        with session_scope(factory) as session:
            row = session.get(AIGatewayRequest, row_id)
            if row is None or row.tenant_id != tenant_id:
                return
            row.input_tokens, row.output_tokens = usage.input_tokens, usage.output_tokens
            row.cost_usd = gw.cost(settings, model, usage.input_tokens, usage.output_tokens)
            row.latency_ms = call.elapsed_ms()
            if error:
                row.status, row.block_reason = 'error', error[:300]

    async def relay():
        error = ''
        try:
            async for chunk in upstream.aiter_raw():
                usage.feed(chunk)
                yield chunk
        except httpx.HTTPError as exc:
            error = f'stream interrupted ({type(exc).__name__})'
        except asyncio.CancelledError:
            error = 'client disconnected'
            raise
        finally:
            usage.close()
            await upstream.aclose()
            await client.aclose()
            try:
                await asyncio.to_thread(_finish, error)
            except Exception:  # metering must never break the response
                log.exception('could not record streamed gateway usage')

    return StreamingResponse(relay(), status_code=upstream.status_code, media_type=upstream.headers.get('content-type', 'text/event-stream'),
                             headers={'x-argus-gateway-request-id': row_id, 'cache-control': 'no-cache'})


@router.post('/openai/v1/chat/completions')
async def openai_chat(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                      principal: Principal = Depends(gateway_principal)):
    return await _proxy(request, db, settings, principal, 'openai', 'chat.completions')


@router.post('/openai/v1/embeddings')
async def openai_embeddings(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                            principal: Principal = Depends(gateway_principal)):
    return await _proxy(request, db, settings, principal, 'openai', 'embeddings')


@router.post('/anthropic/v1/messages')
async def anthropic_messages(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                             principal: Principal = Depends(gateway_principal)):
    return await _proxy(request, db, settings, principal, 'anthropic', 'messages')


async def _models(request: Request, db: Session, settings: Settings, principal: Principal, provider: str):
    policy = gw.tenant_policy(db.get(Tenant, principal.tenant_id))
    if not policy.enabled or (policy.allowed_providers and provider not in policy.allowed_providers):
        return JSONResponse(gw.error_body(provider, 403, f'provider {provider} is not allowed by tenant policy'), status_code=403)
    key = gw.provider_key(settings, provider)
    if not key:
        return JSONResponse(gw.error_body(provider, 503, f'provider {provider} is not configured', 'argus_unavailable'), status_code=503)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0), follow_redirects=False) as client:
            response = await client.get(gw.provider_base(settings, provider) + gw.ENDPOINTS[(provider, 'models')],
                                        headers=_upstream_headers(request, provider, key))
    except httpx.HTTPError as exc:
        return JSONResponse(gw.error_body(provider, 502, f'upstream unreachable ({type(exc).__name__})', 'api_error'), status_code=502)
    try:
        data = response.json()
    except ValueError:
        data = None
    if response.status_code >= 400 or not isinstance(data, dict) or not isinstance(data.get('data'), list):
        return Response(content=response.content, status_code=response.status_code, media_type=response.headers.get('content-type', 'application/json'))
    data['data'] = [m for m in data['data'] if isinstance(m, dict) and gw.model_allowed(policy, str(m.get('id') or ''))]
    return JSONResponse(data)


@router.get('/openai/v1/models')
async def openai_models(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                        principal: Principal = Depends(gateway_principal)):
    return await _models(request, db, settings, principal, 'openai')


@router.get('/anthropic/v1/models')
async def anthropic_models(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                           principal: Principal = Depends(gateway_principal)):
    return await _models(request, db, settings, principal, 'anthropic')


# ---------------------------------------------------------------- management


def _status(settings: Settings, tenant: Tenant | None) -> dict:
    return {'enabled': bool(settings.ai_gateway_enabled), 'configured_providers': gw.configured_providers(settings),
            'base_path': '/api/v1/ai-gateway', 'policy': gw.tenant_policy(tenant).as_dict()}


@router.get('/status')
def gateway_status(db: Session = Depends(get_db), settings: Settings = Depends(get_settings), principal: Principal = Depends(require('ai:read'))):
    tenant = db.get(Tenant, principal.tenant_id)
    data = _status(settings, tenant)
    data['month_spend_usd'] = round(gw.month_spend(db, principal.tenant_id), 4)
    return data


@router.get('/policy')
def get_policy(db: Session = Depends(get_db), principal: Principal = Depends(require('ai:read'))):
    return gw.tenant_policy(db.get(Tenant, principal.tenant_id)).as_dict()


@router.put('/policy')
def put_policy(body: dict = Body(...), db: Session = Depends(get_db), principal: Principal = Depends(require('ai:write'))):
    tenant = db.get(Tenant, principal.tenant_id)
    if tenant is None:
        raise NotFound('Tenant not found')
    try:
        policy = gw.validate_policy(body)
    except ValueError as exc:
        raise BadRequest(str(exc), code='invalid_policy') from None
    before = gw.tenant_policy(tenant).as_dict()
    gw.store_policy(tenant, policy)
    after = policy.as_dict()
    changes = {k: {'from': before.get(k), 'to': v} for k, v in after.items() if before.get(k) != v}
    record_audit(db, principal, 'ai_gateway.policy_updated', tenant.id, {'changes': changes})
    return after


@router.get('/requests')
def list_requests(status: str | None = None, provider: str | None = None, model: str | None = None, api_key_id: str | None = None,
                  page: Page = Depends(_page), db: Session = Depends(get_db), principal: Principal = Depends(require('ai:read'))):
    stmt = scoped(AIGatewayRequest, principal)
    if status:
        stmt = stmt.where(AIGatewayRequest.status == status)
    if provider:
        stmt = stmt.where(AIGatewayRequest.provider == provider)
    if model:
        stmt = stmt.where(AIGatewayRequest.model == model)
    if api_key_id:
        stmt = stmt.where(AIGatewayRequest.api_key_id == api_key_id)
    rows = db.execute(page.apply(stmt.order_by(AIGatewayRequest.created_at.desc(), AIGatewayRequest.id.desc()))).scalars().all()
    return page.wrap(rows, gw.request_to_dict)


@router.get('/requests/{request_id}')
def get_request(request_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('ai:read'))):
    row = db.execute(scoped(AIGatewayRequest, principal).where(AIGatewayRequest.id == request_id)).scalar_one_or_none()
    if row is None:
        raise NotFound('Gateway request not found')
    return gw.request_to_dict(row)


@router.get('/stats')
def stats(days: int = 30, db: Session = Depends(get_db), principal: Principal = Depends(require('ai:read'))):
    days = max(1, min(366, days))
    since = utcnow() - timedelta(days=days)
    base = (AIGatewayRequest.tenant_id == principal.tenant_id, AIGatewayRequest.created_at >= since)

    def grouped(column) -> dict:
        rows = db.execute(select(column, func.count()).where(*base).group_by(column)).all()
        return {str(k or ''): int(n) for k, n in rows}

    totals = db.execute(select(func.count(), func.coalesce(func.sum(AIGatewayRequest.input_tokens), 0),
                               func.coalesce(func.sum(AIGatewayRequest.output_tokens), 0),
                               func.coalesce(func.sum(AIGatewayRequest.cost_usd), 0.0)).where(*base)).one()
    models = db.execute(select(AIGatewayRequest.model, func.count(), func.coalesce(func.sum(AIGatewayRequest.cost_usd), 0.0)).where(*base)
                        .group_by(AIGatewayRequest.model).order_by(func.count().desc()).limit(20)).all()
    dlp_totals: dict[str, int] = {}
    for text in db.execute(select(AIGatewayRequest.dlp_hits_json).where(*base, AIGatewayRequest.dlp_action != '').limit(5000)).scalars():
        for kind, count in (loads(text, {}) or {}).items():
            dlp_totals[kind] = dlp_totals.get(kind, 0) + int(count or 0)
    injections = db.scalar(select(func.count()).select_from(AIGatewayRequest).where(*base, AIGatewayRequest.prompt_injection.is_(True))) or 0
    return {'days': days, 'requests': int(totals[0]), 'input_tokens': int(totals[1]), 'output_tokens': int(totals[2]),
            'cost_usd': round(float(totals[3]), 4), 'by_status': grouped(AIGatewayRequest.status), 'by_provider': grouped(AIGatewayRequest.provider),
            'by_dlp_action': grouped(AIGatewayRequest.dlp_action), 'dlp_hits': dlp_totals, 'prompt_injection_suspected': int(injections),
            'top_models': [{'model': m, 'requests': int(n), 'cost_usd': round(float(c), 4)} for m, n, c in models],
            'month_spend_usd': round(gw.month_spend(db, principal.tenant_id), 4)}


__all__ = ['router']
