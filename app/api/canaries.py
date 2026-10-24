"""Canaries API. Management endpoints are tenant scoped; the hit endpoints are public by design
(an attacker triggers them), keyed only by token and rate limited per token and per source."""
from __future__ import annotations

import json
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.db import get_scoped, scoped
from ..core.errors import NotFound, ArgusError
from ..core.rbac import Principal
from ..detections import canaries as svc
from ..models import utcnow
from ..models.detections import Canary, CanaryHit
from .deps import Page, RateLimiter, get_db, require

router = APIRouter(prefix='/api/v1/canaries', tags=['canaries'])

Kind = Literal['token', 'url', 'credential', 'file', 'dns', 'aws_key', 'api_key', 'document']
MAX_HIT_BODY = 64 * 1024
_NO_STORE = {'Cache-Control': 'no-store, no-cache, must-revalidate', 'Pragma': 'no-cache'}


class HitTooLarge(ArgusError):
    status = 413
    code = 'payload_too_large'


async def _bounded_body(request: Request, limit: int = MAX_HIT_BODY) -> bytes:
    """Read at most `limit` bytes of an unauthenticated hit body without buffering the whole request."""
    declared = request.headers.get('content-length', '')
    if declared.isdigit() and int(declared) > limit:
        raise HitTooLarge('hit payload too large')
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HitTooLarge('hit payload too large')
        chunks.append(chunk)
    return b''.join(chunks)


class CreateCanaryBody(BaseModel):
    kind: Kind
    label: str = Field(min_length=1, max_length=120)
    placement: str = Field(default='', max_length=2000)
    metadata: dict = Field(default_factory=dict)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


def _page(limit: int = 50, cursor: str | None = None) -> Page:
    return Page(limit, cursor)


@router.get('')
def list_canaries(kind: str | None = None, include_revoked: bool = False, page: Page = Depends(_page), db: Session = Depends(get_db),
                  principal: Principal = Depends(require('canaries:read'))):
    stmt = scoped(Canary, principal)
    if kind:
        stmt = stmt.where(Canary.kind == kind)
    if not include_revoked:
        stmt = stmt.where(Canary.revoked_at.is_(None))
    rows = db.execute(page.apply(stmt.order_by(Canary.created_at.desc(), Canary.id.desc()))).scalars().all()
    return page.wrap(rows, svc.canary_to_dict)


@router.post('', status_code=201)
def create_canary(body: CreateCanaryBody, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('canaries:write'))):
    expires_at = utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None
    canary = svc.create_canary(db, principal.tenant_id, kind=body.kind, label=body.label, placement=body.placement, metadata=body.metadata,
                               created_by=principal.actor, expires_at=expires_at, settings=request.app.state.settings)
    record_audit(db, principal, 'canaries.created', canary.id, {'kind': canary.kind, 'label': canary.label, 'placement': canary.placement[:200]})
    return svc.canary_to_dict(canary)


@router.delete('/{canary_id}')
def revoke_canary(canary_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('canaries:write'))):
    canary = get_scoped(db, Canary, principal, canary_id)
    if canary is None:
        raise NotFound('Canary not found')
    svc.revoke_canary(db, canary)
    record_audit(db, principal, 'canaries.revoked', canary.id, {'kind': canary.kind, 'label': canary.label})
    return svc.canary_to_dict(canary)


@router.get('/{canary_id}/hits')
def list_hits(canary_id: str, page: Page = Depends(_page), db: Session = Depends(get_db), principal: Principal = Depends(require('canaries:read'))):
    canary = get_scoped(db, Canary, principal, canary_id)
    if canary is None:
        raise NotFound('Canary not found')
    stmt = scoped(CanaryHit, principal).where(CanaryHit.canary_id == canary.id).order_by(CanaryHit.received_at.desc(), CanaryHit.id.desc())
    rows = db.execute(page.apply(stmt)).scalars().all()
    return page.wrap(rows, svc.hit_to_dict)


@router.get('/{canary_id}/artifact')
def download_artifact(canary_id: str, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('canaries:read'))):
    canary = get_scoped(db, Canary, principal, canary_id)
    if canary is None:
        raise NotFound('Canary not found')
    content, media_type, filename = svc.artifact(canary, request.app.state.settings)
    return Response(content, media_type=media_type, headers={'Content-Disposition': f'attachment; filename="{filename}"', **_NO_STORE})


# ---------------------------------------------------------------- public hit endpoints (no auth by design)


def _client_ip(request: Request) -> str:
    # X-Forwarded-For is attacker-controlled on a public endpoint. Behind a trusted proxy run uvicorn with
    # --proxy-headers and --forwarded-allow-ips so request.client.host already reflects the real peer.
    return (request.client.host if request.client else '')[:64]


async def _hit(token: str, request: Request, db: Session) -> None:
    settings = request.app.state.settings
    limiter: RateLimiter = request.app.state.rate_limiter
    ip = _client_ip(request)
    # Limits apply before lookup so token enumeration is throttled the same as real hits.
    limiter.check(f'canary-ip:{ip}', int(getattr(settings, 'canary_hit_rate_limit_per_ip', 300)), 60.0)
    limiter.check(f'canary:{token[:64]}', int(getattr(settings, 'canary_hit_rate_limit_per_token', 60)), 60.0)
    if not svc.valid_token(token):
        return
    canary = svc.find_canary(db, token)
    if canary is None:
        return
    raw = b''
    if request.method == 'POST':
        raw = await _bounded_body(request)
    payload = {'query': dict(request.query_params)} if request.query_params else {}
    if raw:
        try:
            parsed = json.loads(raw)
            payload['body'] = parsed if isinstance(parsed, (dict, list)) else str(parsed)[:500]
        except ValueError:
            payload['body'] = raw.decode('utf-8', errors='replace')[:1000]
    svc.record_hit(db, canary, source_ip=ip, user_agent=request.headers.get('user-agent', ''), headers=request.headers, payload=payload)


@router.post('/{token}/hit', status_code=204, include_in_schema=True)
async def hit_post(token: str, request: Request, db: Session = Depends(get_db)):
    await _hit(token, request, db)
    return Response(status_code=204, headers=_NO_STORE)


@router.get('/{token}/hit')
async def hit_get(token: str, request: Request, db: Session = Depends(get_db)):
    await _hit(token, request, db)
    return Response(svc.PIXEL_GIF, media_type='image/gif', headers=_NO_STORE)


__all__ = ['router']
