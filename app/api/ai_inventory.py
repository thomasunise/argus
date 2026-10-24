"""Shadow-AI inventory API: which AI services are in use, by whom, on which channel.

  GET   /api/v1/ai/services            list (filters: status, channel, provider, service_key, q)
  GET   /api/v1/ai/services/stats      counts by status, channel, provider and category
  GET   /api/v1/ai/services/{id}
  PATCH /api/v1/ai/services/{id}       review: status sanctioned|blocked|unreviewed, notes (ai:write)
  POST  /api/v1/ai/discover            queue a discovery run (ai:write)
  GET   /api/v1/ai/discovery           discovery cursor and counters
  GET   /api/v1/ai/catalog             the known-service catalog
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..ai import catalog
from ..ai.discovery import service_to_dict, state_to_dict
from ..core.audit import record_audit
from ..core.db import get_scoped, scoped
from ..core.errors import NotFound
from ..core.rbac import Principal
from ..models import utcnow
from ..models.ai import AIDiscoveryState, AIService
from ._common import like
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/ai', tags=['ai'])


def _page(limit: int = 50, cursor: str | None = None) -> Page:
    return Page(limit, cursor)


class ReviewBody(BaseModel):
    status: Literal['unreviewed', 'sanctioned', 'blocked'] | None = None
    notes: str | None = Field(default=None, max_length=2000)
    apply_to_service: bool = True  # apply the status to every actor and channel of the same service (gateway rows excepted)


@router.get('/services')
def list_services(status: str | None = None, channel: str | None = None, provider: str | None = None, service_key: str | None = None,
                  q: str | None = None, page: Page = Depends(_page), db: Session = Depends(get_db), principal: Principal = Depends(require('ai:read'))):
    stmt = scoped(AIService, principal)
    if status:
        stmt = stmt.where(AIService.status == status)
    if channel:
        stmt = stmt.where(AIService.channel == channel)
    if provider:
        stmt = stmt.where(AIService.provider == provider)
    if service_key:
        stmt = stmt.where(AIService.service_key == service_key)
    if q:
        pattern = like(q)
        stmt = stmt.where(or_(AIService.service.ilike(pattern), AIService.actor.ilike(pattern), AIService.evidence.ilike(pattern)))
    rows = db.execute(page.apply(stmt.order_by(AIService.last_seen_at.desc(), AIService.id.desc()))).scalars().all()
    return page.wrap(rows, service_to_dict)


@router.get('/services/stats')
def service_stats(db: Session = Depends(get_db), principal: Principal = Depends(require('ai:read'))):
    def grouped(column) -> dict:
        rows = db.execute(select(column, func.count()).where(AIService.tenant_id == principal.tenant_id).group_by(column)).all()
        return {str(k or ''): int(n) for k, n in rows}

    services = db.execute(select(AIService.service_key, AIService.service, AIService.status, func.count(), func.sum(AIService.event_count),
                                 func.max(AIService.last_seen_at))
                          .where(AIService.tenant_id == principal.tenant_id)
                          .group_by(AIService.service_key, AIService.service, AIService.status)).all()
    by_service: dict[str, dict] = {}
    for key, name, status, actors, events, last_seen in services:
        entry = by_service.setdefault(key, {'service_key': key, 'service': name, 'actors': 0, 'events': 0, 'statuses': {}, 'last_seen_at': None})
        entry['actors'] += int(actors)
        entry['events'] += int(events or 0)
        entry['statuses'][status] = entry['statuses'].get(status, 0) + int(actors)
        if last_seen and (entry['last_seen_at'] is None or last_seen > entry['last_seen_at']):
            entry['last_seen_at'] = last_seen
    return {'total': sum(grouped(AIService.status).values()), 'by_status': grouped(AIService.status), 'by_channel': grouped(AIService.channel),
            'by_provider': grouped(AIService.provider), 'by_category': grouped(AIService.category),
            'services': sorted(by_service.values(), key=lambda e: -e['events'])}


@router.get('/services/{service_id}')
def get_service(service_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('ai:read'))):
    row = get_scoped(db, AIService, principal, service_id)
    if row is None:
        raise NotFound('AI service not found')
    return service_to_dict(row)


@router.patch('/services/{service_id}')
def review_service(service_id: str, body: ReviewBody, db: Session = Depends(get_db), principal: Principal = Depends(require('ai:write'))):
    row = get_scoped(db, AIService, principal, service_id)
    if row is None:
        raise NotFound('AI service not found')
    targets = [row]
    if body.status is not None and body.apply_to_service:
        targets = list(db.execute(scoped(AIService, principal).where(AIService.service_key == row.service_key,
                                                                     or_(AIService.channel != 'gateway', AIService.id == row.id))).scalars().all())
    now = utcnow()
    for target in targets:
        if body.status is not None:
            target.status = body.status
            target.reviewed_by, target.reviewed_at = principal.actor[:200], now
        target.updated_at = now
    if body.notes is not None:
        row.notes = body.notes
    db.flush()
    record_audit(db, principal, 'ai.service_reviewed', row.id, {'service_key': row.service_key, 'status': body.status, 'rows': len(targets),
                                                               'notes_changed': body.notes is not None})
    return service_to_dict(row)


@router.post('/discover', status_code=202)
async def run_discovery(request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('ai:write'))):
    record_audit(db, principal, 'ai.discovery_requested', '', {})
    db.commit()
    job = await request.app.state.queue.enqueue('ai.discover', {'tenant_id': principal.tenant_id}, tenant_id=principal.tenant_id,
                                                idempotency_key=None, priority=5)
    return {'job_id': job.id, 'status': 'queued'}


@router.get('/discovery')
def discovery_state(db: Session = Depends(get_db), principal: Principal = Depends(require('ai:read'))):
    state = db.execute(scoped(AIDiscoveryState, principal)).scalar_one_or_none()
    return state_to_dict(state)


@router.get('/catalog')
def get_catalog(principal: Principal = Depends(require('ai:read'))):
    return {'items': catalog.catalog(), 'cloud_signatures': [{'service_key': s.service_key, 'actions': list(s.action_prefixes), 'note': s.note}
                                                             for s in catalog.CLOUD_SIGNATURES]}


__all__ = ['router']
