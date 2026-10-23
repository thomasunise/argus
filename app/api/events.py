"""Security events: read-only list/search, detail and statistics. Events are created only by
`core.findings.upsert_event` (ingest, collectors, canaries)."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..core.db import get_scoped, scoped
from ..core.errors import NotFound
from ..core.findings import SEVERITIES, event_to_dict
from ..core.rbac import Principal
from ..models import SecurityEvent, utcnow
from ._common import like, parse_since
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/events', tags=['events'])

TOP_N = 10


@router.get('')
def list_events(source: str | None = None, category: str | None = None, severity: str | None = None, actor: str | None = None,
                entity: str | None = None, asset_id: str | None = None, since: str | None = None, search: str | None = None,
                page: Page = Depends(Page), db: Session = Depends(get_db), principal: Principal = Depends(require('events:read'))):
    stmt = scoped(SecurityEvent, principal)
    if source:
        stmt = stmt.where(SecurityEvent.source == source)
    if category:
        stmt = stmt.where(SecurityEvent.category == category)
    if severity:
        stmt = stmt.where(SecurityEvent.severity.in_([s for s in severity.split(',') if s]))
    if actor:
        stmt = stmt.where(SecurityEvent.actor == actor)
    if entity:
        stmt = stmt.where(SecurityEvent.entity == entity)
    if asset_id:
        stmt = stmt.where(SecurityEvent.asset_id == asset_id)
    since_at = parse_since(since)
    if since_at:
        stmt = stmt.where(SecurityEvent.received_at >= since_at)
    if search:
        pattern = like(search.strip())
        stmt = stmt.where(or_(SecurityEvent.title.ilike(pattern, escape='\\'), SecurityEvent.actor.ilike(pattern, escape='\\'),
                              SecurityEvent.entity.ilike(pattern, escape='\\'), SecurityEvent.action.ilike(pattern, escape='\\')))
    rows = db.execute(page.apply(stmt.order_by(SecurityEvent.received_at.desc(), SecurityEvent.id))).scalars().all()
    return page.wrap(rows, event_to_dict)


@router.get('/stats')
def event_stats(db: Session = Depends(get_db), principal: Principal = Depends(require('events:read'))):
    tenant_id = principal.tenant_id
    now = utcnow()
    windows = {'24h': now - timedelta(hours=24), '7d': now - timedelta(days=7)}

    def group(column, since) -> dict[str, int]:
        rows = db.execute(select(column, func.count()).where(SecurityEvent.tenant_id == tenant_id, SecurityEvent.received_at >= since)
                          .group_by(column)).all()
        return {str(key or ''): int(n) for key, n in rows}

    def top(column, since) -> list[dict]:
        rows = db.execute(select(column, func.count().label('n')).where(SecurityEvent.tenant_id == tenant_id, SecurityEvent.received_at >= since,
                                                                           column != '').group_by(column).order_by(func.count().desc(), column)
                          .limit(TOP_N)).all()
        return [{'value': key, 'count': int(n)} for key, n in rows]

    out: dict = {'generated_at': now, 'total': int(db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.tenant_id == tenant_id)) or 0)}
    for label, since in windows.items():
        by_severity = group(SecurityEvent.severity, since)
        out[label] = {'total': sum(by_severity.values()), 'by_source': group(SecurityEvent.source, since),
                      'by_category': group(SecurityEvent.category, since), 'by_severity': {s: by_severity.get(s, 0) for s in SEVERITIES}}
    out['top_actors'] = top(SecurityEvent.actor, windows['7d'])
    out['top_entities'] = top(SecurityEvent.entity, windows['7d'])
    out['top_actions'] = top(SecurityEvent.action, windows['7d'])
    return out


@router.get('/{event_id}')
def get_event(event_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('events:read'))):
    event = get_scoped(db, SecurityEvent, principal, event_id)
    if event is None:
        raise NotFound('Event not found')
    data = event_to_dict(event)
    related = db.execute(scoped(SecurityEvent, principal).where(SecurityEvent.id != event.id, SecurityEvent.actor == event.actor,
                                                                SecurityEvent.actor != '').order_by(SecurityEvent.received_at.desc()).limit(10)).scalars().all()
    data['related_by_actor'] = [{'id': e.id, 'title': e.title, 'severity': e.severity, 'source': e.source, 'received_at': e.received_at} for e in related]
    return data
