"""Bounded behavioral identity-risk summary across the current tenant's events.

This is behavioral evidence, not a computation of effective cloud permissions.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ..core.rbac import Principal
from ..models import SecurityEvent, utcnow
from .deps import get_db, require

router = APIRouter(prefix='/api/v1/identity-risk', tags=['identity'])


def _signals(action: str) -> tuple[bool, bool]:
    action = action.lower()
    failed = any(x in action for x in ('login.fail', 'sign.in.fail', 'auth.failure', 'password.invalid'))
    privileged = any(x in action for x in ('grant.permission', 'attach.role', 'add.role', 'assume.role',
                                            'privilege.escalat', 'create.access.key', 'grant.admin'))
    return failed, privileged


@router.get('/summary')
def identity_risk_summary(days: int = Query(default=7, ge=1, le=30),
                          limit: int = Query(default=50, ge=1, le=200),
                          db: Session = Depends(get_db),
                          principal: Principal = Depends(require('detections:read'))):
    cutoff = utcnow() - timedelta(days=days)
    when = func.coalesce(SecurityEvent.occurred_at, SecurityEvent.received_at)
    events = db.execute(select(SecurityEvent).where(SecurityEvent.tenant_id == principal.tenant_id, when >= cutoff)
                       .order_by(when.desc()).limit(10000)).scalars().all()
    actors = defaultdict(lambda: {'events': 0, 'failed_logins': 0, 'privilege_actions': 0, 'sources': set(), 'recent_event_ids': []})
    for ev in events:
        if not ev.actor:
            continue
        a = actors[ev.actor]
        a['events'] += 1
        a['sources'].add(ev.source)
        failed, privileged = _signals(ev.action or '')
        a['failed_logins'] += int(failed)
        a['privilege_actions'] += int(privileged)
        if (failed or privileged) and len(a['recent_event_ids']) < 10:
            a['recent_event_ids'].append(ev.id)
    items = []
    for actor, a in actors.items():
        score = min(100, 4 * a['failed_logins'] + 20 * a['privilege_actions'] + 4 * max(0, len(a['sources']) - 1))
        if score:
            items.append({'actor': actor, 'behavioral_risk_score': score,
                          'failed_logins': a['failed_logins'], 'privilege_actions': a['privilege_actions'],
                          'sources': sorted(a['sources']), 'event_ids': a['recent_event_ids']})
    return {'items': sorted(items, key=lambda x: (-x['behavioral_risk_score'], x['actor']))[:limit],
            'window_days': days, 'events_examined': len(events),
            'max_events_examined': 10000, 'score_type': 'heuristic_behavioral'}
