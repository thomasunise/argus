"""Daily time series: findings opened and closed, events received, detections created."""
from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Finding, SecurityEvent
from .evidence import utcnow

MAX_DAYS = 365


def _per_day(db: Session, column, *where) -> dict[str, int]:
    day = func.date(column)
    rows = db.execute(select(day, func.count()).where(*where).group_by(day)).all()
    out: dict[str, int] = {}
    for key, n in rows:
        text = key.isoformat() if isinstance(key, date) else str(key)[:10]
        out[text] = out.get(text, 0) + int(n)
    return out


def trends(db: Session, tenant_id: str, days: int = 30) -> dict[str, Any]:
    days = max(1, min(MAX_DAYS, int(days)))
    now = utcnow()
    start_day = (now - timedelta(days=days - 1)).date()
    start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days - 1)
    labels = [(start_day + timedelta(days=i)).isoformat() for i in range(days)]

    opened = _per_day(db, Finding.created_at, Finding.tenant_id == tenant_id, Finding.created_at >= start)
    # Findings have no closed_at column; updated_at of a resolved finding is the close time until it changes again.
    closed = _per_day(db, Finding.updated_at, Finding.tenant_id == tenant_id, Finding.status.in_(['resolved', 'false_positive', 'accepted']),
                      Finding.updated_at >= start)
    events = _per_day(db, SecurityEvent.received_at, SecurityEvent.tenant_id == tenant_id, SecurityEvent.received_at >= start)
    detections: dict[str, int] | None
    try:
        from ..models.detections import Detection

        detections = _per_day(db, Detection.created_at, Detection.tenant_id == tenant_id, Detection.created_at >= start)
    except ImportError:
        detections = None

    series = [{'day': day, 'findings_opened': opened.get(day, 0), 'findings_closed': closed.get(day, 0), 'events': events.get(day, 0),
               'detections': detections.get(day, 0) if detections is not None else None} for day in labels]
    return {'generated_at': now, 'days': days, 'from': labels[0], 'to': labels[-1], 'series': series,
            'totals': {'findings_opened': sum(opened.values()), 'findings_closed': sum(closed.values()), 'events': sum(events.values()),
                       'detections': sum(detections.values()) if detections is not None else None},
            'note': 'findings_closed uses the last update time of resolved/accepted/false-positive findings as the close date.'}
