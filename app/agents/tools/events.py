"""Read-only security event tools: recent activity, per-actor timelines and aggregate stats."""
from __future__ import annotations

from sqlalchemy import func, select

from ...core.db import scoped
from ...models import SecurityEvent
from ._common import clamp_limit, compact_event, event_time, full_event, like, since
from .registry import ToolContext, registry


def _window_hours(value, default: float, maximum: float = 24 * 90) -> float:
    try:
        return max(0.01, min(maximum, float(value if value is not None else default)))
    except (TypeError, ValueError):
        return default


@registry.tool('recent_events', 'Security events received in the last N minutes, optionally filtered by actor, entity, category or source (substring match).',
               {'properties': {'minutes': {'type': 'integer', 'description': 'look-back window, default 60, max 129600 (90 days)'},
                               'actor': {'type': 'string'}, 'entity': {'type': 'string'}, 'category': {'type': 'string'},
                               'source': {'type': 'string'}, 'limit': {'type': 'integer', 'description': 'default 100, max 500'}},
                'required': []}, tags=('events',))
def recent_events(args: dict, ctx: ToolContext) -> dict:
    minutes = _window_hours(args.get('minutes'), 60, maximum=24 * 90 * 60)
    stmt = scoped(SecurityEvent, ctx.principal).where(event_time() >= since(minutes=minutes))
    for field in ('actor', 'entity', 'category', 'source'):
        if args.get(field):
            stmt = stmt.where(getattr(SecurityEvent, field).ilike(like(str(args[field])), escape='\\'))
    limit = clamp_limit(args.get('limit'), default=100, maximum=500)
    rows = ctx.db.execute(stmt.order_by(event_time().desc()).limit(limit)).scalars().all()
    return {'window_minutes': minutes, 'count': len(rows), 'items': [full_event(e) for e in rows]}


@registry.tool('actor_timeline', 'Chronological list of everything one actor (user, role, service account, IP) did in the last N hours, with a summary of actions and entities touched.',
               {'properties': {'actor': {'type': 'string'}, 'hours': {'type': 'integer', 'description': 'default 24'}, 'limit': {'type': 'integer'}},
                'required': ['actor']}, tags=('events',))
def actor_timeline(args: dict, ctx: ToolContext) -> dict:
    hours = _window_hours(args.get('hours'), 24)
    actor = str(args['actor'])
    stmt = (scoped(SecurityEvent, ctx.principal).where(SecurityEvent.actor.ilike(like(actor), escape='\\'), event_time() >= since(hours=hours))
            .order_by(event_time().asc()).limit(clamp_limit(args.get('limit'), default=200, maximum=500)))
    rows = ctx.db.execute(stmt).scalars().all()
    actions: dict[str, int] = {}
    entities: dict[str, int] = {}
    sources: dict[str, int] = {}
    for e in rows:
        actions[e.action or '(none)'] = actions.get(e.action or '(none)', 0) + 1
        if e.entity:
            entities[e.entity] = entities.get(e.entity, 0) + 1
        sources[e.source] = sources.get(e.source, 0) + 1
    return {'actor': actor, 'window_hours': hours, 'count': len(rows),
            'first_seen': (rows[0].occurred_at or rows[0].received_at) if rows else None,
            'last_seen': (rows[-1].occurred_at or rows[-1].received_at) if rows else None,
            'actions': actions, 'distinct_entities': len(entities), 'entities': dict(sorted(entities.items(), key=lambda kv: -kv[1])[:50]),
            'sources': sources, 'timeline': [compact_event(e) for e in rows]}


@registry.tool('event_stats', 'Counts of security events in the last N hours grouped by category, source, severity and action, plus the busiest actors and entities.',
               {'properties': {'hours': {'type': 'integer', 'description': 'default 24'}}, 'required': []}, tags=('events',))
def event_stats(args: dict, ctx: ToolContext) -> dict:
    hours = _window_hours(args.get('hours'), 24)
    start = since(hours=hours)
    tenant = ctx.principal.tenant_id

    def grouped(column, limit: int = 20) -> dict:
        stmt = (select(column, func.count()).where(SecurityEvent.tenant_id == tenant, event_time() >= start)
                .group_by(column).order_by(func.count().desc()).limit(limit))
        return {(key or '(none)'): count for key, count in ctx.db.execute(stmt).all()}

    total = ctx.db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.tenant_id == tenant, event_time() >= start)) or 0
    return {'window_hours': hours, 'total': total, 'by_category': grouped(SecurityEvent.category), 'by_source': grouped(SecurityEvent.source),
            'by_severity': grouped(SecurityEvent.severity), 'by_action': grouped(SecurityEvent.action), 'top_actors': grouped(SecurityEvent.actor, 10),
            'top_entities': grouped(SecurityEvent.entity, 10)}
