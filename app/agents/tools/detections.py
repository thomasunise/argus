"""Read-only detection tools over app.detections (the Detection model and the rules registry);
everything here degrades gracefully when that package is absent."""
from __future__ import annotations

from typing import Any

from ...core.db import get_scoped, scoped
from ._common import clamp_limit, optional_attr, optional_module, serialize, unavailable
from .registry import ToolContext, registry


def detection_model():
    return optional_attr('app.models.detections', 'Detection')


def _column(model, *names: str):
    for name in names:
        column = getattr(model, name, None)
        if column is not None:
            return column
    return None


@registry.tool('list_detections', 'List detections (rule hits) for this tenant, optionally filtered by status, severity or rule id.',
               {'properties': {'status': {'type': 'string'}, 'severity': {'type': 'string'}, 'rule_id': {'type': 'string'}, 'limit': {'type': 'integer'}},
                'required': []}, tags=('detections',))
def list_detections(args: dict, ctx: ToolContext) -> dict:
    Detection = detection_model()
    if Detection is None:
        return unavailable('detections package not installed')
    stmt = scoped(Detection, ctx.principal)
    for arg, names in (('status', ('status',)), ('severity', ('severity',)), ('rule_id', ('rule_id', 'rule'))):
        if args.get(arg):
            column = _column(Detection, *names)
            if column is not None:
                stmt = stmt.where(column == args[arg])
    order = _column(Detection, 'created_at', 'last_seen_at', 'id')
    if order is not None:
        stmt = stmt.order_by(order.desc())
    rows = ctx.db.execute(stmt.limit(clamp_limit(args.get('limit'), default=50, maximum=200))).scalars().all()
    return {'available': True, 'count': len(rows), 'items': [serialize(r) for r in rows]}


@registry.tool('get_detection', 'Fetch one detection with its rule, entity, actor, evidence and linked finding.',
               {'properties': {'detection_id': {'type': 'string'}}, 'required': ['detection_id']}, tags=('detections',))
def get_detection(args: dict, ctx: ToolContext) -> dict:
    Detection = detection_model()
    if Detection is None:
        return unavailable('detections package not installed')
    row = get_scoped(ctx.db, Detection, ctx.principal, args['detection_id'])
    if row is None:
        return {'available': True, 'found': False, 'detection_id': args['detection_id']}
    return {'available': True, 'found': True, **serialize(row)}


def _rules_from(candidate: Any) -> list[Any] | None:
    if candidate is None:
        return None
    if callable(candidate) and not isinstance(candidate, type):
        try:
            candidate = candidate()
        except TypeError:
            return None
    if hasattr(candidate, 'all') and callable(candidate.all):
        candidate = candidate.all()
    if isinstance(candidate, dict):
        return list(candidate.values())
    if isinstance(candidate, (list, tuple)):
        return list(candidate)
    return None


def rule_catalog() -> list[dict] | None:
    for module_name in ('app.detections.rules', 'app.detections.engine', 'app.detections'):
        module = optional_module(module_name)
        if module is None:
            continue
        for attr in ('registry', 'RULES', 'rules', 'all_rules', 'ALL_RULES'):
            rules = _rules_from(getattr(module, attr, None))
            if rules:
                return [{'id': getattr(r, 'id', None) or getattr(r, 'name', ''), 'name': getattr(r, 'name', ''),
                         'severity': getattr(r, 'severity', ''), 'description': str(getattr(r, 'description', ''))[:400],
                         'tags': list(getattr(r, 'tags', []) or [])} for r in rules]
    return None


@registry.tool('detection_rules', 'Catalog of detection rules Argus evaluates (id, name, severity, description), including swarm/coordinated-activity rules.',
               {'properties': {}, 'required': []}, tags=('detections',))
def detection_rules(args: dict, ctx: ToolContext) -> dict:
    rules = rule_catalog()
    if rules is None:
        return unavailable('detections rules registry not installed')
    return {'available': True, 'count': len(rules), 'items': rules}
