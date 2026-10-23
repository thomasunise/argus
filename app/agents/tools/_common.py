"""Shared helpers for agent tools: tenant-scoped loaders, serializers and optional-package access.

Modules starting with an underscore are not auto-imported by app.agents.setup, so this file
registers nothing itself.
"""
from __future__ import annotations

import dataclasses
import importlib
import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func

from ...core.db import get_scoped, scoped
from ...core.findings import SEVERITIES, event_to_dict, finding_to_dict
from ...models import Asset, AssetAuthorization, Finding, SecurityEvent, loads, utcnow
from .registry import ToolContext

log = logging.getLogger('sentinel.agents.tools')

OPEN_STATUSES = ('open', 'investigating')
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def unavailable(reason: str) -> dict:
    return {'available': False, 'reason': reason}


def optional_module(name: str) -> Any | None:
    """Import a sibling package lazily. Returns None when it is missing or broken, so a tool
    degrades instead of crashing the agent."""
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name and (name == exc.name or name.startswith(exc.name + '.')):
            return None
        log.warning('optional module %s failed to import: %s', name, exc)
        return None
    except Exception as exc:  # a broken sibling package must not take agents down
        log.warning('optional module %s failed to import: %s', name, exc)
        return None


def optional_attr(module_name: str, attr: str) -> Any | None:
    module = optional_module(module_name)
    return getattr(module, attr, None) if module is not None else None


def clamp_limit(value: Any, default: int = 50, maximum: int = 200) -> int:
    try:
        return max(1, min(maximum, int(value if value is not None else default)))
    except (TypeError, ValueError):
        return default


def since(*, minutes: float = 0, hours: float = 0, days: float = 0) -> datetime:
    return utcnow() - timedelta(minutes=minutes, hours=hours, days=days)


def like(text: str) -> str:
    escaped = text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    return f'%{escaped}%'


def serialize(value: Any, depth: int = 0) -> Any:
    """Serialize ORM rows, dataclasses and nested containers into JSON-able structures."""
    if depth > 6:
        return str(value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): serialize(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [serialize(v, depth + 1) for v in value]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: serialize(getattr(value, f.name), depth + 1) for f in dataclasses.fields(value)}
    table = getattr(value, '__table__', None)
    if table is not None:
        out: dict[str, Any] = {}
        for column in table.columns:
            raw = getattr(value, column.name, None)
            if column.name.endswith('_json') and isinstance(raw, str):
                out[column.name[:-5]] = loads(raw)
            elif column.name in {'props', 'evidence', 'metadata', 'detail', 'report', 'payload'} and isinstance(raw, str) and raw[:1] in '{[':
                out[column.name] = loads(raw, raw)
            else:
                out[column.name] = serialize(raw, depth + 1)
        return out
    if hasattr(value, '__dict__'):
        return {k: serialize(v, depth + 1) for k, v in vars(value).items() if not k.startswith('_')}
    return str(value)


def compact_finding(f: Finding) -> dict:
    return {'id': f.id, 'title': f.title, 'severity': f.severity, 'status': f.status, 'rule': f.rule, 'source': f.source,
            'asset_id': f.asset_id, 'kev': bool(f.kev), 'epss': f.epss, 'cvss': f.cvss, 'occurrences': f.occurrences,
            'created_at': f.created_at, 'updated_at': f.updated_at}


def full_finding(f: Finding) -> dict:
    return finding_to_dict(f)


def compact_event(e: SecurityEvent) -> dict:
    return {'id': e.id, 'at': e.occurred_at or e.received_at, 'source': e.source, 'category': e.category, 'severity': e.severity,
            'actor': e.actor, 'entity': e.entity, 'action': e.action, 'title': e.title, 'asset_id': e.asset_id}


def full_event(e: SecurityEvent) -> dict:
    return event_to_dict(e)


def asset_dict(a: Asset) -> dict:
    return {'id': a.id, 'name': a.name, 'kind': a.kind, 'target': a.target, 'environment': a.environment, 'criticality': a.criticality,
            'owner': a.owner, 'tags': loads(a.tags_json, []), 'source': a.source, 'approved': bool(a.approved), 'graph_node_id': a.graph_node_id,
            'created_at': a.created_at, 'last_scan_at': a.last_scan_at, 'last_seen_at': a.last_seen_at}


def authorization_valid(auth: AssetAuthorization, now: datetime | None = None) -> bool:
    now = now or utcnow()
    if auth.revoked_at is not None:
        return False
    if auth.expires_at is not None:
        expires = auth.expires_at if auth.expires_at.tzinfo else auth.expires_at.replace(tzinfo=now.tzinfo)
        if expires <= now:
            return False
    return True


def authorization_dict(auth: AssetAuthorization, now: datetime | None = None) -> dict:
    now = now or utcnow()
    return {'id': auth.id, 'asset_id': auth.asset_id, 'allow_active': bool(auth.allow_active), 'allow_intrusive': bool(auth.allow_intrusive),
            'attestation': auth.attestation[:300], 'scope_document_ref': auth.scope_document_ref, 'created_at': auth.created_at,
            'expires_at': auth.expires_at, 'revoked_at': auth.revoked_at, 'valid': authorization_valid(auth, now)}


def load_finding(ctx: ToolContext, finding_id: str) -> Finding | None:
    return get_scoped(ctx.db, Finding, ctx.principal, finding_id)


def load_asset(ctx: ToolContext, asset_id: str) -> Asset | None:
    return get_scoped(ctx.db, Asset, ctx.principal, asset_id)


def asset_authorizations(ctx: ToolContext, asset_id: str) -> list[AssetAuthorization]:
    stmt = scoped(AssetAuthorization, ctx.principal).where(AssetAuthorization.asset_id == asset_id).order_by(AssetAuthorization.created_at.desc())
    return list(ctx.db.execute(stmt).scalars().all())


def event_time():
    return func.coalesce(SecurityEvent.occurred_at, SecurityEvent.received_at)


def open_findings_for_asset(ctx: ToolContext, asset_id: str, limit: int = 50) -> list[Finding]:
    stmt = (scoped(Finding, ctx.principal).where(Finding.asset_id == asset_id, Finding.status.in_(OPEN_STATUSES))
            .order_by(Finding.updated_at.desc()).limit(limit))
    return list(ctx.db.execute(stmt).scalars().all())


def severity_sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_RANK.get(f.severity, 9), -(f.created_at.timestamp() if f.created_at else 0)))
