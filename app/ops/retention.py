"""Data retention: delete old high-volume rows per tenant, in small batches.

Each policy names a table, the timestamp that ages a row, and any condition that keeps live rows (a running
job, an open detection, an undelivered webhook). Defaults come from RETENTION_*_DAYS; a tenant overrides any of
them in `Tenant.settings_json['retention']`. 0 keeps rows forever.

Never pruned: the audit log (it is a hash chain, and the external sink is the long-term record), findings,
assets, authorizations and scopes, action requests and runs, and configuration.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable

from sqlalchemy import Table, delete, func, select
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..core.db import session_scope
from ..models import Base, Tenant, dumps, loads, utcnow

BATCH = 500
MAX_DAYS = 3650


@dataclass(frozen=True)
class Policy:
    key: str
    label: str
    tables: tuple[str, ...]
    column: str
    keep_if: Callable[[Table], list] = field(default=lambda t: [])
    children: tuple[tuple[str, str], ...] = ()  # (child table, column referencing the parent id), deleted first


def _status_in(*values: str):
    return lambda t: [t.c.status.in_(values)]


POLICIES: tuple[Policy, ...] = (
    Policy('events_days', 'Security events', ('events',), 'received_at'),
    Policy('detections_days', 'Resolved and false-positive detections', ('detections',), 'last_seen_at',
           keep_if=_status_in('resolved', 'false_positive')),
    Policy('agent_runs_days', 'Finished agent runs and their steps', ('agent_runs',), 'finished_at',
           children=(('agent_steps', 'run_id'),)),
    Policy('runs_days', 'Finished detection, collector, simulation, autopilot and eval runs',
           ('detection_runs', 'collector_runs', 'simulation_runs', 'autopilot_runs', 'eval_runs'), 'finished_at'),
    Policy('deliveries_days', 'Finished outbound deliveries', ('webhook_deliveries',), 'created_at',
           keep_if=_status_in('sent', 'failed', 'skipped')),
    Policy('ingest_batches_days', 'Ingest batch records', ('ingest_batches',), 'created_at'),
    Policy('ai_gateway_days', 'AI gateway request log', ('ai_gateway_requests',), 'created_at'),
    Policy('canary_hits_days', 'Canary hits', ('canary_hits',), 'received_at'),
)
KEYS = tuple(p.key for p in POLICIES)


def _table(name: str) -> Table:
    return Base.metadata.tables[name]


def defaults(settings: Settings) -> dict[str, int]:
    return {key: max(0, int(getattr(settings, f'retention_{key}'))) for key in KEYS}


def tenant_overrides(tenant: Tenant | None) -> dict[str, int]:
    raw = loads(tenant.settings_json if tenant else '', {}).get('retention') or {}
    return {k: int(v) for k, v in raw.items() if k in KEYS and isinstance(v, int) and 0 <= v <= MAX_DAYS}


def effective(settings: Settings, tenant: Tenant | None) -> dict[str, int]:
    return defaults(settings) | tenant_overrides(tenant)


def set_overrides(db: Session, tenant: Tenant, values: dict[str, int | None]) -> dict[str, int]:
    """Merge overrides into the tenant settings. None removes an override (back to the global default)."""
    settings_json = loads(tenant.settings_json, {})
    current = tenant_overrides(tenant)
    for key, value in values.items():
        if key not in KEYS:
            raise ValueError(f'unknown retention setting {key!r}')
        if value is None:
            current.pop(key, None)
        elif not isinstance(value, int) or not 0 <= value <= MAX_DAYS:
            raise ValueError(f'{key} must be between 0 (keep forever) and {MAX_DAYS} days')
        else:
            current[key] = value
    settings_json['retention'] = current
    tenant.settings_json = dumps(settings_json)
    db.flush()
    return current


def _filters(table: Table, policy: Policy, tenant_id: str, cutoff) -> list:
    return [table.c.tenant_id == tenant_id, table.c[policy.column].is_not(None), table.c[policy.column] < cutoff, *policy.keep_if(table)]


def preview(db: Session, settings: Settings, tenant: Tenant) -> list[dict]:
    """What a run would delete now, per policy."""
    policy_days = effective(settings, tenant)
    now = utcnow()
    out: list[dict] = []
    for policy in POLICIES:
        days = policy_days[policy.key]
        due = 0
        if days:
            cutoff = now - timedelta(days=days)
            for name in policy.tables:
                table = _table(name)
                due += db.execute(select(func.count()).select_from(table).where(*_filters(table, policy, tenant.id, cutoff))).scalar() or 0
        out.append({'key': policy.key, 'label': policy.label, 'days': days, 'default_days': defaults(settings)[policy.key],
                    'overridden': policy.key in tenant_overrides(tenant), 'due': int(due)})
    return out


def prune(db_factory, settings: Settings, tenant_id: str, *, batch: int = BATCH) -> dict[str, int]:
    """Delete everything past its retention for one tenant. Each batch commits on its own so a large first run
    neither holds a long lock nor loses its progress on failure."""
    with session_scope(db_factory) as db:
        tenant = db.get(Tenant, tenant_id)
        if tenant is None:
            raise PermissionError('tenant not found')
        policy_days = effective(settings, tenant)
    now = utcnow()
    deleted: dict[str, int] = {}
    for policy in POLICIES:
        days = policy_days[policy.key]
        if not days:
            continue
        cutoff = now - timedelta(days=days)
        for name in policy.tables:
            table = _table(name)
            total = 0
            while True:
                with session_scope(db_factory) as db:
                    ids = list(db.execute(select(table.c.id).where(*_filters(table, policy, tenant_id, cutoff)).limit(batch)).scalars())
                    if ids:
                        for child_name, column in policy.children:
                            child = _table(child_name)
                            db.execute(delete(child).where(child.c[column].in_(ids)))
                        db.execute(delete(table).where(table.c.id.in_(ids), table.c.tenant_id == tenant_id))
                total += len(ids)
                if len(ids) < batch:
                    break
            if total:
                deleted[name] = total
    return deleted
