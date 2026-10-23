"""Dashboard summary numbers. Cheap counts only; the posture score and compliance mapping are
separate endpoints because they run many queries."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.audit import verify_chain
from ..core.config import Settings
from ..core.findings import SEVERITIES
from ..models import AgentRun, Asset, Finding, SecurityEvent, Tenant
from .evidence import OPEN_STATES, utcnow


def _count(db: Session, model, *where) -> int:
    return int(db.scalar(select(func.count()).select_from(model).where(*where)) or 0)


def _detections(db: Session, tenant_id: str) -> dict[str, Any]:
    try:
        from ..models.detections import Canary, Detection, DetectionRun
    except ImportError:
        return {'available': False}
    last = db.execute(select(DetectionRun).where(DetectionRun.tenant_id == tenant_id).order_by(DetectionRun.started_at.desc()).limit(1)).scalar_one_or_none()
    rows = db.execute(select(Detection.severity, func.count()).where(Detection.tenant_id == tenant_id, Detection.status.in_(OPEN_STATES))
                      .group_by(Detection.severity)).all()
    by_severity = {s: 0 for s in SEVERITIES}
    for severity, n in rows:
        by_severity[severity] = by_severity.get(severity, 0) + int(n)
    return {'available': True, 'open': sum(by_severity.values()), 'open_by_severity': by_severity,
            'canaries_active': _count(db, Canary, Canary.tenant_id == tenant_id, Canary.revoked_at.is_(None)),
            'last_run': {'id': last.id, 'started_at': last.started_at, 'finished_at': last.finished_at, 'rules_run': last.rules_run,
                         'detections_created': last.detections_created} if last else None}


def _actions(db: Session, tenant_id: str) -> dict[str, Any]:
    try:
        from ..models.actions import ActionRequest
    except ImportError:
        return {'available': False, 'pending': 0}
    pending = _count(db, ActionRequest, ActionRequest.tenant_id == tenant_id, ActionRequest.status == 'pending')
    return {'available': True, 'pending': pending}


def _collectors(db: Session, tenant_id: str) -> dict[str, Any]:
    try:
        from ..models.collectors import CollectorConfig, CollectorRun
    except ImportError:
        return {'available': False}
    last = db.execute(select(CollectorRun).where(CollectorRun.tenant_id == tenant_id).order_by(CollectorRun.created_at.desc()).limit(1)).scalar_one_or_none()
    return {'available': True, 'configured': _count(db, CollectorConfig, CollectorConfig.tenant_id == tenant_id),
            'enabled': _count(db, CollectorConfig, CollectorConfig.tenant_id == tenant_id, CollectorConfig.enabled.is_(True)),
            'last_run': {'id': last.id, 'config_id': last.config_id, 'status': last.status, 'created_at': last.created_at,
                         'finished_at': last.finished_at, 'error': last.error} if last else None}


def _tests(db: Session, tenant_id: str) -> dict[str, Any]:
    try:
        from ..models.testing import TestRun
    except ImportError:
        return {'available': False}
    last = db.execute(select(TestRun).where(TestRun.tenant_id == tenant_id).order_by(TestRun.created_at.desc()).limit(1)).scalar_one_or_none()
    day_ago = utcnow() - timedelta(hours=24)
    return {'available': True, 'runs_24h': _count(db, TestRun, TestRun.tenant_id == tenant_id, TestRun.created_at >= day_ago),
            'last_run': {'id': last.id, 'adapter': last.adapter, 'asset_id': last.asset_id, 'status': last.status, 'result_count': last.result_count,
                         'created_at': last.created_at, 'finished_at': last.finished_at} if last else None}


def _graph(db: Session, tenant_id: str) -> dict[str, Any]:
    try:
        from ..graph.service import stats
    except ImportError:
        return {'available': False}
    data = stats(db, tenant_id)
    return {'available': True, 'nodes': sum((data.get('nodes_by_kind') or {}).values()), 'edges': sum((data.get('edges_by_rel') or {}).values()),
            'attack_paths_open': data.get('attack_paths_open', 0), 'stale_nodes': data.get('stale_nodes', 0)}


def summary(db: Session, tenant_id: str, settings: Settings) -> dict[str, Any]:
    now = utcnow()
    day_ago = now - timedelta(hours=24)
    tenant = db.get(Tenant, tenant_id)
    rows = db.execute(select(Finding.severity, func.count()).where(Finding.tenant_id == tenant_id, Finding.status.in_(OPEN_STATES))
                      .group_by(Finding.severity)).all()
    open_by_severity = {s: 0 for s in SEVERITIES}
    for severity, n in rows:
        open_by_severity[severity] = open_by_severity.get(severity, 0) + int(n)
    recent_events = db.execute(select(SecurityEvent).where(SecurityEvent.tenant_id == tenant_id).order_by(SecurityEvent.received_at.desc()).limit(6)).scalars().all()
    agent_rows = db.execute(select(AgentRun.status, func.count()).where(AgentRun.tenant_id == tenant_id, AgentRun.created_at >= day_ago)
                            .group_by(AgentRun.status)).all()
    chain = verify_chain(db, tenant_id)
    return {
        'generated_at': now,
        'tenant': {'id': tenant_id, 'name': tenant.name if tenant else '', 'actions_enabled': bool(tenant and tenant.actions_enabled)},
        'assets': {'total': _count(db, Asset, Asset.tenant_id == tenant_id), 'approved': _count(db, Asset, Asset.tenant_id == tenant_id, Asset.approved.is_(True))},
        'findings': {'open': sum(open_by_severity.values()), 'open_by_severity': open_by_severity,
                     'total': _count(db, Finding, Finding.tenant_id == tenant_id),
                     'new_24h': _count(db, Finding, Finding.tenant_id == tenant_id, Finding.created_at >= day_ago)},
        'events': {'total': _count(db, SecurityEvent, SecurityEvent.tenant_id == tenant_id),
                   'last_24h': _count(db, SecurityEvent, SecurityEvent.tenant_id == tenant_id, SecurityEvent.received_at >= day_ago),
                   'recent': [{'id': e.id, 'title': e.title, 'severity': e.severity, 'source': e.source, 'received_at': e.received_at} for e in recent_events]},
        'detections': _detections(db, tenant_id),
        'agent_runs_24h': {'total': sum(int(n) for _, n in agent_rows), 'by_status': {s: int(n) for s, n in agent_rows}},
        'actions': _actions(db, tenant_id),
        'collectors': _collectors(db, tenant_id),
        'tests': _tests(db, tenant_id),
        'graph': _graph(db, tenant_id),
        'audit_chain': {'valid': bool(chain.get('valid')), 'checked': chain.get('checked', 0), 'signed': bool(chain.get('signed'))},
        'ai_provider': settings.ai_provider,
    }
