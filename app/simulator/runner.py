"""Runs attack scenarios in a sandbox tenant and grades the detection coverage they reveal.

Isolation: every tenant gets one hidden sandbox tenant (inactive, no members, `simulation_sandbox_for`
in its settings). Before each scenario the sandbox is emptied, the real tenant's detection rule settings
and baselines are copied in (so results reflect how the real tenant is tuned), the scenario's events are
written there, and the detection engine runs over them. Nothing is written to the real tenant except the
SimulationRun report, so simulated attacks never reach autonomous response, outbound alerts, findings
or posture. The sandbox is emptied again afterwards.
"""
from __future__ import annotations

import logging
import time
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..core.findings import EventDraft, upsert_event
from ..models import Base, Tenant, dumps, loads, uid, utcnow
from ..models.detections import Baseline, Detection, DetectionRuleState
from .scenarios import SCENARIOS, Build, materialize

log = logging.getLogger('argus.simulator')

SANDBOX_KEY = 'simulation_sandbox_for'
KEEP_TABLES = {'audit_entries', 'simulation_runs'}  # never purged: the sandbox's own audit chain, and reports


def sandbox_for(db: Session, tenant: Tenant) -> Tenant:
    """The tenant's sandbox, created on first use. Inactive so schedulers, deliveries and logins ignore it."""
    slug = f'sim-{tenant.id[:8]}'
    sandbox = db.execute(select(Tenant).where(Tenant.slug == slug)).scalar_one_or_none()
    if sandbox is None:
        sandbox = Tenant(slug=slug, name=f'[simulation] {tenant.name}'[:120], is_active=False, actions_enabled=False,
                         settings_json=dumps({SANDBOX_KEY: tenant.id}))
        db.add(sandbox)
        db.flush()
    elif loads(sandbox.settings_json, {}).get(SANDBOX_KEY) != tenant.id:
        raise PermissionError('sandbox slug is taken by another tenant')
    sandbox.is_active, sandbox.actions_enabled = False, False
    return sandbox


def is_sandbox(tenant: Tenant | None) -> bool:
    return bool(tenant is not None and loads(tenant.settings_json, {}).get(SANDBOX_KEY))


def purge(db: Session, sandbox: Tenant) -> int:
    """Delete every tenant-scoped row of the sandbox (children before parents)."""
    if not is_sandbox(sandbox):
        raise PermissionError('refusing to purge a tenant that is not a simulation sandbox')
    removed = 0
    for table in reversed(Base.metadata.sorted_tables):
        if table.name in KEEP_TABLES or 'tenant_id' not in table.c:
            continue
        removed += db.execute(delete(table).where(table.c.tenant_id == sandbox.id)).rowcount or 0
    db.flush()
    return removed


def _copy_tuning(db: Session, tenant_id: str, sandbox_id: str) -> None:
    for state in db.execute(select(DetectionRuleState).where(DetectionRuleState.tenant_id == tenant_id)).scalars().all():
        db.add(DetectionRuleState(tenant_id=sandbox_id, rule_id=state.rule_id, enabled=state.enabled, params_json=state.params_json, updated_by='simulator'))
    for row in db.execute(select(Baseline).where(Baseline.tenant_id == tenant_id)).scalars().all():
        db.add(Baseline(tenant_id=sandbox_id, dimension=row.dimension, key=row.key, window_minutes=row.window_minutes, mean=row.mean,
                        variance=row.variance, samples=row.samples, last_value=row.last_value, last_bucket_at=row.last_bucket_at))
    db.flush()


def run_scenario(db: Session, tenant: Tenant, sandbox: Tenant, scenario_id: str, *, intensity: str, evasion: bool, run_id: str, settings) -> dict:
    from ..detections import canaries, engine

    scenario = SCENARIOS[scenario_id]
    purge(db, sandbox)
    _copy_tuning(db, tenant.id, sandbox.id)
    plan = scenario.build(Build(run_id=run_id, intensity=intensity, evasion=evasion))
    offsets = [e.offset_ms for e in plan.events] + [c.offset_ms for c in plan.canary_touches]
    span = timedelta(milliseconds=max(offsets or [0]))
    start = utcnow() - span - timedelta(minutes=2)
    for index, (when, event) in enumerate(materialize(plan, start)):
        upsert_event(db, sandbox.id, EventDraft(source=event.source, external_id=f'sim:{run_id}:{scenario_id}:{index}', title=event.title,
                                                severity=event.severity, category=event.category, actor=event.actor, entity=event.entity,
                                                action=event.action, occurred_at=when,
                                                metadata={k: v for k, v in event.metadata.items() if v is not None}))
    for touch in plan.canary_touches:
        canary = canaries.create_canary(db, sandbox.id, kind=touch.kind, label=touch.label, placement='simulation', created_by='simulator', settings=settings)
        canaries.record_hit(db, canary, source_ip=touch.source_ip, user_agent=touch.user_agent, payload=touch.payload,
                            received_at=start + timedelta(milliseconds=touch.offset_ms))
    db.flush()
    began = time.perf_counter()
    result = engine.run(db, sandbox.id, since=start - timedelta(minutes=1), now=utcnow(), settings=settings, trigger='simulation')
    elapsed_ms = round((time.perf_counter() - began) * 1000)
    detections = list(db.execute(select(Detection).where(Detection.tenant_id == sandbox.id)).scalars().all())
    for detection in detections:  # belt and braces: anything that reads these rows sees they are synthetic
        tags = loads(detection.tags_json, [])
        if 'simulation' not in tags:
            detection.tags_json = dumps(list(tags) + ['simulation'])
    db.flush()
    fired = sorted({d.rule_id for d in detections})
    expected = list(scenario.expected_rules)
    missed = [r for r in expected if r not in fired]
    report = {
        'scenario': scenario.id, 'name': scenario.name, 'techniques': scenario.techniques, 'expected_rules': expected, 'fired_rules': fired,
        'missed_rules': missed, 'extra_rules': [r for r in fired if r not in expected],
        'outcome': 'detected' if not missed else ('partial' if len(missed) < len(expected) else 'missed'),
        'events': len(plan.events), 'canary_hits': len(plan.canary_touches), 'engine_ms': elapsed_ms, 'rule_errors': result.get('errors', []),
        'detections': [{'rule_id': d.rule_id, 'title': d.title, 'severity': d.severity, 'confidence': round(float(d.confidence or 0), 2)}
                       for d in sorted(detections, key=lambda d: d.rule_id)][:20],
        'disabled_rules': sorted(r for r in expected if _disabled(db, tenant.id, r)),
    }
    purge(db, sandbox)
    return report


def _disabled(db: Session, tenant_id: str, rule_id: str) -> bool:
    state = db.execute(select(DetectionRuleState).where(DetectionRuleState.tenant_id == tenant_id, DetectionRuleState.rule_id == rule_id)).scalar_one_or_none()
    return state is not None and not state.enabled


def summarize(reports: list[dict]) -> dict:
    total = len(reports)
    detected = sum(1 for r in reports if r['outcome'] == 'detected')
    partial = sum(1 for r in reports if r['outcome'] == 'partial')
    return {'scenarios': total, 'detected': detected, 'partial': partial, 'missed': total - detected - partial,
            'coverage': round((detected + 0.5 * partial) / total, 3) if total else 0.0,
            'gaps': [{'scenario': r['scenario'], 'missed_rules': r['missed_rules'], 'disabled_rules': r['disabled_rules']}
                     for r in reports if r['missed_rules']]}


def new_run_id() -> str:
    return uid()
