"""Shared launch logic for the tests/scans routers and the scheduler.

Both paths resolve a scope, re-check it at request time via harness.precheck (so an
unauthorized run never even reaches the queue), create TestRun rows, and enqueue the
'testing.run' job whose handler re-checks the scope a second time at execution time.
"""
from __future__ import annotations

import logging

from sqlalchemy import select

from ..core.audit import record_audit
from ..core.db import get_scoped, session_scope
from ..core.errors import NotFound, ScopeDenied
from ..core.rbac import Principal, system_principal
from ..models import Asset, dumps, loads, utcnow
from ..models.testing import TestPlan, TestRun, TestScope
from . import harness
from .scope import TIER_RANK

log = logging.getLogger('argus.testing')


def _lease_seconds(settings) -> int:
    return max(settings.test_tool_timeout_seconds + 60, 600)


def scope_to_dict(s) -> dict:
    return {'id': s.id, 'name': s.name, 'asset_ids': loads(s.asset_ids_json, []),
            'allowed_tiers': loads(s.allowed_tiers_json, []), 'environments': loads(s.environments_json, []),
            'window_start': s.window_start, 'window_end': s.window_end, 'max_rps': s.max_rps,
            'max_concurrency': s.max_concurrency, 'signed_document_ref': s.signed_document_ref, 'autonomous': bool(getattr(s, 'autonomous', False)),
            'created_by': s.created_by, 'created_at': s.created_at, 'expires_at': s.expires_at,
            'revoked_at': s.revoked_at}


def plan_to_dict(p) -> dict:
    return {'id': p.id, 'name': p.name, 'scope_id': p.scope_id, 'adapters': loads(p.adapters_json, []),
            'params': loads(p.params_json, {}), 'schedule_minutes': p.schedule_minutes, 'enabled': p.enabled,
            'created_by': p.created_by, 'created_at': p.created_at, 'last_run_at': p.last_run_at}


def run_to_dict(r) -> dict:
    return {'id': r.id, 'plan_id': r.plan_id, 'scope_id': r.scope_id, 'adapter': r.adapter, 'asset_id': r.asset_id, 'params': loads(r.params_json, {}),
            'tier': r.tier, 'status': r.status, 'result_count': r.result_count, 'error': r.error, 'job_id': r.job_id,
            'stats': loads(r.stats_json, {}), 'triggered_by': r.triggered_by, 'created_at': r.created_at,
            'started_at': r.started_at, 'finished_at': r.finished_at}


def result_to_dict(r) -> dict:
    return {'id': r.id, 'run_id': r.run_id, 'finding_id': r.finding_id, 'rule': r.rule, 'title': r.title,
            'severity': r.severity, 'evidence': loads(r.evidence_json, {}), 'raw_hash': r.raw_hash,
            'created_at': r.created_at}


def _adapter_tier(adapter_name: str, requested: str | None) -> tuple[object, str]:
    adapter = harness.get_adapter(adapter_name)
    if adapter is None:
        raise NotFound(f'unknown adapter {adapter_name!r}')
    tier = requested or adapter.tier
    if TIER_RANK.get(tier, 0) < TIER_RANK.get(adapter.tier, 0):
        # Adapters run at their nominal tier whatever the request says (only ZAP degrades by ctx.tier), so a lower
        # requested tier would let scope.check approve an intrusive tool under a passive label.
        raise ScopeDenied(f'adapter {adapter.name} runs at tier {adapter.tier}; a {tier} run cannot use it')
    return adapter, tier


async def _enqueue_run(app, tenant_id: str, *, adapter_name: str, asset_id: str, scope_id: str, tier: str,
                       plan_id: str | None, triggered_by: str, principal: Principal, params: dict | None = None) -> dict:
    """Create a TestRun (request-time scope check already passed) and enqueue its job."""
    settings = app.state.settings
    with session_scope(app.state.db_factory) as db:
        run = TestRun(tenant_id=tenant_id, plan_id=plan_id, scope_id=scope_id, adapter=adapter_name, asset_id=asset_id,
                      tier=tier, status='queued', triggered_by=triggered_by[:64], params_json=dumps(params or {}))
        db.add(run)
        db.flush()
        run_id = run.id
        record_audit(db, principal, 'testing.run.queued', run_id,
                     {'adapter': adapter_name, 'asset_id': asset_id, 'tier': tier, 'scope_id': scope_id})
    job = await app.state.queue.enqueue('testing.run', {'run_id': run_id}, tenant_id=tenant_id,
                                        lease_seconds=_lease_seconds(settings))
    with session_scope(app.state.db_factory) as db:
        run = db.get(TestRun, run_id)
        if run is not None:
            run.job_id = job.id
    return {'id': run_id, 'adapter': adapter_name, 'asset_id': asset_id, 'tier': tier, 'status': 'queued', 'job_id': job.id}


async def launch_scan(app, principal: Principal, *, asset_id: str, adapter_name: str, scope_id: str,
                      requested_tier: str | None = None, triggered_by: str = 'manual', params: dict | None = None) -> dict:
    """Ad-hoc single-asset scan. Resolves the scope and runs the request-time check."""
    settings = app.state.settings
    tenant_id = principal.tenant_id
    adapter, tier = _adapter_tier(adapter_name, requested_tier)
    with session_scope(app.state.db_factory) as db:
        asset = get_scoped(db, Asset, principal, asset_id)
        if asset is None:
            raise NotFound('asset not found')
        scope = get_scoped(db, TestScope, principal, scope_id)
        if scope is None:
            raise NotFound('test scope not found')
        harness.precheck(db, adapter, asset, scope, settings, tier=tier)  # raises ScopeDenied
    return await _enqueue_run(app, tenant_id, adapter_name=adapter_name, asset_id=asset_id, scope_id=scope_id,
                              tier=tier, plan_id=None, triggered_by=triggered_by, principal=principal, params=params)


async def launch_plan(app, plan_id: str, tenant_id: str, *, principal: Principal | None = None,
                      triggered_by: str = 'manual') -> list[dict]:
    """Run every (adapter, asset) pair a plan covers. Pairs that fail the request-time scope
    check are skipped (a denied TestRun is still recorded so the operator can see why)."""
    settings = app.state.settings
    actor = principal or system_principal(tenant_id)
    runs: list[dict] = []
    with session_scope(app.state.db_factory) as db:
        plan = db.execute(select(TestPlan).where(TestPlan.id == plan_id, TestPlan.tenant_id == tenant_id)).scalar_one_or_none()
        if plan is None:
            raise NotFound('test plan not found')
        scope = db.execute(select(TestScope).where(TestScope.id == plan.scope_id, TestScope.tenant_id == tenant_id)).scalar_one_or_none()
        if scope is None:
            raise NotFound('plan scope not found')
        adapters = loads(plan.adapters_json, [])
        asset_ids = loads(scope.asset_ids_json, [])
        plan.last_run_at = utcnow()
        pairs: list[tuple[str, str, str]] = []  # (adapter_name, asset_id, tier)
        denied: list[tuple[str, str, str, str]] = []
        for adapter_name in adapters:
            adapter = harness.get_adapter(adapter_name)
            if adapter is None:
                continue
            for asset_id in asset_ids:
                asset = db.execute(select(Asset).where(Asset.id == asset_id, Asset.tenant_id == tenant_id)).scalar_one_or_none()
                if asset is None or (adapter.target_kinds and asset.kind not in adapter.target_kinds):
                    continue
                try:
                    harness.precheck(db, adapter, asset, scope, settings, tier=adapter.tier)
                    pairs.append((adapter_name, asset_id, adapter.tier))
                except ScopeDenied as exc:
                    denied.append((adapter_name, asset_id, adapter.tier, str(exc)))
        for adapter_name, asset_id, tier, reason in denied:
            run = TestRun(tenant_id=tenant_id, plan_id=plan_id, scope_id=scope.id, adapter=adapter_name, asset_id=asset_id,
                          tier=tier, status='denied', error=reason, triggered_by=triggered_by[:64], finished_at=utcnow())
            db.add(run)
            db.flush()
            record_audit(db, actor, 'testing.run.denied', run.id, {'adapter': adapter_name, 'asset_id': asset_id, 'reason': reason})
            runs.append({'id': run.id, 'adapter': adapter_name, 'asset_id': asset_id, 'tier': tier, 'status': 'denied', 'reason': reason})
        scope_id = scope.id
    for adapter_name, asset_id, tier in pairs:
        runs.append(await _enqueue_run(app, tenant_id, adapter_name=adapter_name, asset_id=asset_id, scope_id=scope_id,
                                       tier=tier, plan_id=plan_id, triggered_by=triggered_by, principal=actor))
    return runs
