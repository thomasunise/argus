"""Opt-in closed-loop verification after a governed remediation action.

Only a previously completed passive/active scanner may be rerun. The linked
test scope must explicitly permit autonomous execution and is rechecked at
launch and at execution. There are no direct remediation/rollback actions here.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import select

from ..core.db import session_scope
from ..core.events import subscribe
from ..core.rbac import system_principal
from ..models import Tenant, dumps, loads, utcnow
from ..models.actions import ActionRequest, ActionRun
from ..models.testing import TestResult, TestRun, TestScope

log = logging.getLogger('argus.testing.auto_verification')
JOB_KIND = 'verification.after_action'


def config(tenant: Tenant | None) -> dict:
    settings = loads(tenant.settings_json, {}) if tenant is not None else {}
    return settings.get('auto_verification', {}) if isinstance(settings, dict) and isinstance(settings.get('auto_verification'), dict) else {}


def enabled(tenant: Tenant | None) -> bool:
    return bool(tenant is not None and tenant.is_active and config(tenant).get('enabled') is True)


def _baseline(db, tenant_id: str, action_run_id: str):
    run = db.get(ActionRun, action_run_id)
    if run is None or run.tenant_id != tenant_id or run.status != 'executed' or run.dry_run:
        return None
    request = db.get(ActionRequest, run.request_id)
    if request is None or request.tenant_id != tenant_id or not request.finding_id:
        return None
    row = db.execute(
        select(TestRun)
        .join(TestResult, TestResult.run_id == TestRun.id)
        .join(TestScope, TestScope.id == TestRun.scope_id)
        .where(TestRun.tenant_id == tenant_id, TestResult.tenant_id == tenant_id,
               TestScope.tenant_id == tenant_id, TestScope.autonomous.is_(True),
               TestResult.finding_id == request.finding_id, TestRun.status == 'completed',
               TestRun.tier.in_(['passive', 'active']))
        .order_by(TestRun.created_at.desc())
    ).scalars().first()
    if row is None or (run.started_at is not None and row.created_at > run.started_at):
        return None
    return row


async def after_action(job, ctx):
    tenant_id = job.tenant_id
    if job.payload.get('tenant_id') not in (None, tenant_id):
        raise PermissionError('job tenant mismatch')
    action_run_id = str(job.payload.get('action_run_id') or '')
    with session_scope(ctx.db_factory) as db:
        if not enabled(db.get(Tenant, tenant_id)):
            return {'status': 'not_enabled'}
        prior = _baseline(db, tenant_id, action_run_id)
        if prior is None:
            return {'status': 'no_eligible_scoped_baseline'}
        marker = f'action_verify:{action_run_id}'
        existing = db.execute(select(TestRun).where(TestRun.tenant_id == tenant_id,
                                                   TestRun.triggered_by == marker)).scalar_one_or_none()
        if existing is not None:
            return {'status': 'already_queued', 'followup_run_id': existing.id}
        asset_id, scope_id, adapter, tier = prior.asset_id, prior.scope_id, prior.adapter, prior.tier
        params = loads(prior.params_json, {})
    from .service import launch_scan
    # launch_scan checks current asset authorization, scope, environment, tier and time window.
    queued = await launch_scan(ctx.app, system_principal(tenant_id),
                               asset_id=asset_id, scope_id=scope_id,
                               adapter_name=adapter, requested_tier=tier,
                               triggered_by=marker, params=params)
    await ctx.heartbeat()
    return {'status': 'queued', 'followup_run_id': queued['id'],
            'baseline_run_id': prior.id, 'remediation_confirmed': False}


def report_retest(db_factory, tenant_id: str, run_id: str) -> dict | None:
    """Persist a bounded comparison for completed automatic retests.

    A disappearing finding is only 'not reproduced', never a proof of a fix.
    """
    with session_scope(db_factory) as db:
        run = db.get(TestRun, run_id)
        if run is None or run.tenant_id != tenant_id or not run.triggered_by.startswith('action_verify:'):
            return None
        action_id = run.triggered_by.removeprefix('action_verify:')
        action_run = db.get(ActionRun, action_id)
        request = db.get(ActionRequest, action_run.request_id) if action_run is not None and action_run.tenant_id == tenant_id else None
        if request is None or request.tenant_id != tenant_id or not request.finding_id:
            return None
        baseline = db.execute(
            select(TestRun)
            .join(TestResult, TestResult.run_id == TestRun.id)
            .where(TestRun.tenant_id == tenant_id, TestResult.tenant_id == tenant_id,
                   TestResult.finding_id == request.finding_id,
                   TestRun.id != run.id, TestRun.status == 'completed',
                   TestRun.asset_id == run.asset_id, TestRun.adapter == run.adapter)
            .order_by(TestRun.created_at.desc())
        ).scalars().first()
        if baseline is None or run.status != 'completed':
            verdict = {'status': 'inconclusive'}
        else:
            before = set(db.execute(select(TestResult.rule).where(TestResult.tenant_id == tenant_id,
                                                                  TestResult.run_id == baseline.id)).scalars().all())
            after = set(db.execute(select(TestResult.rule).where(TestResult.tenant_id == tenant_id,
                                                                 TestResult.run_id == run.id)).scalars().all())
            verdict = {'status': 'compared', 'baseline_run_id': baseline.id,
                       'not_reproduced': sorted(before - after), 'still_detected': sorted(before & after),
                       'newly_detected': sorted(after - before),
                       'remediation_confirmed': False}
        stats = loads(run.stats_json, {})
        stats['auto_verification'] = verdict
        run.stats_json = dumps(stats)
        return verdict


def install(app) -> None:
    @app.state.queue.handler(JOB_KIND)
    async def evaluate_action(job, ctx):
        return await after_action(job, ctx)

    async def on_action(topic: str, payload: dict):
        tenant_id = str(payload.get('tenant_id') or '')
        action_run_id = str(payload.get('run_id') or '')
        if not tenant_id or not action_run_id:
            return
        with session_scope(app.state.db_factory) as db:
            if not enabled(db.get(Tenant, tenant_id)):
                return
        await app.state.queue.enqueue(JOB_KIND, {'action_run_id': action_run_id, 'tenant_id': tenant_id},
                                      tenant_id=tenant_id, idempotency_key=f'auto-verify:{action_run_id}', priority=6)
    subscribe('action.executed', on_action)
