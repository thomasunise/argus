"""Autonomous pentesting: plan with the red-team specialist, run the plan through the normal harness, re-plan
from what was found.

Safety model: every gate is re-checked at the start of the run and again before each test launch, because a
queued job is not a grant. The gates are: global AUTOPENTEST_ENABLED, no global kill switch, tenant active,
tenant opt-in enabled, the scope is unrevoked/unexpired and flagged `autonomous`, and the run is not
stop_requested. The run never launches a test directly: it calls testing.service.launch_scan, which runs the
scope check at request time, and harness.execute_run runs it again at execution time. The agent only plans.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone

from sqlalchemy import select

from ..core.audit import record_audit
from ..core.db import session_scope
from ..core.events import publish
from ..core.rbac import Principal
from ..models import Asset, Tenant, dumps, loads, utcnow
from ..models.simulation import AutopilotRun
from ..models.testing import TestRun, TestScope
from .scope import TIER_RANK

log = logging.getLogger('argus.testing.autopilot')

DEFAULT_MAX_TIER = 'active'
DEFAULT_MAX_ROUNDS = 2
MAX_ROUNDS_CAP = 5
DEFAULT_MAX_TEST_RUNS = 20
POLL_SECONDS = 2.0
TERMINAL_RUN_STATUSES = {'completed', 'failed', 'denied'}


class AutopilotDenied(Exception):
    """A gate refused the run. The message is safe to surface to operators."""


def tenant_config(tenant: Tenant | None) -> dict:
    data = loads(tenant.settings_json, {}) if tenant else {}
    cfg = data.get('autopentest') if isinstance(data, dict) else None
    return cfg if isinstance(cfg, dict) else {}


def tenant_enabled(tenant: Tenant | None) -> bool:
    return bool(tenant_config(tenant).get('enabled'))


def tenant_max_tier(tenant: Tenant | None) -> str:
    tier = str(tenant_config(tenant).get('max_tier') or DEFAULT_MAX_TIER)
    return tier if tier in TIER_RANK else DEFAULT_MAX_TIER


def tenant_cap(tenant: Tenant | None, key: str, default: int, cap: int) -> int:
    try:
        return max(1, min(cap, int(tenant_config(tenant).get(key, default))))
    except (TypeError, ValueError):
        return default


def run_to_dict(r: AutopilotRun) -> dict:
    return {'id': r.id, 'scope_id': r.scope_id, 'asset_ids': loads(r.asset_ids_json, []), 'max_tier': r.max_tier, 'max_rounds': r.max_rounds,
            'status': r.status, 'rounds_completed': r.rounds_completed, 'test_runs': r.test_runs, 'findings_new': r.findings_new,
            'steps': loads(r.steps_json, []), 'summary': loads(r.summary_json, {}), 'error': r.error, 'stop_requested': bool(r.stop_requested),
            'job_id': r.job_id, 'created_by': r.created_by, 'created_at': r.created_at, 'started_at': r.started_at, 'finished_at': r.finished_at}


def _gate(settings, tenant: Tenant | None, scope: TestScope | None, *, now: datetime | None = None) -> None:
    """Raise AutopilotDenied unless every precondition holds. Called at start and before each launch."""
    now = now or datetime.now(timezone.utc)
    if not getattr(settings, 'autopentest_enabled', False):
        raise AutopilotDenied('autonomous pentesting is disabled (AUTOPENTEST_ENABLED=false)')
    if getattr(settings, 'autopentest_kill_switch', False):
        raise AutopilotDenied('autonomous pentesting kill switch is engaged (AUTOPENTEST_KILL_SWITCH)')
    if tenant is None or not tenant.is_active:
        raise AutopilotDenied('tenant is not active')
    if not tenant_enabled(tenant):
        raise AutopilotDenied('autonomous pentesting is not enabled for this tenant')
    if scope is None:
        raise AutopilotDenied('test scope not found')
    if not bool(getattr(scope, 'autonomous', False)):
        raise AutopilotDenied('this test scope is not marked autonomous; a human must authorize unattended runs on it')
    if scope.revoked_at is not None:
        raise AutopilotDenied('test scope has been revoked')
    if scope.expires_at is not None and (scope.expires_at if scope.expires_at.tzinfo else scope.expires_at.replace(tzinfo=timezone.utc)) <= now:
        raise AutopilotDenied('test scope has expired')


def preflight(db, settings, principal: Principal, scope_id: str, asset_ids: list[str]) -> tuple[TestScope, list[str]]:
    """Validate a start request synchronously so the API can return a clear error. Returns (scope, asset_ids)."""
    tenant = db.get(Tenant, principal.tenant_id)
    scope = db.get(TestScope, scope_id) if scope_id else None
    if scope is not None and scope.tenant_id != principal.tenant_id:
        scope = None
    _gate(settings, tenant, scope)
    in_scope = loads(scope.asset_ids_json, [])
    chosen = [a for a in dict.fromkeys(asset_ids)] if asset_ids else list(in_scope)
    outside = [a for a in chosen if a not in set(in_scope)]
    if outside:
        raise AutopilotDenied(f'assets are not in the scope: {", ".join(outside[:5])}')
    if not chosen:
        raise AutopilotDenied('the scope lists no assets to test')
    return scope, chosen


# ---------------------------------------------------------------- planning


async def _plan_asset(app, settings, principal: Principal, db_factory, asset_id: str) -> dict:
    """Run the redteam_plan specialist for one asset and return its structured output."""
    from ..agents import SPECS, get_runtime

    spec = SPECS.get('redteam_plan')
    if spec is None:  # agents package absent
        return {'proposed_tests': [], 'scope_check': {'authorized': False}, 'objectives': ['redteam_plan specialist is unavailable']}
    runtime = get_runtime(app) if app is not None else None
    if runtime is None:
        from ..agents.runtime import AgentRuntime

        runtime = AgentRuntime(settings)
    result = await runtime.run(spec, f'Plan tests for asset {asset_id}', {'asset_id': asset_id}, principal, db_factory)
    return result.output if isinstance(result.output, dict) else {}


def _allowed_tier(tier: str, cap_tier: str, scope_tiers: set[str]) -> bool:
    return tier in scope_tiers and TIER_RANK.get(tier, 99) <= TIER_RANK.get(cap_tier, -1)


# ---------------------------------------------------------------- the run


async def execute(app, db_factory, settings, tenant_id: str, run_id: str, heartbeat=None) -> dict:
    from ..core.rbac import system_principal

    async def beat() -> None:
        if heartbeat is not None:
            await heartbeat()

    principal = system_principal(tenant_id)
    with session_scope(db_factory) as db:
        run = db.get(AutopilotRun, run_id)
        if run is None or run.tenant_id != tenant_id:
            raise PermissionError('autopilot run not found for this tenant')
        if run.status not in {'queued'}:
            return {'status': run.status, 'reason': 'already started'}
        tenant = db.get(Tenant, tenant_id)
        scope = db.get(TestScope, run.scope_id)
        if scope is not None and scope.tenant_id != tenant_id:
            scope = None
        try:
            _gate(settings, tenant, scope)
        except AutopilotDenied as exc:
            run.status, run.error, run.finished_at = 'failed', str(exc), utcnow()
            record_audit(db, principal, 'testing.autopilot.denied', run_id, {'reason': str(exc)}, tenant_id=tenant_id)
            return {'status': 'failed', 'reason': str(exc)}
        run.status, run.started_at = 'running', utcnow()
        cap_tier = min(run.max_tier, tenant_max_tier(tenant), key=lambda t: TIER_RANK.get(t, 99))
        max_rounds = min(run.max_rounds, tenant_cap(tenant, 'max_rounds', DEFAULT_MAX_ROUNDS, MAX_ROUNDS_CAP))
        max_test_runs = tenant_cap(tenant, 'max_test_runs', DEFAULT_MAX_TEST_RUNS, 500)
        scope_tiers = set(loads(scope.allowed_tiers_json, []))
        scope_id = scope.id
        asset_ids = loads(run.asset_ids_json, [])
        record_audit(db, principal, 'testing.autopilot.started', run_id,
                     {'scope_id': run.scope_id, 'assets': len(asset_ids), 'cap_tier': cap_tier, 'max_rounds': max_rounds}, tenant_id=tenant_id)

    steps: list[dict] = []
    launched_total = 0
    tested_pairs: set[tuple[str, str]] = set()  # (asset_id, adapter) already run, so re-planning does not repeat

    def add_step(**step) -> None:
        step['at'] = utcnow().isoformat()
        steps.append(step)

    def stop_requested() -> bool:
        with session_scope(db_factory) as db:
            run = db.get(AutopilotRun, run_id)
            return run is None or bool(run.stop_requested)

    def reload_gate() -> str:
        with session_scope(db_factory) as db:
            try:
                _gate(settings, db.get(Tenant, tenant_id), db.get(TestScope, scope_id))
                return ''
            except AutopilotDenied as exc:
                return str(exc)

    stopped_reason = ''
    for round_index in range(max_rounds):
        if stop_requested():
            stopped_reason = 'stop requested'
            break
        gate_error = reload_gate()
        if gate_error:
            stopped_reason = gate_error
            break
        await beat()
        plan_targets: list[tuple[str, str, str]] = []  # (asset_id, adapter, tier)
        for asset_id in asset_ids:
            output = await _plan_asset(app, settings, principal, db_factory, asset_id)
            proposed = output.get('proposed_tests') if isinstance(output, dict) else None
            if not isinstance(proposed, list):
                proposed = []
            authorized = bool((output.get('scope_check') or {}).get('authorized')) if isinstance(output, dict) else False
            kept, dropped = [], []
            for test in proposed:
                if not isinstance(test, dict):
                    continue
                adapter, tier = str(test.get('adapter') or ''), str(test.get('tier') or 'passive')
                if (asset_id, adapter) in tested_pairs:
                    dropped.append({'adapter': adapter, 'tier': tier, 'reason': 'already run this round-set'})
                elif not _allowed_tier(tier, cap_tier, scope_tiers):
                    dropped.append({'adapter': adapter, 'tier': tier, 'reason': f'tier {tier} exceeds cap {cap_tier} or not in scope'})
                else:
                    kept.append((adapter, tier))
                    plan_targets.append((asset_id, adapter, tier))
            add_step(phase='plan', round=round_index + 1, asset_id=asset_id, authorized=authorized,
                     planned=[{'adapter': a, 'tier': t} for a, t in kept], skipped=dropped,
                     objectives=(output.get('objectives') if isinstance(output, dict) else []) or [])
        if not plan_targets:
            add_step(phase='round_empty', round=round_index + 1, reason='no permitted tests to run')
            break

        launched_run_ids: list[str] = []
        for asset_id, adapter, tier in plan_targets:
            if launched_total >= max_test_runs:
                add_step(phase='cap_reached', round=round_index + 1, max_test_runs=max_test_runs)
                stopped_reason = stopped_reason or 'max_test_runs reached'
                break
            if stop_requested():
                stopped_reason = 'stop requested'
                break
            gate_error = reload_gate()
            if gate_error:
                stopped_reason = gate_error
                break
            try:
                launched = await _launch(app, principal, asset_id, adapter, tier, scope_id, run_id)
            except Exception as exc:  # launch_scan raises ScopeDenied/NotFound; record and continue
                add_step(phase='launch_denied', round=round_index + 1, asset_id=asset_id, adapter=adapter, tier=tier,
                         reason=f'{type(exc).__name__}: {exc}'[:300])
                tested_pairs.add((asset_id, adapter))
                continue
            tested_pairs.add((asset_id, adapter))
            status = launched.get('status')
            if status == 'denied':
                add_step(phase='launch_denied', round=round_index + 1, asset_id=asset_id, adapter=adapter, tier=tier,
                         reason=launched.get('reason', 'scope check denied'))
                continue
            run_db_id = launched.get('id')
            launched_run_ids.append(run_db_id)
            launched_total += 1
            add_step(phase='launched', round=round_index + 1, asset_id=asset_id, adapter=adapter, tier=tier, test_run_id=run_db_id)
        if stopped_reason:
            await _await_runs(db_factory, tenant_id, launched_run_ids, settings, beat)
            with session_scope(db_factory) as db:
                _record_results(db, tenant_id, launched_run_ids, steps, round_index + 1)
            break
        await _await_runs(db_factory, tenant_id, launched_run_ids, settings, beat)
        with session_scope(db_factory) as db:
            produced = _record_results(db, tenant_id, launched_run_ids, steps, round_index + 1)
            run = db.get(AutopilotRun, run_id)
            run.rounds_completed = round_index + 1
            run.test_runs = launched_total
            run.steps_json = dumps(steps, limit=200_000)
        if produced == 0 and round_index + 1 < max_rounds:
            add_step(phase='stop_early', round=round_index + 1, reason='no new findings this round')
            break

    summary = _summarize(steps, launched_total, stopped_reason)
    with session_scope(db_factory) as db:
        run = db.get(AutopilotRun, run_id)
        run.status = 'stopped' if stopped_reason == 'stop requested' else 'completed'
        run.finished_at = utcnow()
        run.steps_json = dumps(steps, limit=200_000)
        run.summary_json = dumps(summary)
        run.findings_new = summary['findings_new']
        run.test_runs = launched_total
        record_audit(db, principal, 'testing.autopilot.completed', run_id,
                     {'test_runs': launched_total, 'findings_new': summary['findings_new'], 'rounds': run.rounds_completed,
                      'stopped': stopped_reason or None}, tenant_id=tenant_id)
    await publish('testing.autopilot.completed', {'tenant_id': tenant_id, 'run_id': run_id, 'title': 'Autonomous pentest completed',
                                                  'summary': f"{launched_total} test run(s), {summary['findings_new']} new finding(s)",
                                                  'status': 'completed', 'severity': 'medium'})
    return summary


async def _launch(app, principal, asset_id: str, adapter: str, tier: str, scope_id: str, run_id: str) -> dict:
    from . import service

    return await service.launch_scan(app, principal, asset_id=asset_id, adapter_name=adapter, scope_id=scope_id,
                                     requested_tier=tier, triggered_by=f'autopilot:{run_id}')


async def _await_runs(db_factory, tenant_id: str, run_ids: list[str], settings, beat) -> None:
    """Poll until every launched TestRun is terminal, bounded by the per-tool timeout plus headroom."""
    if not run_ids:
        return
    deadline = time.monotonic() + settings.test_tool_timeout_seconds + 120
    while time.monotonic() < deadline:
        with session_scope(db_factory) as db:
            rows = db.execute(select(TestRun.status).where(TestRun.tenant_id == tenant_id, TestRun.id.in_(run_ids))).scalars().all()
        if rows and all(s in TERMINAL_RUN_STATUSES for s in rows):
            return
        await beat()
        await asyncio.sleep(POLL_SECONDS)
    log.warning('autopilot timed out waiting for test runs %s', run_ids[:5])


def _record_results(db, tenant_id: str, run_ids: list[str], steps: list[dict], round_index: int) -> int:
    """Append a results step for the round and return how many findings the runs produced."""
    if not run_ids:
        return 0
    rows = db.execute(select(TestRun).where(TestRun.tenant_id == tenant_id, TestRun.id.in_(run_ids))).scalars().all()
    produced = 0
    detail = []
    for row in rows:
        produced += int(row.result_count or 0)
        detail.append({'test_run_id': row.id, 'adapter': row.adapter, 'tier': row.tier, 'status': row.status, 'findings': int(row.result_count or 0)})
    steps.append({'phase': 'results', 'round': round_index, 'runs': detail, 'findings': produced, 'at': utcnow().isoformat()})
    return produced


def _summarize(steps: list[dict], launched_total: int, stopped_reason: str) -> dict:
    findings = sum(s.get('findings', 0) for s in steps if s.get('phase') == 'results')
    denied = sum(1 for s in steps if s.get('phase') == 'launch_denied')
    rounds = max((s.get('round', 0) for s in steps), default=0)
    return {'test_runs': launched_total, 'findings_new': findings, 'launch_denied': denied, 'rounds': rounds,
            'stopped_reason': stopped_reason or None}
