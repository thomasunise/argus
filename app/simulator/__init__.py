"""Agentic attack simulator: replays synthetic agent-driven attacks against the detection engine in an
isolated sandbox tenant and reports which ones the current rules and tuning catch.

setup(app) registers the queue job `simulation.run`. Nothing here generates network traffic or touches a
real system; scenarios are data only.
"""
from __future__ import annotations

import asyncio
import logging

from ..core.audit import record_audit
from ..core.db import session_scope
from ..core.rbac import system_principal
from ..models import Tenant, dumps, loads, utcnow
from ..models.simulation import SimulationRun
from . import runner
from .scenarios import SCENARIOS

log = logging.getLogger('argus.simulator')


def scenario_catalog() -> list[dict]:
    return [{'id': s.id, 'name': s.name, 'description': s.description, 'techniques': s.techniques, 'expected_rules': s.expected_rules}
            for s in SCENARIOS.values()]


def run_to_dict(r: SimulationRun, *, full: bool = True) -> dict:
    data = {'id': r.id, 'scenarios': loads(r.scenarios_json, []), 'intensity': r.intensity, 'evasion': bool(r.evasion), 'status': r.status,
            'coverage': r.coverage, 'summary': loads(r.summary_json, {}), 'error': r.error, 'job_id': r.job_id, 'created_by': r.created_by,
            'created_at': r.created_at, 'started_at': r.started_at, 'finished_at': r.finished_at}
    if full:
        data['results'] = loads(r.results_json, [])
    return data


def execute(db_factory, settings, tenant_id: str, run_id: str) -> dict:
    """Run every scenario of a SimulationRun (blocking; called from the job in a worker thread)."""
    with session_scope(db_factory) as db:
        run = db.get(SimulationRun, run_id)
        tenant = db.get(Tenant, tenant_id)
        if run is None or run.tenant_id != tenant_id or tenant is None or not tenant.is_active:
            raise PermissionError('simulation run not found for an active tenant')
        if run.status in {'completed', 'failed'}:
            return {'status': run.status, 'reason': 'already finished'}
        run.status, run.started_at = 'running', utcnow()
        scenario_ids = [s for s in loads(run.scenarios_json, []) if s in SCENARIOS]
        intensity, evasion = run.intensity, bool(run.evasion)
    reports: list[dict] = []
    try:
        for scenario_id in scenario_ids:
            with session_scope(db_factory) as db:
                tenant = db.get(Tenant, tenant_id)
                sandbox = runner.sandbox_for(db, tenant)
                reports.append(runner.run_scenario(db, tenant, sandbox, scenario_id, intensity=intensity, evasion=evasion, run_id=run_id, settings=settings))
    except Exception as exc:
        log.exception('simulation %s failed', run_id)
        with session_scope(db_factory) as db:
            run = db.get(SimulationRun, run_id)
            run.status, run.error, run.finished_at = 'failed', f'{type(exc).__name__}: {exc}'[:500], utcnow()
            run.results_json = dumps(reports, limit=200_000)
            sandbox = runner.sandbox_for(db, db.get(Tenant, tenant_id))
            runner.purge(db, sandbox)
        raise
    summary = runner.summarize(reports)
    with session_scope(db_factory) as db:
        run = db.get(SimulationRun, run_id)
        run.status, run.finished_at = 'completed', utcnow()
        run.results_json = dumps(reports, limit=200_000)
        run.summary_json = dumps(summary)
        run.coverage = summary['coverage']
        record_audit(db, system_principal(tenant_id), 'simulation.completed', run_id,
                     {'scenarios': len(reports), 'coverage': summary['coverage'], 'missed': summary['missed'], 'evasion': evasion}, tenant_id=tenant_id)
    return summary


def setup(app) -> None:
    queue = app.state.queue

    @queue.handler('simulation.run')
    async def _run(job, ctx):
        run_id = str(job.payload.get('run_id') or '')
        result = await asyncio.to_thread(execute, ctx.db_factory, ctx.settings, job.tenant_id, run_id)
        await ctx.heartbeat()
        return result


__all__ = ['setup', 'scenario_catalog', 'run_to_dict', 'execute', 'SCENARIOS']
