"""Queue handler and scheduler for collector runs.

Flow of `collectors.run`: load config + run row -> resolve secret refs -> build context ->
collect() under a timeout with lease heartbeats -> apply drafts to the graph (lazy import of
app.graph.service; skipped with a warning when absent) -> upsert events through
core.findings.upsert_event -> persist stats and config last_* fields -> audit entry.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.config import Settings
from ..core.db import session_scope
from ..core.findings import upsert_event
from ..core.rbac import system_principal
from ..core.security import resolve_secret
from ..models import dumps, loads, utcnow
from ..models.collectors import CollectorConfig, CollectorRun
from .base import Collector, CollectorContext, CollectorResult, registry

log = logging.getLogger('argus.collectors')

JOB_KIND = 'collectors.run'
SCHEDULER_INTERVAL_SECONDS = 60
HEARTBEAT_SECONDS = 20


# ---------------------------------------------------------------- helpers


def resolved_config(config: CollectorConfig, settings: Settings) -> tuple[dict[str, Any], list[str]]:
    """Merge non-secret config with secret values resolved from their references.
    Returns (config, names of secret fields whose reference resolved to nothing)."""
    merged: dict[str, Any] = dict(loads(config.config_json, {}))
    missing: list[str] = []
    for field, ref in (loads(config.secret_refs_json, {}) or {}).items():
        value = resolve_secret(str(ref), settings)
        if value:
            merged[field] = value
        else:
            missing.append(field)
    return merged, missing


def is_due(config: CollectorConfig, now: datetime | None = None) -> bool:
    if not config.enabled or not config.schedule_minutes or config.schedule_minutes <= 0:
        return False
    now = now or utcnow()
    if config.last_run_at is None:
        return True
    last = config.last_run_at if config.last_run_at.tzinfo else config.last_run_at.replace(tzinfo=timezone.utc)
    return now - last >= timedelta(minutes=config.schedule_minutes)


def _active_run(db: Session, config_id: str, tenant_id: str, max_age_seconds: int) -> CollectorRun | None:
    cutoff = utcnow() - timedelta(seconds=max_age_seconds)
    return db.execute(select(CollectorRun).where(CollectorRun.config_id == config_id, CollectorRun.tenant_id == tenant_id,
                                                 CollectorRun.status.in_(['queued', 'running']), CollectorRun.created_at >= cutoff)
                      .order_by(CollectorRun.created_at.desc())).scalars().first()


async def enqueue_run(app, db: Session, config: CollectorConfig, triggered_by: str) -> tuple[CollectorRun, bool]:
    """Create a CollectorRun and enqueue the job. Returns (run, created). When a run for the
    same config is already queued or running, that run is returned and created is False."""
    settings: Settings = app.state.settings
    timeout = int(settings.test_tool_timeout_seconds)
    existing = _active_run(db, config.id, config.tenant_id, timeout + 120)
    if existing is not None:
        job = await app.state.queue.status(existing.job_id) if existing.job_id else None
        if job is not None and job.status in {'queued', 'running'}:
            return existing, False
        existing.status, existing.error, existing.finished_at = 'failed', 'job lost', utcnow()
    run = CollectorRun(tenant_id=config.tenant_id, config_id=config.id, status='queued', triggered_by=triggered_by[:36])
    db.add(run)
    config.last_run_at = utcnow()
    db.commit()  # the worker (in-process or another process) must see the run row before it claims the job
    job = await app.state.queue.enqueue(JOB_KIND, {'config_id': config.id, 'run_id': run.id}, tenant_id=config.tenant_id, lease_seconds=timeout + 60,
                                        idempotency_key=f'{JOB_KIND}:{config.id}:{run.id}')
    run.job_id = job.id
    db.commit()  # never hold a pending write across an await: the in-process worker shares this event loop and SQLite's lock
    return run, True


async def _with_heartbeat(coro, heartbeat, interval: float = HEARTBEAT_SECONDS):
    task = asyncio.ensure_future(coro)
    try:
        while True:
            done, _ = await asyncio.wait({task}, timeout=interval)
            if done:
                return task.result()
            await heartbeat()
    except BaseException:
        task.cancel()
        raise


async def apply_to_graph(db: Session, tenant_id: str, result: CollectorResult, source: str) -> dict[str, Any]:
    """Hand drafts to app.graph.service.apply when that package exists. Never raises."""
    try:
        from ..graph import service as graph_service  # lazy: the graph package is optional
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith('app.graph'):
            return {'applied': False, 'reason': 'graph package not installed'}
        raise
    apply = getattr(graph_service, 'apply', None)
    if apply is None:
        return {'applied': False, 'reason': 'graph service has no apply()'}
    try:
        outcome = apply(db, tenant_id, result, source)
        if inspect.isawaitable(outcome):
            outcome = await outcome
    except Exception as exc:
        log.exception('graph apply failed for %s', source)
        return {'applied': False, 'reason': f'{type(exc).__name__}: {exc}'[:300]}
    summary: Any = outcome
    if hasattr(outcome, '__dict__') and not isinstance(outcome, dict):
        summary = {k: v for k, v in vars(outcome).items() if isinstance(v, (int, float, str, bool))}
    return {'applied': True, 'result': summary if isinstance(summary, (dict, int, str, bool, list)) else str(summary)[:300]}


async def execute_run(app, settings: Settings, db_factory, tenant_id: str, config_id: str, run_id: str, heartbeat, job_id: str = '') -> dict[str, Any]:
    """The body of the `collectors.run` job, callable without a queue for tests."""
    for attempt in range(5):  # a worker can claim the job a few ms before the enqueuing transaction is visible
        with session_scope(db_factory) as db:
            found = db.execute(select(CollectorRun).where(CollectorRun.id == run_id, CollectorRun.tenant_id == tenant_id)).scalar_one_or_none() is not None
        if found:
            break
        await asyncio.sleep(0.2 * (attempt + 1))
    with session_scope(db_factory) as db:
        config = db.execute(select(CollectorConfig).where(CollectorConfig.id == config_id, CollectorConfig.tenant_id == tenant_id)).scalar_one_or_none()
        run = db.execute(select(CollectorRun).where(CollectorRun.id == run_id, CollectorRun.tenant_id == tenant_id)).scalar_one_or_none()
        if config is None or run is None:
            raise LookupError('collector config or run not found for tenant')
        if not config.enabled:
            run.status, run.error, run.finished_at = 'failed', 'collector config is disabled', utcnow()
            return {'run_id': run_id, 'status': run.status}
        try:
            collector: Collector = registry.get(config.collector)
        except KeyError:
            run.status, run.error, run.finished_at = 'failed', f'unknown collector {config.collector}', utcnow()
            config.last_error = run.error
            return {'run_id': run_id, 'status': run.status}
        if not collector.available():
            run.status, run.error, run.finished_at = 'failed', f'collector {collector.name} is not available: {collector.install_hint()}', utcnow()
            config.last_error = run.error
            return {'run_id': run_id, 'status': run.status}
        merged, missing = resolved_config(config, settings)
        run.status, run.started_at, run.job_id = 'running', utcnow(), job_id or run.job_id
        config.last_run_at = utcnow()
        since = config.last_success_at
        collector_name, source = collector.name, collector.source
    # Secrets live only in this frame and the collector context.
    ctx = CollectorContext(tenant_id=tenant_id, config=merged, settings=settings, logger=logging.getLogger(f'argus.collectors.{collector_name}'),
                           heartbeat=heartbeat, since=since, config_id=config_id, run_id=run_id)
    warnings = [f'secret reference for {name} resolved to an empty value' for name in missing]
    error = ''
    result: CollectorResult | None = None
    started = utcnow()
    try:
        result = await asyncio.wait_for(_with_heartbeat(collector.collect(ctx), heartbeat), timeout=settings.test_tool_timeout_seconds)
    except asyncio.TimeoutError:
        error = f'collector timed out after {settings.test_tool_timeout_seconds}s'
    except asyncio.CancelledError:
        with session_scope(db_factory) as db:
            run = db.get(CollectorRun, run_id)
            if run is not None:
                run.status, run.error, run.finished_at = 'failed', 'cancelled', utcnow()
        raise
    except Exception as exc:
        log.exception('collector %s failed (config %s)', collector_name, config_id)
        error = f'{type(exc).__name__}: {exc}'[:1000]
    del merged, ctx
    stats: dict[str, Any] = {'collector': collector_name, 'duration_seconds': round((utcnow() - started).total_seconds(), 2)}
    with session_scope(db_factory) as db:
        config = db.get(CollectorConfig, config_id)
        run = db.get(CollectorRun, run_id)
        if result is not None:
            result.finalize()
            warnings.extend(result.warnings)
            stats.update(result.stats)
            graph = await apply_to_graph(db, tenant_id, result, source)
            stats['graph'] = graph
            if not graph.get('applied'):
                warnings.append(f"graph not updated: {graph.get('reason')}")
            created = 0
            for draft in result.events:
                _, was_created = upsert_event(db, tenant_id, draft)
                created += int(was_created)
                if created % 200 == 0:
                    await heartbeat()
            stats['events_created'] = created
        run.stats_json = dumps(stats, limit=20000)
        run.warnings_json = dumps(warnings[:200])
        run.finished_at = utcnow()
        if error:
            run.status, run.error = 'failed', error
            config.last_error = error
        else:
            run.status, run.error = 'completed', ''
            config.last_error = ''
            config.last_success_at = run.finished_at
        record_audit(db, system_principal(tenant_id), 'collectors.run', config_id,
                     {'run_id': run_id, 'collector': collector_name, 'status': run.status, 'nodes': stats.get('nodes', 0), 'edges': stats.get('edges', 0),
                      'events': stats.get('events', 0), 'warnings': len(warnings), 'error': error[:300]})
        status = run.status
    if error:
        raise RuntimeError(error)  # surfaces in the job record and triggers retry/backoff policy
    return {'run_id': run_id, 'status': status, 'stats': stats}


# ---------------------------------------------------------------- scheduler


async def scheduler_tick(app, now: datetime | None = None) -> int:
    """Enqueue every due collector config across tenants. Returns how many were enqueued."""
    now = now or utcnow()
    enqueued = 0
    with session_scope(app.state.db_factory) as db:
        rows = db.execute(select(CollectorConfig).where(CollectorConfig.enabled.is_(True), CollectorConfig.schedule_minutes > 0)).scalars().all()
        for config in rows:
            if not is_due(config, now):
                continue
            try:
                run, created = await enqueue_run(app, db, config, 'scheduler')
            except Exception:
                log.exception('scheduler failed to enqueue collector %s', config.id)
                continue
            if created:
                enqueued += 1
                record_audit(db, system_principal(config.tenant_id), 'collectors.scheduled', config.id, {'run_id': run.id, 'collector': config.collector})
                db.commit()
    return enqueued


async def scheduler_loop(app, interval: float = SCHEDULER_INTERVAL_SECONDS) -> None:
    while True:
        await asyncio.sleep(interval)  # sleep first so startup never races the bootstrap
        try:
            n = await scheduler_tick(app)
            if n:
                log.info('scheduler enqueued %d collector run(s)', n)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception('collector scheduler tick failed')


def install(app) -> None:
    queue = app.state.queue

    @queue.handler(JOB_KIND)
    async def run_collector(job, ctx):
        payload = job.payload or {}
        return await execute_run(ctx.app, ctx.settings, ctx.db_factory, job.tenant_id, str(payload.get('config_id', '')), str(payload.get('run_id', '')),
                                 ctx.heartbeat, job_id=job.id)

    async def start_scheduler(app_) -> None:
        if not getattr(app_.state.settings, 'workers_inprocess', True):
            return  # a dedicated worker/scheduler process owns scheduling in multi-process deployments
        from ..main import spawn  # lazy: avoid importing the app factory at module import time

        spawn(app_, scheduler_loop(app_))

    app.state.startup_hooks.append(start_scheduler)
