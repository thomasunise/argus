"""Detections package: rule engine, swarm/identity/canary/anomaly/cloud/k8s/code/agentic rules,
canary tokens, baselines. `setup(app)` registers the queue handlers `detections.run` and
`detections.baselines` and a scheduler loop that evaluates every active tenant periodically.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

from sqlalchemy import select

from ..core.db import session_scope
from ..models import Tenant
from . import engine
from .engine import DetectionDraft, DetectionRule, RuleContext, registry, run, update_baselines  # noqa: F401
from .util import aware

log = logging.getLogger('argus.detections')

DEFAULT_INTERVAL_SECONDS = 60
MIN_INTERVAL_SECONDS = 15


def _parse_since(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return aware(value)
    try:
        return aware(datetime.fromisoformat(str(value).replace('Z', '+00:00')))
    except ValueError:
        return None


def _tenant_active(db, tenant_id: str) -> bool:
    tenant = db.get(Tenant, tenant_id)
    return bool(tenant and tenant.is_active)


def setup(app) -> None:
    registry.ensure_loaded()
    queue = app.state.queue
    settings = app.state.settings

    @queue.handler('detections.run')
    async def run_detections(job, ctx):
        tenant_id = job.payload.get('tenant_id') or job.tenant_id
        if tenant_id != job.tenant_id:
            raise PermissionError('job tenant does not match payload tenant')
        since = _parse_since(job.payload.get('since'))
        rule_ids = [r for r in job.payload.get('rule_ids') or [] if isinstance(r, str)] or None
        with session_scope(ctx.db_factory) as db:
            if not _tenant_active(db, tenant_id):
                raise PermissionError('tenant is not active')
            result = engine.run(db, tenant_id, since=since, rule_ids=rule_ids, settings=ctx.settings, trigger='job')
        await ctx.heartbeat()
        return {k: v for k, v in result.items() if k != 'created_ids'} | {'created_ids': result['created_ids'][:20]}

    @queue.handler('detections.baselines')
    async def run_baselines(job, ctx):
        tenant_id = job.payload.get('tenant_id') or job.tenant_id
        if tenant_id != job.tenant_id:
            raise PermissionError('job tenant does not match payload tenant')
        now = _parse_since(job.payload.get('now'))
        with session_scope(ctx.db_factory) as db:
            if not _tenant_active(db, tenant_id):
                raise PermissionError('tenant is not active')
            return engine.update_baselines(db, tenant_id, now)

    async def _start(app) -> None:
        if settings.app_env == 'test' or not getattr(settings, 'detections_scheduler_enabled', True):
            return
        from ..main import spawn

        spawn(app, _scheduler_loop(app))

    app.state.startup_hooks.append(_start)


async def _scheduler_loop(app) -> None:
    """Sleep first, then every interval evaluate rules and fold baselines for each active tenant."""
    settings = app.state.settings
    interval = max(MIN_INTERVAL_SECONDS, int(getattr(settings, 'detections_interval_seconds', DEFAULT_INTERVAL_SECONDS) or DEFAULT_INTERVAL_SECONDS))
    last_baseline_bucket: dict[str, str] = {}
    while True:
        await asyncio.sleep(interval)
        try:
            with session_scope(app.state.db_factory) as db:
                tenant_ids = [t for t in db.execute(select(Tenant.id).where(Tenant.is_active.is_(True))).scalars().all()]
            for tenant_id in tenant_ids:
                with session_scope(app.state.db_factory) as db:
                    engine.run(db, tenant_id, settings=settings, trigger='scheduler')
                    bucket = engine.bucket_start(engine.utcnow(), engine.BASELINE_WINDOW_MINUTES).isoformat()
                    if last_baseline_bucket.get(tenant_id) != bucket:
                        engine.update_baselines(db, tenant_id)
                        last_baseline_bucket[tenant_id] = bucket
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception('detections scheduler cycle failed')


__all__ = ['setup', 'engine', 'registry', 'run', 'update_baselines', 'DetectionRule', 'DetectionDraft', 'RuleContext']
