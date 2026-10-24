"""AI security package: the AI gateway (governed proxy to model providers) and shadow-AI
discovery (inventory of AI services seen in telemetry).

setup(app) registers the queue handler `ai.discover` and, unless AI_DISCOVERY_ENABLED is false
or APP_ENV is 'test', a loop that runs discovery for every active tenant every
AI_DISCOVERY_INTERVAL_MINUTES. Routers live in app/api/ai_gateway.py and app/api/ai_inventory.py.
"""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from ..core.db import session_scope
from ..models import Tenant

log = logging.getLogger('argus.ai')

MIN_INTERVAL_MINUTES = 1


def run_discovery(db_factory, tenant_id: str) -> dict | None:
    """Discovery for one tenant in its own transaction; None when the tenant is missing or inactive."""
    from .discovery import discover

    with session_scope(db_factory) as db:
        tenant = db.get(Tenant, tenant_id)
        if tenant is None or not tenant.is_active:
            return None
        return discover(db, tenant_id)


def setup(app) -> None:
    queue = app.state.queue
    settings = app.state.settings

    @queue.handler('ai.discover')
    async def discover_job(job, ctx):
        tenant_id = job.payload.get('tenant_id') or job.tenant_id
        if tenant_id != job.tenant_id:
            raise PermissionError('job tenant does not match payload tenant')
        # Blocking database work runs off the loop so SQLite's write lock cannot stall request handling.
        result = await asyncio.to_thread(run_discovery, ctx.db_factory, tenant_id)
        if result is None:
            raise PermissionError('tenant is not active')
        await ctx.heartbeat()
        return result

    async def _start(app) -> None:
        if settings.app_env == 'test' or not settings.ai_discovery_enabled:
            return
        from ..main import spawn

        spawn(app, _loop(app))

    app.state.startup_hooks.append(_start)


async def _loop(app) -> None:
    settings = app.state.settings
    interval = max(MIN_INTERVAL_MINUTES, int(settings.ai_discovery_interval_minutes or 15)) * 60
    while True:
        await asyncio.sleep(interval)
        try:
            def _tenants() -> list[str]:
                with session_scope(app.state.db_factory) as db:
                    return list(db.execute(select(Tenant.id).where(Tenant.is_active.is_(True))).scalars().all())

            for tenant_id in await asyncio.to_thread(_tenants):
                await asyncio.to_thread(run_discovery, app.state.db_factory, tenant_id)
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception('ai discovery cycle failed')


__all__ = ['setup', 'run_discovery']
