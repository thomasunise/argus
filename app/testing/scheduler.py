"""Scheduler loop for scheduled TestPlans. Enqueues one run per (adapter, asset) when a
plan's schedule interval has elapsed. Scope is still re-checked at execution time, so a
scheduled run is never itself a grant.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from ..core.db import session_scope
from ..models import utcnow

log = logging.getLogger('argus.testing')


async def scheduler_loop(app) -> None:
    await asyncio.sleep(15)
    settings = app.state.settings
    factory = app.state.db_factory
    while True:
        try:
            due = _collect_due(factory)
            for plan_id, tenant_id in due:
                try:
                    from .service import launch_plan

                    await launch_plan(app, plan_id, tenant_id, triggered_by='scheduler')
                except Exception:  # noqa: BLE001 - one bad plan must not stop the loop
                    log.exception('scheduled plan %s failed to launch', plan_id)
        except Exception:  # noqa: BLE001
            log.exception('scheduler loop iteration failed')
        await asyncio.sleep(max(60, settings.autoscan_minutes * 60 // 6))


def _collect_due(factory) -> list[tuple[str, str]]:
    from sqlalchemy import select

    from ..models.testing import TestPlan

    now = utcnow()
    due: list[tuple[str, str]] = []
    with session_scope(factory) as db:
        plans = db.execute(select(TestPlan).where(TestPlan.enabled.is_(True), TestPlan.schedule_minutes.isnot(None))).scalars()
        for plan in plans:
            if not plan.schedule_minutes:
                continue
            last = plan.last_run_at
            if last is None or last.replace(tzinfo=last.tzinfo or now.tzinfo) <= now - timedelta(minutes=plan.schedule_minutes):
                due.append((plan.id, plan.tenant_id))
    return due
