"""Threat-intel enrichment: CISA KEV and FIRST EPSS on every finding that names a CVE.

setup(app) registers two queue jobs and an event-bus subscriber:
  intel.enrich   enrich findings of one tenant (new ones after `finding.created`, or a backfill)
  intel.refresh  refresh the KEV catalog now
and, outside tests, a daily loop that refreshes KEV and re-checks open findings (the KEV list grows
every week, so a finding that was not listed yesterday may be today).
Disabled entirely with INTEL_ENRICHMENT_ENABLED=false.
"""
from __future__ import annotations

import asyncio
import logging
import time

from sqlalchemy import select

from ..core.audit import record_audit
from ..core.db import session_scope
from ..core.rbac import system_principal
from ..models import Finding, Tenant
from . import enrich, feeds

log = logging.getLogger('argus.intel')

DEBOUNCE_SECONDS = 5
SWEEP_INTERVAL_SECONDS = 24 * 3600


async def run_enrichment(db_factory, settings, tenant_id: str, *, finding_ids: list[str] | None = None, only_unchecked: bool = False,
                         include_closed: bool = False, actor=None) -> dict:
    """Look up KEV/EPSS for the tenant's candidate findings and write the results. Safe to repeat."""

    def _load() -> list[tuple[str, str]]:
        with session_scope(db_factory) as db:
            tenant = db.get(Tenant, tenant_id)
            if tenant is None or not tenant.is_active:
                raise PermissionError('tenant is not active')
            rows = enrich.candidates(db, tenant_id, finding_ids=finding_ids, only_unchecked=only_unchecked, include_closed=include_closed)
            return [(f.id, f.cve_ids) for f in rows]

    pairs = await asyncio.to_thread(_load)
    if not pairs:
        return {'checked': 0, 'changed': 0, 'kev': 0}
    cves: list[str] = []
    for _, text in pairs:
        cves.extend(c for c in feeds.normalize_cves(text) if c not in cves)
    kev = await feeds.kev_lookup(settings, cves)
    epss = await feeds.epss_lookup(settings, cves)

    def _store() -> dict:
        changed: list[dict] = []
        kev_count = 0
        with session_scope(db_factory) as db:
            ids = [p[0] for p in pairs]
            for finding in db.execute(select(Finding).where(Finding.tenant_id == tenant_id, Finding.id.in_(ids))).scalars().all():
                delta = enrich.apply(finding, kev, epss, settings)
                kev_count += int(bool(finding.kev))
                if delta:
                    changed.append({'finding_id': finding.id, **delta})
            if changed:
                record_audit(db, actor or system_principal(tenant_id), 'intel.enriched', '',
                             {'checked': len(pairs), 'changed': len(changed), 'kev_listed': kev_count, 'sample': changed[:20]}, tenant_id=tenant_id)
        return {'checked': len(pairs), 'changed': len(changed), 'kev': kev_count, 'cves': len(cves), 'kev_cves': len(kev), 'epss_cves': len(epss)}

    return await asyncio.to_thread(_store)


def setup(app) -> None:
    settings = app.state.settings
    queue = app.state.queue

    @queue.handler('intel.enrich')
    async def _enrich(job, ctx):
        tenant_id = job.payload.get('tenant_id') or job.tenant_id
        if tenant_id != job.tenant_id:
            raise PermissionError('job tenant does not match payload tenant')
        ids = [str(i) for i in job.payload.get('finding_ids') or [] if isinstance(i, str)] or None
        result = await run_enrichment(ctx.db_factory, ctx.settings, tenant_id, finding_ids=ids,
                                      only_unchecked=bool(job.payload.get('only_unchecked')), include_closed=bool(job.payload.get('include_closed')))
        await ctx.heartbeat()
        return result

    @queue.handler('intel.refresh')
    async def _refresh(job, ctx):
        return await feeds.refresh_kev(ctx.settings, force=bool(job.payload.get('force', True)))

    if not getattr(settings, 'intel_enrichment_enabled', True):
        return

    from ..core.events import subscribe

    async def on_finding(topic: str, payload: dict) -> None:
        tenant_id = payload.get('tenant_id')
        if not tenant_id or not payload.get('has_cves'):
            return
        bucket = int(time.time() // DEBOUNCE_SECONDS)
        try:  # one job per tenant per few seconds picks up every finding not yet checked (scanners create hundreds at once)
            await queue.enqueue('intel.enrich', {'tenant_id': tenant_id, 'only_unchecked': True}, tenant_id=str(tenant_id),
                                idempotency_key=f'intel.enrich:{tenant_id}:{bucket}', delay_seconds=DEBOUNCE_SECONDS, priority=7)
        except Exception:  # the bus must never fail the producer
            log.exception('could not enqueue intel.enrich')

    subscribe('finding.created', on_finding)

    async def _start(app) -> None:
        if settings.app_env == 'test':
            return
        from ..main import spawn

        spawn(app, _sweep_loop(app))

    app.state.startup_hooks.append(_start)


async def _sweep_loop(app) -> None:
    """Sleep first, then daily: refresh KEV and re-check every open finding with a CVE in each active tenant."""
    settings = app.state.settings
    while True:
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS if settings.intel_offline else 600)
        try:
            await feeds.refresh_kev(settings)
            with session_scope(app.state.db_factory) as db:
                tenant_ids = list(db.execute(select(Tenant.id).where(Tenant.is_active.is_(True))).scalars().all())
            for tenant_id in tenant_ids:
                await run_enrichment(app.state.db_factory, settings, tenant_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception('intel sweep failed')
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)


__all__ = ['setup', 'run_enrichment', 'feeds', 'enrich']
