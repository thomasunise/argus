"""Platform operations: backups and data retention.

setup(app) registers two queue jobs:
  backup.run      back up the whole database, copy it to every store, prune old copies (platform tenant only)
  retention.run   prune one tenant's old rows under its retention policy
and, outside tests, a scheduler on the API process that enqueues them when due: a backup every
BACKUP_INTERVAL_HOURS when BACKUP_ENABLED, and a nightly retention run per active tenant when
RETENTION_ENABLED. Idempotency keys per time bucket stop replicas from enqueueing the same run twice.
The command line (`python -m app.ops`) covers the same ground plus restore, which is never exposed over HTTP.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ..core.audit import record_audit
from ..core.db import session_scope
from ..core.rbac import system_principal
from ..models import Tenant, dumps, loads, utcnow
from ..models.ops import BackupRecord
from . import retention
from .backup import BackupError, dump
from .stores import build_stores

log = logging.getLogger('argus.ops')

SCHEDULER_TICK_SECONDS = 600
BACKUP_LEASE_SECONDS = 6 * 3600
RETENTION_EVERY_HOURS = 24


def platform_tenant_id(db, settings) -> str | None:
    return db.execute(select(Tenant.id).where(Tenant.slug == settings.default_tenant_slug)).scalar_one_or_none()


def run_backup(db_factory, engine, settings, *, trigger: str = 'manual', requested_by: str = 'system') -> dict:
    """Blocking: call from a thread. Records the run, writes the backup, copies it to every store, prunes."""
    from ..main import VERSION

    with session_scope(db_factory) as db:
        record = BackupRecord(trigger=trigger, requested_by=requested_by[:200])
        db.add(record)
        db.flush()
        record_id = record.id
        tenant_id = platform_tenant_id(db, settings) or ''
    landed: list[str] = []
    pruned: dict[str, list[str]] = {}
    result = None
    try:
        stores = build_stores(settings)
        result = dump(engine, settings, settings.backup_dir, app_version=VERSION)
        landed.append('local')
        for store in stores[1:]:
            try:
                store.put(result.path)
            except Exception as exc:
                raise BackupError(f'backup written locally but the upload to {store.name} failed: {type(exc).__name__}: {exc}') from exc
            landed.append(store.name)
        for store in stores:
            pruned[store.name] = store.prune(settings.backup_keep)
    except Exception as exc:
        with session_scope(db_factory) as db:
            record = db.get(BackupRecord, record_id)
            record.status, record.error, record.finished_at = 'failed', f'{type(exc).__name__}: {exc}'[:2000], utcnow()
            record.stores_json = dumps(landed)
            if result is not None:
                record.name, record.size_bytes, record.sha256 = result.name, result.size_bytes, result.sha256
            if tenant_id:
                record_audit(db, system_principal(tenant_id), 'ops.backup.failed', record_id, {'error': record.error[:500], 'trigger': trigger})
        raise
    with session_scope(db_factory) as db:
        record = db.get(BackupRecord, record_id)
        record.status, record.finished_at = 'completed', utcnow()
        record.name, record.size_bytes, record.sha256 = result.name, result.size_bytes, result.sha256
        record.tables, record.rows, record.encrypted, record.key_id = len(result.counts), result.rows, result.encrypted, result.key_id
        record.revision, record.stores_json, record.pruned_json = result.revision, dumps(landed), dumps(pruned)
        if tenant_id:
            record_audit(db, system_principal(tenant_id), 'ops.backup.completed', record_id,
                         {'name': result.name, 'size_bytes': result.size_bytes, 'sha256': result.sha256, 'rows': result.rows,
                          'stores': landed, 'encrypted': result.encrypted, 'trigger': trigger})
    return {'backup_id': record_id, 'name': result.name, 'size_bytes': result.size_bytes, 'sha256': result.sha256, 'rows': result.rows,
            'tables': len(result.counts), 'encrypted': result.encrypted, 'stores': landed, 'pruned': pruned}


def run_retention(db_factory, settings, tenant_id: str, *, actor=None, record_empty: bool = False) -> dict:
    deleted = retention.prune(db_factory, settings, tenant_id)
    with session_scope(db_factory) as db:
        tenant = db.get(Tenant, tenant_id)
        data = loads(tenant.settings_json, {})
        data['retention_state'] = {'last_run_at': utcnow().isoformat(), 'rows': sum(deleted.values())}
        tenant.settings_json = dumps(data)
        if deleted or record_empty:
            record_audit(db, actor or system_principal(tenant_id), 'retention.pruned', '', {'deleted': deleted, 'rows': sum(deleted.values())},
                         tenant_id=tenant_id)
    return {'deleted': deleted, 'rows': sum(deleted.values())}


def last_retention_run(tenant: Tenant) -> datetime | None:
    raw = (loads(tenant.settings_json, {}).get('retention_state') or {}).get('last_run_at')
    try:
        return datetime.fromisoformat(raw) if raw else None
    except (TypeError, ValueError):
        return None


def backup_due(db, settings, now: datetime) -> bool:
    """Due when no backup completed within the interval and none is running (a 'running' record older than the
    job lease is a crashed run and does not block)."""
    recent = db.execute(select(BackupRecord).where(BackupRecord.status.in_(('completed', 'running')))
                        .order_by(BackupRecord.started_at.desc()).limit(5)).scalars().all()
    for record in recent:
        started = record.started_at if record.started_at.tzinfo else record.started_at.replace(tzinfo=timezone.utc)
        if record.status == 'completed' and started > now - timedelta(hours=settings.backup_interval_hours) + timedelta(minutes=15):
            return False
        if record.status == 'running' and started > now - timedelta(seconds=BACKUP_LEASE_SECONDS):
            return False
    return True


def backup_record_to_dict(record: BackupRecord) -> dict:
    from ..models import loads

    return {'id': record.id, 'name': record.name, 'status': record.status, 'trigger': record.trigger, 'size_bytes': record.size_bytes,
            'sha256': record.sha256, 'tables': record.tables, 'rows': record.rows, 'encrypted': record.encrypted, 'key_id': record.key_id,
            'revision': record.revision, 'stores': loads(record.stores_json, []), 'pruned': loads(record.pruned_json, []),
            'error': record.error, 'requested_by': record.requested_by, 'started_at': record.started_at, 'finished_at': record.finished_at}


async def schedule_tick(app, now: float | None = None) -> list[str]:
    """Enqueue whatever is due. Safe to call from every replica: the idempotency keys collapse duplicates."""
    settings = app.state.settings
    queue = app.state.queue
    now = time.time() if now is None else now
    enqueued: list[str] = []

    moment = datetime.fromtimestamp(now, timezone.utc)

    def _state() -> tuple[str | None, bool, list[str]]:
        with session_scope(app.state.db_factory) as db:
            due_tenants: list[str] = []
            for tenant in db.execute(select(Tenant).where(Tenant.is_active.is_(True))).scalars():
                last = last_retention_run(tenant)
                if last is None or last < moment - timedelta(hours=RETENTION_EVERY_HOURS):
                    due_tenants.append(tenant.id)
            return platform_tenant_id(db, settings), backup_due(db, settings, moment), due_tenants

    platform, due, tenants = await asyncio.to_thread(_state)
    if settings.backup_enabled and platform and due:
        bucket = int(now // (settings.backup_interval_hours * 3600))
        job = await queue.enqueue('backup.run', {'trigger': 'schedule'}, tenant_id=platform, idempotency_key=f'backup.run:{bucket}',
                                  lease_seconds=BACKUP_LEASE_SECONDS, priority=8, max_attempts=2)
        enqueued.append(job.id)
    if settings.retention_enabled:
        day = int(now // 86400)
        for tenant_id in tenants:
            job = await queue.enqueue('retention.run', {'tenant_id': tenant_id}, tenant_id=tenant_id,
                                      idempotency_key=f'retention.run:{tenant_id}:{day}', lease_seconds=3600, priority=9)
            enqueued.append(job.id)
    return enqueued


def setup(app) -> None:
    settings = app.state.settings
    queue = app.state.queue

    @queue.handler('backup.run')
    async def _backup(job, ctx):
        def _run() -> dict:
            with session_scope(ctx.db_factory) as db:
                if job.tenant_id != platform_tenant_id(db, ctx.settings):
                    raise PermissionError('backups run only for the platform tenant')
            return run_backup(ctx.db_factory, ctx.app.state.engine, ctx.settings, trigger=str(job.payload.get('trigger') or 'manual'),
                              requested_by=str(job.payload.get('requested_by') or 'system'))

        result = await asyncio.to_thread(_run)
        await ctx.heartbeat()
        return result

    @queue.handler('retention.run')
    async def _retention(job, ctx):
        tenant_id = job.payload.get('tenant_id') or job.tenant_id
        if tenant_id != job.tenant_id:
            raise PermissionError('job tenant does not match payload tenant')
        manual = bool(job.payload.get('requested_by'))
        result = await asyncio.to_thread(run_retention, ctx.db_factory, ctx.settings, tenant_id, record_empty=manual)
        await ctx.heartbeat()
        return result

    async def _start(app) -> None:
        if settings.app_env == 'test' or not (settings.backup_enabled or settings.retention_enabled):
            return
        from ..main import spawn

        spawn(app, _scheduler(app))

    app.state.startup_hooks.append(_start)


async def _scheduler(app) -> None:
    await asyncio.sleep(60)  # let the stack settle after a deploy
    while True:
        try:
            await schedule_tick(app)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception('ops scheduler tick failed')
        await asyncio.sleep(SCHEDULER_TICK_SECONDS)


__all__ = ['setup', 'run_backup', 'run_retention', 'schedule_tick', 'platform_tenant_id', 'BackupError']
