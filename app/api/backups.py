"""Backups API. A backup holds every tenant's data, so only the platform owner (an owner of the bootstrap
tenant) can see or start one. Restore is deliberately not exposed over HTTP: it needs an empty database and a
stopped stack, so it runs from the command line (`python -m app.ops backup restore`, docs/BACKUP.md)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.errors import Forbidden
from ..core.rbac import Principal
from ..models.ops import BackupRecord
from ..ops import backup as backup_mod
from ..ops import backup_record_to_dict, platform_tenant_id
from .deps import get_db, require, write_off_loop

router = APIRouter(prefix='/api/v1/ops/backups', tags=['ops'])


def platform_owner(request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:tenant'))) -> Principal:
    if principal.tenant_id != platform_tenant_id(db, request.app.state.settings):
        raise Forbidden('backups are managed by the platform owner (an owner of the bootstrap tenant)')
    return principal


@router.get('')
def list_backups(request: Request, limit: int = 50, db: Session = Depends(get_db), principal: Principal = Depends(platform_owner)):
    settings = request.app.state.settings
    rows = db.execute(select(BackupRecord).order_by(BackupRecord.started_at.desc()).limit(max(1, min(limit, 200)))).scalars().all()
    last_ok = next((r for r in rows if r.status == 'completed'), None)
    key_id, key = backup_mod.encryption_key(settings)
    stores = ['local'] + (['s3'] if settings.backup_s3_bucket else []) + (['azure'] if settings.backup_azure_container else [])
    return {'config': {'enabled': settings.backup_enabled, 'interval_hours': settings.backup_interval_hours, 'keep': settings.backup_keep,
                       'stores': stores, 'encrypted': bool(key), 'key_id': key_id, 'dedicated_key': bool(settings.backup_encryption_key)},
            'last_success_at': last_ok.finished_at if last_ok else None,
            'items': [backup_record_to_dict(r) for r in rows]}


@router.post('', status_code=202)
async def start_backup(request: Request, db: Session = Depends(get_db), principal: Principal = Depends(platform_owner)):
    job = await request.app.state.queue.enqueue('backup.run', {'trigger': 'manual', 'requested_by': principal.actor}, tenant_id=principal.tenant_id,
                                                lease_seconds=6 * 3600, priority=6, max_attempts=1)
    await write_off_loop(db, lambda: record_audit(db, principal, 'ops.backup.requested', job.id, {}))
    return {'job_id': job.id}
