"""Data retention API: the tenant's effective policy with a preview of what is due, overrides, and a manual run."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.errors import ArgusError
from ..core.rbac import Principal
from ..models import Tenant
from ..ops import last_retention_run, retention
from .deps import get_db, require, write_off_loop

router = APIRouter(prefix='/api/v1/retention', tags=['retention'])


class InvalidRetention(ArgusError):
    status = 422
    code = 'invalid_retention'


class RetentionBody(BaseModel):
    """Days per policy; 0 keeps forever, null removes the override (back to the server default)."""

    overrides: dict[str, int | None] = Field(default_factory=dict)


def _state(request: Request, db: Session, tenant: Tenant) -> dict:
    settings = request.app.state.settings
    return {'scheduled': bool(settings.retention_enabled), 'last_run_at': last_retention_run(tenant),
            'policies': retention.preview(db, settings, tenant)}


@router.get('')
def get_retention(request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:settings'))):
    return _state(request, db, db.get(Tenant, principal.tenant_id))


@router.put('')
def put_retention(body: RetentionBody, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:settings'))):
    tenant = db.get(Tenant, principal.tenant_id)
    try:
        current = retention.set_overrides(db, tenant, body.overrides)
    except ValueError as exc:
        raise InvalidRetention(str(exc)) from None
    record_audit(db, principal, 'retention.policy_updated', tenant.id, {'overrides': current})
    return _state(request, db, tenant)


@router.post('/run', status_code=202)
async def run_now(request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('admin:settings'))):
    job = await request.app.state.queue.enqueue('retention.run', {'tenant_id': principal.tenant_id, 'requested_by': principal.actor},
                                                tenant_id=principal.tenant_id, lease_seconds=3600, priority=6)
    await write_off_loop(db, lambda: record_audit(db, principal, 'retention.run_requested', job.id, {}))
    return {'job_id': job.id}
