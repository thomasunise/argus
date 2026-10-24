"""Autonomous pentest API: start an unattended, scope-checked pentest, list runs, read a run, request a stop.

Off by default. Every start re-validates the gates (global enable, kill switch, tenant opt-in, the scope being
flagged autonomous) synchronously, so the caller gets a clear reason instead of a run that silently does nothing.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.db import get_scoped, scoped
from ..core.errors import Conflict, NotFound, PolicyDenied
from ..core.rbac import Principal
from ..models import dumps
from ..models.simulation import AutopilotRun
from ..testing import autopilot
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/tests/autopilot', tags=['tests'])


class StartBody(BaseModel):
    scope_id: str
    asset_ids: list[str] = Field(default_factory=list, max_length=500)
    max_tier: Literal['passive', 'active', 'intrusive'] = 'active'
    max_rounds: int = Field(default=autopilot.DEFAULT_MAX_ROUNDS, ge=1, le=autopilot.MAX_ROUNDS_CAP)


def _page(limit: int = 20, cursor: str | None = None) -> Page:
    return Page(limit, cursor)


@router.post('', status_code=202)
async def start(body: StartBody, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('tests:run'))):
    settings = request.app.state.settings
    try:
        scope, asset_ids = autopilot.preflight(db, settings, principal, body.scope_id, body.asset_ids)
    except autopilot.AutopilotDenied as exc:
        raise PolicyDenied(str(exc)) from None
    run = AutopilotRun(tenant_id=principal.tenant_id, scope_id=scope.id, asset_ids_json=dumps(asset_ids), max_tier=body.max_tier,
                       max_rounds=body.max_rounds, created_by=principal.actor[:64])
    db.add(run)
    db.flush()
    record_audit(db, principal, 'testing.autopilot.requested', run.id,
                 {'scope_id': scope.id, 'assets': len(asset_ids), 'max_tier': body.max_tier, 'max_rounds': body.max_rounds})
    db.commit()
    job = await request.app.state.queue.enqueue('testing.autopilot', {'run_id': run.id}, tenant_id=principal.tenant_id,
                                                lease_seconds=max(settings.test_tool_timeout_seconds + 300, 1200),
                                                idempotency_key=f'testing.autopilot:{run.id}', priority=4)
    run.job_id = job.id
    db.commit()
    return autopilot.run_to_dict(run)


@router.get('')
def list_runs(page: Page = Depends(_page), db: Session = Depends(get_db), principal: Principal = Depends(require('tests:read'))):
    stmt = scoped(AutopilotRun, principal).order_by(AutopilotRun.created_at.desc(), AutopilotRun.id.desc())
    return page.wrap(db.execute(page.apply(stmt)).scalars().all(), autopilot.run_to_dict)


@router.get('/{run_id}')
def get_run(run_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('tests:read'))):
    run = get_scoped(db, AutopilotRun, principal, run_id)
    if run is None:
        raise NotFound('autopilot run not found')
    return autopilot.run_to_dict(run)


@router.post('/{run_id}/stop')
def stop_run(run_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('tests:run'))):
    run = get_scoped(db, AutopilotRun, principal, run_id)
    if run is None:
        raise NotFound('autopilot run not found')
    if run.status in {'completed', 'failed', 'stopped'}:
        raise Conflict(f'run is {run.status}; it cannot be stopped')
    run.stop_requested = True
    record_audit(db, principal, 'testing.autopilot.stop_requested', run_id, {'status': run.status})
    return autopilot.run_to_dict(run)
