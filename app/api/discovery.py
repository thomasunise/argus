"""Discovery API: start a bounded recon pass, read the facts it produced.

Discovery runs at tier `active`, so it needs a scope, a current authorization that allows active
testing, and the usual permission. It never exploits anything; follow-up tests are queued through
the normal testing harness, which re-checks the scope.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.db import get_scoped, scoped
from ..core.errors import NotFound
from ..core.rbac import Principal
from ..models import utcnow
from ..models.discovery import Discovery, DiscoveryRun, RequestCapture
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/discovery', tags=['discovery'])


class RunBody(BaseModel):
    asset_id: str = Field(min_length=1, max_length=36)
    scope_id: str = Field(min_length=1, max_length=36)


@router.get('/runs')
def list_runs(page: Page = Depends(), asset_id: str | None = None, db: Session = Depends(get_db),
              principal: Principal = Depends(require('tests:read'))):
    from ..discovery import service

    stmt = scoped(DiscoveryRun, principal)
    if asset_id:
        stmt = stmt.where(DiscoveryRun.asset_id == asset_id)
    rows = db.execute(page.apply(stmt.order_by(DiscoveryRun.created_at.desc()))).scalars().all()
    return page.wrap(rows, service.run_to_dict)


@router.post('/runs', status_code=202)
async def start_run(body: RunBody, request: Request, db: Session = Depends(get_db),
                    principal: Principal = Depends(require('tests:run'))):
    from ..models import Asset
    from ..models.testing import TestScope
    from ..discovery import service

    asset = get_scoped(db, Asset, principal, body.asset_id)
    if asset is None:
        raise NotFound('asset not found')
    scope = get_scoped(db, TestScope, principal, body.scope_id)
    if scope is None:
        raise NotFound('test scope not found')
    run = DiscoveryRun(tenant_id=principal.tenant_id, asset_id=asset.id, scope_id=scope.id, status='queued')
    db.add(run)
    db.flush()
    record_audit(db, principal, 'discovery.run.queued', run.id, {'asset_id': asset.id, 'scope_id': scope.id})
    job = await request.app.state.queue.enqueue('discovery.run', {'run_id': run.id}, tenant_id=principal.tenant_id,
                                                lease_seconds=max(600, request.app.state.settings.discovery_max_wall_seconds + 120))
    run.job_id = job.id
    return service.run_to_dict(run)


@router.get('/runs/{run_id}')
def get_run(run_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('tests:read'))):
    from ..discovery import service

    run = get_scoped(db, DiscoveryRun, principal, run_id)
    if run is None:
        raise NotFound('discovery run not found')
    facts = db.execute(scoped(Discovery, principal).where(Discovery.run_id == run_id)
                       .order_by(Discovery.kind.asc(), Discovery.value.asc())).scalars().all()
    return {**service.run_to_dict(run), 'discoveries': [service.fact_to_dict(f) for f in facts]}


@router.get('/facts')
def list_facts(page: Page = Depends(), asset_id: str | None = None, kind: str | None = None,
               db: Session = Depends(get_db), principal: Principal = Depends(require('tests:read'))):
    from ..discovery import service

    stmt = scoped(Discovery, principal)
    if asset_id:
        stmt = stmt.where(Discovery.asset_id == asset_id)
    if kind:
        stmt = stmt.where(Discovery.kind == kind)
    rows = db.execute(page.apply(stmt.order_by(Discovery.last_seen.desc()))).scalars().all()
    return page.wrap(rows, service.fact_to_dict)


@router.get('/requests')
def list_requests(page: Page = Depends(), asset_id: str | None = None, db: Session = Depends(get_db),
                  principal: Principal = Depends(require('tests:read'))):
    """Captured requests (method, path, status). Header values and bodies are never stored."""
    from ..discovery import service

    stmt = scoped(RequestCapture, principal)
    if asset_id:
        stmt = stmt.where(RequestCapture.asset_id == asset_id)
    rows = db.execute(page.apply(stmt.order_by(RequestCapture.last_seen.desc()))).scalars().all()
    return page.wrap(rows, service.capture_to_dict)


@router.post('/requests/{capture_id}/replay')
async def replay_request(capture_id: str, request: Request, principal: Principal = Depends(require('tests:run'))):
    """Re-issue one captured request. GET/HEAD only, scope re-checked, the response body is not returned."""
    from ..discovery import service

    return await service.replay(request.app, principal, capture_id)
