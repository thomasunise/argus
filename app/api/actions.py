"""Action broker API: catalog, requests, approvals, execution, runs, rollback, kill switch."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..actions import broker, catalog
from ..core.errors import Forbidden
from ..core.rbac import Principal, has
from ..models import Tenant, loads
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/actions', tags=['actions'])


class RequestBody(BaseModel):
    action_type: str = Field(min_length=1, max_length=80)
    params: dict = Field(default_factory=dict)
    reason: str = Field(min_length=1, max_length=4000)
    finding_id: str | None = None
    detection_id: str | None = None


class DecisionBody(BaseModel):
    decision: str = Field(pattern='^(approve|reject)$')
    comment: str = Field(default='', max_length=2000)


class CancelBody(BaseModel):
    reason: str = Field(default='', max_length=500)


class KillSwitchBody(BaseModel):
    enabled: bool
    reason: str = Field(default='', max_length=500)


def _tenant_settings(db: Session, principal: Principal) -> dict:
    tenant = db.get(Tenant, principal.tenant_id)
    data = loads(tenant.settings_json, {}) if tenant else {}
    return data if isinstance(data, dict) else {}


# -- catalog ----------------------------------------------------------------


@router.get('/catalog')
def get_catalog(request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('actions:read'))):
    items = broker.catalog_items(request.app.state.settings, _tenant_settings(db, principal))
    return {'items': items, 'count': len(items), 'platforms': sorted({p for a in catalog.all() for p in a.platforms})}


# -- requests ---------------------------------------------------------------


@router.get('/requests')
def list_requests(status: str | None = None, action_type: str | None = None, finding_id: str | None = None, agent_only: bool = False,
                  page: Page = Depends(), db: Session = Depends(get_db), principal: Principal = Depends(require('actions:read'))):
    stmt = broker.list_requests(db, principal, status=status, action_type=action_type, finding_id=finding_id, agent_only=agent_only)
    rows = db.execute(page.apply(stmt)).scalars().all()
    return page.wrap(rows, broker.request_to_dict)


@router.post('/requests', status_code=201)
async def create_request(body: RequestBody, request: Request, db: Session = Depends(get_db),
                         principal: Principal = Depends(require('actions:request'))):
    req = await broker.request(db, principal, body.action_type, body.params, body.reason, finding_id=body.finding_id,
                               detection_id=body.detection_id, settings=request.app.state.settings)
    return broker.request_detail(db, req)


@router.get('/requests/{request_id}')
def get_request(request_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('actions:read'))):
    return broker.request_detail(db, broker.get_request(db, principal, request_id))


@router.post('/requests/{request_id}/approve')
def approve_request(request_id: str, body: DecisionBody, db: Session = Depends(get_db),
                    principal: Principal = Depends(require('actions:approve'))):
    req = broker.approve(db, principal, request_id, body.decision, body.comment)
    return broker.request_detail(db, req)


@router.post('/requests/{request_id}/execute', status_code=202)
async def execute_request(request_id: str, request: Request, db: Session = Depends(get_db),
                          principal: Principal = Depends(require('actions:execute'))):
    run = await broker.execute(request.app, principal, request_id, db=db)
    return {'run': broker.run_to_dict(run), 'job_id': run.job_id, 'request': broker.request_detail(db, broker.get_request(db, principal, request_id))}


@router.post('/requests/{request_id}/cancel')
def cancel_request(request_id: str, body: CancelBody | None = None, db: Session = Depends(get_db),
                   principal: Principal = Depends(require('actions:read'))):
    req = broker.cancel(db, principal, request_id, body.reason if body else '')
    return broker.request_detail(db, req)


# -- runs -------------------------------------------------------------------


@router.get('/runs')
def list_runs(status: str | None = None, request_id: str | None = None, page: Page = Depends(), db: Session = Depends(get_db),
              principal: Principal = Depends(require('actions:read'))):
    rows = db.execute(page.apply(broker.list_runs(db, principal, status=status, request_id=request_id))).scalars().all()
    return page.wrap(rows, broker.run_to_dict)


@router.get('/runs/{run_id}')
def get_run(run_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('actions:read'))):
    run = broker.get_run(db, principal, run_id)
    return broker.run_to_dict(run, include_rollback_payload=has(principal, 'actions:rollback'))


@router.post('/runs/{run_id}/rollback', status_code=202)
async def rollback_run(run_id: str, request: Request, db: Session = Depends(get_db),
                       principal: Principal = Depends(require('actions:rollback'))):
    run = await broker.rollback(request.app, principal, run_id, db=db)
    return {'run': broker.run_to_dict(run), 'job_id': run.rollback_job_id}


# -- kill switch ------------------------------------------------------------


@router.get('/kill-switch')
def get_kill_switch(request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('actions:read'))):
    return broker.kill_switch_state(db, request.app.state.settings, principal.tenant_id)


@router.post('/kill-switch')
def post_kill_switch(body: KillSwitchBody, request: Request, db: Session = Depends(get_db),
                     principal: Principal = Depends(require('actions:kill_switch'))):
    if principal.role not in {'admin', 'owner'} and principal.auth != 'system':
        raise Forbidden('Only admins and owners can operate the kill switch')
    return broker.set_kill_switch(db, principal, body.enabled, body.reason, settings=request.app.state.settings)
