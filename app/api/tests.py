"""Testing-harness API: adapters, scopes, plans and runs."""
from __future__ import annotations

import re
from datetime import datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.db import get_scoped, scoped
from ..core.errors import NotFound
from ..core.rbac import Principal
from ..models import dumps, utcnow
from ..models.testing import TestPlan, TestResult, TestRun, TestScope
from ..testing import harness
from ..testing import service
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/tests', tags=['tests'])

TIERS = ('passive', 'active', 'intrusive')
_HHMM = re.compile(r'^([01]\d|2[0-3]):[0-5]\d$')


class ScopeBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    asset_ids: list[str] = Field(default_factory=list)
    allowed_tiers: list[str] = Field(default_factory=lambda: ['passive'])
    environments: list[str] = Field(default_factory=list)
    window_start: str = ''
    window_end: str = ''
    max_rps: float = 5.0
    max_concurrency: int = 1
    signed_document_ref: str = ''
    expires_at: datetime | None = None

    @field_validator('allowed_tiers')
    @classmethod
    def _tiers(cls, value: list[str]) -> list[str]:
        bad = [t for t in value if t not in TIERS]
        if bad:
            raise ValueError(f'invalid tiers {bad}; allowed: {list(TIERS)}')
        return value or ['passive']

    @field_validator('window_start', 'window_end')
    @classmethod
    def _window(cls, value: str) -> str:
        if value and not _HHMM.match(value):
            raise ValueError('window times must be UTC "HH:MM"')
        return value

    @field_validator('max_rps')
    @classmethod
    def _rps(cls, value: float) -> float:
        if value <= 0 or value > 100:
            raise ValueError('max_rps must be between 0 and 100')
        return value


class PlanBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scope_id: str
    adapters: list[str] = Field(default_factory=list)
    params: dict = Field(default_factory=dict)
    schedule_minutes: int | None = None
    enabled: bool = True

    @field_validator('adapters')
    @classmethod
    def _adapters(cls, value: list[str]) -> list[str]:
        bad = [a for a in value if a not in harness.ADAPTERS]
        if bad:
            raise ValueError(f'unknown adapters {bad}')
        return value


# -- adapters ---------------------------------------------------------------


@router.get('/adapters')
def list_adapters(request: Request, principal: Principal = Depends(require('tests:read'))):
    settings = request.app.state.settings
    items = [{'name': a.name, 'tier': a.tier, 'target_kinds': list(a.target_kinds), 'description': a.description,
              'available': bool(a.available(settings))} for a in harness.ADAPTERS.values()]
    return {'items': sorted(items, key=lambda x: x['name'])}


# -- scopes -----------------------------------------------------------------


@router.get('/scopes')
def list_scopes(page: Page = Depends(), db: Session = Depends(get_db), principal: Principal = Depends(require('tests:read'))):
    stmt = scoped(TestScope, principal).order_by(TestScope.created_at.desc())
    rows = db.execute(page.apply(stmt)).scalars().all()
    return page.wrap(rows, service.scope_to_dict)


@router.post('/scopes', status_code=201)
def create_scope(body: ScopeBody, db: Session = Depends(get_db), principal: Principal = Depends(require('tests:scopes'))):
    scope = TestScope(tenant_id=principal.tenant_id, name=body.name, asset_ids_json=dumps(body.asset_ids),
                      allowed_tiers_json=dumps(body.allowed_tiers), environments_json=dumps(body.environments),
                      window_start=body.window_start, window_end=body.window_end, max_rps=body.max_rps,
                      max_concurrency=body.max_concurrency, signed_document_ref=body.signed_document_ref,
                      expires_at=body.expires_at, created_by=principal.user_id or '')
    db.add(scope)
    db.flush()
    record_audit(db, principal, 'testing.scope.created', scope.id,
                 {'name': body.name, 'tiers': body.allowed_tiers, 'assets': len(body.asset_ids)})
    return service.scope_to_dict(scope)


@router.get('/scopes/{scope_id}')
def get_scope(scope_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('tests:read'))):
    scope = get_scoped(db, TestScope, principal, scope_id)
    if scope is None:
        raise NotFound('test scope not found')
    return service.scope_to_dict(scope)


@router.post('/scopes/{scope_id}/revoke')
def revoke_scope(scope_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('tests:scopes'))):
    scope = get_scoped(db, TestScope, principal, scope_id)
    if scope is None:
        raise NotFound('test scope not found')
    scope.revoked_at = utcnow()
    record_audit(db, principal, 'testing.scope.revoked', scope_id, {'name': scope.name})
    return {'ok': True}


# -- plans ------------------------------------------------------------------


@router.get('/plans')
def list_plans(page: Page = Depends(), db: Session = Depends(get_db), principal: Principal = Depends(require('tests:read'))):
    stmt = scoped(TestPlan, principal).order_by(TestPlan.created_at.desc())
    rows = db.execute(page.apply(stmt)).scalars().all()
    return page.wrap(rows, service.plan_to_dict)


@router.post('/plans', status_code=201)
def create_plan(body: PlanBody, db: Session = Depends(get_db), principal: Principal = Depends(require('tests:write'))):
    scope = get_scoped(db, TestScope, principal, body.scope_id)
    if scope is None:
        raise NotFound('test scope not found')
    plan = TestPlan(tenant_id=principal.tenant_id, name=body.name, scope_id=body.scope_id,
                    adapters_json=dumps(body.adapters), params_json=dumps(body.params),
                    schedule_minutes=body.schedule_minutes, enabled=body.enabled, created_by=principal.user_id or '')
    db.add(plan)
    db.flush()
    record_audit(db, principal, 'testing.plan.created', plan.id, {'name': body.name, 'adapters': body.adapters})
    return service.plan_to_dict(plan)


@router.get('/plans/{plan_id}')
def get_plan(plan_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('tests:read'))):
    plan = get_scoped(db, TestPlan, principal, plan_id)
    if plan is None:
        raise NotFound('test plan not found')
    return service.plan_to_dict(plan)


@router.post('/plans/{plan_id}/run', status_code=202)
async def run_plan(plan_id: str, request: Request, principal: Principal = Depends(require('tests:run'))):
    runs = await service.launch_plan(request.app, plan_id, principal.tenant_id, principal=principal, triggered_by='manual')
    return {'items': runs}


# -- runs -------------------------------------------------------------------


@router.get('/runs')
def list_runs(page: Page = Depends(), status: str | None = None, asset_id: str | None = None,
              db: Session = Depends(get_db), principal: Principal = Depends(require('tests:read'))):
    stmt = scoped(TestRun, principal)
    if status:
        stmt = stmt.where(TestRun.status == status)
    if asset_id:
        stmt = stmt.where(TestRun.asset_id == asset_id)
    stmt = stmt.order_by(TestRun.created_at.desc())
    rows = db.execute(page.apply(stmt)).scalars().all()
    return page.wrap(rows, service.run_to_dict)


@router.get('/runs/{run_id}')
def get_run(run_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('tests:read'))):
    run = get_scoped(db, TestRun, principal, run_id)
    if run is None:
        raise NotFound('test run not found')
    results = db.execute(scoped(TestResult, principal).where(TestResult.run_id == run_id)
                         .order_by(TestResult.created_at.asc())).scalars().all()
    return {**service.run_to_dict(run), 'results': [service.result_to_dict(r) for r in results]}
