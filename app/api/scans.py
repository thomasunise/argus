"""Ad-hoc single-asset scan API. A scan is a TestRun launched directly against one asset
with one adapter, reusing a TestScope for authorization. Scope is checked at request time
(here) and again at execution time (the queue handler)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from ..core.db import get_scoped, scoped
from ..core.errors import NotFound
from ..core.rbac import Principal
from ..models.testing import TestRun
from ..testing import harness, service
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/scans', tags=['scans'])

TIERS = ('passive', 'active', 'intrusive')


class ScanBody(BaseModel):
    asset_id: str
    adapter: str
    scope_id: str
    tier: str | None = None

    @field_validator('adapter')
    @classmethod
    def _adapter(cls, value: str) -> str:
        if value not in harness.ADAPTERS:
            raise ValueError(f'unknown adapter {value!r}')
        return value

    @field_validator('tier')
    @classmethod
    def _tier(cls, value: str | None) -> str | None:
        if value is not None and value not in TIERS:
            raise ValueError(f'tier must be one of {list(TIERS)}')
        return value


@router.post('', status_code=202)
async def launch(body: ScanBody, request: Request, principal: Principal = Depends(require('scans:run'))):
    run = await service.launch_scan(request.app, principal, asset_id=body.asset_id, adapter_name=body.adapter,
                                    scope_id=body.scope_id, requested_tier=body.tier, triggered_by='manual')
    return run


@router.get('')
def list_scans(page: Page = Depends(), asset_id: str | None = None, db: Session = Depends(get_db),
               principal: Principal = Depends(require('scans:read'))):
    stmt = scoped(TestRun, principal).where(TestRun.plan_id.is_(None))
    if asset_id:
        stmt = stmt.where(TestRun.asset_id == asset_id)
    stmt = stmt.order_by(TestRun.created_at.desc())
    rows = db.execute(page.apply(stmt)).scalars().all()
    return page.wrap(rows, service.run_to_dict)


@router.get('/{run_id}')
def get_scan(run_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('scans:read'))):
    run = get_scoped(db, TestRun, principal, run_id)
    if run is None:
        raise NotFound('scan not found')
    return service.run_to_dict(run)
