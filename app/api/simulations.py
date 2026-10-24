"""Attack simulator API: list scenarios, start a run, read reports."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.db import get_scoped, scoped
from ..core.errors import ArgusError, NotFound
from ..core.rbac import Principal
from ..models import dumps
from ..models.simulation import SimulationRun
from ..simulator import SCENARIOS, run_to_dict, scenario_catalog
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/simulations', tags=['simulations'])


class UnknownScenario(ArgusError):
    status = 422
    code = 'unknown_scenario'


class StartBody(BaseModel):
    scenarios: list[str] = Field(default_factory=list, max_length=50, description='scenario ids; empty runs all')
    intensity: Literal['low', 'normal', 'high'] = 'normal'
    evasion: bool = False


def _page(limit: int = 20, cursor: str | None = None) -> Page:
    return Page(limit, cursor)


@router.get('/scenarios')
def scenarios(principal: Principal = Depends(require('detections:read'))):
    return {'items': scenario_catalog()}


@router.post('', status_code=202)
async def start(body: StartBody, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('detections:run'))):
    chosen = list(dict.fromkeys(body.scenarios)) or list(SCENARIOS)
    unknown = [s for s in chosen if s not in SCENARIOS]
    if unknown:
        raise UnknownScenario(f'unknown scenario(s): {", ".join(unknown[:5])}')
    run = SimulationRun(tenant_id=principal.tenant_id, scenarios_json=dumps(chosen), intensity=body.intensity, evasion=body.evasion,
                        created_by=principal.actor[:64])
    db.add(run)
    db.flush()
    record_audit(db, principal, 'simulation.started', run.id, {'scenarios': chosen, 'intensity': body.intensity, 'evasion': body.evasion})
    db.commit()
    job = await request.app.state.queue.enqueue('simulation.run', {'run_id': run.id}, tenant_id=principal.tenant_id, lease_seconds=900,
                                                idempotency_key=f'simulation.run:{run.id}', priority=6)
    run.job_id = job.id
    db.commit()
    return run_to_dict(run)


@router.get('')
def list_runs(page: Page = Depends(_page), db: Session = Depends(get_db), principal: Principal = Depends(require('detections:read'))):
    stmt = scoped(SimulationRun, principal).order_by(SimulationRun.created_at.desc(), SimulationRun.id.desc())
    return page.wrap(db.execute(page.apply(stmt)).scalars().all(), lambda r: run_to_dict(r, full=False))


@router.get('/{run_id}')
def get_run(run_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('detections:read'))):
    run = get_scoped(db, SimulationRun, principal, run_id)
    if run is None:
        raise NotFound('simulation run not found')
    return run_to_dict(run)
