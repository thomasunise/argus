"""Agent runs: specs, tool catalog, queued runs with traces, cancellation."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agents.runtime import SPECS, run_to_dict
from ..agents.tools.registry import registry
from ..core.audit import record_audit
from ..core.db import get_scoped, scoped
from ..core.errors import Conflict, Forbidden, NotFound
from ..core.rbac import Principal, has
from ..models import AgentRun, AgentStep, Finding, dumps, utcnow
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/agents', tags=['agents'])

TERMINAL = {'completed', 'failed', 'cancelled', 'refused', 'budget_exhausted'}


MAX_INPUTS_BYTES = 32_000


class RunBody(BaseModel):
    spec: str = Field(min_length=1, max_length=64)
    task: str = Field(default='', max_length=4000)
    inputs: dict = {}
    finding_id: str | None = Field(default=None, max_length=36)

    @field_validator('inputs')
    @classmethod
    def _inputs(cls, value: dict) -> dict:
        if len(dumps(value)) > MAX_INPUTS_BYTES:
            raise ValueError(f'inputs exceed {MAX_INPUTS_BYTES} bytes')
        return value


def _page(limit: int = 50, cursor: str | None = None) -> Page:
    return Page(limit, cursor)


@router.get('/specs')
def list_specs(principal: Principal = Depends(require('agents:read'))):
    items = [{**spec.as_dict(), 'allowed': has(principal, spec.required_permission)} for spec in sorted(SPECS.values(), key=lambda s: s.name)]
    return {'items': items}


@router.get('/tools')
def list_tools(principal: Principal = Depends(require('agents:read'))):
    return {'items': [{'name': t.name, 'description': t.description, 'risk': t.risk, 'tags': list(t.tags), 'input_schema': t.input_schema} for t in registry.all()]}


@router.post('/run', status_code=202)
async def start_run(body: RunBody, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('agents:run'))):
    spec = SPECS.get(body.spec)
    if spec is None:
        raise NotFound(f'Unknown agent spec {body.spec!r}')
    if not has(principal, spec.required_permission):
        raise Forbidden(f'Missing permission {spec.required_permission}')
    inputs = dict(body.inputs or {})
    finding_id = body.finding_id or (inputs.get('finding_id') if isinstance(inputs.get('finding_id'), str) else None)
    if finding_id:
        if get_scoped(db, Finding, principal, finding_id) is None:
            raise NotFound('Finding not found')
        inputs.setdefault('finding_id', finding_id)
    task = body.task.strip() or spec.description or f'Run {spec.name}'
    run = AgentRun(tenant_id=principal.tenant_id, spec=spec.name, task=task, inputs_json=dumps(inputs, limit=20000), status='queued',
                   created_by=principal.user_id or principal.actor, finding_id=finding_id)
    db.add(run)
    db.flush()
    record_audit(db, principal, 'agents.run_requested', run.id, {'spec': spec.name, 'finding_id': finding_id, 'task': task[:200]})
    db.commit()  # the worker may claim the job before this request finishes; the row must be visible first
    payload = {'run_id': run.id, 'spec': spec.name, 'task': task, 'inputs': inputs, 'finding_id': finding_id, 'role': principal.role.value,
               'user_id': principal.user_id, 'email': principal.email, 'system': principal.auth == 'system'}
    job = await request.app.state.queue.enqueue('agents.run', payload, tenant_id=principal.tenant_id, lease_seconds=max(600, (spec.max_seconds or 300) + 120))
    run.job_id = job.id
    db.commit()
    return {**run_to_dict(run), 'job_id': job.id}


@router.get('/runs')
def list_runs(spec: str | None = None, status: str | None = None, finding_id: str | None = None, page: Page = Depends(_page),
              db: Session = Depends(get_db), principal: Principal = Depends(require('agents:read'))):
    stmt = scoped(AgentRun, principal)
    if spec:
        stmt = stmt.where(AgentRun.spec == spec)
    if status:
        stmt = stmt.where(AgentRun.status == status)
    if finding_id:
        stmt = stmt.where(AgentRun.finding_id == finding_id)
    rows = db.execute(page.apply(stmt.order_by(AgentRun.created_at.desc()))).scalars().all()
    return page.wrap(rows, lambda r: {**run_to_dict(r), 'job_id': r.job_id})


@router.get('/runs/{run_id}')
def get_run(run_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('agents:read'))):
    run = get_scoped(db, AgentRun, principal, run_id)
    if run is None:
        raise NotFound('Agent run not found')
    steps = db.execute(select(AgentStep).where(AgentStep.run_id == run.id).order_by(AgentStep.index.asc(), AgentStep.created_at.asc())).scalars().all()
    return {**run_to_dict(run, steps), 'job_id': run.job_id}


@router.post('/runs/{run_id}/cancel')
async def cancel_run(run_id: str, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('agents:run'))):
    run = get_scoped(db, AgentRun, principal, run_id)
    if run is None:
        raise NotFound('Agent run not found')
    if run.status in TERMINAL:
        raise Conflict(f'Run is already {run.status}')
    cancelled = await request.app.state.queue.cancel(run.job_id) if run.job_id else False
    run.status, run.error, run.finished_at = 'cancelled', 'cancelled by user', utcnow()
    record_audit(db, principal, 'agents.run_cancelled', run.id, {'spec': run.spec, 'job_cancelled': cancelled})
    return {**run_to_dict(run), 'job_id': run.job_id, 'job_cancelled': cancelled}
