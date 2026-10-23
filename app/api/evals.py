"""Specialist evals: suites, queued runs and reports."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..agents import evals
from ..agents.evals.runner import eval_to_dict, list_suites, load_suite
from ..agents.runtime import SPECS
from ..core.audit import record_audit
from ..core.db import get_scoped, scoped
from ..core.errors import NotFound
from ..core.rbac import Principal
from ..models import EvalRun, dumps
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/evals', tags=['evals'])


class EvalBody(BaseModel):
    suite: str = Field(min_length=1, max_length=64)
    spec: str | None = None
    case_ids: list[str] | None = None


def _page(limit: int = 50, cursor: str | None = None) -> Page:
    return Page(limit, cursor)


@router.get('/suites')
def suites(principal: Principal = Depends(require('evals:read'))):
    return {'items': list_suites()}


@router.post('/run', status_code=202)
async def start_eval(body: EvalBody, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('evals:run'))):
    suite = load_suite(body.suite)  # raises NotFound
    if body.spec and body.spec not in SPECS:
        raise NotFound(f'Unknown agent spec {body.spec!r}')
    evals.register(request.app)  # idempotent safety net until app.agents.setup calls it
    run = EvalRun(tenant_id=principal.tenant_id, suite=suite['name'], spec=body.spec or suite.get('spec', ''), status='queued',
                  created_by=principal.user_id or principal.actor)
    db.add(run)
    db.flush()
    record_audit(db, principal, 'evals.run_requested', run.id, {'suite': suite['name'], 'spec': run.spec, 'case_ids': body.case_ids})
    db.commit()
    payload = {'eval_id': run.id, 'suite': suite['name'], 'spec': body.spec, 'case_ids': body.case_ids, 'role': principal.role.value,
               'user_id': principal.user_id, 'email': principal.email, 'system': principal.auth == 'system'}
    job = await request.app.state.queue.enqueue(evals.JOB_KIND, payload, tenant_id=principal.tenant_id, lease_seconds=3600)
    run.report_json = dumps({'job_id': job.id})
    db.commit()
    return {**eval_to_dict(run), 'job_id': job.id}


@router.get('')
def list_evals(suite: str | None = None, status: str | None = None, spec: str | None = None, page: Page = Depends(_page),
               db: Session = Depends(get_db), principal: Principal = Depends(require('evals:read'))):
    stmt = scoped(EvalRun, principal)
    if suite:
        stmt = stmt.where(EvalRun.suite == suite)
    if status:
        stmt = stmt.where(EvalRun.status == status)
    if spec:
        stmt = stmt.where(EvalRun.spec == spec)
    rows = db.execute(page.apply(stmt.order_by(EvalRun.created_at.desc()))).scalars().all()
    return page.wrap(rows, lambda r: eval_to_dict(r, with_report=False))


@router.get('/{eval_id}')
def get_eval(eval_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('evals:read'))):
    run = get_scoped(db, EvalRun, principal, eval_id)
    if run is None:
        raise NotFound('Eval run not found')
    return eval_to_dict(run)
