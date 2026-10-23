"""Investigations: a merged, read-only view over legacy `Investigation` rows (rules-only or
single-shot model summaries) and `AgentRun` rows produced by the investigate/triage specialists."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.db import get_scoped, scoped
from ..core.errors import NotFound
from ..core.rbac import Principal
from ..models import AgentRun, AgentStep, Investigation, loads
from ._common import aware
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/investigations', tags=['investigations'])

AGENT_SPECS = ('investigate', 'triage')


def legacy_to_dict(row: Investigation) -> dict:
    return {'id': row.id, 'kind': 'investigation', 'finding_id': row.finding_id, 'agent_run_id': row.agent_run_id, 'model': row.model,
            'status': 'completed', 'summary': row.summary, 'confidence': row.confidence, 'recommended_steps': loads(row.recommended_steps, []),
            'limitations': loads(row.limitations, []), 'created_by': row.created_by, 'created_at': row.created_at, 'finished_at': row.created_at}


def run_to_investigation(run: AgentRun, steps: list[AgentStep] | None = None) -> dict:
    output = loads(run.output_json)
    data = {'id': run.id, 'kind': 'agent_run', 'spec': run.spec, 'finding_id': run.finding_id, 'agent_run_id': run.id,
            'model': run.model or run.provider or 'rules-only', 'status': run.status,
            'summary': str(output.get('summary') or output.get('assessment') or '')[:4000] if isinstance(output, dict) else '',
            'confidence': output.get('confidence', '') if isinstance(output, dict) else '',
            'recommended_steps': output.get('recommended_steps') or output.get('next_steps') or output.get('proposed_actions') or []
            if isinstance(output, dict) else [],
            'limitations': output.get('limitations', []) if isinstance(output, dict) else [], 'output': output, 'error': run.error,
            'steps_count': run.steps_count, 'cost_estimate_usd': run.cost_estimate_usd, 'created_by': run.created_by, 'created_at': run.created_at,
            'started_at': run.started_at, 'finished_at': run.finished_at, 'job_id': run.job_id}
    if steps is not None:
        data['steps'] = [{'index': s.index, 'kind': s.kind, 'name': s.name, 'input': loads(s.input_json), 'output': loads(s.output_json),
                          'latency_ms': s.latency_ms, 'error': s.error, 'created_at': s.created_at} for s in steps]
    return data


@router.get('')
def list_investigations(finding_id: str | None = None, kind: str | None = None, page: Page = Depends(Page), db: Session = Depends(get_db),
                        principal: Principal = Depends(require('investigations:read'))):
    window = page.offset + page.limit + 1  # fetch enough from each source to merge and slice
    items: list[dict] = []
    if kind in (None, 'investigation'):
        stmt = scoped(Investigation, principal)
        if finding_id:
            stmt = stmt.where(Investigation.finding_id == finding_id)
        items.extend(legacy_to_dict(r) for r in db.execute(stmt.order_by(Investigation.created_at.desc()).limit(window)).scalars())
    if kind in (None, 'agent_run'):
        stmt = scoped(AgentRun, principal).where(AgentRun.spec.in_(AGENT_SPECS))
        if finding_id:
            stmt = stmt.where(AgentRun.finding_id == finding_id)
        items.extend(run_to_investigation(r) for r in db.execute(stmt.order_by(AgentRun.created_at.desc()).limit(window)).scalars())
    items.sort(key=lambda d: aware(d['created_at']) or aware(d.get('finished_at')), reverse=True)
    rows = items[page.offset: page.offset + page.limit + 1]
    return page.wrap(rows, lambda d: d)


@router.get('/{investigation_id}')
def get_investigation(investigation_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('investigations:read'))):
    legacy = get_scoped(db, Investigation, principal, investigation_id)
    if legacy is not None:
        return legacy_to_dict(legacy)
    run = get_scoped(db, AgentRun, principal, investigation_id)
    if run is None or run.spec not in AGENT_SPECS:
        raise NotFound('Investigation not found')
    steps = db.execute(select(AgentStep).where(AgentStep.run_id == run.id).order_by(AgentStep.index.asc(), AgentStep.created_at.asc())).scalars().all()
    return run_to_investigation(run, steps)
