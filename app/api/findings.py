"""Findings: list/search, detail with linked context, lifecycle transitions, agent
investigation, CSV export and statistics. Findings are created only by
`core.findings.upsert_finding`; this router changes workflow state."""
from __future__ import annotations

import csv
import io
import logging
from datetime import timedelta
from typing import Any, Iterator

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.db import get_scoped, scoped
from ..core.errors import Conflict, Forbidden, NotFound, Unavailable
from ..core.events import publish
from ..core.findings import SEVERITIES, finding_to_dict
from ..core.rbac import Principal, has
from ..models import AgentRun, Asset, Finding, Investigation, Membership, dumps, loads, utcnow
from ..models.findings import FINDING_STATUSES
from ._common import BadRequest, aware, asset_to_dict, like
from .deps import Page, get_db, require

log = logging.getLogger('argus.api.findings')

router = APIRouter(prefix='/api/v1/findings', tags=['findings'])

TRANSITIONS: dict[str, set[str]] = {
    'open': {'investigating', 'resolved', 'accepted', 'false_positive'},
    'investigating': {'open', 'resolved', 'accepted', 'false_positive'},
    'resolved': {'open'},
    'accepted': {'open'},
    'false_positive': {'open'},
}
AGING_BUCKETS = (('<1d', 1), ('1-7d', 7), ('7-30d', 30), ('>30d', None))
CSV_COLUMNS = ('id', 'severity', 'status', 'source', 'rule', 'asset_id', 'asset_name', 'title', 'cve_ids', 'cvss', 'epss', 'kev', 'assignee',
               'occurrences', 'created_at', 'updated_at', 'remediation')
MAX_EXPORT_ROWS = 50_000
MAX_INPUTS_BYTES = 32_000
_FORMULA_PREFIX = ('=', '+', '-', '@', '\t', '\r', '\n')


def csv_cell(value: Any) -> Any:
    """Neutralize spreadsheet formula injection: text starting with = + - @ (or a control character) is prefixed with
    a quote so Excel/Sheets render it as literal text. Numbers and empty values pass through unchanged."""
    if not isinstance(value, str) or not value:
        return value
    if value[0] in _FORMULA_PREFIX or value.lstrip()[:1] in ('=', '+', '-', '@'):
        return "'" + value
    return value
SEVERITY_RANK = case({name: index for index, name in enumerate(SEVERITIES)}, value=Finding.severity, else_=len(SEVERITIES))


class FindingPatch(BaseModel):
    status: str | None = None
    assignee: str | None = Field(default=None, max_length=36)
    tags: list[str] | None = None
    comment: str = Field(default='', max_length=2000)


class InvestigateBody(BaseModel):
    task: str = Field(default='', max_length=2000)
    inputs: dict[str, Any] = {}

    @field_validator('inputs')
    @classmethod
    def _inputs(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(dumps(value)) > MAX_INPUTS_BYTES:
            raise ValueError(f'inputs exceed {MAX_INPUTS_BYTES} bytes')
        return value


def _get_finding(db: Session, principal: Principal, finding_id: str) -> Finding:
    finding = get_scoped(db, Finding, principal, finding_id)
    if finding is None:
        raise NotFound('Finding not found')
    return finding


def _filtered(principal: Principal, *, status: str | None, severity: str | None, source: str | None, asset_id: str | None, rule: str | None,
              search: str | None, assignee: str | None):
    stmt = scoped(Finding, principal)
    if status:
        statuses = [s for s in status.split(',') if s]
        stmt = stmt.where(Finding.status.in_(statuses))
    if severity:
        stmt = stmt.where(Finding.severity.in_([s for s in severity.split(',') if s]))
    if source:
        stmt = stmt.where(Finding.source == source)
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if rule:
        stmt = stmt.where(Finding.rule == rule)
    if assignee is not None:
        stmt = stmt.where(Finding.assignee == assignee)
    if search:
        pattern = like(search.strip())
        stmt = stmt.where(or_(Finding.title.ilike(pattern, escape='\\'), Finding.description.ilike(pattern, escape='\\'),
                              Finding.rule.ilike(pattern, escape='\\'), Finding.cve_ids.ilike(pattern, escape='\\')))
    return stmt


def _ordered(stmt, sort: str):
    if sort == 'severity':
        return stmt.order_by(SEVERITY_RANK.asc(), Finding.updated_at.desc(), Finding.id)
    if sort == 'created':
        return stmt.order_by(Finding.created_at.desc(), Finding.id)
    return stmt.order_by(Finding.updated_at.desc(), Finding.id)


def _linked_detection(db: Session, tenant_id: str, detection_id: str | None) -> dict | None:
    if not detection_id:
        return None
    try:
        from ..detections.engine import detection_to_dict
        from ..models.detections import Detection
    except ImportError:
        return {'id': detection_id, 'available': False}
    row = db.execute(select(Detection).where(Detection.tenant_id == tenant_id, Detection.id == detection_id)).scalar_one_or_none()
    return detection_to_dict(row) if row else None


def _action_requests(db: Session, tenant_id: str, finding_id: str) -> list[dict]:
    try:
        from ..models.actions import ActionRequest
    except ImportError:
        return []
    rows = db.execute(select(ActionRequest).where(ActionRequest.tenant_id == tenant_id, ActionRequest.finding_id == finding_id)
                      .order_by(ActionRequest.created_at.desc()).limit(20)).scalars().all()
    out = []
    for r in rows:
        out.append({'id': r.id, 'action_type': getattr(r, 'action_type', ''), 'status': getattr(r, 'status', ''),
                    'risk': getattr(r, 'risk', ''), 'created_at': getattr(r, 'created_at', None)})
    return out


def _investigation_dict(row: Investigation) -> dict:
    return {'id': row.id, 'finding_id': row.finding_id, 'agent_run_id': row.agent_run_id, 'model': row.model, 'summary': row.summary,
            'confidence': row.confidence, 'recommended_steps': loads(row.recommended_steps, []), 'limitations': loads(row.limitations, []),
            'created_by': row.created_by, 'created_at': row.created_at}


# ---------------------------------------------------------------- fixed-path routes (before /{finding_id})


@router.get('')
def list_findings(status: str | None = None, severity: str | None = None, source: str | None = None, asset_id: str | None = None,
                  rule: str | None = None, search: str | None = None, assignee: str | None = None, sort: str = 'updated',
                  page: Page = Depends(Page), db: Session = Depends(get_db), principal: Principal = Depends(require('findings:read'))):
    stmt = _filtered(principal, status=status, severity=severity, source=source, asset_id=asset_id, rule=rule, search=search, assignee=assignee)
    rows = db.execute(page.apply(_ordered(stmt, sort))).scalars().all()
    return page.wrap(rows, finding_to_dict)


@router.get('/export.csv')
def export_csv(status: str | None = None, severity: str | None = None, source: str | None = None, asset_id: str | None = None,
               rule: str | None = None, search: str | None = None, assignee: str | None = None, sort: str = 'severity',
               db: Session = Depends(get_db), principal: Principal = Depends(require('findings:read'))):
    stmt = _filtered(principal, status=status, severity=severity, source=source, asset_id=asset_id, rule=rule, search=search, assignee=assignee)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    record_audit(db, principal, 'findings.exported', '', {'format': 'csv', 'rows': int(total),
                                                           'filters': {k: v for k, v in {'status': status, 'severity': severity, 'source': source,
                                                                                         'asset_id': asset_id, 'rule': rule, 'search': search,
                                                                                         'assignee': assignee}.items() if v}})
    db.commit()
    asset_names = {a.id: a.name for a in db.execute(select(Asset.id, Asset.name).where(Asset.tenant_id == principal.tenant_id)).all()}
    rows = db.execute(_ordered(stmt, sort).limit(MAX_EXPORT_ROWS)).scalars().all()

    def generate() -> Iterator[str]:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(CSV_COLUMNS)
        yield buffer.getvalue()
        for f in rows:
            buffer.seek(0)
            buffer.truncate()
            writer.writerow([csv_cell(v) for v in (
                f.id, f.severity, f.status, f.source, f.rule, f.asset_id or '', asset_names.get(f.asset_id or '', ''), f.title,
                f.cve_ids, f.cvss if f.cvss is not None else '', f.epss if f.epss is not None else '', int(bool(f.kev)), f.assignee,
                f.occurrences, aware(f.created_at).isoformat(), aware(f.updated_at).isoformat(), f.remediation)])
            yield buffer.getvalue()

    return StreamingResponse(generate(), media_type='text/csv',
                             headers={'Content-Disposition': 'attachment; filename="argus-findings.csv"', 'X-Row-Count': str(int(total))})


@router.get('/stats')
def finding_stats(db: Session = Depends(get_db), principal: Principal = Depends(require('findings:read'))):
    tenant_id = principal.tenant_id
    now = utcnow()
    open_states = ['open', 'investigating']

    def group(column, *where) -> dict[str, int]:
        rows = db.execute(select(column, func.count()).where(Finding.tenant_id == tenant_id, *where).group_by(column)).all()
        return {str(key): int(n) for key, n in rows}

    by_severity_open = group(Finding.severity, Finding.status.in_(open_states))
    by_status = group(Finding.status)
    by_source = group(Finding.source)
    by_source_open = group(Finding.source, Finding.status.in_(open_states))
    resolved = db.execute(select(Finding.created_at, Finding.updated_at).where(Finding.tenant_id == tenant_id, Finding.status == 'resolved')
                          .order_by(Finding.updated_at.desc()).limit(5000)).all()
    durations = [(aware(u) - aware(c)).total_seconds() / 3600 for c, u in resolved if c and u]
    mttr_hours = round(sum(durations) / len(durations), 2) if durations else None
    opened = db.execute(select(Finding.created_at).where(Finding.tenant_id == tenant_id, Finding.status.in_(open_states))).scalars().all()
    aging = {label: 0 for label, _ in AGING_BUCKETS}
    for created in opened:
        age_days = (now - aware(created)).total_seconds() / 86400
        for label, limit in AGING_BUCKETS:
            if limit is None or age_days < limit:
                aging[label] += 1
                break
    week_ago = now - timedelta(days=7)
    opened_7d = db.scalar(select(func.count()).select_from(Finding).where(Finding.tenant_id == tenant_id, Finding.created_at >= week_ago)) or 0
    resolved_7d = db.scalar(select(func.count()).select_from(Finding).where(Finding.tenant_id == tenant_id, Finding.status == 'resolved',
                                                                            Finding.updated_at >= week_ago)) or 0
    return {'generated_at': now, 'open_total': sum(by_severity_open.values()),
            'by_severity': {s: by_severity_open.get(s, 0) for s in SEVERITIES},
            'by_status': {s: by_status.get(s, 0) for s in FINDING_STATUSES}, 'by_source': by_source, 'by_source_open': by_source_open,
            'mean_time_to_resolve_hours': mttr_hours, 'resolved_sample': len(durations), 'aging': aging,
            'opened_7d': int(opened_7d), 'resolved_7d': int(resolved_7d), 'kev_open': int(db.scalar(
                select(func.count()).select_from(Finding).where(Finding.tenant_id == tenant_id, Finding.kev == 1, Finding.status.in_(open_states))) or 0)}


# ---------------------------------------------------------------- single finding


@router.get('/{finding_id}')
def get_finding(finding_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('findings:read'))):
    finding = _get_finding(db, principal, finding_id)
    data = finding_to_dict(finding)
    asset = get_scoped(db, Asset, principal, finding.asset_id) if finding.asset_id else None
    data['asset'] = asset_to_dict(asset) if asset else None
    data['investigations'] = [_investigation_dict(r) for r in db.execute(
        select(Investigation).where(Investigation.tenant_id == principal.tenant_id, Investigation.finding_id == finding.id)
        .order_by(Investigation.created_at.desc()).limit(20)).scalars()]
    runs = db.execute(select(AgentRun).where(AgentRun.tenant_id == principal.tenant_id, AgentRun.finding_id == finding.id)
                      .order_by(AgentRun.created_at.desc()).limit(20)).scalars().all()
    data['agent_runs'] = [{'id': r.id, 'spec': r.spec, 'status': r.status, 'model': r.model, 'output': loads(r.output_json), 'error': r.error,
                           'created_at': r.created_at, 'finished_at': r.finished_at} for r in runs]
    data['detection'] = _linked_detection(db, principal.tenant_id, finding.detection_id)
    data['action_requests'] = _action_requests(db, principal.tenant_id, finding.id)
    return data


@router.patch('/{finding_id}')
async def patch_finding(finding_id: str, body: FindingPatch, db: Session = Depends(get_db), principal: Principal = Depends(require('findings:write'))):
    finding = _get_finding(db, principal, finding_id)
    changes: dict[str, Any] = {}
    if body.status is not None and body.status != finding.status:
        if body.status not in FINDING_STATUSES:
            raise BadRequest(f'status must be one of {list(FINDING_STATUSES)}', code='invalid_status')
        if body.status not in TRANSITIONS.get(finding.status, set()):
            raise Conflict(f'Cannot move a finding from {finding.status} to {body.status}', code='invalid_transition')
        changes['status'] = {'from': finding.status, 'to': body.status}
        finding.status = body.status
        record_audit(db, principal, 'findings.status_changed', finding.id, {'from': changes['status']['from'], 'to': body.status, 'comment': body.comment})
    if body.assignee is not None and body.assignee != finding.assignee:
        if body.assignee:
            member = db.execute(select(Membership).where(Membership.tenant_id == principal.tenant_id, Membership.user_id == body.assignee)).scalar_one_or_none()
            if member is None:
                raise BadRequest('assignee must be a user id with a membership in this tenant', code='invalid_assignee')
        changes['assignee'] = {'from': finding.assignee, 'to': body.assignee}
        finding.assignee = body.assignee
        record_audit(db, principal, 'findings.assigned', finding.id, {'from': changes['assignee']['from'], 'to': body.assignee})
    if body.tags is not None:
        tags = sorted({t.strip()[:40] for t in body.tags if t and t.strip()})
        if dumps(tags) != finding.tags_json:
            changes['tags'] = {'from': loads(finding.tags_json, []), 'to': tags}
            finding.tags_json = dumps(tags)
            record_audit(db, principal, 'findings.tagged', finding.id, {'tags': tags})
    if changes:
        finding.updated_at = utcnow()
        db.commit()  # subscribers may read the finding; make the change visible first
        await publish('finding.updated', {'tenant_id': principal.tenant_id, 'finding_id': finding.id, 'severity': finding.severity,
                                          'status': finding.status, 'title': finding.title, 'source': finding.source, 'asset_id': finding.asset_id,
                                          'changes': changes, 'actor': principal.actor})
    return finding_to_dict(finding)


@router.post('/{finding_id}/investigate', status_code=202)
async def investigate_finding(finding_id: str, request: Request, body: InvestigateBody | None = None, db: Session = Depends(get_db),
                              principal: Principal = Depends(require('findings:write', 'agents:run'))):
    """Queue the `investigate` specialist against this finding. Returns the agent run and job ids;
    poll /api/v1/agents/runs/{id} for the trace and result."""
    finding = _get_finding(db, principal, finding_id)
    try:
        from ..agents.runtime import SPECS
    except ImportError as exc:
        raise Unavailable('Agent runtime is not installed') from exc
    spec = SPECS.get('investigate')
    if spec is None:
        raise Unavailable('The investigate specialist is not registered; agent specialists are not loaded on this deployment')
    if not has(principal, spec.required_permission):
        raise Forbidden(f'Missing permission {spec.required_permission}')
    body = body or InvestigateBody()
    inputs = {k: v for k, v in (body.inputs or {}).items() if k != 'finding_id'}
    inputs['finding_id'] = finding.id
    task = body.task.strip() or f'Investigate finding {finding.id}: {finding.title}'[:2000]
    run = AgentRun(tenant_id=principal.tenant_id, spec=spec.name, task=task, inputs_json=dumps(inputs, limit=20000), status='queued',
                   created_by=principal.user_id or principal.actor, finding_id=finding.id)
    db.add(run)
    db.flush()
    record_audit(db, principal, 'findings.investigate_requested', finding.id, {'agent_run_id': run.id, 'spec': spec.name})
    db.commit()  # the worker may claim the job before this request finishes; the row must be visible first
    payload = {'run_id': run.id, 'spec': spec.name, 'task': task, 'inputs': inputs, 'finding_id': finding.id, 'role': principal.role.value,
               'user_id': principal.user_id, 'email': principal.email, 'system': principal.auth == 'system'}
    try:
        job = await request.app.state.queue.enqueue('agents.run', payload, tenant_id=principal.tenant_id,
                                                    lease_seconds=max(600, (spec.max_seconds or 300) + 120))
    except KeyError as exc:
        run.status, run.error, run.finished_at = 'failed', 'agents.run handler not registered', utcnow()
        db.commit()
        raise Unavailable('The agent job handler is not registered on this deployment') from exc
    run.job_id = job.id
    db.commit()
    return {'agent_run_id': run.id, 'job_id': job.id, 'finding_id': finding.id, 'spec': spec.name, 'status': run.status}
