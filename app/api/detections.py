"""Detections API: list/inspect/triage detections, manage per-tenant rule state, trigger runs."""
from __future__ import annotations

from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.db import get_scoped, scoped
from ..core.errors import NotFound, SentinelError
from ..core.rbac import Principal
from ..detections import engine
from ..detections.engine import detection_to_dict, effective_params, registry, rule_states, validate_params
from ..models import dumps, loads, utcnow
from ..models.detections import DETECTION_STATUSES, Detection, DetectionRuleState, DetectionRun
from ._common import like
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/detections', tags=['detections'])

Status = Literal['open', 'investigating', 'resolved', 'false_positive']


class PatchDetectionBody(BaseModel):
    status: Status
    note: str = Field(default='', max_length=2000)


class PatchRuleBody(BaseModel):
    enabled: bool | None = None
    params: dict | None = None


class RunBody(BaseModel):
    since_minutes: int | None = Field(default=None, ge=1, le=10080)
    rule_ids: list[str] = Field(default_factory=list, max_length=50)


def _page(limit: int = 50, cursor: str | None = None) -> Page:
    return Page(limit, cursor)


def _rule_dict(rule, state: DetectionRuleState | None) -> dict:
    return {**rule.to_dict(), 'enabled': state.enabled if state else True, 'params': effective_params(rule, state),
            'overrides': loads(state.params_json) if state else {}, 'updated_at': state.updated_at if state else None,
            'updated_by': state.updated_by if state else ''}


@router.get('')
def list_detections(status: str | None = None, severity: str | None = None, rule_id: str | None = None, entity: str | None = None,
                    page: Page = Depends(_page), db: Session = Depends(get_db), principal: Principal = Depends(require('detections:read'))):
    stmt = scoped(Detection, principal)
    if status:
        stmt = stmt.where(Detection.status == status)
    if severity:
        stmt = stmt.where(Detection.severity == severity)
    if rule_id:
        stmt = stmt.where(Detection.rule_id == rule_id)
    if entity:
        stmt = stmt.where(Detection.entity.ilike(like(entity[:200]), escape='\\'))
    rows = db.execute(page.apply(stmt.order_by(Detection.last_seen_at.desc(), Detection.id.desc()))).scalars().all()
    return page.wrap(rows, detection_to_dict)


@router.get('/rules')
def list_rules(db: Session = Depends(get_db), principal: Principal = Depends(require('detections:read'))):
    states = rule_states(db, principal.tenant_id)
    return {'items': [_rule_dict(rule, states.get(rule.id)) for rule in registry.all()]}


@router.patch('/rules/{rule_id}')
def patch_rule(rule_id: str, body: PatchRuleBody, db: Session = Depends(get_db), principal: Principal = Depends(require('detections:write'))):
    rule = registry.get(rule_id)
    if rule is None:
        raise NotFound('Rule not found')
    state = db.execute(select(DetectionRuleState).where(DetectionRuleState.tenant_id == principal.tenant_id,
                                                        DetectionRuleState.rule_id == rule_id)).scalar_one_or_none()
    if state is None:
        state = DetectionRuleState(tenant_id=principal.tenant_id, rule_id=rule_id)
        db.add(state)
    changes: dict = {}
    if body.enabled is not None:
        state.enabled = body.enabled
        changes['enabled'] = body.enabled
    if body.params is not None:
        try:
            cleaned = validate_params(rule, body.params)
        except ValueError as exc:
            raise SentinelError(str(exc), code='invalid_params', status=400)
        state.params_json = dumps(cleaned, limit=8000)
        changes['params'] = cleaned
    state.updated_at = utcnow()
    state.updated_by = principal.actor
    db.flush()
    record_audit(db, principal, 'detections.rule_updated', rule_id, changes)
    return _rule_dict(rule, state)


@router.get('/stats')
def stats(db: Session = Depends(get_db), principal: Principal = Depends(require('detections:read'))):
    tenant = principal.tenant_id

    def grouped(column) -> dict[str, int]:
        rows = db.execute(select(column, func.count()).where(Detection.tenant_id == tenant).group_by(column)).all()
        return {str(key): int(count) for key, count in rows}

    open_by_severity = db.execute(select(Detection.severity, func.count()).where(Detection.tenant_id == tenant, Detection.status.in_(['open', 'investigating']))
                                  .group_by(Detection.severity)).all()
    last_run = db.execute(select(DetectionRun).where(DetectionRun.tenant_id == tenant).order_by(DetectionRun.started_at.desc()).limit(1)).scalar_one_or_none()
    since_24h = utcnow() - timedelta(hours=24)
    recent = db.scalar(select(func.count()).select_from(Detection).where(Detection.tenant_id == tenant, Detection.last_seen_at >= since_24h)) or 0
    return {'by_rule': grouped(Detection.rule_id), 'by_severity': grouped(Detection.severity), 'by_status': grouped(Detection.status),
            'open_by_severity': {str(k): int(v) for k, v in open_by_severity}, 'last_24h': int(recent), 'rules_registered': len(registry.all()),
            'last_run': None if last_run is None else {
                'id': last_run.id, 'trigger': last_run.trigger, 'since': last_run.since, 'started_at': last_run.started_at,
                'finished_at': last_run.finished_at, 'rules_run': last_run.rules_run, 'detections_created': last_run.detections_created,
                'detections_updated': last_run.detections_updated, 'events_scanned': last_run.events_scanned, 'errors': loads(last_run.errors_json, [])}}


@router.post('/run', status_code=202)
async def trigger_run(body: RunBody, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('detections:run'))):
    unknown = [r for r in body.rule_ids if registry.get(r) is None]
    if unknown:
        raise SentinelError(f'Unknown rule ids: {", ".join(unknown)}', code='invalid_params', status=400)
    since = (utcnow() - timedelta(minutes=body.since_minutes)).isoformat() if body.since_minutes else None
    payload = {'tenant_id': principal.tenant_id, 'since': since, 'rule_ids': body.rule_ids, 'requested_by': principal.actor}
    job = await request.app.state.queue.enqueue('detections.run', payload, tenant_id=principal.tenant_id, lease_seconds=600)
    record_audit(db, principal, 'detections.run_requested', job.id, {'since_minutes': body.since_minutes, 'rule_ids': body.rule_ids})
    return {'job_id': job.id, 'status': job.status}


@router.get('/{detection_id}')
def get_detection(detection_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('detections:read'))):
    detection = get_scoped(db, Detection, principal, detection_id)
    if detection is None:
        raise NotFound('Detection not found')
    return detection_to_dict(detection)


@router.patch('/{detection_id}')
def patch_detection(detection_id: str, body: PatchDetectionBody, db: Session = Depends(get_db),
                    principal: Principal = Depends(require('detections:write'))):
    detection = get_scoped(db, Detection, principal, detection_id)
    if detection is None:
        raise NotFound('Detection not found')
    if body.status not in DETECTION_STATUSES:
        raise SentinelError('Invalid status', code='invalid_status', status=400)
    previous = detection.status
    detection.status = body.status
    detection.updated_at = utcnow()
    db.flush()
    record_audit(db, principal, 'detections.status_changed', detection.id, {'from': previous, 'to': body.status, 'note': body.note, 'rule_id': detection.rule_id})
    return detection_to_dict(detection)


__all__ = ['router', 'engine']
