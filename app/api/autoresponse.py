"""Autonomous-response API: tenant opt-in, playbooks, and the decisions they took (with keep / rollback)."""
from __future__ import annotations

from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..actions import autoresponse as svc
from ..actions import broker
from ..core.audit import record_audit
from ..core.db import get_scoped, scoped
from ..core.errors import ArgusError, NotFound
from ..core.rbac import Principal
from ..models import Tenant, dumps, utcnow
from ..models.autoresponse import AutoresponseExecution, ResponsePlaybook
from .deps import Page, get_db, require

router = APIRouter(prefix='/api/v1/autoresponse', tags=['autoresponse'])

Severity = Literal['critical', 'high', 'medium', 'low', 'informational']
TEMPLATE_LIMIT = 8000


class InvalidPlaybook(ArgusError):
    status = 422
    code = 'invalid_playbook'


class SettingsBody(BaseModel):
    enabled: bool | None = None
    max_per_hour: int | None = Field(default=None, ge=0, le=1000)


class PlaybookBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default='', max_length=2000)
    enabled: bool = True
    mode: Literal['shadow', 'enforce'] = 'shadow'
    rule_ids: list[str] = Field(default_factory=list, max_length=50)
    min_severity: Severity = 'high'
    min_confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    entity_kind: str = Field(default='', max_length=32)
    action_type: str = Field(min_length=1, max_length=80)
    params_template: dict = Field(default_factory=dict)
    max_per_hour: int = Field(default=5, ge=0, le=500)
    max_blast_radius: int = Field(default=1, ge=1, le=100)
    rollback_after_minutes: int = Field(default=60, ge=0, le=60 * 24 * 30)
    allow_high_risk: bool = False


class PlaybookPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool | None = None
    mode: Literal['shadow', 'enforce'] | None = None
    rule_ids: list[str] | None = Field(default=None, max_length=50)
    min_severity: Severity | None = None
    min_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    entity_kind: str | None = Field(default=None, max_length=32)
    action_type: str | None = Field(default=None, min_length=1, max_length=80)
    params_template: dict | None = None
    max_per_hour: int | None = Field(default=None, ge=0, le=500)
    max_blast_radius: int | None = Field(default=None, ge=1, le=100)
    rollback_after_minutes: int | None = Field(default=None, ge=0, le=60 * 24 * 30)
    allow_high_risk: bool | None = None


def _page(limit: int = 50, cursor: str | None = None) -> Page:
    return Page(limit, cursor)


def _validate(action_type: str, allow_high_risk: bool, template: dict, rule_ids: list[str]) -> None:
    problem = svc.check_playbook_action(action_type, allow_high_risk)
    if problem:
        raise InvalidPlaybook(problem)
    if len(dumps(template)) > TEMPLATE_LIMIT:
        raise InvalidPlaybook(f'params_template exceeds {TEMPLATE_LIMIT} bytes')
    if any(not isinstance(r, str) or not r or len(r) > 80 for r in rule_ids):
        raise InvalidPlaybook('rule_ids must be non-empty strings')
    for path in svc.placeholders(template):
        if path.split('.')[0] not in {'id', 'rule_id', 'title', 'severity', 'entity', 'entity_kind', 'confidence', 'finding_id', 'evidence', 'tags'}:
            raise InvalidPlaybook(f'unknown template field {path!r}; use entity, rule_id, severity, confidence, finding_id or evidence.<key>')


def _get_playbook(db: Session, principal: Principal, playbook_id: str) -> ResponsePlaybook:
    row = get_scoped(db, ResponsePlaybook, principal, playbook_id)
    if row is None:
        raise NotFound('playbook not found')
    return row


def _get_execution(db: Session, principal: Principal, execution_id: str) -> AutoresponseExecution:
    row = get_scoped(db, AutoresponseExecution, principal, execution_id)
    if row is None:
        raise NotFound('execution not found')
    return row


# -- status and tenant opt-in ---------------------------------------------------


@router.get('/status')
def status(request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('autoresponse:read'))):
    settings = request.app.state.settings
    tenant = db.get(Tenant, principal.tenant_id)
    since = utcnow() - timedelta(hours=1)
    playbooks = db.execute(scoped(ResponsePlaybook, principal)).scalars().all()
    return {'global_enabled': bool(settings.autoresponse_enabled), 'tenant_enabled': svc.tenant_enabled(tenant),
            'effective': bool(settings.autoresponse_enabled) and svc.tenant_enabled(tenant),
            'max_per_hour': svc.tenant_hourly_cap(tenant, settings),
            'enforced_last_hour': svc._count_since(db, principal.tenant_id, since, outcomes=('enforced',)),
            'kill_switch': broker.kill_switch_state(db, settings, principal.tenant_id),
            'playbooks': {'total': len(playbooks), 'enabled': sum(1 for p in playbooks if p.enabled),
                          'enforcing': sum(1 for p in playbooks if p.enabled and p.mode == 'enforce')}}


@router.put('/settings')
def put_settings(body: SettingsBody, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('autoresponse:write'))):
    svc.set_tenant_config(db, principal, enabled=body.enabled, max_per_hour=body.max_per_hour)
    return status(request, db, principal)


# -- playbooks -----------------------------------------------------------------


@router.get('/playbooks')
def list_playbooks(page: Page = Depends(_page), db: Session = Depends(get_db), principal: Principal = Depends(require('autoresponse:read'))):
    stmt = scoped(ResponsePlaybook, principal).order_by(ResponsePlaybook.created_at.desc(), ResponsePlaybook.id.desc())
    return page.wrap(db.execute(page.apply(stmt)).scalars().all(), svc.playbook_to_dict)


@router.post('/playbooks', status_code=201)
def create_playbook(body: PlaybookBody, db: Session = Depends(get_db), principal: Principal = Depends(require('autoresponse:write'))):
    _validate(body.action_type, body.allow_high_risk, body.params_template, body.rule_ids)
    row = ResponsePlaybook(tenant_id=principal.tenant_id, name=body.name, description=body.description, enabled=body.enabled, mode=body.mode,
                           rule_ids_json=dumps(body.rule_ids), min_severity=body.min_severity, min_confidence=body.min_confidence,
                           entity_kind=body.entity_kind, action_type=body.action_type, params_template_json=dumps(body.params_template),
                           max_per_hour=body.max_per_hour, max_blast_radius=body.max_blast_radius,
                           rollback_after_minutes=body.rollback_after_minutes, allow_high_risk=body.allow_high_risk,
                           created_by=broker.actor_id(principal)[:64])
    db.add(row)
    db.flush()
    record_audit(db, principal, 'autoresponse.playbook_created', row.id, {'name': row.name, 'mode': row.mode, 'action_type': row.action_type,
                                                                      'allow_high_risk': row.allow_high_risk})
    return svc.playbook_to_dict(row)


@router.get('/playbooks/{playbook_id}')
def get_playbook(playbook_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('autoresponse:read'))):
    return svc.playbook_to_dict(_get_playbook(db, principal, playbook_id))


@router.patch('/playbooks/{playbook_id}')
def patch_playbook(playbook_id: str, body: PlaybookPatch, db: Session = Depends(get_db), principal: Principal = Depends(require('autoresponse:write'))):
    row = _get_playbook(db, principal, playbook_id)
    changes = body.model_dump(exclude_unset=True)
    current = svc.playbook_to_dict(row)
    merged = {**current, **{k: v for k, v in changes.items() if v is not None}}
    _validate(merged['action_type'], merged['allow_high_risk'], merged['params_template'], merged['rule_ids'])
    for key, value in changes.items():
        if value is None:
            continue
        if key == 'rule_ids':
            row.rule_ids_json = dumps(value)
        elif key == 'params_template':
            row.params_template_json = dumps(value)
        else:
            setattr(row, key, value)
    row.updated_at = utcnow()
    db.flush()
    record_audit(db, principal, 'autoresponse.playbook_updated', row.id, {'changes': {k: v for k, v in changes.items() if v is not None}})
    return svc.playbook_to_dict(row)


@router.delete('/playbooks/{playbook_id}')
def delete_playbook(playbook_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('autoresponse:write'))):
    row = _get_playbook(db, principal, playbook_id)
    data = svc.playbook_to_dict(row)
    db.delete(row)
    db.flush()
    record_audit(db, principal, 'autoresponse.playbook_deleted', playbook_id, {'name': data['name'], 'action_type': data['action_type']})
    return {'deleted': playbook_id}


# -- executions ----------------------------------------------------------------


@router.get('/executions')
def list_executions(playbook_id: str | None = None, outcome: str | None = None, detection_id: str | None = None, page: Page = Depends(_page),
                    db: Session = Depends(get_db), principal: Principal = Depends(require('autoresponse:read'))):
    stmt = scoped(AutoresponseExecution, principal)
    if playbook_id:
        stmt = stmt.where(AutoresponseExecution.playbook_id == playbook_id)
    if outcome:
        stmt = stmt.where(AutoresponseExecution.outcome == outcome)
    if detection_id:
        stmt = stmt.where(AutoresponseExecution.detection_id == detection_id)
    stmt = stmt.order_by(AutoresponseExecution.created_at.desc(), AutoresponseExecution.id.desc())
    return page.wrap(db.execute(page.apply(stmt)).scalars().all(), svc.execution_to_dict)


@router.get('/executions/{execution_id}')
def get_execution(execution_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('autoresponse:read'))):
    return svc.execution_to_dict(_get_execution(db, principal, execution_id))


@router.post('/executions/{execution_id}/keep')
def keep_execution(execution_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('autoresponse:read', 'actions:approve'))):
    return svc.execution_to_dict(svc.keep(db, principal, _get_execution(db, principal, execution_id)))


@router.post('/executions/{execution_id}/rollback', status_code=202)
async def rollback_execution(execution_id: str, request: Request, db: Session = Depends(get_db),
                             principal: Principal = Depends(require('autoresponse:read', 'actions:rollback'))):
    row = await svc.rollback(request.app, db, principal, _get_execution(db, principal, execution_id))
    return svc.execution_to_dict(row)


__all__ = ['router']
