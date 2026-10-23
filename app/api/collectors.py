"""Collector configuration and run endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..collectors import is_secret_ref, load_builtin, registry, validate_config
from ..collectors.base import literal_refs_allowed
from ..collectors.runner import enqueue_run
from ..core.audit import record_audit
from ..core.config import Settings
from ..core.errors import NotFound, SentinelError
from ..integrations.egress import check_url_config
from ..core.rbac import Principal
from ..core.security import redact
from ..models import dumps, loads, utcnow
from ..models.collectors import CollectorConfig, CollectorRun
from .deps import Page, get_db, get_settings, require

router = APIRouter(prefix='/api/v1/collectors', tags=['collectors'])


class InvalidConfig(SentinelError):
    status = 400
    code = 'invalid_config'


class CreateBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    collector: str = Field(min_length=1, max_length=40)
    config: dict[str, Any] = {}
    secret_refs: dict[str, str] = {}
    enabled: bool = True
    schedule_minutes: int | None = Field(default=None, ge=0, le=10080)


class PatchBody(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    config: dict[str, Any] | None = None
    secret_refs: dict[str, str] | None = None
    enabled: bool | None = None
    schedule_minutes: int | None = Field(default=None, ge=0, le=10080)


def _page(limit: int = 50, cursor: str | None = None) -> Page:
    return Page(limit, cursor)


MAX_CONFIG_BYTES = 32_000


def _validate(collector_name: str, config: dict[str, Any], secret_refs: dict[str, str], settings: Settings | None = None) -> None:
    load_builtin()
    if not registry.has(collector_name):
        raise InvalidConfig(f'unknown collector {collector_name!r}; see GET /api/v1/collectors/types')
    collector = registry.get(collector_name)
    if len(dumps(config)) > MAX_CONFIG_BYTES:
        raise InvalidConfig(f'config exceeds {MAX_CONFIG_BYTES} bytes')
    errors = validate_config(collector.config_schema, config)
    if settings is not None:
        errors += check_url_config(config, settings, allow_http=bool(settings.allow_private_targets))
    allow_literal = literal_refs_allowed(settings) if settings is not None else True
    for key in collector.secret_fields:
        if key in config:
            errors.append(f'{key} is a secret and must be supplied in secret_refs as env:NAME, file:/path or secrets:KEY, never inline')
    for key, value in config.items():
        if isinstance(value, str) and redact(value) != value:
            errors.append(f'config value {key} looks like a credential; move it to secret_refs')
    for key, ref in secret_refs.items():
        if key not in collector.secret_fields:
            errors.append(f'unknown secret field {key}; allowed: {", ".join(collector.secret_fields) or "none"}')
        elif not is_secret_ref(ref):
            errors.append(f'secret_refs.{key} must be a reference (env:NAME, file:/path, secrets:KEY)'
                          + ('; a literal value needs the literal: prefix' if allow_literal else ''))
        elif not allow_literal and str(ref).startswith('literal:'):
            errors.append(f'secret_refs.{key} uses a literal: value; literal secret references are disabled on this deployment '
                          '(ALLOW_LITERAL_SECRET_REFS). Use env:NAME, file:/path or secrets:KEY')
    if errors:
        raise InvalidConfig('; '.join(errors)[:2000])


def _config_dict(config: CollectorConfig) -> dict[str, Any]:
    load_builtin()
    collector = registry.get(config.collector) if registry.has(config.collector) else None
    return {'id': config.id, 'name': config.name, 'collector': config.collector, 'kind': collector.kind if collector else None,
            'config': loads(config.config_json, {}), 'secret_refs': loads(config.secret_refs_json, {}), 'enabled': config.enabled,
            'schedule_minutes': config.schedule_minutes, 'last_run_at': config.last_run_at, 'last_success_at': config.last_success_at,
            'last_error': config.last_error, 'created_by': config.created_by, 'created_at': config.created_at, 'updated_at': config.updated_at,
            'available': bool(collector and collector.available())}


def _run_dict(run: CollectorRun) -> dict[str, Any]:
    return {'id': run.id, 'config_id': run.config_id, 'status': run.status, 'stats': loads(run.stats_json, {}), 'warnings': loads(run.warnings_json, []),
            'error': run.error, 'job_id': run.job_id, 'triggered_by': run.triggered_by, 'created_at': run.created_at, 'started_at': run.started_at,
            'finished_at': run.finished_at}


def _get_config(db: Session, principal: Principal, config_id: str) -> CollectorConfig:
    config = db.execute(select(CollectorConfig).where(CollectorConfig.id == config_id, CollectorConfig.tenant_id == principal.tenant_id)).scalar_one_or_none()
    if config is None:
        raise NotFound('Collector config not found')
    return config


# ---------------------------------------------------------------- routes


@router.get('/types')
def list_types(principal: Principal = Depends(require('collectors:read'))):
    load_builtin()
    return {'items': [c.describe() for c in registry.all()]}


@router.get('')
@router.get('/')
def list_configs(collector: str | None = None, enabled: bool | None = None, db: Session = Depends(get_db), page: Page = Depends(_page),
                 principal: Principal = Depends(require('collectors:read'))):
    stmt = select(CollectorConfig).where(CollectorConfig.tenant_id == principal.tenant_id)
    if collector:
        stmt = stmt.where(CollectorConfig.collector == collector)
    if enabled is not None:
        stmt = stmt.where(CollectorConfig.enabled.is_(enabled))
    rows = db.execute(page.apply(stmt.order_by(CollectorConfig.created_at.desc()))).scalars().all()
    return page.wrap(rows, _config_dict)


@router.post('', status_code=201)
@router.post('/', status_code=201, include_in_schema=False)
def create_config(body: CreateBody, db: Session = Depends(get_db), principal: Principal = Depends(require('collectors:write')),
                  settings: Settings = Depends(get_settings)):
    _validate(body.collector, body.config, body.secret_refs, settings)
    collector = registry.get(body.collector)
    schedule = body.schedule_minutes if body.schedule_minutes is not None else collector.default_schedule_minutes
    config = CollectorConfig(tenant_id=principal.tenant_id, name=body.name, collector=body.collector, config_json=dumps(body.config),
                             secret_refs_json=dumps(body.secret_refs), enabled=body.enabled, schedule_minutes=schedule, created_by=principal.user_id or principal.actor)
    db.add(config)
    db.flush()
    record_audit(db, principal, 'collectors.create', config.id, {'name': body.name, 'collector': body.collector, 'schedule_minutes': schedule,
                                                                 'secret_fields': sorted(body.secret_refs), 'config_keys': sorted(body.config)})
    return _config_dict(config)


@router.get('/runs/{run_id}')
def get_run(run_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('collectors:read'))):
    run = db.execute(select(CollectorRun).where(CollectorRun.id == run_id, CollectorRun.tenant_id == principal.tenant_id)).scalar_one_or_none()
    if run is None:
        raise NotFound('Collector run not found')
    return _run_dict(run)


@router.get('/{config_id}')
def get_config(config_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('collectors:read'))):
    return _config_dict(_get_config(db, principal, config_id))


@router.patch('/{config_id}')
def patch_config(config_id: str, body: PatchBody, db: Session = Depends(get_db), principal: Principal = Depends(require('collectors:write')),
                 settings: Settings = Depends(get_settings)):
    config = _get_config(db, principal, config_id)
    new_config = body.config if body.config is not None else loads(config.config_json, {})
    new_refs = body.secret_refs if body.secret_refs is not None else loads(config.secret_refs_json, {})
    _validate(config.collector, new_config, new_refs, settings)
    changed: dict[str, Any] = {}
    if body.name is not None and body.name != config.name:
        config.name, changed['name'] = body.name, body.name
    if body.config is not None:
        config.config_json, changed['config_keys'] = dumps(new_config), sorted(new_config)
    if body.secret_refs is not None:
        config.secret_refs_json, changed['secret_fields'] = dumps(new_refs), sorted(new_refs)
    if body.enabled is not None and body.enabled != config.enabled:
        config.enabled, changed['enabled'] = body.enabled, body.enabled
    if body.schedule_minutes is not None and body.schedule_minutes != config.schedule_minutes:
        config.schedule_minutes, changed['schedule_minutes'] = body.schedule_minutes, body.schedule_minutes
    if changed:
        config.updated_at = utcnow()
        record_audit(db, principal, 'collectors.update', config.id, changed)
    return _config_dict(config)


@router.delete('/{config_id}')
def delete_config(config_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('collectors:write'))):
    config = _get_config(db, principal, config_id)
    for run in db.execute(select(CollectorRun).where(CollectorRun.config_id == config.id, CollectorRun.tenant_id == principal.tenant_id)).scalars():
        db.delete(run)
    db.delete(config)
    record_audit(db, principal, 'collectors.delete', config_id, {'name': config.name, 'collector': config.collector})
    return {'ok': True}


@router.post('/{config_id}/run', status_code=202)
async def run_config(config_id: str, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('collectors:run'))):
    config = _get_config(db, principal, config_id)
    if not config.enabled:
        raise InvalidConfig('collector config is disabled')
    load_builtin()
    if not registry.has(config.collector):
        raise InvalidConfig(f'unknown collector {config.collector!r}')
    collector = registry.get(config.collector)
    if not collector.available():
        raise SentinelError(f'collector {collector.name} is not available on this server: {collector.install_hint()}', code='unavailable', status=503)
    run, created = await enqueue_run(request.app, db, config, principal.user_id or principal.api_key_id or principal.actor)
    if created:
        record_audit(db, principal, 'collectors.run_requested', config.id, {'run_id': run.id, 'collector': config.collector})
        db.commit()  # async endpoint: release the SQLite write lock before yielding to the in-process worker
    return {'run_id': run.id, 'job_id': run.job_id, 'status': run.status, 'already_queued': not created}


@router.get('/{config_id}/runs')
def list_runs(config_id: str, db: Session = Depends(get_db), page: Page = Depends(_page), principal: Principal = Depends(require('collectors:read'))):
    config = _get_config(db, principal, config_id)
    stmt = select(CollectorRun).where(CollectorRun.config_id == config.id, CollectorRun.tenant_id == principal.tenant_id).order_by(CollectorRun.created_at.desc())
    rows = db.execute(page.apply(stmt)).scalars().all()
    return page.wrap(rows, _run_dict)
