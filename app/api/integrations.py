"""Integration configuration, deliveries and ingest-batch endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.errors import NotFound, SentinelError
from ..core.rbac import Principal
from ..core.config import Settings
from ..core.security import mask_secret_refs, merge_secret_refs
from ..integrations.delivery import TEST_TOPIC, delivery_to_dict, resolve_secrets, send_delivery
from ..integrations.egress import check_url_config
from ..integrations.inbound import registry as inbound_registry
from ..integrations.ingest import batch_to_dict
from ..integrations.outbound import registry as outbound_registry
from ..integrations.schema import validate_no_inline_secrets, validate_schema, validate_secret_refs, validate_severity, validate_topics
from ..models import dumps, loads, utcnow
from ..models.integrations import IngestBatch, IntegrationConfig, WebhookDelivery
from .deps import Page, get_db, get_settings, require

router = APIRouter(prefix='/api/v1/integrations', tags=['integrations'])


class InvalidConfig(SentinelError):
    status = 400
    code = 'invalid_config'


class CreateBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: str = Field(min_length=1, max_length=40)
    config: dict[str, Any] = {}
    secret_refs: dict[str, str] = {}
    enabled: bool = True
    topics: list[str] | None = None
    min_severity: str = 'low'


class PatchBody(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    config: dict[str, Any] | None = None
    secret_refs: dict[str, str] | None = None
    enabled: bool | None = None
    topics: list[str] | None = None
    min_severity: str | None = None


def _page(limit: int = 50, cursor: str | None = None) -> Page:
    return Page(limit, cursor)


def _kind(kind: str) -> tuple[str, Any]:
    """('inbound', parser) or ('outbound', channel); raises InvalidConfig for unknown kinds."""
    if outbound_registry.has(kind):
        return 'outbound', outbound_registry.get(kind)
    if inbound_registry.has(kind):
        return 'inbound', inbound_registry.get(kind)
    raise InvalidConfig(f'unknown integration kind {kind!r}; see GET /api/v1/integrations/types')


MAX_CONFIG_BYTES = 32_000


def _literal_allowed(settings: Settings | None) -> bool:
    return bool(getattr(settings, 'allow_literal_secret_refs', True))


def _validate(kind: str, config: dict[str, Any], secret_refs: dict[str, str], topics: list[str], min_severity: str,
              settings: Settings | None = None) -> None:
    direction, impl = _kind(kind)
    if len(dumps(config)) > MAX_CONFIG_BYTES:
        raise InvalidConfig(f'config exceeds {MAX_CONFIG_BYTES} bytes')
    errors = validate_schema(impl.config_schema, config)
    errors += validate_no_inline_secrets(config, list(impl.secret_fields))
    errors += validate_secret_refs(secret_refs, list(impl.secret_fields), allow_literal=_literal_allowed(settings))
    if settings is not None:
        # Destinations are operator input: never loopback, link-local, metadata or (unless allow-listed) private space.
        errors += check_url_config(config, settings, allow_http=bool(settings.allow_private_targets))
    errors += validate_topics(topics)
    errors += validate_severity(min_severity)
    if direction == 'outbound':
        # '*' is always fine (the fan-out filters by channel.handles); a concrete family the channel cannot deliver is a config error.
        unsupported = [t for t in topics if t != '*' and not impl.handles(t[:-1] + 'created' if t.endswith('*') else t)]
        if unsupported:
            errors.append(f'{kind} does not deliver topics {", ".join(unsupported)}; supported: {", ".join(impl.topics)}')
    if errors:
        raise InvalidConfig('; '.join(errors)[:2000])


def _dict(row: IntegrationConfig) -> dict[str, Any]:
    try:
        direction, impl = _kind(row.kind)
    except InvalidConfig:
        direction, impl = 'unknown', None
    return {'id': row.id, 'name': row.name, 'kind': row.kind, 'direction': direction, 'config': loads(row.config_json, {}),
            'secret_refs': mask_secret_refs(loads(row.secret_refs_json, {})), 'enabled': row.enabled, 'topics': loads(row.topics_json, []), 'min_severity': row.min_severity,
            'state': loads(row.state_json, {}), 'last_delivery_at': row.last_delivery_at, 'last_error': row.last_error, 'created_by': row.created_by,
            'created_at': row.created_at, 'updated_at': row.updated_at,
            'secret_fields': list(impl.secret_fields) if impl else [], 'pull': bool(getattr(impl, 'pull', False)),
            'supports_verify': bool(getattr(impl, 'supports_verify', False))}


def _get(db: Session, principal: Principal, integration_id: str) -> IntegrationConfig:
    row = db.execute(select(IntegrationConfig).where(IntegrationConfig.id == integration_id, IntegrationConfig.tenant_id == principal.tenant_id)).scalar_one_or_none()
    if row is None:
        raise NotFound('Integration not found')
    return row


# ---------------------------------------------------------------- types and configs


@router.get('/types')
def list_types(principal: Principal = Depends(require('integrations:read'))):
    return {'inbound': [p.describe() for p in inbound_registry.all()], 'outbound': [c.describe() for c in outbound_registry.all()],
            'ingest_endpoint': '/api/v1/ingest/{source}', 'verify_endpoint': '/api/v1/ingest/{source}/verify?integration={id}'}


@router.get('')
@router.get('/', include_in_schema=False)
def list_integrations(kind: str | None = None, enabled: bool | None = None, direction: str | None = None, db: Session = Depends(get_db),
                      page: Page = Depends(_page), principal: Principal = Depends(require('integrations:read'))):
    stmt = select(IntegrationConfig).where(IntegrationConfig.tenant_id == principal.tenant_id)
    if kind:
        stmt = stmt.where(IntegrationConfig.kind == kind)
    if enabled is not None:
        stmt = stmt.where(IntegrationConfig.enabled.is_(enabled))
    if direction in {'inbound', 'outbound'}:
        kinds = outbound_registry.kinds() if direction == 'outbound' else inbound_registry.names()
        stmt = stmt.where(IntegrationConfig.kind.in_(kinds))
    rows = db.execute(page.apply(stmt.order_by(IntegrationConfig.created_at.desc()))).scalars().all()
    return page.wrap(rows, _dict)


@router.post('', status_code=201)
@router.post('/', status_code=201, include_in_schema=False)
def create_integration(body: CreateBody, db: Session = Depends(get_db), principal: Principal = Depends(require('integrations:write')),
                       settings: Settings = Depends(get_settings)):
    direction, impl = _kind(body.kind)
    topics = body.topics if body.topics is not None else (list(impl.default_topics) if direction == 'outbound' else [])
    _validate(body.kind, body.config, body.secret_refs, topics, body.min_severity, settings)
    row = IntegrationConfig(tenant_id=principal.tenant_id, name=body.name, kind=body.kind, config_json=dumps(body.config), secret_refs_json=dumps(body.secret_refs),
                            enabled=body.enabled, topics_json=dumps(topics), min_severity=body.min_severity, created_by=principal.user_id or principal.actor)
    db.add(row)
    db.flush()
    record_audit(db, principal, 'integrations.create', row.id, {'name': body.name, 'kind': body.kind, 'direction': direction, 'topics': topics,
                                                                 'min_severity': body.min_severity, 'secret_fields': sorted(body.secret_refs), 'config_keys': sorted(body.config)})
    return _dict(row)


# ---------------------------------------------------------------- deliveries and batches (declared before /{integration_id})


@router.get('/deliveries')
def list_deliveries(integration_id: str | None = None, status: str | None = None, topic: str | None = None, db: Session = Depends(get_db),
                    page: Page = Depends(_page), principal: Principal = Depends(require('integrations:read'))):
    stmt = select(WebhookDelivery).where(WebhookDelivery.tenant_id == principal.tenant_id)
    if integration_id:
        stmt = stmt.where(WebhookDelivery.integration_id == integration_id)
    if status:
        stmt = stmt.where(WebhookDelivery.status == status)
    if topic:
        escaped = topic[:80].replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_').replace('*', '%')
        stmt = stmt.where(WebhookDelivery.topic.like(escaped, escape='\\') if '*' in topic else WebhookDelivery.topic == topic)
    rows = db.execute(page.apply(stmt.order_by(WebhookDelivery.created_at.desc()))).scalars().all()
    return page.wrap(rows, delivery_to_dict)


@router.get('/deliveries/{delivery_id}')
def get_delivery(delivery_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('integrations:read'))):
    row = db.execute(select(WebhookDelivery).where(WebhookDelivery.id == delivery_id, WebhookDelivery.tenant_id == principal.tenant_id)).scalar_one_or_none()
    if row is None:
        raise NotFound('Delivery not found')
    return delivery_to_dict(row)


@router.post('/deliveries/{delivery_id}/retry')
async def retry_delivery(delivery_id: str, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('integrations:write'))):
    row = db.execute(select(WebhookDelivery).where(WebhookDelivery.id == delivery_id, WebhookDelivery.tenant_id == principal.tenant_id)).scalar_one_or_none()
    if row is None:
        raise NotFound('Delivery not found')
    if row.status == 'sent':
        raise InvalidConfig('Delivery was already sent')
    row.status, row.next_attempt_at = 'queued', None
    if row.attempts >= row.max_attempts:
        row.max_attempts = row.attempts + 1
    db.flush()
    job = await request.app.state.queue.enqueue('integrations.deliver', {'delivery_id': row.id}, tenant_id=principal.tenant_id,
                                                idempotency_key=f'deliver:{row.id}:manual:{row.attempts}:{utcnow().timestamp()}')
    row.job_id = job.id
    record_audit(db, principal, 'integrations.delivery_retry', row.id, {'integration_id': row.integration_id, 'topic': row.topic, 'attempts': row.attempts})
    return {'ok': True, 'job_id': job.id, 'delivery': delivery_to_dict(row)}


@router.get('/ingest/batches')
def list_batches(source: str | None = None, db: Session = Depends(get_db), page: Page = Depends(_page), principal: Principal = Depends(require('integrations:read'))):
    stmt = select(IngestBatch).where(IngestBatch.tenant_id == principal.tenant_id)
    if source:
        stmt = stmt.where(IngestBatch.source == source)
    rows = db.execute(page.apply(stmt.order_by(IngestBatch.created_at.desc()))).scalars().all()
    return page.wrap(rows, batch_to_dict)


# ---------------------------------------------------------------- single integration


@router.get('/{integration_id}')
def get_integration(integration_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('integrations:read'))):
    return _dict(_get(db, principal, integration_id))


@router.patch('/{integration_id}')
def patch_integration(integration_id: str, body: PatchBody, db: Session = Depends(get_db), principal: Principal = Depends(require('integrations:write')),
                      settings: Settings = Depends(get_settings)):
    row = _get(db, principal, integration_id)
    config = body.config if body.config is not None else loads(row.config_json, {})
    secret_refs = merge_secret_refs(body.secret_refs, loads(row.secret_refs_json, {})) if body.secret_refs is not None else loads(row.secret_refs_json, {})
    topics = body.topics if body.topics is not None else loads(row.topics_json, [])
    min_severity = body.min_severity if body.min_severity is not None else row.min_severity
    _validate(row.kind, config, secret_refs, topics, min_severity, settings)
    changed: dict[str, Any] = {}
    if body.name is not None and body.name != row.name:
        row.name, changed['name'] = body.name, body.name
    if body.config is not None:
        row.config_json, changed['config_keys'] = dumps(config), sorted(config)
    if body.secret_refs is not None:
        row.secret_refs_json, changed['secret_fields'] = dumps(secret_refs), sorted(secret_refs)
    if body.enabled is not None and body.enabled != row.enabled:
        row.enabled, changed['enabled'] = body.enabled, body.enabled
    if body.topics is not None:
        row.topics_json, changed['topics'] = dumps(topics), topics
    if body.min_severity is not None:
        row.min_severity, changed['min_severity'] = min_severity, min_severity
    row.updated_at = utcnow()
    record_audit(db, principal, 'integrations.update', row.id, changed)
    return _dict(row)


@router.delete('/{integration_id}')
def delete_integration(integration_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('integrations:write'))):
    row = _get(db, principal, integration_id)
    db.execute(delete(WebhookDelivery).where(WebhookDelivery.integration_id == row.id, WebhookDelivery.tenant_id == principal.tenant_id))
    db.delete(row)
    db.flush()
    record_audit(db, principal, 'integrations.delete', integration_id, {'name': row.name, 'kind': row.kind})
    return {'ok': True}


@router.post('/{integration_id}/test')
async def test_integration(integration_id: str, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('integrations:write')),
                           settings=Depends(get_settings)):
    row = _get(db, principal, integration_id)
    direction, impl = _kind(row.kind)
    if direction == 'inbound':
        secrets = resolve_secrets(loads(row.secret_refs_json, {}), settings)
        missing = [f for f in loads(row.secret_refs_json, {}) if f not in secrets]
        record_audit(db, principal, 'integrations.test', row.id, {'kind': row.kind, 'direction': direction, 'secrets_resolved': not missing})
        return {'ok': not missing, 'direction': 'inbound', 'kind': row.kind, 'secrets_resolved': sorted(secrets), 'secrets_missing': missing,
                'ingest_url': f'/api/v1/ingest/{impl.name}' + (f'/verify?integration={row.id}' if impl.supports_verify else ''),
                'pull_job': 'integrations.wazuh_sync' if impl.pull else None}
    payload = {'title': f'Sentinel test event for {row.name}', 'severity': 'low', 'summary': 'This is a synthetic event sent from POST /integrations/{id}/test.',
               'tenant_id': principal.tenant_id, 'source': 'sentinel', 'requested_by': principal.actor}
    delivery = WebhookDelivery(tenant_id=principal.tenant_id, integration_id=row.id, topic=TEST_TOPIC, payload_json=dumps(payload), status='queued', max_attempts=1)
    db.add(delivery)
    db.flush()
    result = await send_delivery(db, delivery, row, settings)
    record_audit(db, principal, 'integrations.test', row.id, {'kind': row.kind, 'ok': result.ok, 'status_code': result.status_code, 'error': result.error[:200]})
    return {'ok': result.ok, 'direction': 'outbound', 'kind': row.kind, 'status_code': result.status_code, 'error': result.error, 'external_ref': result.external_ref,
            'skipped': result.skipped, 'delivery_id': delivery.id}


@router.post('/{integration_id}/sync')
async def sync_integration(integration_id: str, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require('integrations:write'))):
    row = _get(db, principal, integration_id)
    direction, impl = _kind(row.kind)
    if direction != 'inbound' or not getattr(impl, 'pull', False):
        raise InvalidConfig(f'{row.kind} has no pull job')
    job = await request.app.state.queue.enqueue(f'integrations.{impl.name}_sync', {'integration_id': row.id}, tenant_id=principal.tenant_id,
                                                idempotency_key=f'{impl.name}_sync:{row.id}')
    record_audit(db, principal, 'integrations.sync', row.id, {'kind': row.kind, 'job_id': job.id})
    return {'ok': True, 'job_id': job.id}
