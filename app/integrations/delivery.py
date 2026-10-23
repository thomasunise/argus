"""Outbound delivery: event-bus subscriber -> `integrations.fanout` job -> one WebhookDelivery and one
`integrations.deliver` job per matching integration -> channel.send with retries recorded on the
delivery row.

Queue handlers run on the event loop (memory backend), so every blocking database section inside
them runs in a worker thread (`asyncio.to_thread`); otherwise a handler waiting on SQLite's write
lock would stall the loop that the producing request needs in order to commit."""
from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..core.db import session_scope
from ..core.security import resolve_secret
from ..models import Finding, Tenant, dumps, loads, utcnow
from ..models.integrations import IntegrationConfig, WebhookDelivery
from .outbound import Channel, DeliveryResult, OutboundEvent, registry
from .schema import severity_at_least, topic_matches

log = logging.getLogger('sentinel.integrations.delivery')

SUBSCRIBED_PREFIXES = ('finding.', 'detection.', 'action.', 'testing.', 'agent.')
RETRY_SCHEDULE_SECONDS = (15, 60, 300, 600)
DEFAULT_MAX_ATTEMPTS = 5
TEST_TOPIC = 'integration.test'


def retry_delay(attempt: int) -> int:
    """Seconds to wait before the next attempt, given `attempt` attempts already made (1-based)."""
    index = max(0, min(len(RETRY_SCHEDULE_SECONDS) - 1, attempt - 1))
    return RETRY_SCHEDULE_SECONDS[index]


def payload_hash(topic: str, payload: dict) -> str:
    return hashlib.sha256(f'{topic}|{dumps(payload)}'.encode()).hexdigest()


def resolve_secrets(refs: dict[str, Any], settings: Settings) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, ref in (refs or {}).items():
        value = resolve_secret(str(ref), settings) if isinstance(ref, str) else ''
        if value:
            out[key] = value
    return out


def matching_integrations(db: Session, tenant_id: str, topic: str, severity: str | None) -> list[IntegrationConfig]:
    rows = db.execute(select(IntegrationConfig).where(IntegrationConfig.tenant_id == tenant_id, IntegrationConfig.enabled.is_(True))).scalars().all()
    chosen: list[IntegrationConfig] = []
    for row in rows:
        if not registry.has(row.kind):
            continue
        channel = registry.get(row.kind)
        if not channel.handles(topic) or not topic_matches(loads(row.topics_json, []), topic):
            continue
        if severity and not severity_at_least(severity, row.min_severity or 'low'):
            continue
        chosen.append(row)
    return chosen


# ---------------------------------------------------------------- event enrichment


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def build_event(db: Session, tenant_id: str, topic: str, payload: dict, delivery_id: str, settings: Settings) -> OutboundEvent:
    base_url = (settings.base_url or '').rstrip('/')
    tenant = db.get(Tenant, tenant_id)
    event = OutboundEvent(topic=topic, tenant_id=tenant_id, tenant_name=tenant.name if tenant else '', delivery_id=delivery_id, payload=dict(payload),
                          severity=str(payload.get('severity') or 'low'), title=str(payload.get('title') or topic), status=str(payload.get('status') or ''))
    family = topic.split('.', 1)[0]
    if family == 'finding' and payload.get('finding_id'):
        event.subject_kind, event.subject_id = 'finding', str(payload['finding_id'])
        finding = db.get(Finding, event.subject_id)
        if finding and finding.tenant_id == tenant_id:
            event.title, event.severity, event.status = finding.title, finding.severity, finding.status
            event.summary = finding.description[:1000]
            event.occurred_at = _aware(finding.created_at)
            event.payload.update({'source': finding.source, 'rule': finding.rule, 'asset_id': finding.asset_id, 'cve_ids': [c for c in finding.cve_ids.split(',') if c],
                                  'occurrences': finding.occurrences})
        event.url = f'{base_url}/#/findings/{event.subject_id}'
    elif family == 'detection' and payload.get('detection_id'):
        event.subject_kind, event.subject_id = 'detection', str(payload['detection_id'])
        try:
            from ..models.detections import Detection  # detections package model; optional
        except Exception:  # pragma: no cover - detections package absent
            Detection = None  # type: ignore[assignment]
        if Detection is not None:
            detection = db.get(Detection, event.subject_id)
            if detection and getattr(detection, 'tenant_id', None) == tenant_id:
                event.title = str(getattr(detection, 'title', event.title))
                event.severity = str(getattr(detection, 'severity', event.severity))
                event.status = str(getattr(detection, 'status', event.status) or '')
                event.summary = str(getattr(detection, 'description', '') or '')[:1000]
                event.occurred_at = _aware(getattr(detection, 'first_seen_at', None) or getattr(detection, 'created_at', None))
                event.payload.update({'rule_id': getattr(detection, 'rule_id', ''), 'entity': getattr(detection, 'entity', ''),
                                      'confidence': getattr(detection, 'confidence', None)})
        event.url = f'{base_url}/#/detections/{event.subject_id}'
    elif family == 'action':
        event.subject_kind = 'action'
        event.subject_id = str(payload.get('request_id') or payload.get('run_id') or payload.get('action_request_id') or '')
        event.title = str(payload.get('title') or f'Action {payload.get("action_type") or ""} {topic.split(".", 1)[-1]}'.strip())
        event.summary = str(payload.get('summary') or payload.get('reason') or '')[:1000]
        event.url = f'{base_url}/#/actions/{event.subject_id}' if event.subject_id else ''
    elif family == 'testing':
        event.subject_kind = 'test_run'
        event.subject_id = str(payload.get('run_id') or payload.get('plan_id') or '')
        event.title = str(payload.get('title') or f'Test run {topic.split(".", 1)[-1]}')
        event.summary = str(payload.get('summary') or '')[:1000]
        event.url = f'{base_url}/#/tests/runs/{event.subject_id}' if event.subject_id else ''
    elif family == 'agent':
        event.subject_kind = 'agent_run'
        event.subject_id = str(payload.get('run_id') or payload.get('agent_run_id') or '')
        event.title = str(payload.get('title') or f'Agent {payload.get("spec") or payload.get("agent") or "run"} {topic.split(".", 1)[-1]}'.strip())
        event.summary = str(payload.get('summary') or '')[:1000]
        event.url = f'{base_url}/#/agents/runs/{event.subject_id}' if event.subject_id else ''
    elif topic == TEST_TOPIC:
        event.subject_kind, event.subject_id = 'test', delivery_id
        event.summary = str(payload.get('summary') or 'Synthetic test event from Sentinel.')
        event.url = f'{base_url}/#/integrations'
    if event.severity not in {'critical', 'high', 'medium', 'low', 'informational'}:
        event.severity = 'low'
    if topic.endswith('.resolved') and not event.status:
        event.status = 'resolved'
    return event


# ---------------------------------------------------------------- deliveries (prepare -> invoke -> record)


class Prepared:
    __slots__ = ('channel', 'event', 'config', 'secrets', 'error')

    def __init__(self, channel: Channel | None, event: OutboundEvent | None, config: dict, secrets: dict, error: str = ''):
        self.channel, self.event, self.config, self.secrets, self.error = channel, event, config, secrets, error


def prepare_delivery(db: Session, delivery: WebhookDelivery, integration: IntegrationConfig, settings: Settings) -> Prepared:
    """Blocking: load everything a send needs. Secrets are resolved here and never persisted."""
    if not registry.has(integration.kind):
        return Prepared(None, None, {}, {}, f'unknown channel kind {integration.kind}')
    event = build_event(db, integration.tenant_id, delivery.topic, loads(delivery.payload_json, {}), delivery.id, settings)
    return Prepared(registry.get(integration.kind), event, loads(integration.config_json, {}), resolve_secrets(loads(integration.secret_refs_json, {}), settings))


async def invoke(prepared: Prepared) -> DeliveryResult:
    """Non-blocking: perform the channel send."""
    if prepared.channel is None or prepared.event is None:
        return DeliveryResult(ok=False, error=prepared.error or 'nothing to send')
    try:
        return await prepared.channel.send(prepared.event, prepared.config, prepared.secrets)
    except Exception as exc:  # a channel bug must not take the worker down
        log.exception('channel %s raised for delivery %s', prepared.channel.kind, prepared.event.delivery_id)
        return DeliveryResult(ok=False, error=f'{type(exc).__name__}: {str(exc)[:200]}', retryable=True)


def record_result(db: Session, delivery: WebhookDelivery, integration: IntegrationConfig, result: DeliveryResult) -> None:
    """Blocking: write the attempt outcome. Does not commit."""
    delivery.attempts = (delivery.attempts or 0) + 1
    if not delivery.max_attempts:
        delivery.max_attempts = DEFAULT_MAX_ATTEMPTS
    delivery.response_code = result.status_code
    delivery.last_error = '' if result.ok else result.error[:2000]
    delivery.external_ref = (result.external_ref or delivery.external_ref or '')[:200]
    if result.ok:
        delivery.status = 'skipped' if result.skipped else 'sent'
        delivery.sent_at = utcnow()
        delivery.next_attempt_at = None
        integration.last_delivery_at = utcnow()
        integration.last_error = ''
    else:
        delivery.status = 'failed'
        integration.last_error = result.error[:1000]
        if result.retryable and delivery.attempts < delivery.max_attempts:
            delivery.next_attempt_at = utcnow() + timedelta(seconds=retry_delay(delivery.attempts))
        else:
            delivery.next_attempt_at = None


async def send_delivery(db: Session, delivery: WebhookDelivery, integration: IntegrationConfig, settings: Settings) -> DeliveryResult:
    """Same-session convenience used by POST /integrations/{id}/test. Does not commit."""
    prepared = prepare_delivery(db, delivery, integration, settings)
    result = await invoke(prepared)
    record_result(db, delivery, integration, result)
    return result


def create_deliveries(db: Session, tenant_id: str, topic: str, payload: dict, severity: str | None) -> list[WebhookDelivery]:
    rows: list[WebhookDelivery] = []
    for integration in matching_integrations(db, tenant_id, topic, severity):
        delivery = WebhookDelivery(tenant_id=tenant_id, integration_id=integration.id, topic=topic[:80], payload_hash=payload_hash(topic, payload),
                                   payload_json=dumps(payload, limit=16000), status='queued', max_attempts=DEFAULT_MAX_ATTEMPTS)
        db.add(delivery)
        rows.append(delivery)
    db.flush()
    return rows


def delivery_to_dict(delivery: WebhookDelivery) -> dict[str, Any]:
    return {'id': delivery.id, 'integration_id': delivery.integration_id, 'topic': delivery.topic, 'payload_hash': delivery.payload_hash,
            'payload': loads(delivery.payload_json, {}), 'status': delivery.status, 'attempts': delivery.attempts, 'max_attempts': delivery.max_attempts,
            'last_error': delivery.last_error, 'response_code': delivery.response_code, 'external_ref': delivery.external_ref, 'job_id': delivery.job_id,
            'created_at': delivery.created_at, 'next_attempt_at': delivery.next_attempt_at, 'sent_at': delivery.sent_at}


# ---------------------------------------------------------------- queue wiring


def install(app) -> None:
    queue = app.state.queue
    settings: Settings = app.state.settings

    async def on_event(topic: str, payload: dict[str, Any]) -> None:
        if not topic.startswith(SUBSCRIBED_PREFIXES):
            return
        tenant_id = payload.get('tenant_id')
        if not tenant_id:
            return
        try:
            await queue.enqueue('integrations.fanout', {'topic': topic, 'payload': payload}, tenant_id=str(tenant_id), priority=6)
        except Exception:  # queue not started yet (startup) or backend outage; the bus must not fail the producer
            log.exception('could not enqueue integrations.fanout for %s', topic)

    from ..core.events import subscribe

    subscribe('*', on_event)

    @queue.handler('integrations.fanout')
    async def fanout(job, ctx):
        topic = str(job.payload.get('topic') or '')
        payload = job.payload.get('payload') if isinstance(job.payload.get('payload'), dict) else {}
        if payload.get('tenant_id') and str(payload['tenant_id']) != job.tenant_id:
            raise PermissionError('job tenant does not match payload tenant')

        def _create() -> list[str] | None:
            with session_scope(ctx.db_factory) as db:
                tenant = db.get(Tenant, job.tenant_id)
                if not tenant or not tenant.is_active:
                    return None
                return [d.id for d in create_deliveries(db, job.tenant_id, topic, payload, payload.get('severity'))]

        ids = await asyncio.to_thread(_create)
        if ids is None:
            return {'deliveries': 0, 'reason': 'tenant inactive'}
        for delivery_id in ids:
            child = await queue.enqueue('integrations.deliver', {'delivery_id': delivery_id}, tenant_id=job.tenant_id, idempotency_key=f'deliver:{delivery_id}:1')

            def _link(delivery_id=delivery_id, job_id=child.id) -> None:
                with session_scope(ctx.db_factory) as db:
                    row = db.get(WebhookDelivery, delivery_id)
                    if row:
                        row.job_id = job_id

            await asyncio.to_thread(_link)
        return {'deliveries': len(ids), 'topic': topic}

    @queue.handler('integrations.deliver')
    async def deliver(job, ctx):
        delivery_id = str(job.payload.get('delivery_id') or '')

        def _load() -> tuple[str, Prepared | None]:
            with session_scope(ctx.db_factory) as db:
                delivery = db.get(WebhookDelivery, delivery_id)
                if delivery is None or delivery.tenant_id != job.tenant_id:
                    raise PermissionError('delivery not found for this tenant')
                if delivery.status in {'sent', 'skipped'}:
                    return 'already', None
                integration = db.get(IntegrationConfig, delivery.integration_id)
                if integration is None or integration.tenant_id != job.tenant_id:
                    raise PermissionError('integration not found for this tenant')
                if not integration.enabled:
                    delivery.status, delivery.last_error = 'skipped', 'integration disabled'
                    return 'disabled', None
                return 'ok', prepare_delivery(db, delivery, integration, settings)

        state, prepared = await asyncio.to_thread(_load)
        if state == 'already':
            return {'status': 'sent', 'reason': 'already delivered'}
        if state == 'disabled' or prepared is None:
            return {'status': 'skipped', 'reason': 'integration disabled'}
        result = await invoke(prepared)
        await ctx.heartbeat()

        def _store() -> tuple[str, int, datetime | None]:
            with session_scope(ctx.db_factory) as db:
                delivery = db.get(WebhookDelivery, delivery_id)
                integration = db.get(IntegrationConfig, delivery.integration_id) if delivery else None
                if delivery is None or integration is None:
                    raise PermissionError('delivery vanished during send')
                record_result(db, delivery, integration, result)
                return delivery.status, delivery.attempts, delivery.next_attempt_at

        status, attempts, next_at = await asyncio.to_thread(_store)
        retry_in = None
        if status == 'failed' and next_at is not None:
            retry_in = max(0.0, (_aware(next_at) - utcnow()).total_seconds())  # type: ignore[operator]
            await queue.enqueue('integrations.deliver', {'delivery_id': delivery_id}, tenant_id=job.tenant_id, delay_seconds=retry_in,
                                idempotency_key=f'deliver:{delivery_id}:{attempts + 1}')
        return {'status': status, 'attempts': attempts, 'ok': result.ok, 'error': result.error[:200], 'retry_in': None if retry_in is None else int(retry_in)}
