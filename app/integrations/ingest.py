"""Ingest pipeline: parse a payload with the source's parser, upsert events (deduped by
source+external_id), upsert findings for report sources, correlate high-severity alerts into
findings, and record an IngestBatch plus an audit entry."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.errors import NotFound, SentinelError
from ..core.findings import upsert_event, upsert_finding
from ..core.rbac import Principal
from ..models import dumps
from ..models.integrations import IngestBatch
from .inbound import ParseContext, registry

log = logging.getLogger('sentinel.integrations.ingest')

MAX_BATCH = 500
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_DRAFTS = 2000
MAX_ERROR_SAMPLES = 20
ALERT_SEVERITIES = {'high', 'critical'}


class BatchTooLarge(SentinelError):
    status = 413
    code = 'batch_too_large'


class InvalidPayload(SentinelError):
    status = 400
    code = 'invalid_payload'


@dataclass
class IngestResult:
    source: str
    received: int = 0
    accepted: int = 0
    duplicates: int = 0
    findings: int = 0
    findings_created: int = 0
    errors: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    batch_id: str = ''
    # Bus events (topic, payload) for what this batch created. core.findings publishes them itself when
    # ingest runs on the event loop; when it runs in a worker thread they are dropped there, so callers
    # off the loop publish these afterwards via publish_deferred().
    bus_events: list[tuple[str, dict]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop('bus_events', None)
        data['event_ids'] = self.event_ids[:50]
        data['finding_ids'] = self.finding_ids[:50]
        data['errors'] = self.errors[:MAX_ERROR_SAMPLES]
        data['error_count'] = len(self.errors)
        return data


def ingest(db: Session, tenant_id: str, source: str, payload: dict | list, *, actor: Principal | str, headers: dict[str, str] | None = None,
           asset_id: str | None = None, api_key_id: str = '', extra: dict[str, Any] | None = None, audit: bool = True) -> IngestResult:
    """Normalize and persist one batch. Raises NotFound for unknown sources, BatchTooLarge over MAX_BATCH
    top-level items, InvalidPayload for non-JSON-object payloads."""
    if not registry.has(source):
        raise NotFound(f'Unknown ingest source {source!r}; see GET /api/v1/integrations/types')
    parser = registry.get(source)
    if isinstance(payload, list) and len(payload) > MAX_BATCH:
        raise BatchTooLarge(f'Maximum {MAX_BATCH} events per request')
    if not isinstance(payload, (dict, list)):
        raise InvalidPayload('Payload must be a JSON object or array')
    ctx = ParseContext(tenant_id=tenant_id, source=parser.name, asset_id=asset_id, headers=dict(headers or {}), extra=dict(extra or {}))
    result = IngestResult(source=parser.name, received=len(payload) if isinstance(payload, list) else 1)

    drafts = parser.parse(payload, ctx)
    if len(drafts) > MAX_DRAFTS:
        ctx.errors.append(f'{len(drafts) - MAX_DRAFTS} events over the per-request cap of {MAX_DRAFTS} were dropped')
        drafts = drafts[:MAX_DRAFTS]
    for draft in drafts:
        try:
            record, created = upsert_event(db, tenant_id, draft)
        except Exception as exc:  # pragma: no cover - defensive against odd drafts
            log.debug('upsert_event failed for %s', parser.name, exc_info=True)
            ctx.errors.append(f'{draft.external_id[:40]}: {type(exc).__name__}')
            continue
        if created:
            result.accepted += 1
            result.event_ids.append(record.id)
            result.bus_events.append(('event.created', {'tenant_id': tenant_id, 'event_id': record.id, 'severity': record.severity, 'source': record.source,
                                                        'category': record.category, 'actor': record.actor, 'entity': record.entity, 'action': record.action}))
            if parser.correlate_alerts and record.severity in ALERT_SEVERITIES:
                finding, f_created = upsert_finding(
                    db, tenant_id, source=record.source, rule=f'alert:{record.external_id}', title=f'Security alert: {record.title[:170]}',
                    description=('A monitoring source reported a high-severity event. Validate its details and scope before taking action. '
                                 f'Source: {record.source}. Action: {record.action}. Entity: {record.entity or "unknown"}.'),
                    remediation='Review the originating console and correlate identity, host and network telemetry before acting.',
                    severity_name=record.severity, asset_id=record.asset_id,
                    evidence={'event_id': record.id, 'source': record.source, 'external_id': record.external_id, 'action': record.action,
                              'actor': record.actor, 'entity': record.entity}, tags=['alert', record.source])
                result.findings += 1
                result.findings_created += 1 if f_created else 0
                result.finding_ids.append(finding.id)
                if f_created:
                    result.bus_events.append(('finding.created', _finding_payload(tenant_id, finding)))
        else:
            result.duplicates += 1

    if parser.kind in {'findings', 'both'}:
        for draft in parser.findings(payload, ctx):
            try:
                finding, created = upsert_finding(db, tenant_id, source=draft.source, rule=draft.rule, title=draft.title, description=draft.description,
                                                  severity_name=draft.severity, asset_id=draft.asset_id, remediation=draft.remediation, evidence=draft.evidence,
                                                  cve_ids=draft.cve_ids, cvss=draft.cvss, tags=draft.tags)
            except Exception as exc:  # pragma: no cover - defensive
                log.debug('upsert_finding failed for %s', parser.name, exc_info=True)
                ctx.errors.append(f'{draft.rule[:60]}: {type(exc).__name__}')
                continue
            result.findings += 1
            result.findings_created += 1 if created else 0
            result.finding_ids.append(finding.id)
            if created:
                result.bus_events.append(('finding.created', _finding_payload(tenant_id, finding)))

    result.errors = ctx.errors
    batch = IngestBatch(tenant_id=tenant_id, source=parser.name, accepted=result.accepted, duplicates=result.duplicates, findings=result.findings,
                        errors=len(result.errors), error_samples_json=dumps(result.errors[:MAX_ERROR_SAMPLES]), received=result.received, api_key_id=api_key_id)
    db.add(batch)
    db.flush()
    result.batch_id = batch.id
    if audit:
        record_audit(db, actor, 'integrations.ingest', parser.name, {'batch_id': batch.id, 'received': result.received, 'accepted': result.accepted,
                                                                      'duplicates': result.duplicates, 'findings': result.findings, 'errors': len(result.errors)},
                     tenant_id=tenant_id)
    return result


def _finding_payload(tenant_id: str, finding) -> dict[str, Any]:
    """Same shape core.findings.upsert_finding publishes for finding.created."""
    return {'tenant_id': tenant_id, 'finding_id': finding.id, 'severity': finding.severity, 'title': finding.title, 'source': finding.source,
            'asset_id': finding.asset_id}


async def publish_deferred(result: IngestResult) -> None:
    """Publish the bus events of a batch that was ingested off the event loop."""
    from ..core.events import publish

    for topic, payload in result.bus_events:
        await publish(topic, payload)


async def ingest_async(db: Session, tenant_id: str, source: str, payload: dict | list, **kwargs: Any) -> IngestResult:
    """Run `ingest` in a worker thread so the event loop stays free (queue handlers share it), then
    publish the resulting bus events on the loop."""
    result = await asyncio.to_thread(ingest, db, tenant_id, source, payload, **kwargs)
    await publish_deferred(result)
    return result


def batch_to_dict(batch: IngestBatch) -> dict[str, Any]:
    from ..models import loads

    return {'id': batch.id, 'source': batch.source, 'received': batch.received, 'accepted': batch.accepted, 'duplicates': batch.duplicates,
            'findings': batch.findings, 'errors': batch.errors, 'error_samples': loads(batch.error_samples_json, []), 'api_key_id': batch.api_key_id,
            'created_at': batch.created_at}
