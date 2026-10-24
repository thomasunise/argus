"""Shadow-AI discovery: classify SecurityEvents against the AI-service catalog and keep an
inventory of which AI services are used, by whom, on which channel.

`discover(db, tenant_id)` scans events received after the tenant's cursor (bounded per run),
upserts AIService rows and advances the cursor. It never calls out and never stores the event
payload, only the matched domain, API action or application name.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.security import redact
from ..models import SecurityEvent, loads, utcnow
from ..models.ai import AIDiscoveryState, AIService
from . import catalog
from .catalog import AIServiceDef

log = logging.getLogger('argus.ai.discovery')

MAX_EVENTS_PER_RUN = 20_000
INITIAL_LOOKBACK_DAYS = 30
_HOST_KEYS = ('host', 'hostname', 'domain', 'dst_host', 'dest_host', 'destination_host', 'server_name', 'sni', 'query', 'dns_query', 'qname',
              'url', 'uri', 'http_host', 'request_host', 'remote_host', 'top_destination', 'destination', 'dst', 'fqdn', 'event_source', 'endpoint')
_APP_KEYS = ('app', 'app_name', 'application', 'app_display_name', 'appdisplayname', 'client_app', 'target_app', 'service_principal', 'target',
             'targets', 'display_name', 'resource_display_name', 'client', 'oauth_client')
_SERVICE_KEYS = ('event_source', 'service', 'resource_provider', 'provider', 'method_name', 'operation', 'operation_name', 'api', 'service_name')


@dataclass
class Match:
    service: AIServiceDef
    channel: str
    evidence: str


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    from datetime import timezone

    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _strings(value: Any, depth: int = 0) -> Iterable[str]:
    if depth > 3:
        return
    if isinstance(value, str):
        yield value[:2000]
    elif isinstance(value, dict):
        for v in list(value.values())[:40]:
            yield from _strings(v, depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in list(value)[:40]:
            yield from _strings(v, depth + 1)


def _values(meta: dict, keys: tuple[str, ...]) -> list[str]:
    lowered = {str(k).lower(): v for k, v in meta.items()}
    out: list[str] = []
    for key in keys:
        if key in lowered:
            out.extend(_strings(lowered[key]))
    return out


def classify(event: SecurityEvent) -> Match | None:
    """The AI service an event shows being used, or None. Cloud API signatures first, then OAuth/app
    grants, then hostnames."""
    meta = loads(event.metadata_json, {})
    meta = meta if isinstance(meta, dict) else {}
    source = (event.source or '').lower()
    action = (event.action or '').lower()

    service_strings = [s.lower() for s in _values(meta, _SERVICE_KEYS)]
    for sig in catalog.CLOUD_SIGNATURES:
        if sig.sources and not source.startswith(sig.sources) and not any(sig_s in s for s in service_strings for sig_s in sig.strings):
            continue
        if any(action.startswith(p) for p in sig.action_prefixes) or any(sig_s in s for s in service_strings for sig_s in sig.strings):
            service = catalog.BY_KEY[sig.service_key]
            return Match(service, 'cloud_api', (event.action or sig.note)[:300])

    haystack = ' '.join([action, (event.title or '').lower(), str(meta.get('event_type') or '').lower(), str(meta.get('activity') or '').lower()])
    if source.startswith(catalog.IDENTITY_SOURCES) or event.category in {'identity', 'auth'}:
        if any(h in haystack for h in catalog.OAUTH_HINTS):
            for text in [event.entity or '', *_values(meta, _APP_KEYS), event.title or '']:
                found = catalog.match_app_name(text)
                if found:
                    return Match(found[0], 'oauth_app', found[1][:300])

    candidates = _values(meta, _HOST_KEYS) + [event.entity or '']
    if event.category in {'network', 'dns', 'proxy', 'web', 'host', 'endpoint'} or source in {'netflow', 'osquery', 'dns', 'proxy', 'zeek', 'generic'}:
        candidates.append(event.title or '')
    for text in candidates:
        for host in catalog.hosts_in(text):
            found = catalog.match_domain(host)
            if found:
                channel = 'cloud_api' if found[0].category == 'cloud' and source.startswith(('aws', 'azure', 'gcp', 'cloudtrail')) else 'network'
                return Match(found[0], channel, host[:300])
    return None


def upsert_service(db: Session, tenant_id: str, service: AIServiceDef, channel: str, actor: str, *, evidence: str = '', asset_id: str | None = None,
                   seen_at: datetime | None = None, event_id: str = '', count: int = 1, status: str | None = None) -> tuple[AIService, bool]:
    actor = redact(actor or '')[:200]
    seen = _aware(seen_at) or utcnow()
    row = db.execute(select(AIService).where(AIService.tenant_id == tenant_id, AIService.service_key == service.key, AIService.channel == channel,
                                             AIService.actor == actor)).scalar_one_or_none()
    created = row is None
    if row is None:
        initial = status or _inherited_status(db, tenant_id, service.key)
        row = AIService(tenant_id=tenant_id, service_key=service.key, provider=service.provider, service=service.name, category=service.category,
                        channel=channel, actor=actor, asset_id=asset_id, evidence=redact(evidence)[:300], first_seen_at=seen, last_seen_at=seen,
                        event_count=0, status=initial)
        db.add(row)
    elif status == 'sanctioned' and row.status == 'unreviewed':
        row.status = status
    row.event_count = (row.event_count or 0) + count
    if seen > (_aware(row.last_seen_at) or seen):
        row.last_seen_at = seen
    if seen < (_aware(row.first_seen_at) or seen):
        row.first_seen_at = seen
    if event_id:
        row.last_event_id = event_id[:36]
    if asset_id and not row.asset_id:
        row.asset_id = asset_id
    if evidence and not row.evidence:
        row.evidence = redact(evidence)[:300]
    row.updated_at = utcnow()
    db.flush()
    return row, created


def _inherited_status(db: Session, tenant_id: str, service_key: str) -> str:
    """A service already reviewed for this tenant keeps its decision for new actors and channels
    (the gateway channel excepted: that row is always sanctioned)."""
    rows = db.execute(select(AIService.status).where(AIService.tenant_id == tenant_id, AIService.service_key == service_key,
                                                     AIService.channel != 'gateway', AIService.status != 'unreviewed')).scalars().all()
    if 'blocked' in rows:
        return 'blocked'
    if 'sanctioned' in rows:
        return 'sanctioned'
    return 'unreviewed'


def _state(db: Session, tenant_id: str) -> AIDiscoveryState:
    state = db.execute(select(AIDiscoveryState).where(AIDiscoveryState.tenant_id == tenant_id)).scalar_one_or_none()
    if state is None:
        state = AIDiscoveryState(tenant_id=tenant_id)
        db.add(state)
        db.flush()
    return state


def discover(db: Session, tenant_id: str, *, since: datetime | None = None, max_events: int = MAX_EVENTS_PER_RUN) -> dict:
    """Scan new events for one tenant. Returns run statistics."""
    state = _state(db, tenant_id)
    start = _aware(since) or _aware(state.cursor) or (utcnow() - timedelta(days=INITIAL_LOOKBACK_DAYS))
    stmt = (select(SecurityEvent).where(SecurityEvent.tenant_id == tenant_id, SecurityEvent.received_at > start)
            .order_by(SecurityEvent.received_at.asc(), SecurityEvent.id.asc()).limit(max(1, max_events)))
    events = db.execute(stmt).scalars().all()
    matched = created = 0
    services: set[str] = set()
    newest = start
    for event in events:
        received = _aware(event.received_at) or newest
        if received > newest:
            newest = received
        found = classify(event)
        if found is None:
            continue
        matched += 1
        actor = event.actor or (loads(event.metadata_json, {}) or {}).get('user') or ''
        _, was_created = upsert_service(db, tenant_id, found.service, found.channel, str(actor), evidence=found.evidence, asset_id=event.asset_id,
                                        seen_at=_aware(event.occurred_at) or received, event_id=event.id)
        created += int(was_created)
        services.add(found.service.key)
    state.cursor = newest
    state.last_run_at = utcnow()
    state.events_scanned = (state.events_scanned or 0) + len(events)
    state.matches = (state.matches or 0) + matched
    db.flush()
    if matched:
        log.info('ai discovery tenant=%s scanned=%d matched=%d new=%d', tenant_id, len(events), matched, created)
    return {'events_scanned': len(events), 'matched': matched, 'new_services': created, 'services': sorted(services),
            'cursor': newest.isoformat() if newest else None, 'truncated': len(events) >= max_events}


def service_to_dict(row: AIService) -> dict:
    return {'id': row.id, 'service_key': row.service_key, 'provider': row.provider, 'service': row.service, 'category': row.category,
            'channel': row.channel, 'actor': row.actor, 'asset_id': row.asset_id, 'evidence': row.evidence, 'first_seen_at': row.first_seen_at,
            'last_seen_at': row.last_seen_at, 'event_count': row.event_count, 'status': row.status, 'notes': row.notes,
            'reviewed_by': row.reviewed_by, 'reviewed_at': row.reviewed_at}


def state_to_dict(state: AIDiscoveryState | None) -> dict:
    if state is None:
        return {'cursor': None, 'last_run_at': None, 'events_scanned': 0, 'matches': 0}
    return {'cursor': state.cursor, 'last_run_at': state.last_run_at, 'events_scanned': state.events_scanned, 'matches': state.matches}
