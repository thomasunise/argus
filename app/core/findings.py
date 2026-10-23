"""Shared upsert helpers for findings and events. Every producer (test adapters, detections,
collectors, inbound integrations) goes through these so dedupe, severity normalization,
tenant scoping, metrics and event-bus publication happen in one place."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Finding, SecurityEvent, dumps, utcnow
from .events import publish_soon
from .security import redact
from .telemetry import FINDINGS_OPEN

SEVERITIES = ('critical', 'high', 'medium', 'low', 'informational')
_SEVERITY_ALIASES = {
    'emergency': 'critical', 'alert': 'critical', 'fatal': 'critical', 'crit': 'critical', 'p0': 'critical', 'p1': 'critical',
    'error': 'high', 'err': 'high', 'important': 'high', 'p2': 'high',
    'warning': 'medium', 'warn': 'medium', 'moderate': 'medium', 'p3': 'medium',
    'notice': 'low', 'minor': 'low', 'p4': 'low',
    'info': 'informational', 'informative': 'informational', 'debug': 'informational', 'unknown': 'informational', 'none': 'informational',
}


def severity(value: Any) -> str:
    if isinstance(value, (int, float)):
        # Wazuh-style numeric levels and CVSS-like scores.
        if value >= 12 or (0 < value <= 10 and value >= 9.0):
            return 'critical'
        if value >= 9 or value >= 7.0:
            return 'high'
        if value >= 6 or value >= 4.0:
            return 'medium'
        if value >= 3 or value > 0:
            return 'low'
        return 'informational'
    text = str(value or 'low').strip().lower()
    if text in SEVERITIES:
        return text
    return _SEVERITY_ALIASES.get(text, 'low')


def fingerprint(tenant_id: str, asset_id: str | None, source: str, rule: str) -> str:
    return hashlib.sha256(f'{tenant_id}|{asset_id or ""}|{source}|{rule}'.encode()).hexdigest()


def upsert_finding(db: Session, tenant_id: str, *, source: str, rule: str, title: str, description: str,
                   severity_name: str | int | float, asset_id: str | None = None, remediation: str = '',
                   evidence: dict | None = None, cve_ids: list[str] | None = None, cvss: float | None = None,
                   epss: float | None = None, kev: bool = False, detection_id: str | None = None,
                   tags: list[str] | None = None, reopen: bool = True) -> tuple[Finding, bool]:
    """Returns (finding, created). Re-detection bumps occurrences and reopens resolved findings,
    but never reopens accepted risks or false positives."""
    fp = fingerprint(tenant_id, asset_id, source, rule)
    record = db.execute(select(Finding).where(Finding.tenant_id == tenant_id, Finding.fingerprint == fp)).scalar_one_or_none()
    evidence_text = dumps({k: (redact(v) if isinstance(v, str) else v) for k, v in (evidence or {}).items()}, limit=6000)
    if record:
        record.occurrences += 1
        record.updated_at = utcnow()
        record.evidence = evidence_text
        record.severity = min([record.severity, severity(severity_name)], key=SEVERITIES.index)
        if cvss is not None:
            record.cvss = cvss
        if epss is not None:
            record.epss = epss
        if kev:
            record.kev = 1
        if detection_id:
            record.detection_id = detection_id
        if reopen and record.status == 'resolved':
            record.status = 'open'
        return record, False
    record = Finding(tenant_id=tenant_id, asset_id=asset_id, detection_id=detection_id, fingerprint=fp, rule=rule[:160], source=source[:40],
                     title=redact(title)[:240], description=redact(description)[:4000], remediation=redact(remediation)[:4000],
                     evidence=evidence_text, severity=severity(severity_name), cve_ids=','.join(sorted(set(cve_ids or [])))[:512],
                     cvss=cvss, epss=epss, kev=1 if kev else 0, tags_json=dumps(tags or []))
    db.add(record)
    db.flush()
    publish_soon('finding.created', {'tenant_id': tenant_id, 'finding_id': record.id, 'severity': record.severity, 'title': record.title,
                                     'source': record.source, 'asset_id': asset_id})
    return record, True


@dataclass
class EventDraft:
    source: str
    external_id: str
    title: str
    severity: Any = 'low'
    category: str = ''
    actor: str = ''
    entity: str = ''
    action: str = ''
    asset_id: str | None = None
    occurred_at: datetime | None = None
    metadata: dict = field(default_factory=dict)


def upsert_event(db: Session, tenant_id: str, draft: EventDraft) -> tuple[SecurityEvent, bool]:
    existing = db.execute(select(SecurityEvent).where(SecurityEvent.tenant_id == tenant_id, SecurityEvent.source == draft.source,
                                                      SecurityEvent.external_id == draft.external_id[:128])).scalar_one_or_none()
    if existing:
        return existing, False
    meta = {k: (redact(v)[:2000] if isinstance(v, str) else v) for k, v in (draft.metadata or {}).items()}
    event = SecurityEvent(tenant_id=tenant_id, source=draft.source[:30], external_id=draft.external_id[:128], asset_id=draft.asset_id,
                          severity=severity(draft.severity), category=draft.category[:40], actor=redact(draft.actor)[:200],
                          entity=redact(draft.entity)[:200], action=draft.action[:120], title=redact(draft.title)[:300],
                          metadata_json=dumps(meta, limit=8000), occurred_at=draft.occurred_at)
    db.add(event)
    db.flush()
    publish_soon('event.created', {'tenant_id': tenant_id, 'event_id': event.id, 'severity': event.severity, 'source': event.source,
                                   'category': event.category, 'actor': event.actor, 'entity': event.entity, 'action': event.action})
    return event, True


def refresh_open_metrics(db: Session, tenant_id: str) -> dict[str, int]:
    counts = {}
    for level in SEVERITIES:
        n = db.scalar(select(func.count()).select_from(Finding).where(Finding.tenant_id == tenant_id, Finding.severity == level,
                                                                       Finding.status.in_(['open', 'investigating']))) or 0
        counts[level] = n
        FINDINGS_OPEN.labels(tenant_id, level).set(n)
    return counts


def finding_to_dict(f: Finding) -> dict:
    from ..models import loads

    return {'id': f.id, 'asset_id': f.asset_id, 'detection_id': f.detection_id, 'rule': f.rule, 'title': f.title, 'description': f.description,
            'remediation': f.remediation, 'evidence': loads(f.evidence), 'severity': f.severity, 'status': f.status, 'source': f.source,
            'cve_ids': [c for c in f.cve_ids.split(',') if c], 'cvss': f.cvss, 'epss': f.epss, 'kev': bool(f.kev), 'assignee': f.assignee,
            'tags': loads(f.tags_json, []), 'occurrences': f.occurrences, 'created_at': f.created_at, 'updated_at': f.updated_at}


def event_to_dict(e: SecurityEvent) -> dict:
    from ..models import loads

    return {'id': e.id, 'source': e.source, 'external_id': e.external_id, 'asset_id': e.asset_id, 'severity': e.severity, 'category': e.category,
            'actor': e.actor, 'entity': e.entity, 'action': e.action, 'title': e.title, 'metadata': loads(e.metadata_json),
            'occurred_at': e.occurred_at, 'received_at': e.received_at}
