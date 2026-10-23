from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select

from .models import Asset, Finding, SecurityEvent, utcnow

SEVERITIES = {'critical', 'high', 'medium', 'low', 'informational'}


def severity(value: str) -> str:
    x = (value or 'low').strip().lower()
    if x in SEVERITIES:
        return x
    return {'emergency':'critical', 'alert':'critical', 'error':'high', 'warning':'medium', 'warn':'medium',
            'notice':'low', 'info':'informational', 'debug':'informational'}.get(x, 'low')


def add_finding(db, *, asset_id: str | None, source: str, rule: str, title: str,
                description: str, remediation: str, severity_name: str, evidence: dict | None = None) -> Finding:
    fingerprint = hashlib.sha256(f'{asset_id}|{source}|{rule}'.encode()).hexdigest()
    record = db.execute(select(Finding).where(Finding.fingerprint == fingerprint)).scalar_one_or_none()
    if record:
        record.occurrences += 1
        record.updated_at = utcnow()
        record.evidence = json.dumps(evidence or {}, default=str)[:2400]
        # Reopen if a new scan detects the same issue again; retain manually accepted risks.
        if record.status == 'resolved':
            record.status = 'open'
        return record
    record = Finding(asset_id=asset_id, source=source[:40], fingerprint=fingerprint,
                     title=title[:240], description=description[:1600], remediation=remediation[:1600],
                     severity=severity(severity_name), evidence=json.dumps(evidence or {}, default=str)[:2400])
    db.add(record)
    db.flush()
    return record


def add_event(db, *, source: str, external_id: str, title: str, severity_name: str,
              asset_id: str | None = None, metadata: dict | None = None):
    exists = db.execute(select(SecurityEvent).where(SecurityEvent.source == source,
                                                     SecurityEvent.external_id == external_id)).scalar_one_or_none()
    if exists:
        return exists, False
    event = SecurityEvent(source=source[:30], external_id=external_id[:128], asset_id=asset_id,
                          title=title[:300], severity=severity(severity_name),
                          metadata_json=json.dumps(metadata or {}, default=str)[:1800])
    db.add(event)
    db.flush()
    return event, True


def correlate_event(db, event: SecurityEvent):
    """Create evidence-based findings for high severity alerts; avoid inferred exploitation claims."""
    if event.severity not in {'high', 'critical'}:
        return None
    return add_finding(db, asset_id=event.asset_id, source=event.source,
                       rule=f'alert:{event.external_id}',
                       title=f'Security alert: {event.title[:170]}',
                       description='A monitoring source reported a high-severity event. Validate its details and scope before taking action.',
                       remediation='Review the originating monitoring console and correlate identity, host, and network telemetry.',
                       severity_name=event.severity,
                       evidence={'event_id': event.id, 'source': event.source, 'external_id': event.external_id})


def normalize_wazuh(item: dict) -> dict:
    rule = item.get('rule') or {}
    agent = item.get('agent') or {}
    level = int(rule.get('level') or 0)
    severity_name = 'critical' if level >= 13 else 'high' if level >= 10 else 'medium' if level >= 6 else 'low'
    origin = str(item.get('id') or hashlib.sha256(json.dumps(item, sort_keys=True, default=str).encode()).hexdigest())[:128]
    return dict(source='wazuh', external_id=origin, title=str(rule.get('description') or 'Wazuh alert'),
                severity_name=severity_name,
                metadata={'rule_id': str(rule.get('id', '')), 'agent': str(agent.get('name', '')),
                          'rule_level': level, 'groups': (rule.get('groups') or [])[:12]})


def normalize_falco(item: dict) -> dict:
    external_id = item.get('event_id') or hashlib.sha256(json.dumps(item, sort_keys=True, default=str).encode()).hexdigest()
    return dict(source='falco', external_id=str(external_id), title=str(item.get('rule') or 'Falco runtime alert'),
                severity_name=str(item.get('priority') or 'low'),
                metadata={'host': str(item.get('hostname', '')), 'time': str(item.get('time', '')),
                          'tags': (item.get('tags') or [])[:10]})


def import_trivy(db, report: dict, asset_id: str | None = None) -> int:
    """Accept a Trivy JSON report; never ingest secret contents."""
    count = 0
    for result in (report.get('Results') or [])[:250]:
        location = str(result.get('Target') or 'unknown')[:200]
        for category, key in [('vuln', 'Vulnerabilities'), ('misconfig', 'Misconfigurations'), ('secret', 'Secrets')]:
            for item in (result.get(key) or [])[:500]:
                if category == 'vuln':
                    ident = str(item.get('VulnerabilityID') or 'unknown')
                    title = f'{ident} in {str(item.get("PkgName") or "package")[:90]}'
                    desc = f'Affected package: {str(item.get("PkgName") or "unknown")[:90]}. Location: {location}. Fixed version: {str(item.get("FixedVersion") or "not specified")[:90]}.'
                    fix = 'Upgrade the affected package to a vendor-supported fixed version, then rescan.'
                elif category == 'misconfig':
                    ident = str(item.get('ID') or 'misconfiguration')
                    title = str(item.get('Title') or ident)
                    desc = f'Configuration issue in {location}. {str(item.get("Message") or "")[:500]}'
                    fix = str(item.get('Resolution') or 'Review and correct the affected configuration.')[:500]
                else:
                    ident = str(item.get('RuleID') or 'secret')
                    title = f'Potential secret exposure: {str(item.get("Category") or ident)[:90]}'
                    desc = f'Potential credential found in {location}. Secret contents were not imported.'
                    fix = 'Inspect the source securely, revoke exposed credentials if confirmed, and prevent recurrence.'
                if count >= 1000:
                    return count
                add_finding(db, asset_id=asset_id, source='trivy', rule=f'{category}:{location}:{ident}',
                            title=title, description=desc, remediation=fix,
                            severity_name=str(item.get('Severity') or 'medium'),
                            evidence={'target': location, 'identifier': ident, 'kind': category})
                count += 1
    return count
