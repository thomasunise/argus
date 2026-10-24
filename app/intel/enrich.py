"""Finding enrichment with CISA KEV membership and EPSS scores.

`enrich_findings` sets Finding.kev / Finding.epss, adds a 'kev' tag, and writes an `intel` block to
the finding evidence (which CVEs are listed, KEV due dates, ransomware use, per-CVE EPSS). A
KEV-listed finding is raised to at least INTEL_KEV_MIN_SEVERITY (default 'high'); the original
severity is kept in the evidence. Severity is never lowered.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.findings import SEVERITIES
from ..models import Finding, dumps, loads
from . import feeds

log = logging.getLogger('argus.intel')

OPEN_STATUSES = ('open', 'investigating')
MAX_BATCH = 2000


def _more_severe(a: str, b: str) -> str:
    return min([a, b], key=lambda s: SEVERITIES.index(s) if s in SEVERITIES else len(SEVERITIES))


def candidates(db: Session, tenant_id: str, *, finding_ids: list[str] | None = None, only_unchecked: bool = False,
               include_closed: bool = False, limit: int = MAX_BATCH) -> list[Finding]:
    stmt = select(Finding).where(Finding.tenant_id == tenant_id, Finding.cve_ids != '')
    if finding_ids:
        stmt = stmt.where(Finding.id.in_(list(finding_ids)[:limit]))
    elif not include_closed:
        stmt = stmt.where(Finding.status.in_(OPEN_STATUSES))
    if only_unchecked:
        stmt = stmt.where(Finding.evidence.not_like('%"intel":%'))
    return list(db.execute(stmt.order_by(Finding.created_at.desc()).limit(limit)).scalars().all())


def apply(finding: Finding, kev: dict[str, dict], epss: dict[str, dict], settings: Any, now: datetime | None = None) -> dict:
    """Update one finding in place from looked-up intel. Returns a summary of what changed."""
    cves = feeds.normalize_cves(finding.cve_ids)
    listed = {c: kev[c] for c in cves if c in kev}
    scored = {c: epss[c] for c in cves if c in epss}
    changed: dict[str, Any] = {}

    new_kev = 1 if listed else 0
    if int(finding.kev or 0) != new_kev:
        changed['kev'] = bool(new_kev)
        finding.kev = new_kev
    if scored:
        best = max(float(v['epss']) for v in scored.values())
        if finding.epss is None or abs(float(finding.epss) - best) > 1e-9:
            changed['epss'] = best
            finding.epss = best

    tags = loads(finding.tags_json, [])
    tags = tags if isinstance(tags, list) else []
    if listed and 'kev' not in tags:
        finding.tags_json = dumps(tags + ['kev'])
    elif not listed and 'kev' in tags:
        finding.tags_json = dumps([t for t in tags if t != 'kev'])

    evidence = loads(finding.evidence, {})
    evidence = evidence if isinstance(evidence, dict) else {'value': evidence}
    previous = evidence.get('intel') if isinstance(evidence.get('intel'), dict) else {}
    intel: dict[str, Any] = {
        'checked_at': (now or datetime.now(timezone.utc)).isoformat(),
        'kev': {c: {'date_added': v.get('dateAdded'), 'due_date': v.get('dueDate'), 'ransomware': v.get('knownRansomwareCampaignUse'),
                    'vendor': v.get('vendorProject'), 'product': v.get('product')} for c, v in listed.items()},
        'epss': {c: {'score': v.get('epss'), 'percentile': v.get('percentile'), 'date': v.get('date')} for c, v in scored.items()},
    }
    if previous.get('severity_raised_from'):
        intel['severity_raised_from'] = previous['severity_raised_from']

    floor = str(getattr(settings, 'intel_kev_min_severity', 'high') or '').lower()
    if listed and floor in SEVERITIES:
        raised = _more_severe(finding.severity, floor)
        if raised != finding.severity:
            intel['severity_raised_from'] = finding.severity
            changed['severity'] = raised
            finding.severity = raised
    threshold = float(getattr(settings, 'intel_epss_escalate_threshold', 0) or 0)
    if threshold > 0 and finding.epss is not None and finding.epss >= threshold and SEVERITIES.index(finding.severity) > SEVERITIES.index('high'):
        intel.setdefault('severity_raised_from', finding.severity)
        changed['severity'] = 'high'
        finding.severity = 'high'

    evidence['intel'] = intel
    finding.evidence = dumps(evidence, limit=12000)
    if changed:
        finding.updated_at = now or datetime.now(timezone.utc)
    return changed

