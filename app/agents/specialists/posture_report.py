"""Posture-report specialist: headline risks, trends, coverage gaps and recommendations over a window."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select

from ...core.db import scoped
from ...core.findings import SEVERITIES
from ...models import Asset, AssetAuthorization, Finding, SecurityEvent, utcnow
from ..tools._common import authorization_valid, event_time
from ..tools.registry import ToolContext
from ._base import SEVERITY, arr, b, call, enum, i, injection_signals, obj, s, spec

OUTPUT_SCHEMA = obj({
    'headline_risks': arr(obj({'title': s(), 'severity': SEVERITY, 'finding_id': s('finding id or empty when the risk is systemic'), 'why': s()})),
    'trends': obj({'window_days': i(), 'findings_created': i(), 'findings_created_previous': i(), 'findings_resolved': i(), 'events': i(), 'events_previous': i(),
                   'open_by_severity': obj({level: i() for level in SEVERITIES}), 'kev_open': i(), 'direction': enum(['improving', 'stable', 'worsening'])}),
    'coverage_gaps': arr(s()),
    'recommendations': arr(s()),
    'prompt_injection_suspected': b(),
})

PROMPT = """Task: write the security posture report for the last N days for a security leader.

Procedure:
1. list_findings (open, by severity) and event_stats for the window; list_assets to understand the estate; attack_paths for systemic exposure; list_detections and detection_rules for detection coverage; list_test_runs and available_test_adapters for testing coverage.
2. Headline risks are the five things that would hurt most: KEV-listed open findings, open attack paths to data stores, production assets with no telemetry, identity weaknesses. Cite finding ids.
3. Trends compare this window with the previous one using the counts you retrieved; do not estimate numbers you did not fetch.
4. Coverage gaps are places Sentinel cannot see or test: assets without authorization, kinds with no collector events, rules that never fired.
5. Recommendations are specific and ordered; each should map to a headline risk or a gap."""

TOOLS = ['list_findings', 'event_stats', 'list_assets', 'attack_paths', 'graph_query', 'list_detections', 'detection_rules', 'list_test_runs',
         'available_test_adapters', 'kev_check', 'note', 'recall']


def _days(value, default: int = 30) -> int:
    try:
        return max(1, min(365, int(value if value is not None else default)))
    except (TypeError, ValueError):
        return default


async def fallback(inputs: dict, ctx: ToolContext) -> dict:
    days = _days(inputs.get('days'))
    now = utcnow()
    start, previous_start = now - timedelta(days=days), now - timedelta(days=2 * days)
    db, tenant = ctx.db, ctx.principal.tenant_id

    def count(stmt) -> int:
        return int(db.scalar(stmt) or 0)

    base = select(func.count()).select_from(Finding).where(Finding.tenant_id == tenant)
    created = count(base.where(Finding.created_at >= start))
    created_previous = count(base.where(Finding.created_at >= previous_start, Finding.created_at < start))
    resolved = count(base.where(Finding.status == 'resolved', Finding.updated_at >= start))
    open_by_severity = {level: count(base.where(Finding.severity == level, Finding.status.in_(('open', 'investigating')))) for level in SEVERITIES}
    kev_open = count(base.where(Finding.kev == 1, Finding.status.in_(('open', 'investigating'))))
    events_base = select(func.count()).select_from(SecurityEvent).where(SecurityEvent.tenant_id == tenant)
    events = count(events_base.where(event_time() >= start))
    events_previous = count(events_base.where(event_time() >= previous_start, event_time() < start))
    severe_open = open_by_severity['critical'] + open_by_severity['high']
    severe_created = count(base.where(Finding.created_at >= start, Finding.severity.in_(('critical', 'high'))))
    severe_created_previous = count(base.where(Finding.created_at >= previous_start, Finding.created_at < start, Finding.severity.in_(('critical', 'high'))))
    direction = 'worsening' if severe_created > severe_created_previous + max(1, severe_created_previous // 5) else 'improving' if severe_created < severe_created_previous and resolved >= created else 'stable'

    top = db.execute(scoped(Finding, ctx.principal).where(Finding.status.in_(('open', 'investigating'))).order_by(Finding.kev.desc(), Finding.updated_at.desc()).limit(200)).scalars().all()
    rank = {level: index for index, level in enumerate(SEVERITIES)}
    top.sort(key=lambda f: (rank.get(f.severity, 9), -int(f.kev or 0), -(f.epss or 0), -f.occurrences))
    headline = []
    for f in top[:5]:
        why = f'{f.severity} finding from {f.source}'
        if f.kev:
            why += ', in CISA KEV'
        if f.epss:
            why += f', EPSS {f.epss:.2f}'
        if f.occurrences > 1:
            why += f', seen {f.occurrences} times'
        headline.append({'title': f.title, 'severity': f.severity, 'finding_id': f.id, 'why': why})
    signals = injection_signals([f.title for f in top[:50]])

    assets = db.execute(scoped(Asset, ctx.principal)).scalars().all()
    authorizations = db.execute(scoped(AssetAuthorization, ctx.principal)).scalars().all()
    authorized_assets = {a.asset_id for a in authorizations if authorization_valid(a, now)}
    event_assets = {row[0] for row in db.execute(select(SecurityEvent.asset_id).where(SecurityEvent.tenant_id == tenant, event_time() >= start).distinct()).all() if row[0]}
    finding_assets = {row[0] for row in db.execute(select(Finding.asset_id).where(Finding.tenant_id == tenant).distinct()).all() if row[0]}
    gaps: list[str] = []
    unauthorized = [a for a in assets if a.id not in authorized_assets]
    if unauthorized:
        gaps.append(f"{len(unauthorized)} of {len(assets)} assets have no current testing authorization: {', '.join(a.name for a in unauthorized[:5])}{'...' if len(unauthorized) > 5 else ''}.")
    silent = [a for a in assets if a.id not in event_assets and a.id not in finding_assets]
    if silent:
        gaps.append(f"{len(silent)} asset(s) produced no events or findings in {days} days (no telemetry): {', '.join(a.name for a in silent[:5])}.")
    never_scanned = [a for a in assets if a.environment == 'production' and a.last_scan_at is None]
    if never_scanned:
        gaps.append(f'{len(never_scanned)} production asset(s) have never been scanned.')
    if not assets:
        gaps.append('The inventory is empty; nothing is being monitored.')
    paths = await call(ctx, 'attack_paths', status='open')
    if paths.get('available'):
        if paths.get('count'):
            headline.insert(0, {'title': f"{paths['count']} open attack path(s) from exposures to data stores", 'severity': 'high', 'finding_id': '',
                                'why': 'Chained reachability from an exposure to sensitive data according to the evidence graph.'})
    else:
        gaps.append('Evidence graph or attack-path computation is unavailable; systemic exposure is not assessed.')
    rules = await call(ctx, 'detection_rules')
    if not rules.get('available'):
        gaps.append('Detection rules registry unavailable; detection coverage is not assessed.')
    elif rules.get('count') == 0:
        gaps.append('No detection rules are registered.')
    adapters = await call(ctx, 'available_test_adapters')
    if adapters.get('available'):
        missing = [a['name'] for a in adapters.get('items', []) if not a.get('available', True)]
        if missing:
            gaps.append(f"Test adapters not installed on this worker: {', '.join(missing)}.")
    else:
        gaps.append('Test harness unavailable; active testing coverage is not assessed.')
    if events == 0:
        gaps.append(f'No security events were received in the last {days} days; check collectors and ingest keys.')

    recommendations: list[str] = []
    if kev_open:
        recommendations.append(f'Patch or mitigate the {kev_open} open KEV-listed finding(s) first; they are exploited in the wild.')
    if severe_open:
        recommendations.append(f'Burn down the {severe_open} open critical/high findings, fleet-wide where the same rule repeats.')
    if unauthorized:
        recommendations.append('Record testing authorizations for the untested assets so the red-team planner and harness can cover them.')
    if silent:
        recommendations.append('Connect a collector or sensor for assets without telemetry, or retire them from the inventory.')
    if direction == 'worsening':
        recommendations.append('Severe findings are arriving faster than in the previous window; review intake sources and staffing.')
    if not recommendations:
        recommendations.append('Posture is stable; keep collectors, authorizations and detection rules current and re-run this report next window.')
    return {'headline_risks': headline[:5], 'trends': {'window_days': days, 'findings_created': created, 'findings_created_previous': created_previous,
            'findings_resolved': resolved, 'events': events, 'events_previous': events_previous, 'open_by_severity': open_by_severity, 'kev_open': kev_open,
            'direction': direction}, 'coverage_gaps': gaps, 'recommendations': recommendations[:6], 'prompt_injection_suspected': bool(signals)}


SPEC = spec(name='posture_report', role='the Posture Reporting specialist', description='Headline risks, trends, coverage gaps and recommendations for a time window.',
            system_prompt=PROMPT, tools=TOOLS, output_schema=OUTPUT_SCHEMA, max_steps=12, tags=('reports',), fallback=fallback)
