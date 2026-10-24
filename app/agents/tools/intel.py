"""Threat-intel lookups: NVD (CVE details), CISA KEV and FIRST EPSS.

All network access goes through `_fetch_json` so tests can monkeypatch it. Responses are
cached in-process. Nothing here raises on network failure; callers get {'available': False}.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

import httpx

from .registry import ToolContext, registry

log = logging.getLogger('argus.agents.tools.intel')

NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
EPSS_URL = 'https://api.first.org/data/v1/epss?cve='
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')
HOUR = 3600.0
TIMEOUT_SECONDS = 10.0

_cache: dict[str, tuple[float, Any]] = {}
_lock = asyncio.Lock()


async def _fetch_json(url: str) -> Any:
    """Single network choke point. Raises httpx errors; `_cached` turns them into unavailability."""
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, trust_env=False, follow_redirects=False,
                                 headers={'User-Agent': 'Argus-Intel/1.0', 'Accept': 'application/json'}) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


async def _cached(url: str, ttl: float) -> tuple[Any, str]:
    """Returns (data, error). data is None on failure."""
    now = time.monotonic()
    hit = _cache.get(url)
    if hit and hit[0] > now:
        return hit[1], ''
    try:
        data = await _fetch_json(url)
    except (httpx.HTTPError, ValueError, OSError) as exc:
        log.warning('intel fetch failed for %s: %s', url.split('?')[0], type(exc).__name__)
        return None, f'{type(exc).__name__}'
    except Exception as exc:  # never propagate into the agent loop
        log.warning('intel fetch crashed for %s: %s', url.split('?')[0], type(exc).__name__)
        return None, f'{type(exc).__name__}'
    async with _lock:
        _cache[url] = (now + ttl, data)
    return data, ''


def clear_cache() -> None:
    _cache.clear()


def normalize_ids(values: Any) -> tuple[list[str], list[str]]:
    valid: list[str] = []
    invalid: list[str] = []
    for raw in values if isinstance(values, list) else [values]:
        text = str(raw or '').strip().upper()
        if CVE_RE.match(text):
            if text not in valid:
                valid.append(text)
        elif text:
            invalid.append(text[:40])
    return valid[:100], invalid


def _cvss_from_metrics(metrics: dict) -> dict:
    for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get('cvssData', {})
            return {'version': data.get('version'), 'score': data.get('baseScore'), 'severity': data.get('baseSeverity') or entries[0].get('baseSeverity'),
                    'vector': data.get('vectorString'), 'attack_vector': data.get('attackVector') or data.get('accessVector')}
    return {'version': None, 'score': None, 'severity': None, 'vector': None, 'attack_vector': None}


@registry.tool('cve_lookup', 'Look up a CVE in the NVD: description, CVSS score/vector, CWE, publish date and whether CISA lists it as exploited.',
               {'properties': {'cve_id': {'type': 'string', 'description': 'e.g. CVE-2024-3094'}}, 'required': ['cve_id']}, tags=('intel',))
async def cve_lookup(args: dict, ctx: ToolContext) -> dict:
    valid, invalid = normalize_ids(args.get('cve_id'))
    if not valid:
        return {'available': False, 'reason': 'invalid CVE id', 'invalid': invalid}
    cve_id = valid[0]
    data, error = await _cached(NVD_URL + cve_id, HOUR)
    if data is None:
        return {'available': False, 'cve_id': cve_id, 'reason': f'NVD unreachable ({error})'}
    vulns = data.get('vulnerabilities') or []
    if not vulns:
        return {'available': True, 'cve_id': cve_id, 'found': False}
    cve = vulns[0].get('cve', {})
    description = next((d.get('value') for d in cve.get('descriptions', []) if d.get('lang') == 'en'), '')
    cwes = sorted({d.get('value') for w in cve.get('weaknesses', []) for d in w.get('description', []) if str(d.get('value', '')).startswith('CWE')})
    return {'available': True, 'cve_id': cve_id, 'found': True, 'description': (description or '')[:1500], 'published': cve.get('published'),
            'last_modified': cve.get('lastModified'), 'status': cve.get('vulnStatus'), 'cvss': _cvss_from_metrics(cve.get('metrics') or {}),
            'cwes': cwes, 'kev': bool(cve.get('cisaExploitAdd')), 'kev_due_date': cve.get('cisaActionDue'),
            'reference_count': len(cve.get('references') or [])}


def _local_kev(ctx: ToolContext) -> dict | None:
    try:
        from ...intel import feeds

        return feeds.kev_raw(ctx.settings)
    except Exception:  # the cache is an optimisation; never fail the tool over it
        return None

@registry.tool('kev_check', 'Check which of the given CVE ids are in the CISA Known Exploited Vulnerabilities catalog (actively exploited in the wild).',
               {'properties': {'cve_ids': {'type': 'array', 'items': {'type': 'string'}}}, 'required': ['cve_ids']}, tags=('intel',))
async def kev_check(args: dict, ctx: ToolContext) -> dict:
    valid, invalid = normalize_ids(args.get('cve_ids'))
    if not valid:
        return {'available': False, 'reason': 'no valid CVE ids', 'invalid': invalid}
    data = _local_kev(ctx)  # the enrichment package's on-disk catalog, when present (works offline)
    error = ''
    if data is None:
        if getattr(ctx.settings, 'intel_offline', False):
            return {'available': False, 'reason': 'offline mode and no cached KEV catalog', 'checked': valid}
        data, error = await _cached(KEV_URL, 6 * HOUR)
    if data is None:
        return {'available': False, 'reason': f'KEV feed unreachable ({error})', 'checked': valid}
    index = {str(v.get('cveID', '')).upper(): v for v in data.get('vulnerabilities') or []}
    in_kev = {cve: {'date_added': v.get('dateAdded'), 'due_date': v.get('dueDate'), 'vendor': v.get('vendorProject'), 'product': v.get('product'),
                    'ransomware': str(v.get('knownRansomwareCampaignUse', '')).lower() == 'known'}
              for cve, v in ((c, index.get(c)) for c in valid) if v}
    return {'available': True, 'catalog_version': data.get('catalogVersion'), 'in_kev': in_kev,
            'not_in_kev': [c for c in valid if c not in in_kev], 'invalid': invalid}


@registry.tool('epss_scores', 'EPSS exploitation-probability scores (0-1) and percentiles for the given CVE ids.',
               {'properties': {'cve_ids': {'type': 'array', 'items': {'type': 'string'}}}, 'required': ['cve_ids']}, tags=('intel',))
async def epss_scores(args: dict, ctx: ToolContext) -> dict:
    valid, invalid = normalize_ids(args.get('cve_ids'))
    if not valid:
        return {'available': False, 'reason': 'no valid CVE ids', 'invalid': invalid}
    if getattr(ctx.settings, 'intel_offline', False):
        from ...intel import feeds

        cached = await feeds.epss_lookup(ctx.settings, valid)
        scores = {c: {'epss': v['epss'], 'percentile': v['percentile'], 'date': v.get('date')} for c, v in cached.items()}
        return {'available': True, 'scores': scores, 'missing': [c for c in valid if c not in scores], 'invalid': invalid, 'offline': True}
    data, error = await _cached(EPSS_URL + ','.join(valid), HOUR)
    if data is None:
        return {'available': False, 'reason': f'EPSS API unreachable ({error})', 'checked': valid}
    scores: dict[str, dict] = {}
    for row in data.get('data') or []:
        cve = str(row.get('cve', '')).upper()
        try:
            scores[cve] = {'epss': float(row.get('epss', 0)), 'percentile': float(row.get('percentile', 0)), 'date': row.get('date')}
        except (TypeError, ValueError):
            continue
    return {'available': True, 'scores': scores, 'missing': [c for c in valid if c not in scores], 'invalid': invalid}
