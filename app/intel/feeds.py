"""CISA KEV and FIRST EPSS feeds with an on-disk cache, so enrichment keeps working offline.

Layout of INTEL_CACHE_DIR (default ./data/intel):
  kev.json                      the CISA KEV catalog as published (refreshed every INTEL_KEV_REFRESH_HOURS)
  epss.json                     per-CVE EPSS scores fetched from the FIRST API, with fetch times
  epss_scores-current.csv[.gz]  optional bulk EPSS file (https://epss.cyentia.com/epss_scores-current.csv.gz)
                                dropped in by an operator; used before the API and required when INTEL_OFFLINE=true

With INTEL_OFFLINE=true nothing here touches the network; operators copy kev.json and the bulk EPSS
file into the cache directory (air-gapped installs). Every network call goes through `_get_json`.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger('argus.intel')

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
EPSS_API = 'https://api.first.org/data/v1/epss'
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')
EPSS_BATCH = 100
TIMEOUT_SECONDS = 20.0
BULK_NAMES = ('epss_scores-current.csv.gz', 'epss_scores-current.csv')

_lock = threading.RLock()
_memo: dict[str, tuple[float, Any]] = {}  # path -> (mtime, parsed)


def cache_dir(settings: Any) -> Path:
    path = Path(getattr(settings, 'intel_cache_dir', '') or './data/intel')
    path.mkdir(parents=True, exist_ok=True)
    return path


def offline(settings: Any) -> bool:
    return bool(getattr(settings, 'intel_offline', False))


def normalize_cves(values: Any) -> list[str]:
    out: list[str] = []
    items = values.split(',') if isinstance(values, str) else (values or [])
    for raw in items:
        text = str(raw or '').strip().upper()
        if CVE_RE.match(text) and text not in out:
            out.append(text)
    return out


async def _get_json(url: str, params: dict | None = None) -> Any:
    """Single network choke point (tests mock it with respx)."""
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, trust_env=False, follow_redirects=False,
                                 headers={'User-Agent': 'Argus-Intel/1.0', 'Accept': 'application/json'}) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


def _write_atomic(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(data, separators=(',', ':')), encoding='utf-8')
    os.replace(tmp, path)


def _read_json(path: Path) -> Any:
    """Parsed JSON, memoized by mtime. None when the file is missing or unreadable."""
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    with _lock:
        hit = _memo.get(str(path))
        if hit and hit[0] == mtime:
            return hit[1]
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            log.warning('intel cache file %s is unreadable; ignoring it', path.name)
            return None
        _memo[str(path)] = (mtime, data)
        return data


def clear_memo() -> None:
    with _lock:
        _memo.clear()


# ---------------------------------------------------------------- KEV


def _kev_path(settings: Any) -> Path:
    return cache_dir(settings) / 'kev.json'


def kev_age_hours(settings: Any) -> float | None:
    try:
        return (time.time() - _kev_path(settings).stat().st_mtime) / 3600.0
    except OSError:
        return None


def kev_raw(settings: Any) -> dict | None:
    data = _read_json(_kev_path(settings))
    return data if isinstance(data, dict) and isinstance(data.get('vulnerabilities'), list) else None


def kev_index(settings: Any) -> dict[str, dict]:
    """{CVE id: KEV entry} from the cached catalog ({} when there is none)."""
    raw = kev_raw(settings)
    if raw is None:
        return {}
    key = str(_kev_path(settings)) + '#index'
    mtime = _kev_path(settings).stat().st_mtime
    with _lock:
        hit = _memo.get(key)
        if hit and hit[0] == mtime:
            return hit[1]
        index = {str(v.get('cveID', '')).upper(): v for v in raw['vulnerabilities'] if isinstance(v, dict) and v.get('cveID')}
        _memo[key] = (mtime, index)
        return index


async def refresh_kev(settings: Any, *, force: bool = False) -> dict:
    """Download the KEV catalog when the cache is missing or stale. Never raises."""
    age = kev_age_hours(settings)
    max_age = float(getattr(settings, 'intel_kev_refresh_hours', 12) or 12)
    if not force and age is not None and age < max_age:
        return {'refreshed': False, 'reason': 'fresh', 'age_hours': round(age, 2)}
    if offline(settings):
        return {'refreshed': False, 'reason': 'offline mode', 'age_hours': age}
    try:
        data = await _get_json(KEV_URL)
    except (httpx.HTTPError, ValueError, OSError) as exc:
        log.warning('KEV refresh failed: %s', type(exc).__name__)
        return {'refreshed': False, 'reason': f'fetch failed ({type(exc).__name__})', 'age_hours': age}
    if not isinstance(data, dict) or not isinstance(data.get('vulnerabilities'), list) or not data['vulnerabilities']:
        return {'refreshed': False, 'reason': 'malformed catalog', 'age_hours': age}
    with _lock:
        _write_atomic(_kev_path(settings), data)
    log.info('KEV catalog refreshed: version %s, %d entries', data.get('catalogVersion'), len(data['vulnerabilities']))
    return {'refreshed': True, 'catalog_version': data.get('catalogVersion'), 'count': len(data['vulnerabilities'])}


async def kev_lookup(settings: Any, cves: list[str]) -> dict[str, dict]:
    """KEV entries for the CVEs that are listed. Refreshes a stale catalog first (unless offline)."""
    await refresh_kev(settings)
    index = kev_index(settings)
    return {c: index[c] for c in cves if c in index}


# ---------------------------------------------------------------- EPSS


def _epss_path(settings: Any) -> Path:
    return cache_dir(settings) / 'epss.json'


def _bulk_path(settings: Any) -> Path | None:
    for name in BULK_NAMES:
        path = cache_dir(settings) / name
        if path.is_file():
            return path
    return None


def _bulk_index(settings: Any) -> tuple[dict[str, dict], str]:
    """({CVE: {'epss', 'percentile'}}, score_date) from the bulk file, memoized by mtime."""
    path = _bulk_path(settings)
    if path is None:
        return {}, ''
    mtime = path.stat().st_mtime
    with _lock:
        hit = _memo.get(str(path))
        if hit and hit[0] == mtime:
            return hit[1]
        try:
            raw = gzip.decompress(path.read_bytes()) if path.suffix == '.gz' else path.read_bytes()
            text = raw.decode('utf-8', errors='replace')
        except (OSError, EOFError, gzip.BadGzipFile):
            log.warning('bulk EPSS file %s is unreadable; ignoring it', path.name)
            return {}, ''
        score_date = ''
        lines = text.splitlines()
        if lines and lines[0].startswith('#'):
            match = re.search(r'score_date:([0-9T:\-+Z.]+)', lines[0])
            score_date = match.group(1)[:10] if match else ''
            lines = lines[1:]
        index: dict[str, dict] = {}
        for row in csv.DictReader(io.StringIO('\n'.join(lines))):
            cve = str(row.get('cve', '')).upper()
            try:
                index[cve] = {'epss': float(row['epss']), 'percentile': float(row['percentile'])}
            except (KeyError, TypeError, ValueError):
                continue
        result = (index, score_date)
        _memo[str(path)] = (mtime, result)
        return result


def epss_cache(settings: Any) -> dict[str, dict]:
    data = _read_json(_epss_path(settings))
    return dict(data) if isinstance(data, dict) else {}


async def epss_lookup(settings: Any, cves: list[str]) -> dict[str, dict]:
    """{CVE: {'epss', 'percentile', 'date', 'source'}} for scored CVEs. Order: fresh API cache, bulk file,
    API (unless offline), then stale cache entries rather than nothing."""
    ttl = float(getattr(settings, 'intel_epss_ttl_hours', 24) or 24) * 3600.0
    now = time.time()
    cache = epss_cache(settings)
    out: dict[str, dict] = {}
    missing: list[str] = []
    for cve in cves:
        entry = cache.get(cve)
        if isinstance(entry, dict) and now - float(entry.get('fetched_at', 0) or 0) < ttl:
            out[cve] = {**entry, 'source': 'api-cache'}
        else:
            missing.append(cve)
    if missing:
        bulk, score_date = _bulk_index(settings)
        still: list[str] = []
        for cve in missing:
            if cve in bulk:
                out[cve] = {**bulk[cve], 'date': score_date, 'source': 'bulk-file'}
            else:
                still.append(cve)
        missing = still
    if missing and not offline(settings):
        fetched: dict[str, dict] = {}
        for start in range(0, len(missing), EPSS_BATCH):
            chunk = missing[start:start + EPSS_BATCH]
            try:
                data = await _get_json(EPSS_API, params={'cve': ','.join(chunk)})
            except (httpx.HTTPError, ValueError, OSError) as exc:
                log.warning('EPSS fetch failed: %s', type(exc).__name__)
                break
            for row in (data.get('data') or []) if isinstance(data, dict) else []:
                try:
                    cve = str(row['cve']).upper()
                    fetched[cve] = {'epss': float(row['epss']), 'percentile': float(row['percentile']), 'date': str(row.get('date', ''))[:10],
                                    'fetched_at': now}
                except (KeyError, TypeError, ValueError):
                    continue
            for cve in chunk:  # unscored CVEs are cached too, so they are not refetched on every run
                fetched.setdefault(cve, {'epss': None, 'percentile': None, 'date': '', 'fetched_at': now})
        if fetched:
            with _lock:
                merged = epss_cache(settings)
                merged.update(fetched)
                _write_atomic(_epss_path(settings), merged)
            for cve, entry in fetched.items():
                if entry.get('epss') is not None:
                    out[cve] = {**entry, 'source': 'api'}
            missing = [c for c in missing if c not in fetched]
    for cve in missing:  # stale beats nothing
        entry = cache.get(cve)
        if isinstance(entry, dict) and entry.get('epss') is not None:
            out[cve] = {**entry, 'source': 'stale-cache'}
    return {c: v for c, v in out.items() if v.get('epss') is not None}


def status(settings: Any) -> dict:
    raw = kev_raw(settings)
    age = kev_age_hours(settings)
    bulk_path = _bulk_path(settings)
    bulk, score_date = _bulk_index(settings) if bulk_path else ({}, '')
    max_age = float(getattr(settings, 'intel_kev_refresh_hours', 12) or 12)
    return {'offline': offline(settings), 'enabled': bool(getattr(settings, 'intel_enrichment_enabled', True)),
            'kev': {'cached': raw is not None, 'catalog_version': (raw or {}).get('catalogVersion'), 'count': len((raw or {}).get('vulnerabilities', [])),
                    'age_hours': round(age, 2) if age is not None else None, 'stale': age is None or age >= max_age},
            'epss': {'cached_cves': len(epss_cache(settings)), 'bulk_file': bulk_path.name if bulk_path else None, 'bulk_cves': len(bulk),
                     'bulk_score_date': score_date}}
