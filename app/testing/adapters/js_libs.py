"""Vulnerable JavaScript library detection (passive): Retire.js-lite.

Reads the page and the bundles it loads, recognises a handful of libraries and versions, and flags
the known-vulnerable ones with their CVE. This is not a CVE database: it is the small set of
libraries that show up in almost every application and whose thresholds are unambiguous.
"""
from __future__ import annotations

import re

import httpx

from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register
from .js_analyze import script_urls

MAX_BUNDLES = 10
MAX_BYTES = 2 * 1024 * 1024

PATTERNS = {
    'jquery': re.compile(r'jQuery[^\n]{0,60}?v?(\d+\.\d+\.\d+)'),
    'jquery-ui': re.compile(r'jQuery UI[^\n]{0,60}?v?(\d+\.\d+\.\d+)'),
    'bootstrap': re.compile(r'Bootstrap[^\n]{0,60}?v(\d+\.\d+\.\d+)'),
    'lodash': re.compile(r'lodash[^\n]{0,60}?v?(\d+\.\d+\.\d+)', re.IGNORECASE),
    'moment': re.compile(r'moment[^\n]{0,60}?v?(\d+\.\d+\.\d+)', re.IGNORECASE),
    'handlebars': re.compile(r'Handlebars[^\n]{0,60}?v?(\d+\.\d+\.\d+)', re.IGNORECASE),
    'underscore': re.compile(r'Underscore[^\n]{0,60}?v?(\d+\.\d+\.\d+)', re.IGNORECASE),
}

# name -> (first fixed version, cve, severity)
FIXED = {
    'jquery': ((3, 5, 0), 'CVE-2020-11022', 'medium'),
    'jquery-ui': ((1, 13, 2), 'CVE-2022-31160', 'medium'),
    'bootstrap': ((3, 4, 1), 'CVE-2019-8331', 'medium'),
    'lodash': ((4, 17, 21), 'CVE-2021-23337', 'high'),
    'moment': ((2, 29, 4), 'CVE-2022-31129', 'medium'),
    'handlebars': ((4, 7, 7), 'CVE-2021-23369', 'high'),
    'underscore': ((1, 13, 3), 'CVE-2021-23358', 'medium'),
}


def _version(text: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(part) for part in text.split('.'))
    except ValueError:
        return None


def detect(text: str) -> dict[str, str]:
    """Library name -> version string, for the libraries present in this text."""
    found: dict[str, str] = {}
    for name, pattern in PATTERNS.items():
        match = pattern.search(text or '')
        if match and name not in found:
            found[name] = match.group(1)
    return found


def vulnerable(name: str, version: str) -> tuple[str, str] | None:
    """(cve, severity) when this version is below the first fixed release."""
    threshold = FIXED.get(name)
    parsed = _version(version)
    if threshold is None or parsed is None:
        return None
    fixed, cve, severity = threshold
    if parsed < fixed:
        return cve, severity
    return None


class JsLibsAdapter(TestAdapter):
    name = 'js_libs'
    tier = 'passive'
    target_kinds = ('web',)
    description = 'Detects vulnerable jQuery/Bootstrap/lodash/moment versions in loaded JavaScript.'

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        target = ctx.target or asset.target
        page_url = target.rstrip('/') + '/'
        findings: list[NormalizedFinding] = []
        async with httpx.AsyncClient(base_url=target, timeout=httpx.Timeout(15.0), follow_redirects=False,
                                     trust_env=False, verify=True, headers=ctx.auth_headers or None) as client:
            await ctx.rate_limiter.acquire()
            try:
                page = await client.get('/')
            except httpx.HTTPError:
                return findings
            sources = [('inline', page.text[:MAX_BYTES])]
            for url in script_urls(page.text, page_url)[:MAX_BUNDLES]:
                await ctx.rate_limiter.acquire()
                try:
                    response = await client.get(url)
                except httpx.HTTPError:
                    continue
                if response.status_code < 400:
                    sources.append((url, response.text[:MAX_BYTES]))

        seen: set[tuple[str, str]] = set()
        for source, text in sources:
            for name, version in detect(text).items():
                if (name, version) in seen:
                    continue
                seen.add((name, version))
                result = vulnerable(name, version)
                if result is None:
                    continue
                cve, severity = result
                findings.append(NormalizedFinding(
                    rule=f'js-lib:{name}:{version}', title=f'Vulnerable {name} {version}',
                    description=f'{name} {version} is below the first fixed release and is affected by {cve}.',
                    remediation=f'Upgrade {name} to the fixed release (or later).',
                    severity=severity, cve_ids=[cve],
                    evidence={'library': name, 'version': version, 'source': source, 'cve': cve}))
        return findings


register(JsLibsAdapter())
