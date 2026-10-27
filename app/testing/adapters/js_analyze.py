"""JavaScript analysis (passive): endpoints and hardcoded secrets in the bundles a page loads.

Fetches the entry page, then up to ten same-origin bundles plus inline scripts. Extracts path-like
strings and a small set of high-signal secret patterns. A discovered secret is never stored: the
finding keeps the pattern name, the length and a four-character prefix only.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

import httpx

from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register

MAX_BUNDLES = 10
MAX_BYTES = 2 * 1024 * 1024

_SCRIPT_SRC = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_INLINE = re.compile(r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)
_PATH = re.compile(r'["\'](/(?:api/)?[A-Za-z0-9_\-./]{3,80})["\']')

SECRET_PATTERNS = (
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'aws_access_key', 'critical'),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 'google_api_key', 'high'),
    (re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}'), 'slack_token', 'high'),
    (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), 'private_key', 'critical'),
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), 'jwt', 'medium'),
)

SKIP_SUFFIXES = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.ico', '.css')


def same_origin(url: str, origin: str) -> bool:
    parts = urlsplit(url)
    return not parts.hostname or f'{parts.scheme}://{parts.netloc}' == origin


def script_urls(html: str, page_url: str) -> list[str]:
    origin = f'{urlsplit(page_url).scheme}://{urlsplit(page_url).netloc}'
    urls: list[str] = []
    for match in _SCRIPT_SRC.finditer(html or ''):
        candidate = urljoin(page_url, match.group(1).strip())
        if same_origin(candidate, origin) and candidate not in urls:
            urls.append(candidate)
    return urls[:MAX_BUNDLES]


def extract_paths(text: str) -> list[str]:
    found: list[str] = []
    for match in _PATH.finditer(text or ''):
        path = match.group(1)
        if path.lower().endswith(SKIP_SUFFIXES) or path in found:
            continue
        found.append(path)
    return found[:50]


def find_secrets(text: str) -> list[tuple[str, str, str]]:
    """(pattern name, severity, masked sample) for each distinct pattern present."""
    out: list[tuple[str, str, str]] = []
    for pattern, name, severity in SECRET_PATTERNS:
        match = pattern.search(text or '')
        if match:
            sample = match.group(0)
            out.append((name, severity, f'{sample[:4]}…({len(sample)} chars)'))
    return out


class JsAnalyzeAdapter(TestAdapter):
    name = 'js_analyze'
    tier = 'passive'
    target_kinds = ('web',)
    description = 'Reads the page and its JavaScript bundles for endpoints and hardcoded secrets.'

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        target = ctx.target or asset.target
        page_url = target.rstrip('/') + '/'
        findings: list[NormalizedFinding] = []

        async with httpx.AsyncClient(base_url=target, timeout=httpx.Timeout(15.0), follow_redirects=False,
                                     trust_env=False, verify=True, limits=httpx.Limits(max_connections=2),
                                     headers=ctx.auth_headers or None) as client:
            await ctx.rate_limiter.acquire()
            try:
                page = await client.get('/')
            except httpx.HTTPError:
                return findings
            html = page.text[:MAX_BYTES]
            bundles = script_urls(html, page_url)
            sources = [('inline', html)]

            for url in bundles:
                await ctx.rate_limiter.acquire()
                try:
                    response = await client.get(url)
                except httpx.HTTPError:
                    continue
                if response.status_code >= 400:
                    continue
                sources.append((url, response.text[:MAX_BYTES]))

        endpoints: list[str] = []
        for source, text in sources:
            for path in extract_paths(text):
                if path not in endpoints:
                    endpoints.append(path)
            for name, severity, sample in find_secrets(text):
                findings.append(NormalizedFinding(
                    rule=f'js:secret:{name}', title=f'Possible hardcoded {name.replace("_", " ")} in JavaScript',
                    description=f'A {name} pattern appears in {source}. Rotate it if it is live; never commit secrets to '
                                'client-side bundles.',
                    remediation='Move the secret server-side, rotate it, and add a secret scan to CI.',
                    severity=severity, evidence={'source': source, 'pattern': name, 'sample': sample}))

        if endpoints:
            findings.append(NormalizedFinding(
                rule='js:endpoints', title=f'{len(endpoints)} API paths referenced by JavaScript',
                description='Client-side code references these paths; they are candidates for authorization testing: '
                            + ', '.join(endpoints[:20]),
                remediation='Confirm each endpoint enforces authorization server-side.',
                severity='informational', evidence={'count': len(endpoints), 'paths': endpoints[:50]}))
        return findings


register(JsAnalyzeAdapter())
