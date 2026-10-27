"""Bounded path discovery (active): the ffuf-lite Argus runs itself.

A curated list of paths a real application leaks by accident, plus caller-supplied paths, requested
one by one through the run's rate limiter. No wordlist brute force: 45 paths, not 45,000.
"""
from __future__ import annotations

from pathlib import Path

import httpx

from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register

PATHS = (
    '/admin', '/api', '/api/v1', '/api/v2', '/backup', '/backup.zip', '/config.json', '/console',
    '/dashboard', '/db.sql', '/debug', '/dev', '/docs', '/graphql', '/health', '/login', '/metrics',
    '/openapi.json', '/phpmyadmin', '/redoc', '/register', '/robots.txt', '/server-status',
    '/sitemap.xml', '/staging', '/static/', '/swagger', '/swagger-ui.html', '/test', '/uploads',
    '/wp-admin', '/wp-login.php', '/.env', '/.git/config', '/.git/HEAD', '/.svn/entries',
    '/.well-known/security.txt', '/actuator', '/actuator/env', '/actuator/health', '/config.yml',
    '/docker-compose.yml', '/Dockerfile', '/package.json', '/web.config',
)

SENSITIVE = ('.env', '.git', '.svn', 'db.sql', 'backup', 'config', 'dockerfile', 'docker-compose',
             'package.json', 'actuator', 'server-status', 'console', 'phpmyadmin', 'web.config')

MAX_PATHS = 60
MAX_WORDLIST = 500


def classify(path: str, status: int) -> NormalizedFinding | None:
    """404/5xx are noise; 401/403 is a protected path; 2xx is reachable (high when sensitive)."""
    if status == 404 or status >= 500:
        return None
    sensitive = any(marker in path.lower() for marker in SENSITIVE)
    if status in (401, 403):
        return NormalizedFinding(
            rule=f'path-protected:{path[:80]}', title=f'Protected path {path}',
            description=f'GET {path} returned {status}: the path exists but requires authorization. '
                        'Confirm it is intended to be reachable and that the authz check is correct.',
            remediation='Remove the path if unused; otherwise verify authorization and rate limiting.',
            severity='low', evidence={'path': path, 'status': status})
    if 200 <= status < 300:
        return NormalizedFinding(
            rule=f'path-exposed:{path[:80]}', title=f'Reachable path {path}',
            description=f'GET {path} returned {status} without redirecting to a login page.',
            remediation='Confirm this path is meant to be public; remove backups, VCS metadata and debug endpoints.',
            severity='high' if sensitive else 'medium', evidence={'path': path, 'status': status})
    return None


def _from_wordlist(name: object, settings) -> list[str]:
    """Paths from a file inside SCAN_ROOT: one per line, '#' comments, bounded."""
    if not name:
        return []
    root = Path(settings.scan_root).resolve()
    candidate = (root / str(name)).resolve()
    if root not in candidate.parents or not candidate.is_file():
        return []
    try:
        lines = candidate.read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return []
    out = [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
    return [line if line.startswith('/') else '/' + line for line in out][:MAX_WORDLIST]


class DirProbeAdapter(TestAdapter):
    name = 'dir_probe'
    tier = 'active'
    target_kinds = ('web',)
    description = 'Curated path discovery (45 paths) for backups, VCS metadata and debug endpoints.'

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        target = ctx.target or asset.target
        extra = [str(p) for p in (plan_params.get('paths') or []) if str(p).startswith('/')]
        extra += _from_wordlist(plan_params.get('wordlist'), ctx.settings)
        paths = list(dict.fromkeys(extra + list(PATHS)))[:MAX_WORDLIST]
        findings: list[NormalizedFinding] = []
        async with httpx.AsyncClient(base_url=target, timeout=httpx.Timeout(10.0), follow_redirects=False,
                                     trust_env=False, verify=True, limits=httpx.Limits(max_connections=2),
                                     headers=ctx.auth_headers or None) as client:
            for path in paths:
                await ctx.rate_limiter.acquire()
                try:
                    response = await client.get(path)
                except httpx.HTTPError:
                    continue
                finding = classify(path, response.status_code)
                if finding is not None:
                    findings.append(finding)
        return findings


register(DirProbeAdapter())
