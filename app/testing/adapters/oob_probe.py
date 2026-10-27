"""Out-of-band probe (intrusive): blind SSRF/XXE callbacks, proven by a listener hit.

Each probe gets a fresh single-use token, embedded in a URL under /api/v1/oob/<token>, and placed
in parameters that commonly cause a server-side fetch (url, next, callback, redirect, file). The
adapter then watches the token table for a short window: a hit is proof that the server followed
the URL, which is what makes blind SSRF a finding instead of a guess.
"""
from __future__ import annotations

import asyncio
import secrets
import time

import httpx
from sqlalchemy import select

from ...core.db import session_scope
from ...models import utcnow
from ...models.oob import OobToken
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register

MAX_ENDPOINTS = 3
PARAMS = ('url', 'next', 'callback', 'redirect', 'file', 'target', 'dest', 'continue')


class OobProbeAdapter(TestAdapter):
    name = 'oob_probe'
    tier = 'intrusive'
    target_kinds = ('web',)
    description = 'Blind SSRF/XXE probe using single-use callback tokens recorded by /api/v1/oob.'

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        settings = ctx.settings
        if not getattr(settings, 'oob_enabled', False):
            return []
        factory = getattr(ctx, 'db_factory', None)
        if factory is None:
            return []
        base = str(getattr(settings, 'oob_base_url', '') or settings.base_url).rstrip('/')
        endpoints = [str(e) for e in (plan_params.get('endpoints') or ['/']) if str(e).startswith('/')][:MAX_ENDPOINTS]
        params = [str(p) for p in (plan_params.get('params') or PARAMS)][:4]
        wait = float(getattr(settings, 'oob_wait_seconds', 5))

        probes: list[tuple[str, str, str]] = []
        with session_scope(factory) as db:
            for endpoint in endpoints:
                for param in params:
                    token = secrets.token_urlsafe(14)[:40]
                    db.add(OobToken(tenant_id=ctx.tenant_id, asset_id=asset.id, token=token,
                                    run_id=ctx.run_id, kind='ssrf'))
                    probes.append((token, endpoint, param))

        target = ctx.target or asset.target
        async with httpx.AsyncClient(base_url=target, timeout=httpx.Timeout(10.0), follow_redirects=False,
                                     trust_env=False, verify=True, limits=httpx.Limits(max_connections=2),
                                     headers=ctx.auth_headers or None) as client:
            for token, endpoint, param in probes:
                await ctx.rate_limiter.acquire()
                callback = f'{base}/api/v1/oob/{token}'
                try:
                    await client.get(endpoint, params={param: callback})
                except httpx.HTTPError:
                    continue

        deadline = time.monotonic() + max(1.0, wait)
        hit_tokens: set[str] = set()
        while time.monotonic() < deadline:
            with session_scope(factory) as db:
                rows = db.execute(select(OobToken).where(OobToken.token.in_([p[0] for p in probes]))).scalars().all()
                hit_tokens = {row.token for row in rows if row.first_hit_at is not None}
                hits = {row.token: (row.source_ip, row.user_agent, row.hit_count) for row in rows
                        if row.first_hit_at is not None}
            if hit_tokens:
                break
            await asyncio.sleep(0.5)

        findings: list[NormalizedFinding] = []
        for token, endpoint, param in probes:
            if token not in hit_tokens:
                continue
            source_ip, user_agent, count = hits.get(token, ('', '', 1))
            findings.append(NormalizedFinding(
                rule=f'oob:ssrf:{param}', title=f'Blind SSRF confirmed in {param!r}',
                description=f'The server fetched the callback URL placed in {param!r} ({count} hit(s)). That is '
                            'proof the application makes a server-side request to a URL the client controls.',
                remediation='Allowlist outbound destinations; do not fetch user-supplied URLs from the server.',
                severity='high',
                evidence={'endpoint': endpoint, 'parameter': param, 'source_ip': source_ip,
                          'user_agent': user_agent[:120], 'hits': count, 'callback': f'/api/v1/oob/{token}'}))
        return findings


register(OobProbeAdapter())
