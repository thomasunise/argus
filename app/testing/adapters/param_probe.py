"""Parameter probe (active): finds reflected query parameters with a benign marker.

This sends a random marker value, never an injection payload. A reflected marker is a low-severity
finding (the endpoint mirrors input) and a pointer for review or for the intrusive fuzzer. It is
deliberately rate-limited by the harness and bounded to a handful of endpoints and names.
"""
from __future__ import annotations

import secrets

import httpx

from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register

COMMON_PARAMS = ('q', 'search', 'query', 'id', 'page', 'lang', 'redirect', 'url', 'next', 'file', 'name')
MAX_ENDPOINTS = 5
MAX_PARAMS = 8


class ParamProbeAdapter(TestAdapter):
    name = 'param_probe'
    tier = 'active'
    target_kinds = ('web',)
    description = 'Benign marker probe for reflected query parameters (no payloads).'

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        target = ctx.target or asset.target
        endpoints = [str(e) for e in (plan_params.get('endpoints') or ['/']) if str(e).startswith('/')][:MAX_ENDPOINTS]
        params = list(dict.fromkeys(list(COMMON_PARAMS[:MAX_PARAMS]) + [str(p) for p in (plan_params.get('params') or [])]))[:MAX_PARAMS]
        marker = f'arguscanary{secrets.token_hex(4)}'
        findings: list[NormalizedFinding] = []
        seen: set[str] = set()

        async with httpx.AsyncClient(base_url=target, timeout=httpx.Timeout(10.0), follow_redirects=False,
                                     trust_env=False, verify=True, limits=httpx.Limits(max_connections=2),
                                     headers=ctx.auth_headers or None) as client:
            for endpoint in endpoints:
                for param in params:
                    if param in seen:
                        continue
                    await ctx.rate_limiter.acquire()
                    try:
                        response = await client.get(endpoint, params={param: marker})
                    except httpx.HTTPError:
                        continue
                    if response.status_code >= 500:
                        continue
                    if marker not in response.text[:200_000]:
                        continue
                    seen.add(param)
                    findings.append(NormalizedFinding(
                        rule=f'param-reflected:{param}',
                        title=f'Query parameter {param!r} is reflected in the response',
                        description=f'GET {endpoint}?{param}={marker} returned the marker unchanged, so the endpoint '
                                    'mirrors client input. Reflected input is a candidate for XSS after encoding review.',
                        remediation='Encode output for the response context and validate that this parameter is expected.',
                        severity='low',
                        evidence={'endpoint': endpoint, 'parameter': param, 'status': response.status_code,
                                  'content_type': response.headers.get('content-type', '')[:120]}))
        return findings


register(ParamProbeAdapter())
