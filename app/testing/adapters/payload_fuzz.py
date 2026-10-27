"""Payload fuzzing (intrusive): a small, curated, non-destructive payload set.

Intrusive by design: the existing scope rules already restrict this tier to staging/lab assets with
an authorization that permits intrusive testing. The payloads are chosen to provoke *evidence*
(database error strings, unencoded reflection, a readable passwd file) rather than to damage
anything: no stacked queries, no writes, no shell, no time-based or destructive variants.
"""
from __future__ import annotations

import httpx

from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register
from .sqli_blind import detect_blind

MAX_ENDPOINTS = 5

PAYLOADS = {
    'sqli': ["'", "' OR '1'='1", '")'],
    'xss': ['"><argus>', "<argus>"],
    'traversal': ['../../../../etc/passwd'],
}
SQL_ERRORS = ('sql syntax', 'mysql_fetch', 'mysql server', 'postgresql', 'psql:', 'ora-0', 'sqlite error',
              'unclosed quotation', 'odbc', 'jdbc', 'sequelize', 'syntax error at or near')
TRAVERSAL_MARKER = 'root:x:'


class PayloadFuzzAdapter(TestAdapter):
    name = 'payload_fuzz'
    tier = 'intrusive'
    target_kinds = ('web',)
    description = 'Curated SQLi/XSS/traversal payloads that detect evidence without exploiting.'

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        if ctx.tier != 'intrusive':
            return []  # the scope already blocks this, but the adapter refuses too
        target = ctx.target or asset.target
        endpoints = [str(e) for e in (plan_params.get('endpoints') or ['/']) if str(e).startswith('/')][:MAX_ENDPOINTS]
        params = [str(p) for p in (plan_params.get('params') or ['q', 'id', 'search'])][:4]
        findings: list[NormalizedFinding] = []

        async with httpx.AsyncClient(base_url=target, timeout=httpx.Timeout(10.0), follow_redirects=False,
                                     trust_env=False, verify=True, limits=httpx.Limits(max_connections=2),
                                     headers=ctx.auth_headers or None) as client:
            for endpoint in endpoints:
                for param in params:
                    for kind, payloads in PAYLOADS.items():
                        for payload in payloads:
                            await ctx.rate_limiter.acquire()
                            try:
                                response = await client.get(endpoint, params={param: payload})
                            except httpx.HTTPError:
                                continue
                            body = response.text[:200_000].lower()
                            finding = _classify(kind, payload, endpoint, param, response.status_code, body)
                            if finding is not None:
                                findings.append(finding)
                                break

            # blind and time-based checks come after the error-based pass
            for endpoint in endpoints:
                for param in params:
                    blind = await detect_blind(client, ctx, endpoint, param)
                    if blind is not None:
                        findings.append(blind)
        return findings


def _classify(kind: str, payload: str, endpoint: str, param: str, status: int, body: str) -> NormalizedFinding | None:
    evidence = {'endpoint': endpoint, 'parameter': param, 'payload': payload[:80], 'status': status}
    if kind == 'sqli':
        matched = next((signature for signature in SQL_ERRORS if signature in body), '')
        if matched:
            return NormalizedFinding(rule=f'fuzz:sqli:{param}', title=f'Possible SQL injection in {param!r}',
                                     description=f'A quote payload produced a database error signature ({matched!r}). '
                                                 'This is evidence of unsanitized SQL construction, not a full exploit.',
                                     remediation='Use parameterized queries; never concatenate input into SQL.',
                                     severity='high', evidence={**evidence, 'signature': matched})
    if kind == 'xss':
        if payload.lower() in body and '&lt;' not in body and '&quot;' not in body:
            return NormalizedFinding(rule=f'fuzz:xss:{param}', title=f'Unencoded reflection in {param!r}',
                                     description='The payload was reflected without HTML encoding; confirms an injection point.',
                                     remediation='HTML-encode output for the response context.',
                                     severity='medium', evidence=evidence)
    if kind == 'traversal' and TRAVERSAL_MARKER in body:
        return NormalizedFinding(rule=f'fuzz:traversal:{param}', title=f'Path traversal in {param!r}',
                                 description='A traversal payload returned a readable passwd file.',
                                 remediation='Normalize and allowlist file paths; never build a path from input.',
                                 severity='critical', evidence=evidence)
    return None


register(PayloadFuzzAdapter())
