"""WAF detection (active, non-intrusive): fingerprints the edge in front of the asset.

One request with a benign marker parameter, then a signature match over headers, cookies and the
response body. Knowing there is a WAF changes how every other result should be read: a 403 to a
payload may mean "blocked", not "not vulnerable".
"""
from __future__ import annotations

import httpx

from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register

# (name, where, pattern) - matched case-insensitively.
SIGNATURES = (
    ('cloudflare', 'server', 'cloudflare'),
    ('cloudflare-cookie', 'cookie', 'cf_clearance'),
    ('akamai', 'server', 'akamaighost'),
    ('imperva', 'cookie', 'incap_ses'),
    ('imperva-visid', 'cookie', 'visid_incap'),
    ('aws-waf', 'header', 'x-amzn-waf'),
    ('f5-bigip', 'cookie', 'bigipserver'),
    ('sucuri', 'header', 'x-sucuri-id'),
    ('modsecurity', 'server', 'mod_security'),
    ('barracuda', 'cookie', 'barra_counter_session'),
    ('fastly', 'header', 'x-fastly-request-id'),
    ('azure-frontdoor', 'header', 'x-azure-ref'),
)


def detect(headers: dict[str, str], body: str, status: int) -> list[str]:
    """Names of WAF signatures present in one response."""
    lowered = {key.lower(): str(value).lower() for key, value in headers.items()}
    cookie = lowered.get('cookie', '')
    found: list[str] = []
    for name, where, pattern in SIGNATURES:
        if where == 'server' and pattern in lowered.get('server', ''):
            found.append(name)
        elif where == 'cookie' and pattern in cookie:
            found.append(name)
        elif where == 'header' and any(pattern in key for key in lowered):
            found.append(name)
    text = (body or '').lower()
    if status in (403, 406, 429) and any(word in text for word in ('blocked', 'access denied', 'security policy', 'captcha')):
        found.append('generic-block-page')
    return sorted(set(found))


class WafDetectAdapter(TestAdapter):
    name = 'waf_detect'
    tier = 'active'
    target_kinds = ('web',)
    description = 'Fingerprints the WAF/CDN in front of the asset from one benign request.'

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        target = ctx.target or asset.target
        await ctx.rate_limiter.acquire()
        async with httpx.AsyncClient(base_url=target, timeout=httpx.Timeout(10.0), follow_redirects=False,
                                     trust_env=False, verify=True, headers=ctx.auth_headers or None) as client:
            try:
                response = await client.get('/', params={'argus_probe': 'waf-detect'})
            except httpx.HTTPError:
                return []
        names = detect(dict(response.headers), response.text[:20_000], response.status_code)
        if not names:
            return []
        return [NormalizedFinding(
            rule='waf:detected', title=f'WAF/CDN detected: {", ".join(names[:3])}',
            description='The edge returns signatures for: ' + ', '.join(names) + '. Treat 403/406 responses to payloads '
                        'as "possibly blocked", not as "not vulnerable", and test through an authenticated browser '
                        'session where the WAF allows it.',
            remediation='Keep the WAF; verify it is not the only control in front of the application.',
            severity='informational',
            evidence={'signatures': names[:6], 'status': response.status_code})]


register(WafDetectAdapter())
