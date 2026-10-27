"""JWT analysis (active): flags tokens the application hands out that are unsigned or long-lived.

Decodes the tokens a response sets (cookies, headers, JSON bodies) and reports structural problems:
`alg: none`, no expiry, already-expired tokens still being issued, or lifetimes over 30 days. The
token itself is never stored - only a short hash and the decoded claims that matter.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time

import httpx

from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register

TOKEN_RE = re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}')
MAX_TOKENS = 10
LONG_LIVED_SECONDS = 30 * 24 * 3600


def decode_segment(segment: str) -> dict | None:
    padded = segment + '=' * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode('ascii'))
    except (ValueError, TypeError):
        return None
    try:
        value = json.loads(raw.decode('utf-8', 'replace'))
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def analyze(token: str, *, now: float | None = None) -> list[NormalizedFinding]:
    parts = token.split('.')
    if len(parts) < 2:
        return []
    header = decode_segment(parts[0]) or {}
    payload = decode_segment(parts[1]) or {}
    fingerprint = hashlib.sha256(token.encode()).hexdigest()[:12]
    alg = str(header.get('alg') or '').lower()
    evidence = {'token': fingerprint, 'alg': alg or 'none', 'issuer': str(payload.get('iss') or '')[:120]}
    findings: list[NormalizedFinding] = []

    if alg in ('', 'none'):
        findings.append(NormalizedFinding(
            rule='jwt:alg-none', title='JWT issued without a signature',
            description='A token with alg "none" was issued to an unauthenticated client; if any endpoint accepts it, '
                        'authentication is bypassable.',
            remediation='Reject alg "none" in the verifier and pin the expected algorithm.',
            severity='high', evidence=evidence))

    exp = payload.get('exp')
    current = time.time() if now is None else now
    if isinstance(exp, (int, float)):
        remaining = float(exp) - current
        evidence['expires_in_days'] = round(remaining / 86400, 1)
        if remaining < 0:
            findings.append(NormalizedFinding(
                rule='jwt:expired-issued', title='Expired JWT issued to a client',
                description='The token set in this response had already expired, which usually means expiry is not '
                            'validated when issuing or refreshing.',
                remediation='Validate exp before issuing and before accepting a token.',
                severity='medium', evidence=evidence))
        elif remaining > LONG_LIVED_SECONDS:
            findings.append(NormalizedFinding(
                rule='jwt:long-lived', title='Long-lived JWT issued',
                description=f'The token is valid for about {int(remaining / 86400)} days; a stolen token stays usable '
                            'for that whole window.',
                remediation='Shorten access-token lifetimes and use refresh tokens with revocation.',
                severity='low', evidence=evidence))
    else:
        findings.append(NormalizedFinding(
            rule='jwt:no-expiry', title='JWT issued without an expiry',
            description='The token carries no exp claim, so it never expires on the server side.',
            remediation='Add a short exp and enforce it during verification.',
            severity='medium', evidence=evidence))
    return findings


def tokens_in(text: str) -> list[str]:
    found: list[str] = []
    for match in TOKEN_RE.finditer(text or ''):
        token = match.group(0)
        if token not in found:
            found.append(token)
    return found[:MAX_TOKENS]


class JwtAnalyzeAdapter(TestAdapter):
    name = 'jwt_analyze'
    tier = 'active'
    target_kinds = ('web',)
    description = 'Decodes JWTs the app issues and flags unsigned, expired or over-long-lived tokens.'

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        target = ctx.target or asset.target
        findings: list[NormalizedFinding] = []
        async with httpx.AsyncClient(base_url=target, timeout=httpx.Timeout(10.0), follow_redirects=False,
                                     trust_env=False, verify=True, limits=httpx.Limits(max_connections=2),
                                     headers=ctx.auth_headers or None) as client:
            await ctx.rate_limiter.acquire()
            try:
                response = await client.get('/')
            except httpx.HTTPError:
                return findings
        text = '\n'.join([str(value) for key, value in response.headers.items() if key.lower() in ('set-cookie', 'authorization')])
        text += '\n' + response.text[:500_000]
        seen: set[str] = set()
        for token in tokens_in(text):
            for finding in analyze(token):
                key = f'{finding.rule}:{finding.evidence.get("token")}'
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)
        return findings


register(JwtAnalyzeAdapter())
