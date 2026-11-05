"""Passive HTTPS baseline adapter.

Ports the legacy read-only header/TLS checks exactly (verified TLS, no redirects, no proxy
env, DNS policy enforced upstream by scope.check) and extends them with cookie flags,
server-header disclosure, CORS wildcard-with-credentials, X-Content-Type-Options, and the
negotiated TLS protocol version. It performs exactly one HEAD (falling back to GET) request
and one TLS handshake; it never follows redirects and never sends a body.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime

import httpx

from ...core.errors import ScopeDenied
from ...core.policy import allowed_ip
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register

# (header, title, severity, remediation) — mirrors the legacy list.
MISSING_HEADERS = [
    ('strict-transport-security', 'HSTS not configured', 'medium',
     'Configure an appropriate Strict-Transport-Security policy.'),
    ('content-security-policy', 'Content Security Policy missing', 'medium',
     'Define and test a restrictive Content-Security-Policy appropriate for the application.'),
    ('x-content-type-options', 'MIME-sniffing protection missing', 'low',
     'Send X-Content-Type-Options: nosniff.'),
    ('referrer-policy', 'Referrer policy missing', 'low',
     'Set a privacy-conscious Referrer-Policy.'),
    ('x-frame-options', 'Clickjacking protection missing', 'low',
     'Set X-Frame-Options: DENY or a frame-ancestors CSP directive.'),
]

WEAK_TLS = {'TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'}


def _tls_inspect(hostname: str, port: int, pinned_address: str | None = None) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((pinned_address or hostname, port), timeout=6) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as wrapped:
            cert = wrapped.getpeercert() or {}
            expiry_str = cert.get('notAfter')
            days = None
            if isinstance(expiry_str, str) and expiry_str:
                expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry_str), tz=UTC)
                days = (expiry - datetime.now(UTC)).days
            return {'version': wrapped.version(), 'days_left': days}


def _pin_target(hostname: str, port: int, settings) -> str:
    """Pin production traffic to approved DNS answers. Deny any mixed unsafe IPs."""
    try:
        addresses = {str(entry[4][0]) for entry in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ScopeDenied('Could not resolve scan target') from exc
    if not addresses or any(not allowed_ip(ip, settings) for ip in addresses):
        raise ScopeDenied('Scan target resolves outside authorized IP ranges')
    return sorted(addresses)[0]


class WebBaselineAdapter(TestAdapter):
    name = 'web_baseline'
    tier = 'passive'
    target_kinds = ('web',)
    description = 'Passive HTTPS security-header and TLS baseline (read-only, no redirects).'

    def available(self, settings) -> bool:
        return True

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        url = ctx.target or asset.target
        host = httpx.URL(url).host
        port = httpx.URL(url).port or 443
        findings: list[NormalizedFinding] = []
        # Pin the TCP destination for both the HTTP request and certificate check,
        # keeping the original hostname for Host and TLS SNI verification.
        pin = _pin_target(host, port, ctx.settings) if ctx.settings.is_production else None
        request_url = str(httpx.URL(url).copy_with(host=pin)) if pin else url
        host_header = f'{host}:{port}' if port != 443 else host
        pin_kwargs: dict = {'headers': {'Host': host_header}, 'extensions': {'sni_hostname': host}} if pin else {}

        # Acquire capacity before performing any network I/O (including TLS).
        await ctx.rate_limiter.acquire()
        # --- TLS handshake (verified; never disables CA/hostname verification) ---
        try:
            tls = (await asyncio.to_thread(_tls_inspect, host, port, pin) if pin
                   else await asyncio.to_thread(_tls_inspect, host, port))
            days = tls.get('days_left')
            if days is not None and days < 30:
                findings.append(NormalizedFinding(
                    rule='tls-expiration', title='TLS certificate expires soon',
                    description=f'Certificate expires in approximately {days} days.',
                    remediation='Renew the TLS certificate and verify automatic renewal.',
                    severity='high' if days < 7 else 'medium', evidence={'days_left': days}))
            version = tls.get('version') or ''
            if version in WEAK_TLS:
                findings.append(NormalizedFinding(
                    rule='tls-version', title='Weak TLS protocol negotiated',
                    description=f'The server negotiated {version}, which is deprecated.',
                    remediation='Disable TLS 1.1 and earlier; require TLS 1.2 or 1.3.',
                    severity='high', evidence={'tls_version': version}))
        except (ssl.SSLError, OSError, ValueError) as exc:
            findings.append(NormalizedFinding(
                rule='tls-trust', title='TLS validation failed',
                description=f'A verified TLS connection could not be established ({type(exc).__name__}).',
                remediation='Check TLS certificate validity, trust chain, and hostname configuration.',
                severity='high', evidence={'failure_type': type(exc).__name__}))

        # A second request must not evade the scope's request rate limit.
        await ctx.rate_limiter.acquire()
        # --- a single read-only HTTP response (HEAD, GET fallback) ---
        async with httpx.AsyncClient(follow_redirects=False, trust_env=False, timeout=httpx.Timeout(10.0),
                                     verify=True, limits=httpx.Limits(max_connections=1)) as client:
            async with client.stream('HEAD', request_url, **pin_kwargs) as response:
                if response.status_code in {405, 501}:
                    await ctx.rate_limiter.acquire()
                    async with client.stream('GET', request_url, **pin_kwargs) as fallback:
                        headers, status = fallback.headers, fallback.status_code
                        set_cookies = fallback.headers.get_list('set-cookie')
                else:
                    headers, status = response.headers, response.status_code
                    set_cookies = response.headers.get_list('set-cookie')

        for header, title, level, remediation in MISSING_HEADERS:
            if header not in headers:
                findings.append(NormalizedFinding(
                    rule=f'header:{header}', title=title,
                    description=f'HTTPS response status {status} did not include {header}.',
                    remediation=remediation, severity=level,
                    evidence={'status': status, 'missing_header': header}))

        xcto = headers.get('x-content-type-options', '').lower()
        if xcto and xcto != 'nosniff':
            findings.append(NormalizedFinding(
                rule='header:xcto-value', title='Invalid X-Content-Type-Options value',
                description='The X-Content-Type-Options response header is not nosniff.',
                remediation='Set X-Content-Type-Options to nosniff.', severity='low',
                evidence={'value': xcto}))

        server = headers.get('server', '')
        if server and any(ch.isdigit() for ch in server):
            findings.append(NormalizedFinding(
                rule='header:server-disclosure', title='Server header discloses software version',
                description=f'The Server response header advertises version detail: {server!r}.',
                remediation='Suppress or genericize the Server header to avoid version disclosure.',
                severity='low', evidence={'server': server}))

        # CORS: wildcard origin combined with credentials is an exploitable misconfiguration.
        acao = headers.get('access-control-allow-origin', '')
        acac = headers.get('access-control-allow-credentials', '').lower()
        if acao == '*' and acac == 'true':
            findings.append(NormalizedFinding(
                rule='cors:wildcard-credentials', title='CORS allows any origin with credentials',
                description='Access-Control-Allow-Origin is * while Access-Control-Allow-Credentials is true.',
                remediation='Reflect only explicitly allowed origins when credentials are permitted; never combine * with credentials.',
                severity='high', evidence={'allow_origin': acao, 'allow_credentials': acac}))

        for raw in set_cookies:
            name = raw.split('=', 1)[0].strip()
            low = raw.lower()
            missing = [flag for flag in ('secure', 'httponly') if flag not in low]
            if 'samesite' not in low:
                missing.append('samesite')
            if missing:
                findings.append(NormalizedFinding(
                    rule=f'cookie:{name}', title=f'Cookie {name} missing protective attributes',
                    description=f'Set-Cookie for {name} is missing: {", ".join(missing)}.',
                    remediation='Set Secure, HttpOnly and an appropriate SameSite attribute on session cookies.',
                    severity='medium' if 'secure' in missing or 'httponly' in missing else 'low',
                    evidence={'cookie': name, 'missing': missing}))

        return findings


register(WebBaselineAdapter())
