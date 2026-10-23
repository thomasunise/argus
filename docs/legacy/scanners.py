"""Deliberately limited scanners: HTTPS read-only baseline and local Trivy filesystem scans.
No arbitrary commands, exploit templates, lateral movement, or network enumeration."""
from __future__ import annotations

import asyncio
import json
import shutil
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from .config import Settings
from .policy import PolicyDenied, validate_repo_target, validate_web_target

HEADERS = [
    ('strict-transport-security', 'HSTS not configured', 'medium', 'Configure an appropriate Strict-Transport-Security policy.'),
    ('content-security-policy', 'Content Security Policy missing', 'medium', 'Define and test a restrictive Content-Security-Policy appropriate for the application.'),
    ('x-content-type-options', 'MIME-sniffing protection missing', 'low', 'Send X-Content-Type-Options: nosniff.'),
    ('referrer-policy', 'Referrer policy missing', 'low', 'Set a privacy-conscious Referrer-Policy.'),
]


async def tls_days_remaining(url: str) -> int:
    """A verified TLS handshake; never disable CA/hostname verification."""
    parsed = urlsplit(url)
    hostname, port = parsed.hostname, parsed.port or 443

    def inspect():
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as wrapped:
                expiry_str = wrapped.getpeercert().get('notAfter')
                if not expiry_str:
                    raise ValueError('TLS certificate missing expiration')
                expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry_str), tz=timezone.utc)
                return (expiry - datetime.now(timezone.utc)).days

    return await asyncio.to_thread(inspect)


async def web_baseline_scan(target: str, settings: Settings) -> list[dict]:
    url = validate_web_target(target, settings)
    findings = []
    try:
        days = await tls_days_remaining(url)
        if days < 30:
            findings.append(dict(rule='tls-expiration', title='TLS certificate expires soon',
                                 description=f'Certificate expires in approximately {days} days.',
                                 remediation='Renew the TLS certificate and verify automatic renewal.',
                                 severity_name='high' if days < 7 else 'medium', evidence={'days_left': days}))
    except (ssl.SSLError, OSError, ValueError) as exc:
        findings.append(dict(rule='tls-trust', title='TLS validation failed',
                             description=f'A verified TLS connection could not be established ({type(exc).__name__}).',
                             remediation='Check TLS certificate validity, trust chain, and hostname configuration.',
                             severity_name='high', evidence={'failure_type': type(exc).__name__}))
    # No redirects and no proxy environment variables. Egress filtering is still mandatory in production.
    async with httpx.AsyncClient(follow_redirects=False, trust_env=False, timeout=httpx.Timeout(10.0),
                                 verify=True, limits=httpx.Limits(max_connections=1)) as client:
        async with client.stream('HEAD', url) as response:
            if response.status_code in {405, 501}:
                async with client.stream('GET', url) as fallback:
                    headers = dict(fallback.headers)
                    status = fallback.status_code
            else:
                headers = dict(response.headers)
                status = response.status_code
    for header, title, level, remediation in HEADERS:
        if header not in headers:
            findings.append(dict(rule=f'header:{header}', title=title,
                                 description=f'HTTPS response status {status} did not include {header}.',
                                 remediation=remediation, severity_name=level,
                                 evidence={'status': status, 'missing_header': header}))
    if headers.get('x-content-type-options', '').lower() not in {'nosniff', ''}:
        findings.append(dict(rule='header:xcto-value', title='Invalid X-Content-Type-Options value',
                             description='The X-Content-Type-Options response header is not nosniff.',
                             remediation='Set X-Content-Type-Options to nosniff.', severity_name='low',
                             evidence={'header': 'x-content-type-options'}))
    return findings


async def trivy_repo_scan(target: str, settings: Settings) -> dict:
    if not settings.enable_trivy:
        raise PolicyDenied('Trivy disabled')
    if not shutil.which('trivy'):
        raise RuntimeError('Trivy executable not installed in the worker')
    path = validate_repo_target(target, settings)
    process = await asyncio.create_subprocess_exec(
        'trivy', 'fs', '--format', 'json', '--scanners', 'vuln,misconfig,secret',
        '--skip-db-update', '--skip-java-db-update', '--quiet', str(path),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp', 'TRIVY_NO_PROGRESS': 'true'},
    )
    try:
        out, err = await asyncio.wait_for(process.communicate(), timeout=120)
    except TimeoutError:
        process.kill()
        await process.communicate()
        raise RuntimeError('Trivy scan exceeded 120-second limit')
    if len(out) > 12_000_000:
        raise RuntimeError('Trivy output exceeds allowed size')
    if process.returncode != 0:
        raise RuntimeError(f'Trivy failed with exit code {process.returncode}; verify the vulnerability DB is available')
    try:
        return json.loads(out)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError('Trivy returned invalid JSON') from exc
