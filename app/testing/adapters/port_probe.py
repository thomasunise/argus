"""TCP service probe (active): which management and database ports answer on the asset.

A connect-only scan of a small fixed port set: no banners are parsed, no credentials are tried, no
payloads are sent. An open management port on a web asset is worth a finding on its own.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urlsplit

from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register

WEB_PORTS = {80: 'http', 443: 'https', 8080: 'http-alt', 8443: 'https-alt'}
RISKY_PORTS = {
    22: 'ssh', 2375: 'docker', 2376: 'docker-tls', 3306: 'mysql', 3389: 'rdp', 5432: 'postgres',
    5900: 'vnc', 6379: 'redis', 9200: 'elasticsearch', 11211: 'memcached', 27017: 'mongodb',
    5985: 'winrm', 5986: 'winrm-tls',
}
CONNECT_TIMEOUT = 1.5
BANNER_BYTES = 128
_SSH = re.compile(r'^(SSH-([\d.]+)-([\w.\-]+))', re.IGNORECASE)
_HTTP = re.compile(r'^HTTP/[\d.]+\s+\d{3}[^\r\n]*\r?\n(?:.*?\r?\n)*?server:\s*([^\r\n]+)', re.IGNORECASE)
_SMTP = re.compile(r'^220[- ]([^\r\n]{1,80})', re.IGNORECASE)
_REDIS = re.compile(r'^-ERR|^\+OK|^\$\d+', re.IGNORECASE)


def describe_banner(banner: str) -> str:
    """A short service/version string from a volunteered banner, or '' when nothing is recognisable."""
    text = (banner or '').strip()
    if not text:
        return ''
    match = _SSH.match(text)
    if match:
        return f'ssh {match.group(2)} ({match.group(3)[:40]})'
    match = _HTTP.search(text)
    if match:
        return f'http {match.group(1).strip()[:60]}'
    match = _SMTP.match(text)
    if match:
        return f'smtp {match.group(1).strip()[:60]}'
    if _REDIS.match(text):
        return 'redis'
    return text[:60]
TOP_PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1194, 2049, 2181, 2375, 2379, 3000, 3306,
             3389, 5000, 5432, 5601, 5900, 5985, 5986, 6379, 6443, 7001, 8000, 8080, 8081, 8443, 8888,
             9000, 9090, 9200, 9443, 10000, 11211, 27017)
MAX_PORTS = 20


async def connect(host: str, port: int) -> tuple[bool, str]:
    """(open, banner). The banner is whatever the service volunteers; nothing is sent."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return False, ''
    banner = ''
    try:
        raw = await asyncio.wait_for(reader.read(BANNER_BYTES), timeout=1.0)
        banner = raw.decode('utf-8', 'replace').strip()[:120]
    except (OSError, asyncio.TimeoutError):
        banner = ''
    writer.close()
    try:
        await writer.wait_closed()
    except (OSError, RuntimeError):
        pass
    return True, banner


def finding_for(port: int, is_open: bool, banner: str = '') -> NormalizedFinding | None:
    if not is_open:
        return None
    if port in RISKY_PORTS:
        service = RISKY_PORTS[port]
        return NormalizedFinding(
            rule=f'port:{port}:{service}', title=f'{service} port {port} is reachable',
            description=f'A TCP connection to port {port} ({service}) succeeded from the scanner. A web asset that '
                        'exposes a database or management port widens the attack surface considerably.',
            remediation=f'Restrict port {port} to the networks that need it and require authentication.',
            severity='high' if service in {'docker', 'docker-tls', 'redis', 'mongodb', 'elasticsearch', 'memcached'} else 'medium',
            evidence={'port': port, 'service': service, 'banner': banner,
                      'version': describe_banner(banner)})
    if port in WEB_PORTS and port not in (443,):
        return NormalizedFinding(
            rule=f'port:{port}:{WEB_PORTS[port]}', title=f'Alternate web port {port} is reachable',
            description=f'Port {port} ({WEB_PORTS[port]}) answered in addition to the scoped origin.',
            remediation='Close unused web ports or put them behind the same controls as the primary origin.',
            severity='informational', evidence={'port': port, 'service': WEB_PORTS[port], 'banner': banner,
                                                 'version': describe_banner(banner)})
    return None


class PortProbeAdapter(TestAdapter):
    name = 'port_probe'
    tier = 'active'
    target_kinds = ('web',)
    description = 'Connect-only scan of 17 web, database and management ports on the asset host.'

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        target = ctx.target or asset.target
        host = urlsplit(target).hostname or ''
        if not host:
            return []
        ports = sorted(set(WEB_PORTS) | set(RISKY_PORTS))
        if plan_params.get('extended'):
            ports = sorted(set(ports) | set(TOP_PORTS))
        ports = ports[:MAX_PORTS]
        findings: list[NormalizedFinding] = []
        for port in ports:
            await ctx.rate_limiter.acquire()
            is_open, banner = await connect(host, port)
            finding = finding_for(port, is_open, banner)
            if finding is not None:
                findings.append(finding)
        return findings


register(PortProbeAdapter())
