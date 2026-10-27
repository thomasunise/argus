"""Nmap service/version fingerprinting adapter (active): `nmap -sT -sV --version-light -Pn -T4 -oX - <host>`.

Replaces the 17-port connect scan when nmap is installed, identifying real service names, product
banners, versions and CPEs across the top or caller-specified ports so downstream checks can chain
targeted templates against what actually answers.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from ...core.config import Settings
from ...core.errors import ScopeDenied, Unavailable
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register, run_tool

_PORT_SPEC_RE = re.compile(r'^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$')
_HOST_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:\[\]-]{0,253}$')

HIGH_RISK_SERVICES = {
    'docker', 'docker-tls', 'redis', 'mongodb', 'mongod', 'elasticsearch', 'memcached',
    'telnet', 'rexec', 'rlogin', 'microsoft-ds', 'netbios-ssn', 'vnc', 'etcd', 'kubelet',
}
MEDIUM_RISK_SERVICES = {
    'ssh', 'mysql', 'postgresql', 'postgres', 'ms-sql-s', 'oracle', 'rdp', 'ms-wbt-server',
    'winrm', 'wsman', 'ldap', 'ldaps', 'ftp', 'smtp', 'snmp', 'amqp', 'kafka', 'zookeeper',
}
WEB_SERVICES = {'http', 'https', 'http-alt', 'https-alt', 'ssl/http', 'http-proxy'}

DEFAULT_TOP_PORTS = 50
MAX_TOP_PORTS = 200


def extract_host(target: str) -> str:
    """Extract a safe hostname or IP from a URL or host target. Rejects flags and malformed strings."""
    raw = (target or '').strip()
    if '://' in raw:
        host = urlsplit(raw).hostname or ''
    elif raw.startswith('image:'):
        raise ScopeDenied('nmap_sv cannot scan a container image reference')
    else:
        host = raw.split('/')[0].split(':')[0]
    if not host or host.startswith('-') or not _HOST_RE.match(host):
        raise ScopeDenied(f'invalid host target for nmap_sv: {target!r}')
    return host


def safe_ports(value: object) -> str:
    """Validate a comma/range port list (e.g. '22,80,443,8000-8100'). Raises ScopeDenied on bad input."""
    text = str(value or '').strip()
    if not text:
        return ''
    if not _PORT_SPEC_RE.match(text):
        raise ScopeDenied('nmap_sv ports must be comma-separated port numbers or ranges (e.g. 22,80,443,8000-8100)')
    for token in text.split(','):
        lo, _, hi = token.partition('-')
        p1 = int(lo)
        p2 = int(hi) if hi else p1
        if p1 < 1 or p2 > 65535 or p1 > p2:
            raise ScopeDenied(f'port range out of bounds in {token!r}')
    return text


def _severity_for(port: int, service: str, product: str, version: str) -> str | None:
    svc = (service or '').lower()
    if svc in HIGH_RISK_SERVICES or port in {2375, 2376, 6379, 9200, 11211, 27017}:
        return 'high'
    if svc in MEDIUM_RISK_SERVICES or port in {21, 22, 25, 445, 3306, 3389, 5432, 5900, 5985, 5986}:
        return 'medium'
    if svc in WEB_SERVICES or port in {80, 443, 8080, 8443}:
        if product or version:
            return 'low'
        if port != 443:
            return 'informational'
        return None
    return 'medium'


def parse_xml(xml_text: str) -> list[NormalizedFinding]:
    """Parse nmap -oX XML into NormalizedFindings for open ports and fingerprinted services."""
    text = (xml_text or '').strip()
    if not text:
        return []
    upper = text[:4096].upper()
    if '<!DOCTYPE' in upper and '<!ENTITY' in upper:
        raise ScopeDenied('nmap XML with entity declarations is rejected')
    # Strip any standard DOCTYPE line nmap emits before parsing with ElementTree.
    cleaned = re.sub(r'<!DOCTYPE[^>]*>', '', text, count=1)
    try:
        root = ET.fromstring(cleaned)  # nosec B314 - DOCTYPE/ENTITY declarations stripped above
    except ET.ParseError:
        return []

    findings: list[NormalizedFinding] = []
    seen: set[tuple[int, str]] = set()
    for port_el in root.findall('.//host/ports/port'):
        state_el = port_el.find('state')
        if state_el is None or state_el.attrib.get('state') != 'open':
            continue
        try:
            port = int(port_el.attrib.get('portid') or 0)
        except ValueError:
            continue
        protocol = str(port_el.attrib.get('protocol') or 'tcp')
        svc_el = port_el.find('service')
        service = str((svc_el.attrib.get('name') if svc_el is not None else '') or 'unknown').lower()
        product = str((svc_el.attrib.get('product') if svc_el is not None else '') or '').strip()
        version = str((svc_el.attrib.get('version') if svc_el is not None else '') or '').strip()
        extrainfo = str((svc_el.attrib.get('extrainfo') if svc_el is not None else '') or '').strip()
        cpes = [c.text.strip() for c in (svc_el.findall('cpe') if svc_el is not None else []) if c.text and c.text.strip()][:5]
        banner = ''
        for script_el in port_el.findall('script'):
            if script_el.attrib.get('id') in ('banner', 'http-server-header'):
                banner = str(script_el.attrib.get('output') or '')[:200]
                break

        if (port, protocol) in seen:
            continue
        seen.add((port, protocol))

        severity = _severity_for(port, service, product, version)
        if severity is None:
            continue

        version_label = ' '.join(p for p in (product, version) if p).strip()
        title_detail = f'{service} ({version_label})' if version_label else service
        findings.append(NormalizedFinding(
            rule=f'nmap:{port}:{service}',
            title=f'Open {protocol.upper()} port {port}: {title_detail}'[:240],
            description=(
                f'Nmap fingerprinted {protocol.upper()}/{port} as {service}'
                + (f' running {version_label}' if version_label else '')
                + (f' ({extrainfo})' if extrainfo else '')
                + '. Verify that this service is intended to be reachable and patched.'
            )[:2000],
            remediation=f'Restrict network access to port {port} ({service}), suppress version banners where appropriate, and patch {product or service}.',
            severity=severity,
            evidence={
                'port': port,
                'protocol': protocol,
                'service': service,
                'product': product,
                'version': version,
                'extrainfo': extrainfo,
                'cpe': cpes,
                'banner': banner,
            },
        ))
    return findings


class NmapSvAdapter(TestAdapter):
    name = 'nmap_sv'
    tier = 'active'
    target_kinds = ('web', 'host', 'network', 'database')
    description = 'Nmap service and version fingerprinting (-sT -sV) across top or specified ports.'

    def available(self, settings: Settings) -> bool:
        import shutil

        return bool(shutil.which(settings.nmap_bin))

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        settings = ctx.settings
        host = extract_host(ctx.target or asset.target)
        ports = safe_ports(plan_params.get('ports')) if plan_params.get('ports') else ''
        try:
            top_ports = max(1, min(MAX_TOP_PORTS, int(plan_params.get('top_ports') or DEFAULT_TOP_PORTS)))
        except (TypeError, ValueError):
            top_ports = DEFAULT_TOP_PORTS

        argv = [
            settings.nmap_bin, '-sT', '-sV', '--version-light', '-Pn', '-T4',
            '--max-retries', '1', '--host-timeout', '120s',
        ]
        if ports:
            argv += ['-p', ports]
        else:
            argv += ['--top-ports', str(top_ports)]
        argv += ['-oX', '-', host]

        await ctx.rate_limiter.acquire()
        code, out, err = await run_tool(argv, timeout=settings.test_tool_timeout_seconds)
        if not out.strip() and code not in (0,):
            raise Unavailable(f'nmap exited {code} with no XML output')
        return parse_xml(out)


register(NmapSvAdapter())
