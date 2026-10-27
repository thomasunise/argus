"""Subdomain enumeration (passive): resolves common names under the asset's registered domain.

This never tests a discovered host. The asset authorization covers one host; a subdomain that
resolves is reported as an out-of-scope asset for a human to authorize separately. Enumeration is
DNS-only: 38 names, no brute-force wordlist, no HTTP request.
"""
from __future__ import annotations

import asyncio
import socket

from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register

PREFIXES = (
    'www', 'api', 'app', 'admin', 'dev', 'staging', 'test', 'uat', 'qa', 'git', 'mail', 'vpn',
    'portal', 'dashboard', 'auth', 'sso', 'cdn', 'static', 'assets', 'db', 'redis', 'jenkins',
    'grafana', 'kibana', 'prometheus', 's3', 'backup', 'internal', 'intranet', 'beta', 'demo',
    'docs', 'status', 'support', 'uploads', 'files', 'shop', 'blog',
)
# Registrable-domain approximation: enough to avoid enumerating 'co.uk' as a domain.
SECOND_LEVEL = {'co.uk', 'org.uk', 'com.au', 'net.au', 'co.jp', 'co.nz', 'com.br', 'co.za', 'com.mx'}


def base_domain(host: str) -> str:
    labels = (host or '').lower().strip('.').split('.')
    if len(labels) <= 2:
        return '.'.join(labels)
    if '.'.join(labels[-2:]) in SECOND_LEVEL and len(labels) >= 3:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def resolve(host: str) -> list[str]:
    """Addresses for a name. Empty when it does not resolve."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return []
    return sorted({info[4][0] for info in infos if ':' not in info[4][0]})


class SubdomainEnumAdapter(TestAdapter):
    name = 'subdomain_enum'
    tier = 'passive'
    target_kinds = ('web',)
    description = 'Resolves 38 common subdomains of the asset domain; reports them as out-of-scope hosts.'

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        target = ctx.target or asset.target
        host = target.split('://', 1)[-1].split('/', 1)[0].split(':')[0]
        domain = base_domain(host)
        if not domain or domain.count('.') < 1:
            return []
        findings: list[NormalizedFinding] = []
        for prefix in PREFIXES:
            name = f'{prefix}.{domain}'
            if name == host:
                continue
            addresses = await asyncio.to_thread(resolve, name)
            if not addresses:
                continue
            findings.append(NormalizedFinding(
                rule=f'subdomain:{name}', title=f'Subdomain {name} resolves',
                description=f'{name} resolves to {", ".join(addresses[:3])}. It is outside this test scope, so Argus '
                            'did not send it any traffic. Authorize it as its own asset if it should be tested.',
                remediation='Confirm the host is expected; add it to the inventory and authorize it before testing.',
                severity='informational',
                evidence={'host': name, 'addresses': addresses[:5], 'tested': False}))
        return findings


register(SubdomainEnumAdapter())
