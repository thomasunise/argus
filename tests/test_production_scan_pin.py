"""Native TCP scanner DNS pinning regressions in production mode."""
from __future__ import annotations

import logging
import types

import pytest

from app.testing.adapters import nmap_sv, port_probe, web_baseline
from app.testing.harness import HarnessContext
from app.testing.ratelimit import RateLimiter


def _context(settings):
    async def heartbeat():
        return None
    return HarnessContext(settings=settings, tenant_id='test-tenant', run_id='test-run',
                          heartbeat=heartbeat, rate_limiter=RateLimiter(200),
                          logger=logging.getLogger('argus.tests'), scan_root=settings.scan_root,
                          tier='active', target='https://example.test')


@pytest.mark.asyncio
async def test_nmap_uses_approved_literal_ip_in_production(settings, monkeypatch):
    prod = settings.model_copy(update={'app_env': 'production'})
    monkeypatch.setattr(web_baseline, '_pin_target', lambda host, port, config: '8.8.8.8')
    seen = {}

    async def fake_run(argv, **kwargs):
        seen['argv'] = argv
        return (0, '', '')

    monkeypatch.setattr(nmap_sv, 'run_tool', fake_run)
    asset = types.SimpleNamespace(target='https://example.test')
    await nmap_sv.NmapSvAdapter().run({}, asset, None, _context(prod))
    assert seen['argv'][-1] == '8.8.8.8'
    assert 'example.test' not in seen['argv']


@pytest.mark.asyncio
async def test_port_probe_uses_pinned_ip_for_every_connection(settings, monkeypatch):
    prod = settings.model_copy(update={'app_env': 'production'})
    monkeypatch.setattr(web_baseline, '_pin_target', lambda host, port, config: '8.8.8.8')
    seen = []

    async def fake_connect(host, port):
        seen.append((host, port))
        return False, ''

    monkeypatch.setattr(port_probe, 'connect', fake_connect)
    asset = types.SimpleNamespace(target='https://example.test')
    await port_probe.PortProbeAdapter().run({}, asset, None, _context(prod))
    assert seen
    assert all(host == '8.8.8.8' for host, _ in seen)
