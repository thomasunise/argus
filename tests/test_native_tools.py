"""Native testing tools at Strix-toolkit parity: path discovery, JS analysis, JWT checks, ports."""
from __future__ import annotations

import base64
import json
import time

import httpx
import pytest
import respx

from app.testing.adapters import dir_probe, js_analyze, jwt_analyze, port_probe
from tests.test_testing_adapters import _asset, _ctx, _scope

TARGET = 'https://app.example.test'
ANY = r'^https://app\.example\.test/.*$'


# ---- path discovery --------------------------------------------------------


def test_dir_probe_classifies_paths():
    assert dir_probe.classify('/.git/config', 200).severity == 'high'
    assert dir_probe.classify('/admin', 200).severity == 'medium'
    assert dir_probe.classify('/admin', 401).severity == 'low'
    assert dir_probe.classify('/nothing', 404) is None
    assert dir_probe.classify('/boom', 500) is None


@pytest.mark.asyncio
@respx.mock
async def test_dir_probe_finds_an_exposed_vcs_path(settings):
    def handler(request):
        return httpx.Response(200, text='[core]') if request.url.path == '/.git/config' else httpx.Response(404)

    respx.route(method='GET', url__regex=ANY).mock(side_effect=handler)
    findings = await dir_probe.DirProbeAdapter().run({}, _asset('web', TARGET), _scope(),
                                                     _ctx(settings, target=TARGET, tier='active'))
    assert [f.rule for f in findings] == ['path-exposed:/.git/config']
    assert findings[0].severity == 'high'


# ---- javascript analysis ---------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_js_analyze_finds_secrets_and_endpoints(settings):
    html = '<html><script src="/app.js"></script></html>'
    bundle = 'const k="AKIAABCDEFGHIJKLMNOP"; fetch("/api/users");'

    def handler(request):
        if request.url.path == '/':
            return httpx.Response(200, text=html, headers={'content-type': 'text/html'})
        if request.url.path == '/app.js':
            return httpx.Response(200, text=bundle)
        return httpx.Response(404)

    respx.route(method='GET', url__regex=ANY).mock(side_effect=handler)
    findings = await js_analyze.JsAnalyzeAdapter().run({}, _asset('web', TARGET), _scope(),
                                                       _ctx(settings, target=TARGET))
    rules = {f.rule for f in findings}
    assert 'js:secret:aws_access_key' in rules and 'js:endpoints' in rules

    secret = next(f for f in findings if f.rule == 'js:secret:aws_access_key')
    assert 'AKIAABCDEFGHIJKLMNOP' not in json.dumps(secret.evidence)  # the secret is never stored
    assert secret.evidence['sample'].startswith('AKIA')

    endpoints = next(f for f in findings if f.rule == 'js:endpoints')
    assert '/api/users' in endpoints.evidence['paths']


def test_js_helpers_ignore_assets_and_dedupe():
    assert js_analyze.extract_paths('"/a.png" "/api/x" "/api/x"') == ['/api/x']
    assert js_analyze.script_urls('<script src="https://cdn.other/x.js"></script>', 'https://app.example.test/') == []


# ---- jwt analysis ----------------------------------------------------------


def _b64(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')


def _token(header: dict, payload: dict) -> str:
    return f'{_b64(header)}.{_b64(payload)}.signature'


def test_jwt_analysis_flags_none_and_expiry():
    unsigned = _token({'alg': 'none'}, {'sub': '1'})
    rules = {f.rule for f in jwt_analyze.analyze(unsigned)}
    assert 'jwt:alg-none' in rules and 'jwt:no-expiry' in rules

    expired = _token({'alg': 'HS256'}, {'exp': time.time() - 60})
    assert 'jwt:expired-issued' in {f.rule for f in jwt_analyze.analyze(expired)}

    long_lived = _token({'alg': 'HS256'}, {'exp': time.time() + 60 * 86400})
    assert 'jwt:long-lived' in {f.rule for f in jwt_analyze.analyze(long_lived)}

    healthy = _token({'alg': 'HS256'}, {'exp': time.time() + 3600})
    assert jwt_analyze.analyze(healthy) == []


@pytest.mark.asyncio
@respx.mock
async def test_jwt_adapter_reads_the_set_cookie(settings):
    token = _token({'alg': 'none'}, {'sub': '1'})
    respx.route(method='GET', url__regex=ANY).mock(
        return_value=httpx.Response(200, text='ok', headers={'set-cookie': f'session={token}; HttpOnly'}))
    findings = await jwt_analyze.JwtAnalyzeAdapter().run({}, _asset('web', TARGET), _scope(),
                                                        _ctx(settings, target=TARGET, tier='active'))
    assert any(f.rule == 'jwt:alg-none' for f in findings)
    assert token not in json.dumps([f.evidence for f in findings])


# ---- port probe ------------------------------------------------------------


def test_port_findings_only_for_open_ports():
    assert port_probe.finding_for(6379, False) is None
    assert port_probe.finding_for(6379, True).severity == 'high'
    assert port_probe.finding_for(3306, True).severity == 'medium'
    assert port_probe.finding_for(443, True) is None
    assert port_probe.finding_for(8080, True).severity == 'informational'


@pytest.mark.asyncio
async def test_port_probe_scans_and_reports(settings, monkeypatch):
    async def fake_connect(host, port):
        return (port in {443, 6379, 8080}, '-ERR unknown command' if port == 6379 else '')

    monkeypatch.setattr(port_probe, 'connect', fake_connect)
    findings = await port_probe.PortProbeAdapter().run({}, _asset('web', TARGET), _scope(),
                                                      _ctx(settings, target=TARGET, tier='active'))
    rules = {f.rule for f in findings}
    assert rules == {'port:6379:redis', 'port:8080:http-alt'}


def test_tiers_are_the_conservative_ones():
    assert dir_probe.DirProbeAdapter().tier == 'active'
    assert js_analyze.JsAnalyzeAdapter().tier == 'passive'
    assert jwt_analyze.JwtAnalyzeAdapter().tier == 'active'
    assert port_probe.PortProbeAdapter().tier == 'active'
