"""Fuzzing adapters: benign parameter probing (active) and curated payloads (intrusive)."""
from __future__ import annotations

import httpx
import pytest
import respx

from app.testing.adapters import param_probe, payload_fuzz
from tests.test_testing_adapters import _asset, _ctx, _scope

TARGET = 'https://app.example.test'
ANY = r'^https://app\.example\.test/.*$'


@pytest.mark.asyncio
@respx.mock
async def test_param_probe_flags_a_reflected_parameter(settings):
    def echo(request):
        marker = request.url.params.get('q', request.url.params.get('search', ''))
        return httpx.Response(200, text=f'<p>{marker}</p>')

    respx.route(method='GET', url__regex=ANY).mock(side_effect=echo)
    findings = await param_probe.ParamProbeAdapter().run({}, _asset('web', TARGET), _scope(),
                                                        _ctx(settings, target=TARGET, tier='active'))
    assert findings and findings[0].rule.startswith('param-reflected:')
    assert findings[0].severity == 'low' and findings[0].evidence['parameter']


@pytest.mark.asyncio
@respx.mock
async def test_param_probe_is_quiet_without_reflection(settings):
    respx.route(method='GET', url__regex=ANY).mock(return_value=httpx.Response(200, text='static page'))
    findings = await param_probe.ParamProbeAdapter().run({}, _asset('web', TARGET), _scope(),
                                                        _ctx(settings, target=TARGET, tier='active'))
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_payload_fuzz_detects_a_sql_error_signature(settings):
    def sqli(request):
        value = request.url.params.get('q', '')
        if "'" in value or '"' in value:
            return httpx.Response(500, text='You have an error in your SQL syntax near ...')
        return httpx.Response(200, text='ok')

    respx.route(method='GET', url__regex=ANY).mock(side_effect=sqli)
    findings = await payload_fuzz.PayloadFuzzAdapter().run({}, _asset('web', TARGET), _scope(),
                                                          _ctx(settings, target=TARGET, tier='intrusive'))
    assert findings and findings[0].rule.startswith('fuzz:sqli:')
    assert findings[0].severity == 'high' and 'syntax' in findings[0].evidence['signature'].lower()


@pytest.mark.asyncio
@respx.mock
async def test_payload_fuzz_detects_unencoded_reflection(settings):
    respx.route(method='GET', url__regex=ANY).mock(
        side_effect=lambda request: httpx.Response(200, text=request.url.params.get('q', '')))
    findings = await payload_fuzz.PayloadFuzzAdapter().run({}, _asset('web', TARGET), _scope(),
                                                          _ctx(settings, target=TARGET, tier='intrusive'))
    assert any(f.rule.startswith('fuzz:xss:') for f in findings)


@pytest.mark.asyncio
@respx.mock
async def test_payload_fuzz_detects_traversal(settings):
    respx.route(method='GET', url__regex=ANY).mock(
        side_effect=lambda request: httpx.Response(200, text='root:x:0:0:root:/root:/bin/bash'))
    findings = await payload_fuzz.PayloadFuzzAdapter().run({}, _asset('web', TARGET), _scope(),
                                                          _ctx(settings, target=TARGET, tier='intrusive'))
    assert any(f.rule.startswith('fuzz:traversal:') and f.severity == 'critical' for f in findings)


@pytest.mark.asyncio
@respx.mock
async def test_payload_fuzz_refuses_below_intrusive(settings):
    route = respx.route(method='GET', url__regex=ANY).mock(return_value=httpx.Response(200, text='root:x:0:0'))
    findings = await payload_fuzz.PayloadFuzzAdapter().run({}, _asset('web', TARGET), _scope(),
                                                          _ctx(settings, target=TARGET, tier='active'))
    assert findings == [] and route.call_count == 0


def test_adapters_are_registered_at_their_tiers():
    assert param_probe.ParamProbeAdapter().tier == 'active'
    assert payload_fuzz.PayloadFuzzAdapter().tier == 'intrusive'
