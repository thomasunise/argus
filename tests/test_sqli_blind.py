"""Blind and time-based SQL injection detection."""
from __future__ import annotations

import httpx
import pytest
import respx

from app.testing.adapters import payload_fuzz, sqli_blind
from tests.test_testing_adapters import _asset, _ctx, _scope

TARGET = 'https://app.example.test'
ANY = r'^https://app\.example\.test/.*$'


def test_response_difference_is_length_or_status():
    assert sqli_blind.responses_differ((200, 'x' * 100, 0.1), (200, 'x' * 90, 0.1)) is False
    assert sqli_blind.responses_differ((200, 'x' * 100, 0.1), (200, 'y' * 10, 0.1)) is True
    assert sqli_blind.responses_differ((200, 'same', 0.1), (500, 'same', 0.1)) is True


@pytest.mark.asyncio
@respx.mock
async def test_boolean_difference_is_reported_through_the_adapter(settings):
    big = 'welcome admin ' + ('x' * 4000)
    small = 'denied'

    def handler(request):
        value = request.url.params.get('q', '')
        if "1'='1" in value or '1=1' in value:
            return httpx.Response(200, text=big)
        if "1'='2" in value or '1=2' in value:
            return httpx.Response(200, text=small)
        return httpx.Response(200, text='home page')

    respx.route(method='GET', url__regex=ANY).mock(side_effect=handler)
    findings = await payload_fuzz.PayloadFuzzAdapter().run({}, _asset('web', TARGET), _scope(),
                                                          _ctx(settings, target=TARGET, tier='intrusive'))
    assert any(f.rule == 'fuzz:sqli-blind:q' for f in findings)
    blind = next(f for f in findings if f.rule == 'fuzz:sqli-blind:q')
    assert blind.severity == 'high'


@pytest.mark.asyncio
@respx.mock
async def test_time_delay_is_reported(settings, monkeypatch):
    ticks = {'value': 0.0}

    def slow_clock():
        ticks['value'] += 10.0
        return ticks['value']

    monkeypatch.setattr(sqli_blind, 'CLOCK', slow_clock)
    respx.route(method='GET', url__regex=ANY).mock(return_value=httpx.Response(200, text='ok'))
    findings = await payload_fuzz.PayloadFuzzAdapter().run({}, _asset('web', TARGET), _scope(),
                                                          _ctx(settings, target=TARGET, tier='intrusive'))
    assert any(f.rule == 'fuzz:sqli-time:q' for f in findings)
    timed = next(f for f in findings if f.rule == 'fuzz:sqli-time:q')
    assert timed.severity == 'critical' and timed.evidence['elapsed_seconds'] >= 2.5


@pytest.mark.asyncio
@respx.mock
async def test_a_stable_endpoint_produces_no_blind_finding(settings):
    respx.route(method='GET', url__regex=ANY).mock(return_value=httpx.Response(200, text='identical body'))
    findings = await payload_fuzz.PayloadFuzzAdapter().run({}, _asset('web', TARGET), _scope(),
                                                          _ctx(settings, target=TARGET, tier='intrusive'))
    assert [f for f in findings if f.rule.startswith('fuzz:sqli-')] == []
