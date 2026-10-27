"""Subdomain enumeration, WAF detection, vulnerable JS libraries, and wordlist-driven path discovery."""
from __future__ import annotations

import httpx
import pytest
import respx

from app.testing.adapters import dir_probe, js_libs, subdomain_enum, waf_detect
from tests.test_testing_adapters import _asset, _ctx, _scope

TARGET = 'https://app.example.test'
ANY = r'^https://app\.example\.test/.*$'


# ---- subdomains ------------------------------------------------------------


def test_base_domain_handles_second_level_tlds():
    assert subdomain_enum.base_domain('app.example.com') == 'example.com'
    assert subdomain_enum.base_domain('app.example.co.uk') == 'example.co.uk'
    assert subdomain_enum.base_domain('localhost') == 'localhost'


@pytest.mark.asyncio
async def test_subdomains_are_reported_but_never_tested(settings, monkeypatch):
    def fake_resolve(host):
        return ['203.0.113.20'] if host in ('www.example.test', 'api.example.test') else []

    monkeypatch.setattr(subdomain_enum, 'resolve', fake_resolve)
    findings = await subdomain_enum.SubdomainEnumAdapter().run(
        {}, _asset('web', TARGET), _scope(), _ctx(settings, target=TARGET))
    assert {f.evidence['host'] for f in findings} == {'www.example.test', 'api.example.test'}
    assert all(f.evidence['tested'] is False and f.severity == 'informational' for f in findings)


# ---- WAF -------------------------------------------------------------------


def test_waf_signatures_and_block_pages():
    assert 'cloudflare' in waf_detect.detect({'server': 'cloudflare'}, '', 200)
    assert 'imperva' in waf_detect.detect({'cookie': 'incap_ses_123=abc'}, '', 200)
    assert 'aws-waf' in waf_detect.detect({'x-amzn-waf-action': 'block'}, '', 403)
    assert 'generic-block-page' in waf_detect.detect({}, 'Request blocked by security policy', 403)
    assert waf_detect.detect({'server': 'nginx'}, 'welcome', 200) == []


@pytest.mark.asyncio
@respx.mock
async def test_waf_adapter_reports_the_edge(settings):
    respx.route(method='GET', url__regex=ANY).mock(return_value=httpx.Response(200, text='ok', headers={'server': 'cloudflare'}))
    findings = await waf_detect.WafDetectAdapter().run({}, _asset('web', TARGET), _scope(),
                                                      _ctx(settings, target=TARGET, tier='active'))
    assert findings and findings[0].rule == 'waf:detected'
    assert 'cloudflare' in findings[0].evidence['signatures']


# ---- vulnerable libraries --------------------------------------------------


def test_library_detection_and_thresholds():
    assert js_libs.detect('/*! jQuery v3.4.1 */') == {'jquery': '3.4.1'}
    assert js_libs.vulnerable('jquery', '3.4.1') == ('CVE-2020-11022', 'medium')
    assert js_libs.vulnerable('jquery', '3.5.0') is None
    assert js_libs.vulnerable('lodash', '4.17.20') == ('CVE-2021-23337', 'high')
    assert js_libs.vulnerable('moment', '2.29.4') is None


@pytest.mark.asyncio
@respx.mock
async def test_js_libs_adapter_finds_a_vulnerable_bundle(settings):
    html = '<html><script src="/libs/jquery.min.js"></script></html>'

    def handler(request):
        if request.url.path == '/':
            return httpx.Response(200, text=html, headers={'content-type': 'text/html'})
        return httpx.Response(200, text='/*! jQuery v3.4.1 */')

    respx.route(method='GET', url__regex=ANY).mock(side_effect=handler)
    findings = await js_libs.JsLibsAdapter().run({}, _asset('web', TARGET), _scope(), _ctx(settings, target=TARGET))
    assert findings and findings[0].rule == 'js-lib:jquery:3.4.1'
    assert findings[0].cve_ids == ['CVE-2020-11022']


# ---- wordlist-driven path discovery ---------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_dir_probe_reads_a_wordlist_from_scan_root(settings):
    (settings.scan_root).mkdir(parents=True, exist_ok=True)
    (settings.scan_root / 'words.txt').write_text('# comment\n/secret\nadmin2\n', encoding='utf-8')

    def handler(request):
        return httpx.Response(200, text='ok') if request.url.path in ('/secret', '/admin2') else httpx.Response(404)

    respx.route(method='GET', url__regex=ANY).mock(side_effect=handler)
    findings = await dir_probe.DirProbeAdapter().run({'wordlist': 'words.txt'}, _asset('web', TARGET), _scope(),
                                                     _ctx(settings, target=TARGET, tier='active'))
    assert {f.evidence['path'] for f in findings} == {'/secret', '/admin2'}


def test_wordlist_outside_scan_root_is_ignored(settings, monkeypatch):
    assert dir_probe._from_wordlist('../../etc/passwd', settings) == []
    assert dir_probe._from_wordlist('missing.txt', settings) == []
