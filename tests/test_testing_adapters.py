"""Adapter tests against recorded fixture output. No network, no real tools: subprocess
adapters have run_tool monkeypatched to return/record fixtures; HTTP adapters use respx."""
from __future__ import annotations

import json
import types
from pathlib import Path

import httpx
import pytest
import respx

from app.testing import harness
from app.testing.ratelimit import RateLimiter
from app.testing.adapters import caldera, gitleaks, nuclei, prowler, semgrep, trivy, web_baseline, zap

FIX = Path(__file__).parent / 'fixtures' / 'testing'


def _read(*parts) -> str:
    return (FIX.joinpath(*parts)).read_text(encoding='utf-8')


def _ctx(settings, *, target='', tier='passive'):
    async def _hb():
        return None

    return harness.HarnessContext(settings=settings, tenant_id='t1', run_id='run-123456', heartbeat=_hb,
                                  rate_limiter=RateLimiter(1000), logger=harness.log, scan_root=settings.scan_root,
                                  tier=tier, target=target)


def _asset(kind, target):
    return types.SimpleNamespace(id='a1', name='a', kind=kind, target=target, environment='staging',
                                 criticality='medium', tenant_id='t1')


def _scope(max_rps=5.0):
    return types.SimpleNamespace(id='s1', max_rps=max_rps)


# ------------------------------- parse functions ---------------------------


def test_trivy_parse():
    findings = trivy.parse_report(json.loads(_read('trivy', 'report.json')))
    rules = {f.rule.split(':')[0] for f in findings}
    assert rules == {'vuln', 'misconfig', 'secret'}
    vuln = next(f for f in findings if f.rule.startswith('vuln'))
    assert 'CVE-2023-12345' in vuln.cve_ids and vuln.cvss == 7.5 and vuln.severity == 'high'
    secret = next(f for f in findings if f.rule.startswith('secret'))
    assert 'AKIAIOSFODNN7EXAMPLE' not in json.dumps(secret.evidence) and secret.evidence['line'] == 12


def test_semgrep_parse():
    findings = semgrep.parse_report(json.loads(_read('semgrep', 'report.json')))
    assert len(findings) == 2
    hi = findings[0]
    assert hi.severity == 'high' and hi.evidence['line'] == 42 and hi.evidence['file'] == 'app/runner.py'


def test_gitleaks_parse_never_includes_secret():
    findings = gitleaks.parse_report(json.loads(_read('gitleaks', 'report.json')))
    assert len(findings) == 2
    blob = json.dumps([f.evidence for f in findings])
    assert 'super-secret-value' not in blob and 'AKIAIOSFODNN7EXAMPLE' not in blob
    assert all(f.severity == 'high' and f.evidence['fingerprint'] for f in findings)


def test_nuclei_parse_jsonl():
    findings = nuclei.parse_jsonl(_read('nuclei', 'output.jsonl'))
    assert len(findings) == 2
    crit = next(f for f in findings if f.severity == 'critical')
    assert 'CVE-2021-44228' in crit.cve_ids and crit.cvss == 10.0
    info = next(f for f in findings if f.severity == 'informational')
    assert info.rule == 'nuclei:tech-detect'


def test_zap_parse_dedupes_and_maps_risk():
    findings = zap.ZapAdapter._parse(json.loads(_read('zap', 'alerts.json')))
    assert len(findings) == 2  # the duplicate SQLi alert is collapsed
    sqli = next(f for f in findings if 'SQL Injection' in f.title)
    assert sqli.severity == 'high' and sqli.evidence['param'] == 'q' and sqli.evidence['cwe'] == '89'


def test_prowler_parse_only_failures():
    findings = prowler.parse_report(json.loads(_read('prowler', 'report.json')))
    assert len(findings) == 2  # the PASS check is skipped
    crit = next(f for f in findings if f.severity == 'critical')
    assert crit.evidence['check_id'] == 'iam_root_mfa_enabled'


def test_caldera_parse_only_successful_steps():
    findings = caldera.parse_report(json.loads(_read('caldera', 'report.json')))
    assert len(findings) == 1  # only the status==0 step
    assert findings[0].evidence['technique_id'] == 'T1005' and findings[0].severity == 'high'


# ------------------------------- adapter.run (subprocess mocked) ------------


@pytest.mark.asyncio
async def test_trivy_run(settings, monkeypatch):
    (settings.scan_root / 'repo').mkdir(parents=True, exist_ok=True)
    report = _read('trivy', 'report.json')

    async def fake(argv, timeout, cwd=None, env=None, stdin=None):
        assert argv[0] == settings.trivy_bin and '--format' in argv and 'json' in argv
        return 0, report, ''

    monkeypatch.setattr(trivy, 'run_tool', fake)
    findings = await trivy.TrivyAdapter().run({}, _asset('repo', 'repo'), _scope(), _ctx(settings))
    assert len(findings) == 3


@pytest.mark.asyncio
async def test_trivy_image_host(settings, monkeypatch):
    report = _read('trivy', 'report.json')
    seen = {}

    async def fake(argv, timeout, cwd=None, env=None, stdin=None):
        seen['argv'] = argv
        return 0, report, ''

    monkeypatch.setattr(trivy, 'run_tool', fake)
    findings = await trivy.TrivyAdapter().run({}, _asset('host', 'image:nginx:1.25'), _scope(), _ctx(settings))
    assert 'image' in seen['argv'] and 'nginx:1.25' in seen['argv'] and len(findings) == 3


@pytest.mark.asyncio
async def test_semgrep_run(settings, monkeypatch):
    (settings.scan_root / 'repo').mkdir(parents=True, exist_ok=True)
    report = _read('semgrep', 'report.json')

    async def fake(argv, timeout, cwd=None, env=None, stdin=None):
        return 0, report, ''

    monkeypatch.setattr(semgrep, 'run_tool', fake)
    findings = await semgrep.SemgrepAdapter().run({}, _asset('repo', 'repo'), _scope(), _ctx(settings))
    assert len(findings) == 2


@pytest.mark.asyncio
async def test_nuclei_run_respects_rps(settings, monkeypatch):
    jsonl = _read('nuclei', 'output.jsonl')
    seen = {}

    async def fake(argv, timeout, cwd=None, env=None, stdin=None):
        seen['argv'] = argv
        return 0, jsonl, ''

    monkeypatch.setattr(nuclei, 'run_tool', fake)
    findings = await nuclei.NucleiAdapter().run({}, _asset('web', 'https://app.example.test'),
                                                _scope(max_rps=3), _ctx(settings, target='https://app.example.test', tier='active'))
    assert len(findings) == 2
    i = seen['argv'].index('-rate-limit')
    assert seen['argv'][i + 1] == '3'


@pytest.mark.asyncio
async def test_gitleaks_run_reads_report_file(settings, monkeypatch):
    (settings.scan_root / 'repo').mkdir(parents=True, exist_ok=True)
    report = _read('gitleaks', 'report.json')

    async def fake(argv, timeout, cwd=None, env=None, stdin=None):
        path = argv[argv.index('-r') + 1]
        Path(path).write_text(report, encoding='utf-8')
        return 0, '', ''

    monkeypatch.setattr(gitleaks, 'run_tool', fake)
    findings = await gitleaks.GitleaksAdapter().run({}, _asset('repo', 'repo'), _scope(), _ctx(settings))
    assert len(findings) == 2


@pytest.mark.asyncio
async def test_prowler_run_reads_output_dir(settings, monkeypatch):
    report = _read('prowler', 'report.json')

    async def fake(argv, timeout, cwd=None, env=None, stdin=None):
        out_dir = argv[argv.index('--output-directory') + 1]
        Path(out_dir, 'prowler-output.json').write_text(report, encoding='utf-8')
        return 3, '', ''  # prowler exits 3 when findings exist

    monkeypatch.setattr(prowler, 'run_tool', fake)
    findings = await prowler.ProwlerAdapter().run({'provider': 'aws'}, _asset('cloud_account', 'aws'), _scope(), _ctx(settings))
    assert len(findings) == 2


# ------------------------------- adapter.run (HTTP mocked) ------------------


@pytest.mark.asyncio
async def test_web_baseline_run(settings, monkeypatch):
    monkeypatch.setattr(web_baseline, '_tls_inspect', lambda host, port: {'version': 'TLSv1', 'days_left': 5})
    headers = [('server', 'nginx/1.2.3'), ('access-control-allow-origin', '*'),
               ('access-control-allow-credentials', 'true'), ('set-cookie', 'sid=abc')]
    with respx.mock(assert_all_called=False) as mock:
        mock.route(method='HEAD', host='app.example.test').mock(return_value=httpx.Response(200, headers=headers))
        findings = await web_baseline.WebBaselineAdapter().run(
            {}, _asset('web', 'https://app.example.test'), _scope(), _ctx(settings, target='https://app.example.test'))
    rules = {f.rule for f in findings}
    assert 'tls-expiration' in rules and 'tls-version' in rules
    assert 'cors:wildcard-credentials' in rules and 'header:server-disclosure' in rules
    assert 'header:content-security-policy' in rules and any(r.startswith('cookie:') for r in rules)


@pytest.mark.asyncio
async def test_zap_run_active_skips_ascan(settings, monkeypatch):
    settings = settings.model_copy(update={'zap_url': 'http://zap.local', 'zap_api_key': 'k'})
    alerts = json.loads(_read('zap', 'alerts.json'))
    with respx.mock(base_url='http://zap.local', assert_all_called=False) as mock:
        mock.get('/JSON/spider/action/scan/').mock(return_value=httpx.Response(200, json={'scan': '0'}))
        mock.get('/JSON/spider/view/status/').mock(return_value=httpx.Response(200, json={'status': '100'}))
        ascan = mock.get('/JSON/ascan/action/scan/').mock(return_value=httpx.Response(200, json={'scan': '1'}))
        mock.get('/JSON/core/view/alerts/').mock(return_value=httpx.Response(200, json=alerts))
        findings = await zap.ZapAdapter().run({}, _asset('web', 'https://app.example.test'), _scope(),
                                              _ctx(settings, target='https://app.example.test', tier='active'))
    assert not ascan.called  # active tier runs spider only, never the active scanner
    assert len(findings) == 2


@pytest.mark.asyncio
async def test_zap_run_intrusive_runs_ascan(settings):
    settings = settings.model_copy(update={'zap_url': 'http://zap.local', 'zap_api_key': 'k'})
    alerts = json.loads(_read('zap', 'alerts.json'))
    with respx.mock(base_url='http://zap.local', assert_all_called=False) as mock:
        mock.get('/JSON/spider/action/scan/').mock(return_value=httpx.Response(200, json={'scan': '0'}))
        mock.get('/JSON/spider/view/status/').mock(return_value=httpx.Response(200, json={'status': '100'}))
        ascan = mock.get('/JSON/ascan/action/scan/').mock(return_value=httpx.Response(200, json={'scan': '1'}))
        mock.get('/JSON/ascan/view/status/').mock(return_value=httpx.Response(200, json={'status': '100'}))
        mock.get('/JSON/core/view/alerts/').mock(return_value=httpx.Response(200, json=alerts))
        findings = await zap.ZapAdapter().run({}, _asset('web', 'https://app.example.test'), _scope(),
                                              _ctx(settings, target='https://app.example.test', tier='intrusive'))
    assert ascan.called and len(findings) == 2


@pytest.mark.asyncio
async def test_caldera_run(settings):
    settings = settings.model_copy(update={'caldera_url': 'http://caldera.local', 'caldera_api_key': 'k'})
    report = json.loads(_read('caldera', 'report.json'))
    with respx.mock(base_url='http://caldera.local', assert_all_called=False) as mock:
        mock.post('/api/v2/operations').mock(return_value=httpx.Response(200, json={'id': 'op1'}))
        mock.get('/api/v2/operations/op1').mock(return_value=httpx.Response(200, json={'state': 'finished'}))
        mock.post('/api/v2/operations/op1/report').mock(return_value=httpx.Response(200, json=report))
        findings = await caldera.CalderaAdapter().run({'adversary_id': 'adv1', 'group': 'red'},
                                                      _asset('host', 'red'), _scope(), _ctx(settings, tier='intrusive'))
    assert len(findings) == 1 and findings[0].evidence['technique_id'] == 'T1005'
