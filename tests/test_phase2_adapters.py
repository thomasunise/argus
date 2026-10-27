"""Phase 2 coverage adapters: nmap_sv, ffuf_dir, param_mine, retire_js, trufflehog_verify."""
from __future__ import annotations

import json
import httpx
import pytest
import respx

from app.core.errors import ScopeDenied
from app.pentest.orchestrator import derive_followups
from app.testing.adapters import ffuf_dir, nmap_sv, param_mine, retire_js, trufflehog_verify
from scripts import update_retirejs_db
from tests.test_testing_adapters import _asset, _ctx, _scope

TARGET = 'https://app.example.test'
ANY = r'^https://app\.example\.test/.*$'


# ---- 1. nmap_sv ------------------------------------------------------------

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV -oX - app.example.test">
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.10">
          <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open" reason="syn-ack"/>
        <service name="redis" product="Redis key-value store" version="7.0.5"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed" reason="reset"/>
        <service name="mysql"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_sv_parse_xml_and_validation():
    findings = nmap_sv.parse_xml(SAMPLE_NMAP_XML)
    by_rule = {f.rule: f for f in findings}
    assert set(by_rule) == {'nmap:22:ssh', 'nmap:443:https', 'nmap:6379:redis'}
    assert by_rule['nmap:6379:redis'].severity == 'high'
    assert by_rule['nmap:22:ssh'].severity == 'medium'
    assert by_rule['nmap:443:https'].severity == 'low'
    assert by_rule['nmap:22:ssh'].evidence['cpe'] == ['cpe:/a:openbsd:openssh:8.9p1']

    assert nmap_sv.extract_host('https://app.example.test:8443/path') == 'app.example.test'
    assert nmap_sv.safe_ports('22,80,443,8000-8080') == '22,80,443,8000-8080'
    with pytest.raises(ScopeDenied):
        nmap_sv.extract_host('--script=evil')
    with pytest.raises(ScopeDenied):
        nmap_sv.safe_ports('80,--script=vuln')
    with pytest.raises(ScopeDenied):
        nmap_sv.parse_xml('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><nmaprun/>')


@pytest.mark.asyncio
async def test_nmap_sv_run_and_chaining(settings, monkeypatch):
    seen = {}

    async def fake_run_tool(argv, timeout, cwd=None, env=None, stdin=None):
        seen['argv'] = argv
        return 0, SAMPLE_NMAP_XML, ''

    monkeypatch.setattr(nmap_sv, 'run_tool', fake_run_tool)
    findings = await nmap_sv.NmapSvAdapter().run(
        {'ports': '22,443,6379'}, _asset('web', TARGET), _scope(), _ctx(settings, target=TARGET, tier='active')
    )
    assert '-p' in seen['argv'] and '22,443,6379' in seen['argv']
    assert len(findings) == 3
    followups = derive_followups([{'adapter': 'nmap_sv', 'evidence': findings[0].evidence}])
    assert any(f['adapter'] == 'nuclei' and f['params'] == {'templates': 'ssh'} for f in followups)


# ---- 2. ffuf_dir -----------------------------------------------------------

def test_ffuf_dir_clusters_soft_404s_and_keeps_unique_hits():
    # 6 soft-404 responses with identical (status=200, words=42, lines=10) + 2 real endpoints
    soft_404s = [
        {'input': {'FUZZ': f'fake{i}'}, 'url': f'{TARGET}/fake{i}', 'status': 200, 'length': 512, 'words': 42, 'lines': 10}
        for i in range(6)
    ]
    real_hits = [
        {'input': {'FUZZ': '.env'}, 'url': f'{TARGET}/.env', 'status': 200, 'length': 128, 'words': 8, 'lines': 6, 'content-type': 'text/plain'},
        {'input': {'FUZZ': 'admin'}, 'url': f'{TARGET}/admin', 'status': 403, 'length': 90, 'words': 11, 'lines': 3, 'content-type': 'text/html'},
    ]
    findings = ffuf_dir.parse_report({'results': soft_404s + real_hits})
    rules = {f.rule: f for f in findings}
    assert set(rules) == {'ffuf:exposed:/.env', 'ffuf:protected:/admin'}
    assert rules['ffuf:exposed:/.env'].severity == 'high'
    assert rules['ffuf:exposed:/.env'].evidence['endpoint'] == '/.env'
    assert rules['ffuf:protected:/admin'].severity == 'low'


@pytest.mark.asyncio
async def test_ffuf_dir_run_and_chaining(settings, monkeypatch):
    report = json.dumps({
        'results': [
            {'input': {'FUZZ': 'api/v1'}, 'url': f'{TARGET}/api/v1', 'status': 200, 'length': 240, 'words': 19, 'lines': 4},
        ]
    })
    seen = {}

    async def fake_run_tool(argv, timeout, cwd=None, env=None, stdin=None):
        seen['argv'] = argv
        out_path = argv[argv.index('-o') + 1]
        with open(out_path, 'w', encoding='utf-8') as fh:
            fh.write(report)
        return 0, '', ''

    monkeypatch.setattr(ffuf_dir, 'run_tool', fake_run_tool)
    findings = await ffuf_dir.FfufDirAdapter().run(
        {'recursion_depth': 1}, _asset('web', TARGET), _scope(max_rps=7), _ctx(settings, target=TARGET, tier='active')
    )
    assert '-recursion' in seen['argv'] and '-ac' in seen['argv']
    assert len(findings) == 1 and findings[0].evidence['endpoint'] == '/api/v1'
    followups = derive_followups([{'adapter': 'ffuf_dir', 'evidence': findings[0].evidence}])
    assert {f['adapter'] for f in followups} == {'param_mine', 'payload_fuzz'}


# ---- 3. param_mine ---------------------------------------------------------

def test_param_mine_parses_arjun_json():
    raw = json.dumps({'https://app.example.test/api/search': {'params': ['debug', 'page'], 'method': 'GET'}})
    findings = param_mine.parse_arjun_report(raw)
    by_param = {f.evidence['parameter']: f for f in findings}
    assert set(by_param) == {'debug', 'page'}
    assert by_param['debug'].severity == 'medium'
    assert by_param['page'].severity == 'low'


@pytest.mark.asyncio
@respx.mock
async def test_param_mine_discovers_reflected_and_differential_params(settings):
    def handler(request: httpx.Request):
        q = dict(request.url.params)
        if 'debug' in q:
            # Mirrors value in response
            return httpx.Response(200, text=f'<html>debug mode: {q["debug"]}</html>')
        if 'admin' in q:
            # Status shift vs 200 baseline
            return httpx.Response(403, text='<html>Forbidden admin parameter</html>')
        return httpx.Response(200, text='<html>normal page body with standard words</html>')

    respx.route(method='GET', url__regex=ANY).mock(side_effect=handler)
    findings = await param_mine.ParamMineAdapter().run(
        {'endpoints': ['/profile'], 'params': ['debug', 'admin', 'unused1', 'unused2'], 'chunk_size': 2},
        _asset('web', TARGET), _scope(), _ctx(settings, target=TARGET, tier='active'),
    )
    discovered = {f.evidence['parameter']: f.evidence for f in findings}
    assert 'debug' in discovered and discovered['debug']['reflected'] is True
    assert 'admin' in discovered and 'status_change' in discovered['admin']['reason']
    followups = derive_followups([{'adapter': 'param_mine', 'evidence': discovered['debug']}])
    assert followups and followups[0]['adapter'] == 'payload_fuzz'
    assert followups[0]['params'] == {'endpoints': ['/profile'], 'params': ['debug']}


# ---- 4. retire_js ----------------------------------------------------------

def test_retire_js_db_and_updater_script():
    assert update_retirejs_db.main(['--verify-only']) == 0
    db = retire_js.load_db()
    assert len(db) >= 20
    assert retire_js.version_in_range('3.4.1', below='3.5.0', at_or_above='1.2.0') is True
    assert retire_js.version_in_range('3.5.0', below='3.5.0', at_or_above='1.2.0') is False
    nf = retire_js.evaluate_library('handlebars', '4.7.6', source='/vendor.js', db=db)
    assert nf is not None and nf.severity == 'critical' and 'CVE-2021-23369' in nf.cve_ids


@pytest.mark.asyncio
@respx.mock
async def test_retire_js_scans_web_bundles_and_repo(settings):
    html = '<html><script src="/static/axios-0.21.1.min.js"></script><script>/*! DOMPurify 2.3.0 */</script></html>'

    def handler(request: httpx.Request):
        if request.url.path == '/':
            return httpx.Response(200, text=html)
        if request.url.path == '/static/axios-0.21.1.min.js':
            return httpx.Response(200, text='// axios v0.21.1 bundle')
        return httpx.Response(404)

    respx.route(method='GET', url__regex=ANY).mock(side_effect=handler)
    web_findings = await retire_js.RetireJsAdapter().run({}, _asset('web', TARGET), _scope(), _ctx(settings, target=TARGET))
    libs = {f.evidence['library']: f for f in web_findings}
    assert 'axios' in libs and 'CVE-2021-3749' in libs['axios'].cve_ids
    assert 'dompurify' in libs and 'CVE-2022-25887' in libs['dompurify'].cve_ids

    # Repo scan (package.json + JS file)
    repo_dir = settings.scan_root / 'frontend-repo'
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / 'package.json').write_text(json.dumps({'dependencies': {'lodash': '^4.17.15'}}), encoding='utf-8')
    (repo_dir / 'vendor.js').write_text('/*! jQuery v3.3.1 */', encoding='utf-8')
    repo_findings = await retire_js.RetireJsAdapter().run({}, _asset('repo', 'frontend-repo'), _scope(), _ctx(settings))
    repo_libs = {f.evidence['library'] for f in repo_findings}
    assert {'lodash', 'jquery'} <= repo_libs


# ---- 5. trufflehog_verify --------------------------------------------------

def test_trufflehog_parse_jsonl_never_stores_raw_secret():
    raw_secret = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz'
    line = json.dumps({
        'DetectorName': 'GitHub',
        'Verified': True,
        'Raw': raw_secret,
        'SourceMetadata': {'Data': {'Filesystem': {'file': 'src/config.py', 'line': 19}}},
    })
    findings = trufflehog_verify.parse_jsonl(line)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == 'critical' and f.evidence['verified'] is True
    assert raw_secret not in json.dumps(f.evidence) and raw_secret not in f.title and raw_secret not in f.description
    assert f.evidence['sample'] == 'ghp_****' and len(f.evidence['fingerprint']) == 16


@pytest.mark.asyncio
@respx.mock
async def test_trufflehog_verify_web_live_verification(settings):
    gh_token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    html = f'<html><script>const token = "{gh_token}";</script></html>'
    respx.get('https://app.example.test/').mock(return_value=httpx.Response(200, text=html))
    respx.get('https://api.github.com/user').mock(return_value=httpx.Response(200, json={'login': 'octocat'}))

    findings = await trufflehog_verify.TrufflehogVerifyAdapter().run(
        {'verify': True}, _asset('web', TARGET), _scope(), _ctx(settings, target=TARGET, tier='active')
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == 'critical'
    assert f.evidence['verified'] is True
    assert f.evidence['verification_detail'] == 'github_user:octocat'
    assert gh_token not in json.dumps(f.evidence)
