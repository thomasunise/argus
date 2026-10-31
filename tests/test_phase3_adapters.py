"""Tests for Phase 3 proof-bounded depth adapters, multi-role credentials, and verified finding wiring."""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from sqlalchemy import select

from app.models import Asset, AssetAuthorization, Finding, dumps
from app.models.testing import TestResult, TestRun, TestScope
from app.pentest.orchestrator import derive_followups
from app.testing import harness
from app.testing.adapters import browser_xss, idor_probe, jwt_attack, sqli_proof
from app.testing.auth import load_role_headers
from tests.test_testing_adapters import _asset, _ctx, _scope


def _intrusive_ctx(settings, *, target: str = 'https://app.example.test',
                   auth_headers: dict | None = None, role_headers: dict | None = None) -> harness.HarnessContext:
    ctx = _ctx(settings, target=target, tier='intrusive')
    ctx.auth_headers = auth_headers or {}
    ctx.role_headers = role_headers or {}
    return ctx


def _patch_async_client(monkeypatch, handler):
    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def _factory(**kwargs):
        kwargs.pop('transport', None)
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr(httpx, 'AsyncClient', _factory)


# ------------------------------------------------------------------ Credential roles

def test_multi_role_credentials_and_load_role_headers(owner, app, default_tenant_id):
    client, headers = owner
    asset = client.post('/api/v1/assets', json={
        'kind': 'web', 'name': 'portal', 'target': 'https://portal.internal.example', 'environment': 'staging',
    }, headers=headers).json()

    r_a = client.post(f'/api/v1/assets/{asset["id"]}/credentials', json={
        'name': 'User A Token', 'kind': 'bearer', 'role': 'user_a', 'value': 'tok-alice-111',
    }, headers=headers)
    assert r_a.status_code == 201, r_a.text
    assert r_a.json()['role'] == 'user_a'

    r_b = client.post(f'/api/v1/assets/{asset["id"]}/credentials', json={
        'name': 'User B Token', 'kind': 'bearer', 'role': 'user_b', 'value': 'tok-bob-222',
    }, headers=headers)
    assert r_b.status_code == 201, r_b.text
    assert r_b.json()['role'] == 'user_b'

    with app.state.db_factory() as db:
        roles = load_role_headers(db, default_tenant_id, asset['id'])
    assert roles['user_a'] == {'Authorization': 'Bearer tok-alice-111'}
    assert roles['user_b'] == {'Authorization': 'Bearer tok-bob-222'}


# ------------------------------------------------------------------ sqli_proof

def test_sqli_proof_sqlmap_output_parser():
    sample = """
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 5123=5123 AND 'a'='a
---
[INFO] the back-end DBMS is PostgreSQL
web application technology: Nginx
back-end DBMS: PostgreSQL
banner: 'PostgreSQL 15.4 on x86_64-pc-linux-gnu'
current database: 'appdb'
current user: 'app_ro'
"""
    findings = sqli_proof.parse_sqlmap_output(sample, endpoint='/items', fallback_param='id')
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == 'sqli-proof:/items:id'
    assert f.severity == 'critical'
    assert f.verified is True
    assert f.evidence['dbms'] == 'PostgreSQL'
    assert 'PostgreSQL 15.4' in f.evidence['banner']
    assert f.evidence['current_db'] == 'appdb'
    assert f.evidence['verified'] is True


def test_sqli_proof_dual_boolean_equivalence(settings, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        val = request.url.params.get('id', '')
        if val in sqli_proof.TRUE_PAIRS:
            return httpx.Response(200, text='<html>Item #1: Widget Pro (PostgreSQL 15.2) - Full details and specifications here.</html>')
        if val in sqli_proof.FALSE_PAIRS:
            return httpx.Response(200, text='<html>No item found.</html>')
        return httpx.Response(200, text='<html>Default</html>')

    _patch_async_client(monkeypatch, handler)
    asset = _asset('web', 'https://shop.example.test')
    adapter = harness.get_adapter('sqli_proof')
    assert adapter is not None

    findings = asyncio.run(adapter.run(
        {'endpoints': ['/item'], 'params': ['id'], 'use_native': True},
        asset, _scope(), _intrusive_ctx(settings, target='https://shop.example.test'),
    ))
    assert len(findings) == 1
    assert findings[0].rule == 'sqli-proof:/item:id'
    assert findings[0].verified is True
    assert findings[0].evidence['dbms'] == 'postgresql'


# ------------------------------------------------------------------ jwt_attack

def test_jwt_attack_weak_secret_and_verification_oracles(settings, monkeypatch):
    header = {'alg': 'HS256', 'typ': 'JWT'}
    payload_b64 = jwt_attack._b64url_encode(json.dumps({'sub': 'u1', 'iss': 'portal'}).encode())
    sample_token = jwt_attack._sign_hmac(header, payload_b64, b'secret')

    # Offline weak secret check
    weak = jwt_attack.check_weak_hmac_secret(sample_token)
    assert weak is not None
    assert weak.rule == 'jwt:weak-secret'
    assert weak.verified is True
    assert sample_token not in json.dumps(weak.evidence)

    # Verification oracle: rejects corrupted signature (401) but accepts alg:none and jwk-injected tokens (200)
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get('authorization', '')
        if not auth.startswith('Bearer '):
            return httpx.Response(200, headers={'Authorization': f'Bearer {sample_token}'}, text='ok')
        tok = auth.removeprefix('Bearer ').strip()
        parts = tok.split('.')
        hdr = jwt_attack.decode_segment(parts[0]) or {}
        if hdr.get('alg') == 'none' and parts[2] == '':
            return httpx.Response(200, text='{"user": "u1"}')
        if 'jwk' in hdr:
            return httpx.Response(200, text='{"user": "u1"}')
        return httpx.Response(401, text='invalid signature')

    _patch_async_client(monkeypatch, handler)
    asset = _asset('web', 'https://api.example.test')
    adapter = harness.get_adapter('jwt_attack')
    assert adapter is not None

    findings = asyncio.run(adapter.run(
        {'endpoint': '/api/me'}, asset, _scope(),
        _intrusive_ctx(settings, target='https://api.example.test'),
    ))
    rules = {f.rule for f in findings}
    assert 'jwt:weak-secret' in rules
    assert 'jwt:alg-none-accepted' in rules
    assert 'jwt:jwk-injection-accepted' in rules
    assert all(f.verified for f in findings)


# ------------------------------------------------------------------ browser_xss

def test_browser_xss_confirms_dom_sink_and_ignores_inert_contexts(settings, monkeypatch):
    nonce = 'argus998877'
    # Safe contexts must NOT be flagged
    assert browser_xss.confirm_dom_sink(f'<!-- "><argus-xss data-canary="{nonce}"> -->', nonce) is None
    assert browser_xss.confirm_dom_sink(f'<textarea>"><argus-xss data-canary="{nonce}"></textarea>', nonce) is None
    assert browser_xss.confirm_dom_sink(f'<div>&quot;&gt;&lt;argus-xss data-canary=&quot;{nonce}&quot;&gt;</div>', nonce) is None

    # Live DOM element breakout MUST be confirmed
    sink = browser_xss.confirm_dom_sink(f'<input value=""><argus-xss data-canary="{nonce}">">', nonce)
    assert sink is not None
    assert sink['sink_type'] == 'dom_element_injection'

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == '/search':
            q = request.url.params.get('q', '')
            return httpx.Response(200, headers={'content-type': 'text/html'}, text=f'<html><body>Results for <input value="{q}"></body></html>')
        if request.url.path == '/safe':
            q = request.url.params.get('q', '')
            return httpx.Response(200, headers={'content-type': 'text/html'}, text=f'<html><body><textarea>{q}</textarea></body></html>')
        return httpx.Response(404)

    _patch_async_client(monkeypatch, handler)
    asset = _asset('web', 'https://web.example.test')
    adapter = harness.get_adapter('browser_xss')
    assert adapter is not None

    findings = asyncio.run(adapter.run(
        {'endpoints': ['/search', '/safe'], 'params': ['q'], 'nonce': nonce},
        asset, _scope(), _intrusive_ctx(settings, target='https://web.example.test'),
    ))
    assert len(findings) == 1
    assert findings[0].rule == 'xss-injection:/search:q'
    assert findings[0].verified is False
    assert findings[0].evidence['validation_level'] == 'injection_context'


# ------------------------------------------------------------------ idor_probe

def test_idor_probe_confirms_cross_role_access_and_ignores_forbidden(settings, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get('authorization', '')
        if request.url.path == '/api/orders/1':
            if not auth:
                return httpx.Response(401, text='{"error": "unauthorized"}')
            # Broken authorization: both Alice and Bob receive Alice's order #1
            return httpx.Response(200, text=json.dumps({'id': 1, 'owner_id': 'alice', 'total': 199.95}))
        if request.url.path == '/api/orders/2':
            if auth == 'Bearer alice-token':
                return httpx.Response(200, text=json.dumps({'id': 2, 'owner_id': 'alice', 'total': 49.00}))
            return httpx.Response(403, text='{"error": "forbidden"}')
        return httpx.Response(404)

    _patch_async_client(monkeypatch, handler)
    asset = _asset('web', 'https://api.example.test')
    adapter = harness.get_adapter('idor_probe')
    assert adapter is not None

    ctx = _intrusive_ctx(
        settings,
        target='https://api.example.test',
        role_headers={
            'user_a': {'Authorization': 'Bearer alice-token'},
            'user_b': {'Authorization': 'Bearer bob-token'},
        },
    )
    findings = asyncio.run(adapter.run(
        {'endpoints': ['/api/orders/1', '/api/orders/2']},
        asset, _scope(), ctx,
    ))
    assert len(findings) == 1
    assert findings[0].rule == 'idor-proof:/api/orders/1'
    assert findings[0].verified is True
    assert findings[0].evidence['owner_role'] == 'user_a'
    assert findings[0].evidence['attacker_role'] == 'user_b'


# ------------------------------------------------------------------ Verified finding wiring + chaining

@pytest.mark.asyncio
async def test_execute_run_marks_finding_validation_status_verified(app, settings, default_tenant_id):
    class _FakeProofAdapter(harness.TestAdapter):
        name = 'fake_proof_repo'
        tier = 'passive'
        target_kinds = ('repo',)

        async def run(self, plan_params, asset, scope, ctx):
            return [harness.NormalizedFinding(
                rule='proof:verified-rule', title='Verified proof finding',
                description='Confirmed via bounded proof.', severity='critical',
                verified=True, evidence={'verified': True},
            )]

    harness.register(_FakeProofAdapter())
    factory = app.state.db_factory
    with factory() as db:
        (settings.scan_root / 'repo_proof').mkdir(parents=True, exist_ok=True)
        asset = Asset(tenant_id=default_tenant_id, name='repo-proof', kind='repo', target='repo_proof',
                      environment='staging', approved=True)
        db.add(asset)
        db.flush()
        db.add(AssetAuthorization(tenant_id=default_tenant_id, asset_id=asset.id, authorized_by='u',
                                  attestation='ok', allow_active=True, allow_intrusive=True))
        scope = TestScope(tenant_id=default_tenant_id, name='s', asset_ids_json=dumps([asset.id]),
                          allowed_tiers_json=dumps(['passive', 'active', 'intrusive']),
                          environments_json='[]', max_rps=20.0)
        db.add(scope)
        db.flush()
        run = TestRun(tenant_id=default_tenant_id, scope_id=scope.id, adapter='fake_proof_repo',
                      asset_id=asset.id, tier='passive', status='queued')
        db.add(run)
        db.commit()
        run_id = run.id

    res = await harness.execute_run(run_id, factory, settings, app)
    assert res['status'] == 'completed' and res['result_count'] == 1

    with factory() as db:
        result_row = db.execute(select(TestResult).where(TestResult.run_id == run_id)).scalar_one()
        finding = db.get(Finding, result_row.finding_id)
        assert finding is not None
        assert finding.validation_status == 'verified'
        assert finding.validated_at is not None


def test_orchestrator_chains_phase3_proof_adapters():
    followups = derive_followups([
        {'adapter': 'payload_fuzz', 'rule': 'fuzz:sqli:id', 'evidence': {'endpoint': '/item', 'parameter': 'id'}},
        {'adapter': 'payload_fuzz', 'rule': 'fuzz:xss:q', 'evidence': {'endpoint': '/search', 'parameter': 'q'}},
        {'adapter': 'jwt_analyze', 'rule': 'jwt:alg-none', 'evidence': {'token': 'abc123456789'}},
    ])
    by_adapter = {f['adapter']: f for f in followups}
    assert 'sqli_proof' in by_adapter
    assert by_adapter['sqli_proof']['params'] == {'endpoints': ['/item'], 'params': ['id']}
    assert 'browser_xss' in by_adapter
    assert by_adapter['browser_xss']['params'] == {'endpoints': ['/search'], 'params': ['q']}
    assert 'jwt_attack' in by_adapter
    assert by_adapter['jwt_attack']['params'] == {'endpoint': '/'}
