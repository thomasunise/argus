"""Regression tests from the pre-production adversarial security review.

One test per fixed issue (`test_sec_<issue>`): approver/requester identity through API keys, params re-validation at
execution, cross-tenant detection links, test-scope asset ownership, plan-param injection into tool argv, harness
tenant checks, CSV formula injection, canary hit body cap, egress checks on operator-supplied URLs, literal secret
references, and request-size bounds.
"""
from __future__ import annotations

import logging
import os
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import respx
from sqlalchemy import select

from app.actions import broker, catalog, credentials
from app.core.errors import ScopeDenied, Unavailable
from app.integrations.egress import EgressDenied, validate_outbound_url
from app.integrations.outbound import registry as outbound_registry
from app.integrations.wazuh_sync import WazuhSyncError, fetch_alerts
from app.models import Asset, AssetAuthorization, dumps, loads
from app.models.actions import ActionRequest
from app.models.testing import TestRun, TestScope
from app.testing import harness
from app.testing.adapters import nuclei, semgrep, zap
from app.testing.ratelimit import RateLimiter
from tests.conftest import login
from tests.test_actions import PW, FakeAction, FakeMedium, as_user, enable_actions, make_request
from tests.test_api_findings import make_finding
from tests.test_detections_api import seed_detection
from tests.test_integrations_outbound import make_event

METADATA = 'https://169.254.169.254/latest/meta-data/'


@pytest.fixture
def fakes():
    instances = {cls.name: cls() for cls in (FakeAction, FakeMedium)}
    for inst in instances.values():
        catalog.register(inst)
    yield instances
    for name in instances:
        catalog.unregister(name)


def _ctx(settings, tier='passive', target=''):
    async def heartbeat():
        return None

    return harness.HarnessContext(settings=settings, tenant_id='t', run_id='run-1', heartbeat=heartbeat, rate_limiter=RateLimiter(100),
                                  logger=logging.getLogger('test'), scan_root=settings.scan_root, tier=tier, target=target)


# ---------------------------------------------------------------- action broker


def test_sec_api_key_cannot_approve_its_owners_request(app, owner, api_key, make_user, fakes):
    """Two approvals from one human (session + a key they minted) must not satisfy dual control."""
    client, headers = owner
    enable_actions(client, headers)
    rid = make_request(client, headers)['id']  # requested by the owner's session
    via_key = client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers={'X-API-Key': api_key})
    assert via_key.status_code == 403 and 'own request' in via_key.json()['detail']
    # a genuinely different person still can
    make_user('op1@test.local', PW, 'operator')
    op1, h1 = as_user(app, 'op1@test.local', PW)
    assert op1.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=h1).json()['approval_count'] == 1
    # and that person cannot count twice through a key minted for them by an admin
    key = client.post('/api/v1/auth/api-keys', json={'name': 'op1-key', 'role': 'operator'}, headers=headers).json()['key']
    assert client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers={'X-API-Key': key}).status_code == 403


def test_sec_params_revalidated_at_execution(app, owner, make_user, fakes, db):
    client, headers = owner
    enable_actions(client, headers)
    make_user('op1@test.local', PW, 'operator')
    make_user('op2@test.local', PW, 'operator')
    op1, h1 = as_user(app, 'op1@test.local', PW)
    op2, h2 = as_user(app, 'op2@test.local', PW)
    rid = make_request(op1, h1, action_type='test.fake.medium', target='srv-1')['id']
    assert op2.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=h2).json()['status'] == 'approved'
    # Tamper with the stored params after approval (what a DB-level attacker or a buggy migration could do).
    req = db.get(ActionRequest, rid)
    req.params_json = dumps({'target': 'srv-1', 'count': 'not-an-int', 'extra': True})
    db.commit()
    denied = op1.post(f'/api/v1/actions/requests/{rid}/execute', headers=h1)
    assert denied.status_code == 403 and 'schema' in denied.json()['detail']
    assert fakes['test.fake.medium'].calls[-1][0] == 'dry_run'  # nothing executed
    assert broker.approvals_satisfied(req, [], db) is False


def test_sec_request_rejects_foreign_detection_id(owner, second_tenant, db, fakes):
    client, headers = owner
    enable_actions(client, headers)
    foreign = seed_detection(db, second_tenant['tenant_id'])
    resp = client.post('/api/v1/actions/requests', json={'action_type': 'test.fake.medium', 'params': {'target': 'x'}, 'reason': 'r',
                                                       'detection_id': foreign.id}, headers=headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------- testing harness


def test_sec_scope_requires_tenant_owned_assets(app, owner, second_tenant):
    client, headers = owner
    with app.state.db_factory() as session:
        foreign = Asset(tenant_id=second_tenant['tenant_id'], name='theirs', kind='host', target='h1', environment='production')
        mine = Asset(tenant_id=app.state.default_tenant_id, name='mine', kind='host', target='h2', environment='production')
        session.add_all([foreign, mine])
        session.commit()
        foreign_id, mine_id = foreign.id, mine.id
    assert client.post('/api/v1/tests/scopes', json={'name': 's', 'asset_ids': [foreign_id]}, headers=headers).status_code == 404
    assert client.post('/api/v1/tests/scopes', json={'name': 's', 'asset_ids': [mine_id, foreign_id]}, headers=headers).status_code == 404
    assert client.post('/api/v1/tests/scopes', json={'name': 's', 'asset_ids': [mine_id], 'max_concurrency': 0}, headers=headers).status_code == 422
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    assert client.post('/api/v1/tests/scopes', json={'name': 's', 'asset_ids': [mine_id], 'expires_at': past}, headers=headers).status_code == 400
    assert client.post('/api/v1/tests/scopes', json={'name': 's', 'asset_ids': [mine_id]}, headers=headers).status_code == 201


@pytest.mark.asyncio
async def test_sec_plan_params_cannot_inject_tool_arguments(settings, monkeypatch):
    called = []

    async def fake_run_tool(argv, timeout, cwd=None, env=None, stdin=None):
        called.append(argv)
        return 0, '', ''

    monkeypatch.setattr(nuclei, 'run_tool', fake_run_tool)
    monkeypatch.setattr(semgrep, 'run_tool', fake_run_tool)
    asset = types.SimpleNamespace(id='a', name='web', kind='web', target='https://app.example.test', environment='staging', criticality='medium')
    scope = types.SimpleNamespace(max_rps=10)
    for hostile in ('/etc/passwd', '../../../../templates', 'http://evil.test/t.yaml', '-code', 'a;b', 'C:\\Windows\\win.ini'):
        with pytest.raises(ScopeDenied):
            await nuclei.NucleiAdapter().run({'templates': hostile}, asset, scope, _ctx(settings, 'active', 'https://app.example.test'))
    (settings.scan_root / 'repo').mkdir(parents=True, exist_ok=True)
    repo = types.SimpleNamespace(id='r', name='repo', kind='repo', target='repo', environment='production', criticality='medium')
    for hostile in ('/etc/passwd', 'https://evil.test/rules.yaml', '../rules', 'p/../x'):
        with pytest.raises(ScopeDenied):
            await semgrep.SemgrepAdapter().run({'config': hostile}, repo, scope, _ctx(settings))
    assert called == []
    # safe values still pass validation
    assert semgrep.safe_config('p/ci') == 'p/ci' and nuclei.safe_templates('http/cves,misconfiguration') == 'http/cves,misconfiguration'


@pytest.mark.asyncio
async def test_sec_execute_run_rejects_cross_tenant_rows(app, settings, default_tenant_id, second_tenant):
    class _Adapter(harness.TestAdapter):
        name = 'sec_fake'
        target_kinds = ('host',)

        async def run(self, plan_params, asset, scope, ctx):
            raise AssertionError('adapter must not run')

    harness.register(_Adapter())
    factory = app.state.db_factory
    other = second_tenant['tenant_id']
    with factory() as session:
        asset = Asset(tenant_id=other, name='theirs', kind='host', target='h1', environment='production', approved=True)
        session.add(asset)
        session.flush()
        session.add(AssetAuthorization(tenant_id=other, asset_id=asset.id, authorized_by='u', attestation='ok'))
        scope = TestScope(tenant_id=default_tenant_id, name='s', asset_ids_json=f'["{asset.id}"]', allowed_tiers_json='["passive"]')
        session.add(scope)
        session.flush()
        run = TestRun(tenant_id=default_tenant_id, scope_id=scope.id, adapter='sec_fake', asset_id=asset.id, tier='passive', status='queued')
        session.add(run)
        session.commit()
        run_id = run.id
    result = await harness.execute_run(run_id, factory, settings, app)
    assert result['status'] == 'denied' and 'asset' in result['reason']


# ---------------------------------------------------------------- exports and public endpoints


def test_sec_csv_export_neutralizes_formulas(owner, db, default_tenant_id):
    client, headers = owner
    make_finding(db, default_tenant_id, rule='=cmd|calc', title='=HYPERLINK("https://evil.test","x")', remediation='+1+1', severity='low')
    make_finding(db, default_tenant_id, rule='r2', title='@SUM(A1)', remediation='-2+3', severity='low')
    text = client.get('/api/v1/findings/export.csv', headers=headers).text
    assert "'=HYPERLINK" in text and "'=cmd|calc" in text and "'+1+1" in text and "'@SUM(A1)" in text and "'-2+3" in text
    for line in text.splitlines()[1:]:
        for cell in line.split(','):
            assert not cell.startswith(('=', '+', '-', '@')), line


def test_sec_canary_hit_body_is_bounded(owner):
    client, headers = owner
    token = client.post('/api/v1/canaries', json={'kind': 'url', 'label': 'bait'}, headers=headers).json()['token']
    big = client.post(f'/api/v1/canaries/{token}/hit', content=b'x' * (70 * 1024), headers={'Content-Type': 'text/plain'})
    assert big.status_code == 413
    assert client.post(f'/api/v1/canaries/{token}/hit', content=b'{"ok": true}', headers={'Content-Type': 'application/json'}).status_code == 204
    hits = client.get(f"/api/v1/canaries/{client.get('/api/v1/canaries', headers=headers).json()['items'][0]['id']}/hits", headers=headers).json()['items']
    assert len(hits) == 1


def test_sec_list_bounds(owner):
    client, headers = owner
    assert client.get('/api/v1/investigations', params={'cursor': '999999999999'}, headers=headers).json()['items'] == []
    big = client.post('/api/v1/agents/run', json={'spec': 'triage', 'inputs': {'blob': 'x' * 40_000}}, headers=headers)
    assert big.status_code == 422
    assert client.post('/api/v1/evals/run', json={'suite': 'x', 'case_ids': ['c'] * 501}, headers=headers).status_code == 422


# ---------------------------------------------------------------- egress


def test_sec_outbound_url_policy(settings):
    for bad in (METADATA, 'https://localhost/hook', 'https://127.0.0.1:8443/', 'https://[::1]/', 'https://10.0.0.5/', 'https://192.168.1.1/',
                'https://metadata.google.internal/computeMetadata/v1/', 'https://user:pw@hooks.example.test/', 'http://hooks.example.test/',
                'ftp://hooks.example.test/', 'https://kubernetes.default.svc.cluster.local/', 'https://a.localhost/'):
        with pytest.raises(EgressDenied):
            validate_outbound_url(bad, settings)
    assert validate_outbound_url('https://hooks.example.test/x', settings) == 'https://hooks.example.test/x'
    assert validate_outbound_url('https://8.8.8.8/', settings, resolve=False) == 'https://8.8.8.8/'


def test_sec_integration_config_rejects_internal_destinations(owner):
    client, headers = owner
    for url in (METADATA, 'https://localhost/x', 'https://10.1.2.3/hook', 'http://hooks.example.test/plain'):
        resp = client.post('/api/v1/integrations', json={'name': 'x', 'kind': 'webhook', 'config': {'url': url}}, headers=headers)
        assert resp.status_code == 400, (url, resp.text)
    assert client.post('/api/v1/integrations', json={'name': 'x', 'kind': 'jira', 'config': {'base_url': 'https://169.254.169.254', 'project_key': 'SEC'}},
                       headers=headers).status_code == 400
    ok = client.post('/api/v1/integrations', json={'name': 'ok', 'kind': 'webhook', 'config': {'url': 'https://hooks.example.test/x'}}, headers=headers)
    assert ok.status_code == 201
    assert client.patch(f"/api/v1/integrations/{ok.json()['id']}", json={'config': {'url': 'https://127.0.0.1/'}}, headers=headers).status_code == 400
    assert client.post('/api/v1/collectors', json={'name': 'fleet', 'collector': 'osquery', 'config': {'mode': 'fleet', 'fleet_url': METADATA}},
                       headers=headers).status_code == 400


@pytest.mark.asyncio
async def test_sec_channels_refuse_internal_destinations_at_send_time(settings):
    with respx.mock(assert_all_called=False, assert_all_mocked=True):
        hook = await outbound_registry.get('webhook').send(make_event(), {'url': METADATA}, {})
        assert not hook.ok and 'refused' in hook.error
        slack = await outbound_registry.get('slack').send(make_event(), {'mode': 'webhook'}, {'webhook_url': 'https://127.0.0.1/services/x'})
        assert not slack.ok and 'refused' in slack.error
        jira = await outbound_registry.get('jira').send(make_event(), {'base_url': 'https://10.0.0.9', 'project_key': 'SEC'}, {'bearer_token': 't'})
        assert not jira.ok and 'refused' in jira.error
        snow = await outbound_registry.get('servicenow').send(make_event(), {'instance_url': 'https://localhost'}, {'bearer_token': 't'})
        assert not snow.ok and 'refused' in snow.error
    with pytest.raises(WazuhSyncError):
        await fetch_alerts('https://169.254.169.254:9200', 'wazuh-alerts-*', None, '', datetime.now(timezone.utc), 10, settings)
    with pytest.raises(WazuhSyncError):
        await fetch_alerts('https://indexer.test:9200', '../_cluster/settings', None, '', datetime.now(timezone.utc), 10, settings)


# ---------------------------------------------------------------- literal secret references


def test_sec_literal_secret_refs_rejected_for_collectors(app, owner, monkeypatch):
    client, headers = owner
    body = {'name': 'acct', 'collector': 'osquery', 'config': {'mode': 'directory', 'path': 'osq'}, 'secret_refs': {'fleet_token': 'literal:dev-token'}}
    assert client.post('/api/v1/collectors', json=body, headers=headers).status_code == 201  # allowed by default outside production
    monkeypatch.setattr(app.state.settings, 'allow_literal_secret_refs', False)
    denied = client.post('/api/v1/collectors', json=body, headers=headers)
    assert denied.status_code == 400 and 'literal' in denied.json()['detail']
    created = client.get('/api/v1/collectors', headers=headers).json()['items'][0]
    assert client.patch(f"/api/v1/collectors/{created['id']}", json={'secret_refs': {'fleet_token': 'literal:again'}}, headers=headers).status_code == 400
    assert client.patch(f"/api/v1/collectors/{created['id']}", json={'secret_refs': {'fleet_token': 'env:FLEET_TOKEN'}}, headers=headers).status_code == 200


def test_sec_literal_secret_refs_rejected_for_integrations(app, owner, monkeypatch):
    client, headers = owner
    body = {'name': 'hook', 'kind': 'webhook', 'config': {'url': 'https://hooks.example.test/x'}, 'secret_refs': {'signing_secret': 'literal:shh'}}
    assert client.post('/api/v1/integrations', json=body, headers=headers).status_code == 201
    monkeypatch.setattr(app.state.settings, 'allow_literal_secret_refs', False)
    denied = client.post('/api/v1/integrations', json=body, headers=headers)
    assert denied.status_code == 400 and 'literal' in denied.json()['detail']
    created = client.get('/api/v1/integrations', headers=headers).json()['items'][0]
    assert client.patch(f"/api/v1/integrations/{created['id']}", json={'secret_refs': {'signing_secret': 'literal:x'}}, headers=headers).status_code == 400


def test_sec_literal_secret_refs_rejected_for_action_credentials(settings, monkeypatch):
    monkeypatch.setenv('ACTIONS_CLOUDFLARE_TOKEN', 'literal:cf-token')
    assert credentials.resolve('cloudflare', 'token', settings, {}) == 'cf-token'
    monkeypatch.setattr(settings, 'allow_literal_secret_refs', False)
    assert credentials.resolve('cloudflare', 'token', settings, {}) == ''
    # tenant overrides never resolve literals, whatever the setting
    monkeypatch.setattr(settings, 'allow_literal_secret_refs', True)
    assert credentials.resolve('cloudflare', 'token', settings, {'action_credentials': {'cloudflare': {'token': 'literal:inline'}}}) == 'cf-token'
    monkeypatch.delenv('ACTIONS_CLOUDFLARE_TOKEN')
    assert credentials.resolve('cloudflare', 'token', settings, {'action_credentials': {'cloudflare': {'token': 'literal:inline'}}}) == ''


@pytest.mark.asyncio
async def test_sec_literal_secret_refs_rejected_for_test_adapters(settings, monkeypatch):
    monkeypatch.setattr(settings, 'zap_url', 'https://zap.example.test')
    monkeypatch.setattr(settings, 'zap_api_key', 'literal:zap-key')
    monkeypatch.setattr(settings, 'allow_literal_secret_refs', False)
    asset = types.SimpleNamespace(id='a', name='web', kind='web', target='https://app.example.test', environment='staging', criticality='medium')
    with pytest.raises(Unavailable):
        await zap.ZapAdapter().run({}, asset, types.SimpleNamespace(max_rps=10), _ctx(settings, 'active', 'https://app.example.test'))
