"""Regression tests from the pre-production adversarial security review.

One test per fixed issue (`test_sec_<issue>`): approver/requester identity through API keys, params re-validation at
execution, cross-tenant detection links, test-scope asset ownership, plan-param injection into tool argv, harness
tenant checks, CSV formula injection, canary hit body cap, egress checks on operator-supplied URLs, literal secret
references, and request-size bounds.
"""
from __future__ import annotations

import logging
import time
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import respx
from app.actions import broker, catalog, credentials
from app.actions.identity import approvals_satisfied, identity_of
from app.core.audit import _entry_hash, _sign, record_audit, verify_chain
from app.core.errors import ScopeDenied, Unavailable
from app.core.security import _totp_code, generate_api_key
from app.integrations.egress import EgressDenied, validate_outbound_url
from app.integrations.outbound import registry as outbound_registry
from app.integrations.wazuh_sync import WazuhSyncError, fetch_alerts
from app.models import ApiKey, Asset, AssetAuthorization, AuditEntry, dumps
from app.models.actions import ActionApproval, ActionRequest
from app.models.testing import TestRun, TestScope
from app.testing import harness
from app.testing.adapters import nuclei, semgrep, zap
from app.testing.ratelimit import RateLimiter
from tests.test_actions import PW, FakeAction, FakeCritical, FakeMedium, as_user, enable_actions, make_request
from tests.test_api_findings import make_finding
from tests.test_detections_api import seed_detection
from tests.test_integrations_outbound import make_event

METADATA = 'https://169.254.169.254/latest/meta-data/'


@pytest.fixture
def fakes():
    instances = {cls.name: cls() for cls in (FakeAction, FakeMedium, FakeCritical)}
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
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
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
        await fetch_alerts('https://169.254.169.254:9200', 'wazuh-alerts-*', None, '', datetime.now(UTC), 10, settings)
    with pytest.raises(WazuhSyncError):
        await fetch_alerts('https://indexer.test:9200', '../_cluster/settings', None, '', datetime.now(UTC), 10, settings)


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


# ---------------------------------------------------------------- Phase 0 regression tests


def test_phase0_api_key_approval_bypass(app, owner, make_user, fakes, db, default_tenant_id):
    """One owner plus two key-minted keys must not get a critical request to approved; keys with no creator are refused."""
    client, headers = owner
    enable_actions(client, headers)
    root_key = client.post('/api/v1/auth/api-keys', json={'name': 'root-owner', 'role': 'owner'}, headers=headers).json()['key']
    k1 = client.post('/api/v1/auth/api-keys', json={'name': 'minted-1', 'role': 'owner'}, headers={'X-API-Key': root_key}).json()
    k2 = client.post('/api/v1/auth/api-keys', json={'name': 'minted-2', 'role': 'owner'}, headers={'X-API-Key': root_key}).json()

    rid = make_request(client, headers, action_type='test.fake.critical', target='srv-crit')['id']
    r1 = client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers={'X-API-Key': k1['key']})
    r2 = client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers={'X-API-Key': k2['key']})
    assert r1.status_code == 403
    assert r2.status_code == 403
    assert client.get(f'/api/v1/actions/requests/{rid}', headers=headers).json()['status'] == 'pending'

    # Even if another user creates the request, owner + key-minted keys still represent only one human identity.
    make_user('op-req@test.local', PW, 'operator')
    op_client, op_headers = as_user(app, 'op-req@test.local', PW)
    rid2 = make_request(op_client, op_headers, action_type='test.fake.critical', target='srv-crit-2')['id']
    assert client.post(f'/api/v1/actions/requests/{rid2}/approve', json={'decision': 'approve'}, headers=headers).status_code == 200
    assert client.post(f'/api/v1/actions/requests/{rid2}/approve', json={'decision': 'approve'}, headers={'X-API-Key': k1['key']}).status_code == 409
    assert client.get(f'/api/v1/actions/requests/{rid2}', headers=headers).json()['status'] == 'pending'

    # A key with no recorded creator in the database must be refused by identity_of and broker.approve.
    plaintext, prefix, key_hash = generate_api_key()
    unowned = ApiKey(tenant_id=default_tenant_id, name='legacy-unowned', prefix=prefix, key_hash=key_hash, role='owner', created_by='')
    db.add(unowned)
    db.commit()
    assert identity_of(db, f'api_key:{unowned.id}') == ''
    assert client.post(f'/api/v1/actions/requests/{rid2}/approve', json={'decision': 'approve'}, headers={'X-API-Key': plaintext}).status_code == 403
    req_row = db.get(ActionRequest, rid2)
    fake_approval = ActionApproval(tenant_id=default_tenant_id, request_id=rid2, approver_id=f'api_key:{unowned.id}',
                                   approver_role='owner', can_approve_critical=True, decision='approve')
    assert approvals_satisfied(req_row, [fake_approval], db) is False


def test_phase0_stale_session_mfa_bypass(owner):
    """Enabling TOTP invalidates pre-enrolment cookies, re-issues the enrolling session, and ignores pending_totp_secret once enabled."""
    client, headers = owner
    pre_enroll_cookie = client.cookies.get('argus_session')
    pre_enroll_headers = dict(headers)
    assert pre_enroll_cookie

    # Start a first enrollment to capture a cookie containing a stale pending_totp_secret.
    enroll_1 = client.post('/api/v1/auth/totp/enroll', headers=headers)
    assert enroll_1.status_code == 200
    secret_1 = enroll_1.json()['secret']
    stale_pending_cookie = client.cookies.get('argus_session')
    stale_pending_headers = dict(headers)

    # Start a second enrollment and confirm it.
    enroll_2 = client.post('/api/v1/auth/totp/enroll', headers=headers)
    assert enroll_2.status_code == 200
    secret_2 = enroll_2.json()['secret']
    assert secret_2 != secret_1
    step = int(time.time()) // 30
    verify_resp = client.post('/api/v1/auth/totp/verify', json={'code': _totp_code(secret_2, step)}, headers=headers)
    assert verify_resp.status_code == 200
    new_cookie = client.cookies.get('argus_session')
    new_headers = {'X-CSRF-Token': verify_resp.json()['csrf']}
    assert new_cookie and new_cookie != pre_enroll_cookie

    # The re-issued session after enrolment works.
    assert client.get('/api/v1/assets', headers=new_headers).status_code == 200

    # Replaying the cookie from before enrolment must return 401.
    client.cookies.clear()
    client.cookies.set('argus_session', pre_enroll_cookie)
    assert client.get('/api/v1/assets', headers=pre_enroll_headers).status_code == 401
    assert client.post('/api/v1/auth/api-keys', json={'name': 'replay', 'role': 'viewer'}, headers=pre_enroll_headers).status_code == 401

    # Replaying the stale cookie that held secret_1 as pending_totp_secret must also return 401.
    client.cookies.clear()
    client.cookies.set('argus_session', stale_pending_cookie)
    assert client.post('/api/v1/auth/totp/verify', json={'code': _totp_code(secret_1, step + 1)}, headers=stale_pending_headers).status_code == 401


def test_phase0_audit_hash_truncation_versioning_and_multi_break(db, default_tenant_id):
    """Overlong fields truncate before hashing; actor_kind and request_id are length-prefixed into v2 hash; v1 still verifies; all breaks reported."""
    # 1. Overlong actor, action, subject, and request_id must verify after storage truncation.
    long_actor = 'u' * 250
    long_action = 'a' * 150
    long_subject = 's' * 250
    long_req_id = 'r' * 90
    e_long = record_audit(db, long_actor, long_action, long_subject, {'k': 'v'}, tenant_id=default_tenant_id,
                          actor_kind='user', request_id=long_req_id)
    db.commit()
    assert len(e_long.actor) == 200 and len(e_long.action) == 100 and len(e_long.subject) == 200 and len(e_long.request_id) == 64
    assert verify_chain(db, default_tenant_id)['valid'] is True

    # 2. Length-prefixing prevents pipe-delimiter boundary collisions, and includes actor_kind and request_id.
    h1 = _entry_hash(default_tenant_id, '0' * 64, 'alice|admin', 'read', 'subj', '{}', '2026-01-01T00:00:00.000000',
                     actor_kind='user', request_id='req-1')
    h2 = _entry_hash(default_tenant_id, '0' * 64, 'alice', 'admin|read', 'subj', '{}', '2026-01-01T00:00:00.000000',
                     actor_kind='user', request_id='req-1')
    h3 = _entry_hash(default_tenant_id, '0' * 64, 'alice|admin', 'read', 'subj', '{}', '2026-01-01T00:00:00.000000',
                     actor_kind='system', request_id='req-1')
    h4 = _entry_hash(default_tenant_id, '0' * 64, 'alice|admin', 'read', 'subj', '{}', '2026-01-01T00:00:00.000000',
                     actor_kind='user', request_id='req-2')
    assert len({h1, h2, h3, h4}) == 4

    # 3. Legacy v1 entries still verify in a mixed v1 -> v2 chain.
    legacy_tenant = 'tenant-legacy-v1'
    ts = datetime(2026, 1, 1, 0, 0, 0)
    v1_hash = _entry_hash(legacy_tenant, '0' * 64, 'legacy@test', 'legacy.act', 'sub', '{}', '2026-01-01T00:00:00.000000', version=1)
    v1_entry = AuditEntry(tenant_id=legacy_tenant, actor='legacy@test', actor_kind='user', action='legacy.act', subject='sub',
                          detail='{}', request_id='', previous_hash='0' * 64, entry_hash=v1_hash, signature=_sign(v1_hash), created_at=ts)
    db.add(v1_entry)
    db.flush()
    e2 = record_audit(db, 'admin@test', 'v2.one', 'sub2', {'x': 1}, tenant_id=legacy_tenant, actor_kind='user', request_id='req-a')
    e3 = record_audit(db, 'admin@test', 'v2.two', 'sub3', {'x': 2}, tenant_id=legacy_tenant, actor_kind='user', request_id='req-b')
    e4 = record_audit(db, 'admin@test', 'v2.three', 'sub4', {'x': 3}, tenant_id=legacy_tenant, actor_kind='user', request_id='req-c')
    db.commit()
    assert verify_chain(db, legacy_tenant)['valid'] is True

    # 4. Tampering with actor_kind on e2 and request_id on e4 must both be reported by verify_chain.
    e2.actor_kind = 'system'
    e4.request_id = 'tampered-req'
    db.commit()
    res = verify_chain(db, legacy_tenant)
    assert res['valid'] is False
    assert res['broken_at'] == e2.id
    assert res['broken_ids'] == [e2.id, e4.id]
    assert [b['id'] for b in res['breaks']] == [e2.id, e4.id]
    assert e3.id not in res['broken_ids']


def test_phase0_lockfile_opentelemetry_api_version():
    """requirements.lock.txt pins opentelemetry-api to at least 1.45.2."""
    lock_path = Path(__file__).resolve().parents[1] / 'requirements.lock.txt'
    lines = [line.strip() for line in lock_path.read_text(encoding='utf-8').splitlines() if line.strip() and not line.startswith('#')]
    otel_lines = [line for line in lines if line.startswith('opentelemetry-api==')]
    assert otel_lines == ['opentelemetry-api==1.45.2']


def test_phase0_trusted_proxy_hops_ignores_spoofed_xff(app, client, owner, monkeypatch):
    """TRUSTED_PROXY_HOPS takes the address N hops from the right of X-Forwarded-For, ignoring client-spoofed leftmost entries."""
    _, headers = owner
    assert app.state.settings.trusted_proxy_hops == 0

    # With trusted_proxy_hops=1 (e.g. behind 1 ALB), rotating spoofed leftmost XFF IPs cannot bypass IP login throttling.
    monkeypatch.setattr(app.state.settings, 'trusted_proxy_hops', 1)
    for i in range(app.state.settings.login_max_attempts):
        r = client.post('/api/v1/auth/login', json={'email': f'user{i}@test.local', 'password': 'wrong-password-long'},
                        headers={'X-Forwarded-For': f'10.0.0.{i}, 198.51.100.77'})
        assert r.status_code == 401
    throttled = client.post('/api/v1/auth/login', json={'email': 'fresh@test.local', 'password': 'wrong-password-long'},
                            headers={'X-Forwarded-For': '203.0.113.99, 198.51.100.77'})
    assert throttled.status_code == 429
    other_ip = client.post('/api/v1/auth/login', json={'email': 'fresh@test.local', 'password': 'wrong-password-long'},
                           headers={'X-Forwarded-For': '203.0.113.99, 198.51.100.88'})
    assert other_ip.status_code == 401

    # With trusted_proxy_hops=2, canary hits record the address 2 hops from the right.
    monkeypatch.setattr(app.state.settings, 'trusted_proxy_hops', 2)
    canary = client.post('/api/v1/canaries', json={'kind': 'url', 'label': 'xff-hop-test'}, headers=headers).json()
    hit = client.post(f"/api/v1/canaries/{canary['token']}/hit", content=b'{}',
                      headers={'Content-Type': 'application/json', 'X-Forwarded-For': '1.2.3.4, 198.51.100.55, 10.0.1.2'})
    assert hit.status_code == 204
    hits = client.get(f"/api/v1/canaries/{canary['id']}/hits", headers=headers).json()['items']
    assert hits[0]['source_ip'] == '198.51.100.55'

