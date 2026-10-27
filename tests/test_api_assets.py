from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.findings import upsert_finding
from app.models import Finding, ScanRun
from tests.conftest import login

ATTESTATION = 'I confirm that this organization owns and controls this asset and authorizes testing.'


def make_asset(client, headers, **overrides) -> dict:
    body = {'name': 'Staging site', 'kind': 'web', 'target': 'https://example.org', 'environment': 'staging'}
    body.update(overrides)
    response = client.post('/api/v1/assets', json=body, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def test_create_validate_and_list(owner):
    client, headers = owner
    asset = make_asset(client, headers, target='https://Example.org/', tags=['pci', 'web', 'pci'])
    assert asset['approved'] is False and asset['target'] == 'https://example.org' and asset['tags'] == ['pci', 'web']
    bad_kind = client.post('/api/v1/assets', json={'name': 'x1', 'kind': 'mainframe', 'target': 'a'}, headers=headers)
    assert bad_kind.status_code == 400 and bad_kind.json()['code'] == 'invalid_kind'
    bad_target = client.post('/api/v1/assets', json={'name': 'x2', 'kind': 'web', 'target': 'http://example.org'}, headers=headers)
    assert bad_target.status_code == 400 and bad_target.json()['code'] == 'invalid_target'
    bad_env = client.post('/api/v1/assets', json={'name': 'x3', 'kind': 'host', 'target': 'db-01', 'environment': 'moon'}, headers=headers)
    assert bad_env.status_code == 400 and bad_env.json()['code'] == 'invalid_environment'
    localhost = client.post('/api/v1/assets', json={'name': 'x4', 'kind': 'web', 'target': 'https://localhost'}, headers=headers)
    assert localhost.status_code == 400
    make_asset(client, headers, name='Prod account', kind='cloud_account', target='123456789012', environment='production', owner='platform')
    listed = client.get('/api/v1/assets', headers=headers).json()
    assert len(listed['items']) == 2 and listed['next_cursor'] is None
    assert [a['name'] for a in client.get('/api/v1/assets?kind=web').json()['items']] == ['Staging site']
    assert [a['name'] for a in client.get('/api/v1/assets?search=platform').json()['items']] == ['Prod account']
    assert client.get('/api/v1/assets?approved=true').json()['items'] == []
    page = client.get('/api/v1/assets?limit=1').json()
    assert len(page['items']) == 1 and page['next_cursor'] == '1'
    assert len(client.get(f"/api/v1/assets?limit=1&cursor={page['next_cursor']}").json()['items']) == 1
    detail = client.get(f"/api/v1/assets/{asset['id']}").json()
    assert detail['authorization'] is None and detail['authorization_status'] == 'none'
    assert detail['open_findings']['total'] == 0 and set(detail['last_runs']) == {'test_runs', 'scan_runs'}
    assert client.get('/api/v1/assets/does-not-exist').status_code == 404


def test_authorize_and_revoke(owner):
    client, headers = owner
    asset = make_asset(client, headers)
    short = client.post(f"/api/v1/assets/{asset['id']}/authorize", json={'attestation': 'yes'}, headers=headers)
    assert short.status_code == 400 and short.json()['code'] == 'attestation_required'
    blank = client.post(f"/api/v1/assets/{asset['id']}/authorize", json={'attestation': '   '}, headers=headers)
    assert blank.status_code in (400, 422)
    tiers = client.post(f"/api/v1/assets/{asset['id']}/authorize", json={'attestation': ATTESTATION, 'allow_intrusive': True}, headers=headers)
    assert tiers.status_code == 400 and tiers.json()['code'] == 'invalid_tiers'
    too_long = client.post(f"/api/v1/assets/{asset['id']}/authorize", json={'attestation': ATTESTATION, 'expires_in_days': 400}, headers=headers)
    assert too_long.status_code == 422
    ok = client.post(f"/api/v1/assets/{asset['id']}/authorize", json={'attestation': ATTESTATION, 'allow_active': True, 'allow_intrusive': True,
                                                                     'expires_in_days': 30, 'scope_document_ref': 'docs/scope-2026.pdf'}, headers=headers)
    assert ok.status_code == 201, ok.text
    data = ok.json()
    assert data['approved'] is True and data['authorization']['active'] is True and data['authorization']['allow_intrusive'] is True
    detail = client.get(f"/api/v1/assets/{asset['id']}").json()
    assert detail['authorization_status'] == 'active' and detail['authorization']['scope_document_ref'] == 'docs/scope-2026.pdf'
    # A second authorization supersedes the first.
    again = client.post(f"/api/v1/assets/{asset['id']}/authorize", json={'attestation': ATTESTATION, 'allow_active': True}, headers=headers)
    assert again.status_code == 201
    auths = client.get(f"/api/v1/assets/{asset['id']}/authorizations").json()['items']
    assert len(auths) == 2 and [a['active'] for a in auths] == [True, False]
    audit = client.get('/api/v1/audit?action=assets.authorized').json()['items']
    assert len(audit) == 2 and audit[0]['detail']['attestation'] == ATTESTATION and audit[0]['subject'] == asset['id']
    # Intrusive testing is only authorizable for staging/lab assets.
    prod = make_asset(client, headers, name='Prod', target='https://prod.example.org', environment='production')
    denied = client.post(f"/api/v1/assets/{prod['id']}/authorize", json={'attestation': ATTESTATION, 'allow_active': True, 'allow_intrusive': True}, headers=headers)
    assert denied.status_code == 403
    # Moving an intrusively authorized asset to production is blocked until revoked.
    intrusive = client.post(f"/api/v1/assets/{asset['id']}/authorize", json={'attestation': ATTESTATION, 'allow_active': True, 'allow_intrusive': True}, headers=headers)
    assert intrusive.status_code == 201
    assert client.patch(f"/api/v1/assets/{asset['id']}", json={'environment': 'production'}, headers=headers).status_code == 409
    revoked = client.post(f"/api/v1/assets/{asset['id']}/revoke-authorization", json={'reason': 'engagement ended'}, headers=headers)
    assert revoked.status_code == 200 and revoked.json()['approved'] is False and len(revoked.json()['revoked']) == 1
    detail = client.get(f"/api/v1/assets/{asset['id']}").json()
    assert detail['authorization'] is None and detail['authorization_status'] == 'expired_or_revoked'
    assert client.get('/api/v1/audit?action=assets.authorization_revoked').json()['items'][0]['detail']['reason'] == 'engagement ended'
    assert client.get('/api/v1/audit/verify').json()['valid'] is True


def test_patch_and_delete_detaches_findings(owner, db, default_tenant_id):
    client, headers = owner
    asset = make_asset(client, headers)
    patched = client.patch(f"/api/v1/assets/{asset['id']}", json={'name': 'Renamed', 'owner': 'appsec', 'criticality': 'high', 'tags': ['b', 'a']}, headers=headers)
    assert patched.status_code == 200
    assert patched.json()['name'] == 'Renamed' and patched.json()['criticality'] == 'high' and patched.json()['tags'] == ['a', 'b']
    assert client.patch(f"/api/v1/assets/{asset['id']}", json={'criticality': 'extreme'}, headers=headers).status_code == 400
    audit = client.get('/api/v1/audit?action=assets.updated').json()['items']
    assert audit and set(audit[0]['detail']['changes']) == {'name', 'owner', 'criticality', 'tags'}
    finding, _ = upsert_finding(db, default_tenant_id, source='test', rule='r1', title='Attached finding', description='d', severity_name='low', asset_id=asset['id'])
    db.commit()
    deleted = client.delete(f"/api/v1/assets/{asset['id']}", headers=headers)
    assert deleted.status_code == 200 and deleted.json()['detached'] == 1
    db.expire_all()
    assert db.get(Finding, finding.id).asset_id is None
    assert client.get(f"/api/v1/assets/{asset['id']}").status_code == 404


def test_delete_blocked_by_run_history(owner, db, default_tenant_id):
    client, headers = owner
    asset = make_asset(client, headers)
    db.add(ScanRun(tenant_id=default_tenant_id, asset_id=asset['id'], scanner='web-baseline', status='completed'))
    db.commit()
    response = client.delete(f"/api/v1/assets/{asset['id']}", headers=headers)
    assert response.status_code == 409
    assert client.get(f"/api/v1/assets/{asset['id']}").json()['last_runs']['scan_runs'][0]['scanner'] == 'web-baseline'


def test_bulk_import(owner):
    client, headers = owner
    make_asset(client, headers, name='Existing', target='https://dup.example.org')
    rows = [
        {'name': 'Good one', 'kind': 'host', 'target': 'web-01.internal', 'environment': 'lab'},
        {'name': 'Bad kind', 'kind': 'nope', 'target': 'x'},
        {'name': 'Bad url', 'kind': 'web', 'target': 'ftp://example.org'},
        {'name': 'Duplicate', 'kind': 'web', 'target': 'https://dup.example.org'},
        'not an object',
        {'name': 'G', 'kind': 'host', 'target': 'too-short-name'},
    ]
    response = client.post('/api/v1/assets/import', json=rows, headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data['received'] == 6 and data['created'] == 1 and data['failed'] == 5
    codes = {r['index']: r.get('code') for r in data['results'] if not r['ok']}
    assert codes[1] == 'invalid_kind' and codes[2] == 'invalid_target' and codes[3] == 'exists' and codes[5] == 'validation'
    assert len(client.get('/api/v1/assets').json()['items']) == 2
    assert client.post('/api/v1/assets/import', json=[{}] * 1001, headers=headers).status_code == 400
    assert client.get('/api/v1/audit?action=assets.imported').json()['items'][0]['detail']['created'] == 1


def test_asset_graph_neighborhood(owner):
    client, headers = owner
    asset = make_asset(client, headers)
    assert asset['graph_node_id']
    graph = client.get(f"/api/v1/assets/{asset['id']}/graph").json()
    assert graph['available'] is True and graph['node_id'] == asset['graph_node_id']
    assert any(n['id'] == asset['graph_node_id'] and n['kind'] == 'asset' for n in graph['nodes'])


def test_rbac_viewer_and_analyst(client, owner, make_user):
    _, owner_headers = owner
    asset = make_asset(client, owner_headers)
    make_user('viewer@test.local', 'viewer-password-long-1', 'viewer')
    make_user('analyst@test.local', 'analyst-password-long-1', 'analyst')
    viewer = TestClient(client.app)
    vh = login(viewer, 'viewer@test.local', 'viewer-password-long-1')
    assert viewer.get('/api/v1/assets').status_code == 200
    assert viewer.post('/api/v1/assets', json={'name': 'Nope', 'kind': 'host', 'target': 'h'}, headers=vh).status_code == 403
    assert viewer.patch(f"/api/v1/assets/{asset['id']}", json={'name': 'Nope2'}, headers=vh).status_code == 403
    assert viewer.delete(f"/api/v1/assets/{asset['id']}", headers=vh).status_code == 403
    analyst = TestClient(client.app)
    ah = login(analyst, 'analyst@test.local', 'analyst-password-long-1')
    assert analyst.post(f"/api/v1/assets/{asset['id']}/authorize", json={'attestation': ATTESTATION}, headers=ah).status_code == 403


def test_cross_tenant_isolation(owner, second_tenant):
    client, headers = owner
    asset = make_asset(client, headers)
    other, oh = second_tenant['client'], second_tenant['headers']
    assert other.get('/api/v1/assets').json()['items'] == []
    assert other.get(f"/api/v1/assets/{asset['id']}").status_code == 404
    assert other.get(f"/api/v1/assets/{asset['id']}/graph").status_code == 404
    assert other.get(f"/api/v1/assets/{asset['id']}/authorizations").status_code == 404
    assert other.patch(f"/api/v1/assets/{asset['id']}", json={'name': 'Hijack'}, headers=oh).status_code == 404
    assert other.post(f"/api/v1/assets/{asset['id']}/authorize", json={'attestation': ATTESTATION}, headers=oh).status_code == 404
    assert other.post(f"/api/v1/assets/{asset['id']}/revoke-authorization", headers=oh).status_code == 404
    assert other.delete(f"/api/v1/assets/{asset['id']}", headers=oh).status_code == 404
    # The same target can exist in both tenants independently.
    assert other.post('/api/v1/assets', json={'name': 'Acme site', 'kind': 'web', 'target': 'https://example.org'}, headers=oh).status_code == 201
    assert len(client.get('/api/v1/assets').json()['items']) == 1


def test_delete_asset_with_revoked_credentials(owner):
    client, headers = owner
    asset = make_asset(client, headers)
    created = client.post(f"/api/v1/assets/{asset['id']}/credentials",
                          json={'kind': 'bearer', 'name': 'token', 'value': 'secret-token'},
                          headers=headers)
    assert created.status_code == 201, created.text
    revoked = client.delete(f"/api/v1/assets/{asset['id']}/credentials/{created.json()['id']}",
                            headers=headers)
    assert revoked.status_code == 200, revoked.text
    deleted = client.delete(f"/api/v1/assets/{asset['id']}", headers=headers)
    assert deleted.status_code == 200, deleted.text
