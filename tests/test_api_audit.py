from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.models import AuditEntry
from tests.conftest import login


def test_list_filters_verify_and_actions(owner):
    client, headers = owner
    asset = client.post('/api/v1/assets', json={'name': 'Site', 'kind': 'web', 'target': 'https://example.org'}, headers=headers).json()
    client.patch(f"/api/v1/assets/{asset['id']}", json={'owner': 'appsec'}, headers=headers)
    everything = client.get('/api/v1/audit').json()['items']
    assert everything[0]['action'] == 'assets.updated' and everything[0]['previous_hash'] == everything[1]['entry_hash']
    assert everything[0]['signed'] is True and isinstance(everything[0]['detail'], dict)
    by_prefix = client.get('/api/v1/audit?action=assets.').json()['items']
    assert [e['action'] for e in by_prefix] == ['assets.updated', 'assets.created']
    assert [e['action'] for e in client.get(f"/api/v1/audit?subject={asset['id']}&action=assets.created").json()['items']] == ['assets.created']
    assert client.get('/api/v1/audit?actor=nobody@nowhere').json()['items'] == []
    assert len(client.get('/api/v1/audit?since=1h&action=assets.').json()['items']) == 2
    assert client.get('/api/v1/audit?since=2000-01-01T00:00:00Z&until=2000-01-02T00:00:00Z').json()['items'] == []
    assert client.get('/api/v1/audit?since=bogus').status_code == 400
    assert client.get('/api/v1/audit?search=appsec').json()['items'][0]['action'] == 'assets.updated'
    page = client.get('/api/v1/audit?limit=1').json()
    assert len(page['items']) == 1 and page['next_cursor'] == '1'
    verify = client.get('/api/v1/audit/verify').json()
    assert verify['valid'] is True and verify['signed'] is True and verify['checked'] >= 4
    actions = {a['action']: a['count'] for a in client.get('/api/v1/audit/actions').json()['items']}
    assert actions['assets.created'] == 1 and actions['auth.login'] >= 1


def test_tamper_is_detected(owner, db, default_tenant_id):
    client, headers = owner
    client.post('/api/v1/assets', json={'name': 'Site', 'kind': 'web', 'target': 'https://example.org'}, headers=headers)
    entry = db.query(AuditEntry).filter(AuditEntry.tenant_id == default_tenant_id, AuditEntry.action == 'assets.created').one()
    entry.detail = entry.detail.replace('Site', 'Sate')
    db.commit()
    verify = client.get('/api/v1/audit/verify').json()
    assert verify['valid'] is False and verify['broken_at'] == entry.id


def test_export_jsonl_requires_admin_role(client, owner, make_user):
    _, headers = owner
    client.post('/api/v1/assets', json={'name': 'Site', 'kind': 'web', 'target': 'https://example.org'}, headers=headers)
    response = client.get('/api/v1/audit/export.jsonl?action=assets.')
    assert response.status_code == 200 and response.headers['content-type'].startswith('application/x-ndjson')
    records = [json.loads(line) for line in response.text.strip().splitlines()]
    assert len(records) == 1 and response.headers['x-row-count'] == '1'
    assert {'entry_hash', 'previous_hash', 'signature', 'tenant_id', 'detail'} <= set(records[0])
    assert client.get('/api/v1/audit?action=audit.exported').json()['items'][0]['detail']['rows'] == 1
    for email, role in (('viewer@test.local', 'viewer'), ('analyst@test.local', 'analyst'), ('operator@test.local', 'operator')):
        make_user(email, 'another-password-long-1', role)
        other = TestClient(client.app)
        login(other, email, 'another-password-long-1')
        assert other.get('/api/v1/audit').status_code == 200
        assert other.get('/api/v1/audit/export.jsonl').status_code == 403, role
    make_user('admin2@test.local', 'another-password-long-1', 'admin')
    admin = TestClient(client.app)
    login(admin, 'admin2@test.local', 'another-password-long-1')
    assert admin.get('/api/v1/audit/export.jsonl').status_code == 200


def test_cross_tenant_isolation(owner, second_tenant):
    client, headers = owner
    asset = client.post('/api/v1/assets', json={'name': 'Site', 'kind': 'web', 'target': 'https://example.org'}, headers=headers).json()
    other = second_tenant['client']
    acme = other.get('/api/v1/audit').json()['items']
    assert all(e['subject'] != asset['id'] for e in acme) and all(e['action'] != 'assets.created' for e in acme)
    assert other.get(f"/api/v1/audit?subject={asset['id']}").json()['items'] == []
    exported = other.get('/api/v1/audit/export.jsonl').text
    assert asset['id'] not in exported
    assert other.get('/api/v1/audit/verify').json()['valid'] is True
    assert client.get('/api/v1/audit/verify').json()['valid'] is True
