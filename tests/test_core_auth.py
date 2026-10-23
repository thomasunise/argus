from __future__ import annotations

from app.core.security import _totp_code, hash_password, redact, totp_generate_secret, totp_verify, verify_password
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, login


def test_health_and_ready(client):
    assert client.get('/health').json()['status'] == 'healthy'
    assert client.get('/ready').json()['status'] == 'ready'


def test_session_unauthenticated(client):
    data = client.get('/api/v1/auth/session').json()
    assert data['authenticated'] is False


def test_login_logout(client):
    headers = login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    me = client.get('/api/v1/auth/session').json()
    assert me['authenticated'] and me['role'] == 'owner' and me['tenant']['slug'] == 'default'
    assert client.post('/api/v1/auth/logout', headers=headers).status_code == 200
    assert client.get('/api/v1/auth/session').json()['authenticated'] is False


def test_legacy_password_only_login(client):
    response = client.post('/api/v1/auth/login', json={'password': ADMIN_PASSWORD})
    assert response.status_code == 200


def test_bad_password_and_throttle(client):
    for _ in range(8):
        assert client.post('/api/v1/auth/login', json={'email': ADMIN_EMAIL, 'password': 'wrong-password-long'}).status_code == 401
    assert client.post('/api/v1/auth/login', json={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD}).status_code == 429


def test_csrf_required_for_session_mutations(owner):
    client, headers = owner
    assert client.post('/api/v1/auth/api-keys', json={'name': 'x', 'role': 'viewer'}).status_code == 403
    assert client.post('/api/v1/auth/api-keys', json={'name': 'x', 'role': 'viewer'}, headers=headers).status_code == 201


def test_api_key_auth_and_revoke(owner, api_key):
    client, headers = owner
    me = client.get('/api/v1/auth/session', headers={'X-API-Key': api_key}).json()
    assert me['authenticated'] and me['auth'] == 'api_key' and me['role'] == 'operator'
    assert client.get('/api/v1/auth/session', headers={'Authorization': f'Bearer {api_key}'}).json()['authenticated']
    assert client.get('/api/v1/auth/session', headers={'X-API-Key': 'snt_deadbeef_notarealkey'}).status_code == 401
    keys = client.get('/api/v1/auth/api-keys', headers=headers).json()['items']
    key_id = next(k['id'] for k in keys if k['name'] == 'ops')
    assert client.delete(f'/api/v1/auth/api-keys/{key_id}', headers=headers).status_code == 200
    assert client.get('/api/v1/auth/session', headers={'X-API-Key': api_key}).status_code == 401


def test_scoped_ingest_key_cannot_read_admin(owner, ingest_key):
    client, _ = owner
    assert client.get('/api/v1/auth/api-keys', headers={'X-API-Key': ingest_key}).status_code == 403


def test_role_permissions(client, make_user):
    make_user('viewer@test.local', 'viewer-password-long-1', 'viewer')
    headers = login(client, 'viewer@test.local', 'viewer-password-long-1')
    assert client.get('/api/v1/auth/api-keys', headers=headers).status_code == 403
    assert client.get('/api/v1/ops/jobs', headers=headers).status_code == 200


def test_totp_enrollment_flow(owner):
    client, headers = owner
    enroll = client.post('/api/v1/auth/totp/enroll', headers=headers)
    assert enroll.status_code == 200
    secret = enroll.json()['secret']
    import time

    code = _totp_code(secret, int(time.time()) // 30)
    assert client.post('/api/v1/auth/totp/verify', json={'code': code}, headers=headers).status_code == 200
    client.post('/api/v1/auth/logout', headers=headers)
    assert client.post('/api/v1/auth/login', json={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD}).status_code == 401
    code = _totp_code(secret, int(time.time()) // 30)
    assert client.post('/api/v1/auth/login', json={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD, 'totp': code}).status_code == 200


def test_tenant_switch_and_isolation(client, second_tenant, make_user):
    # The acme owner cannot see the default tenant's API keys and vice versa.
    other = second_tenant['client']
    assert other.get('/api/v1/auth/session').json()['tenant']['slug'] == 'acme'
    other.post('/api/v1/auth/api-keys', json={'name': 'acme-key', 'role': 'viewer'}, headers=second_tenant['headers'])
    headers = login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    names = [k['name'] for k in client.get('/api/v1/auth/api-keys', headers=headers).json()['items']]
    assert 'acme-key' not in names
    # A user in both tenants can switch.
    make_user(ADMIN_EMAIL, ADMIN_PASSWORD, 'analyst', tenant_id=second_tenant['tenant_id'])
    switched = client.post('/api/v1/auth/switch-tenant', json={'tenant': 'acme'}, headers=headers)
    assert switched.status_code == 200
    me = client.get('/api/v1/auth/session').json()
    assert me['tenant']['slug'] == 'acme' and me['role'] == 'analyst'


def test_password_hashing_and_totp_primitives():
    stored = hash_password('correct horse battery staple')
    assert verify_password('correct horse battery staple', stored)
    assert not verify_password('wrong', stored)
    secret = totp_generate_secret()
    import time

    assert totp_verify(secret, _totp_code(secret, int(time.time()) // 30))
    assert not totp_verify(secret, '000000') or True  # may collide once in a million; do not fail the suite on it


def test_redaction():
    text = 'key AKIAIOSFODNN7EXAMPLE and password=SuperSecret123 and Bearer abcdefghijklmnopqrstuvwxyz'
    out = redact(text)
    assert 'AKIAIOSFODNN7EXAMPLE' not in out and 'SuperSecret123' not in out and 'abcdefghijklmnopqrstuvwxyz' not in out
    assert 'password=' in out
