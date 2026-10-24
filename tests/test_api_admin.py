from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import ADMIN_EMAIL, login


def as_user(client, make_user, email, role, password='member-password-long-1'):
    user_id = make_user(email, password, role)
    other = TestClient(client.app)
    headers = login(other, email, password)
    return other, headers, user_id


# ---------------------------------------------------------------- tenants


def test_tenant_list_create_patch(client, owner, make_user):
    _, headers = owner
    tenants = client.get('/api/v1/admin/tenants').json()['items']
    assert [t['slug'] for t in tenants] == ['default'] and tenants[0]['role'] == 'owner'
    assert client.post('/api/v1/admin/tenants', json={'slug': 'Bad Slug!', 'name': 'Bad'}, headers=headers).status_code == 400
    created = client.post('/api/v1/admin/tenants', json={'slug': 'Globex', 'name': 'Globex Corp'}, headers=headers)
    assert created.status_code == 201, created.text
    tenant = created.json()
    assert tenant['slug'] == 'globex' and tenant['role'] == 'owner'
    assert client.post('/api/v1/admin/tenants', json={'slug': 'globex', 'name': 'Again'}, headers=headers).status_code == 409
    assert [t['slug'] for t in client.get('/api/v1/admin/tenants').json()['items']] == ['default', 'globex']
    # The creator is the owner of the new tenant and can switch into it.
    switched = client.post('/api/v1/auth/switch-tenant', json={'tenant': 'globex'}, headers=headers)
    assert switched.status_code == 200
    me = client.get('/api/v1/auth/session').json()
    assert me['tenant']['slug'] == 'globex' and me['role'] == 'owner'
    gh = {'X-CSRF-Token': switched.json()['csrf']}
    assert client.get('/api/v1/admin/overview').json()['members']['total'] == 1
    assert client.patch(f"/api/v1/admin/tenants/{tenant['id']}", json={'is_active': False}, headers=gh).status_code == 409
    renamed = client.patch(f"/api/v1/admin/tenants/{tenant['id']}", json={'name': 'Globex Inc', 'actions_enabled': True}, headers=gh)
    assert renamed.status_code == 200 and renamed.json()['name'] == 'Globex Inc' and renamed.json()['actions_enabled'] is True
    audit = client.get('/api/v1/audit?action=admin.tenant_').json()['items']
    assert {e['action'] for e in audit} == {'admin.tenant_created', 'admin.tenant_updated'}
    assert client.patch('/api/v1/admin/tenants/missing', json={'name': 'xx'}, headers=gh).status_code == 404
    # Admins (non-owners) cannot manage tenants at all.
    admin, ah, _ = as_user(client, make_user, 'admin2@test.local', 'admin')
    assert admin.get('/api/v1/admin/tenants').status_code == 403
    assert admin.post('/api/v1/admin/tenants', json={'slug': 'nope', 'name': 'Nope'}, headers=ah).status_code == 403


def test_tenant_creation_requires_interactive_user(owner, api_key):
    client, headers = owner
    owner_key = client.post('/api/v1/auth/api-keys', json={'name': 'root', 'role': 'owner'}, headers=headers).json()['key']
    response = client.post('/api/v1/admin/tenants', json={'slug': 'bykey', 'name': 'By Key'}, headers={'X-API-Key': owner_key})
    assert response.status_code == 403
    assert client.post('/api/v1/admin/tenants', json={'slug': 'bykey', 'name': 'By Key'}, headers={'X-API-Key': api_key}).status_code == 403


# ---------------------------------------------------------------- users and roles


def test_user_lifecycle_and_last_owner_protection(client, owner, make_user):
    _, headers = owner
    me = client.get('/api/v1/auth/session').json()['user']['id']
    # Temp password is returned once and works for login.
    created = client.post('/api/v1/admin/users', json={'email': 'Analyst@Test.local', 'role': 'analyst'}, headers=headers)
    assert created.status_code == 201, created.text
    analyst = created.json()
    assert analyst['email'] == 'analyst@test.local' and analyst['role'] == 'analyst' and analyst['created'] is True
    temp = analyst['temporary_password']
    fresh = TestClient(client.app)
    login(fresh, 'analyst@test.local', temp)
    assert fresh.get('/api/v1/auth/session').json()['role'] == 'analyst'
    audit = client.get('/api/v1/audit?action=admin.user_created').json()['items'][0]
    assert temp not in str(audit['detail']) and audit['detail']['email'] == 'analyst@test.local'
    # Invite flag creates a user without a local password.
    invited = client.post('/api/v1/admin/users', json={'email': 'invitee@test.local', 'role': 'viewer', 'invite': True}, headers=headers).json()
    assert invited['has_password'] is False and invited['invited'] is True and 'temporary_password' not in invited
    assert client.post('/api/v1/auth/login', json={'email': 'invitee@test.local', 'password': 'anything-long-enough-1'}).status_code == 401
    assert client.post('/api/v1/admin/users', json={'email': 'invitee@test.local', 'role': 'viewer'}, headers=headers).status_code == 409
    assert client.post('/api/v1/admin/users', json={'email': 'not-an-email', 'role': 'viewer'}, headers=headers).status_code == 400
    assert client.post('/api/v1/admin/users', json={'email': 'short@test.local', 'password': 'short'}, headers=headers).status_code == 422
    users = client.get('/api/v1/admin/users').json()['items']
    assert [u['email'] for u in users] == [ADMIN_EMAIL, 'analyst@test.local', 'invitee@test.local']
    assert [u['email'] for u in client.get('/api/v1/admin/users?role=analyst').json()['items']] == ['analyst@test.local']
    assert [u['email'] for u in client.get('/api/v1/admin/users?search=invitee').json()['items']] == ['invitee@test.local']
    # Patch, reset password, role changes.
    patched = client.patch(f"/api/v1/admin/users/{analyst['id']}", json={'display_name': 'Ana Lyst'}, headers=headers)
    assert patched.status_code == 200 and patched.json()['display_name'] == 'Ana Lyst'
    reset = client.post(f"/api/v1/admin/users/{analyst['id']}/reset-password", headers=headers).json()
    assert reset['temporary_password'] != temp
    login(TestClient(client.app), 'analyst@test.local', reset['temporary_password'])
    promoted = client.post('/api/v1/admin/memberships', json={'user_id': analyst['id'], 'role': 'operator'}, headers=headers)
    assert promoted.status_code == 200 and promoted.json()['role'] == 'operator'
    assert client.get('/api/v1/audit?action=admin.role_changed').json()['items'][0]['detail'] == {'email': 'analyst@test.local', 'from': 'analyst', 'to': 'operator'}
    # Last owner protection: demote, deactivate or remove the only owner is refused.
    assert client.post('/api/v1/admin/memberships', json={'user_id': me, 'role': 'admin'}, headers=headers).status_code == 409
    assert client.delete(f'/api/v1/admin/users/{me}', headers=headers).status_code == 409
    assert client.patch(f'/api/v1/admin/users/{me}', json={'is_active': False}, headers=headers).status_code == 409
    # Promote a second owner, then the original can step down.
    assert client.post('/api/v1/admin/memberships', json={'user_id': analyst['id'], 'role': 'owner'}, headers=headers).status_code == 200
    assert client.get('/api/v1/admin/overview').json()['members']['active_owners'] == 2
    assert client.post('/api/v1/admin/memberships', json={'user_id': me, 'role': 'admin'}, headers=headers).status_code == 200
    # Now the analyst is the last owner.
    assert client.get('/api/v1/auth/session').json()['role'] == 'admin'
    admin_headers = headers
    assert client.delete(f"/api/v1/admin/users/{analyst['id']}", headers=admin_headers).status_code == 403  # admins cannot touch owners
    assert client.delete(f"/api/v1/admin/users/{invited['id']}", headers=admin_headers).status_code == 200
    assert len(client.get('/api/v1/admin/users').json()['items']) == 2
    assert client.get('/api/v1/audit/verify').json()['valid'] is True


def test_role_assignment_limits(client, owner, make_user):
    _, headers = owner
    admin, ah, admin_id = as_user(client, make_user, 'admin2@test.local', 'admin')
    assert admin.post('/api/v1/admin/users', json={'email': 'newowner@test.local', 'role': 'owner'}, headers=ah).status_code == 403
    created = admin.post('/api/v1/admin/users', json={'email': 'newadmin@test.local', 'role': 'admin'}, headers=ah)
    assert created.status_code == 201
    assert admin.post('/api/v1/admin/memberships', json={'user_id': created.json()['id'], 'role': 'owner'}, headers=ah).status_code == 403
    owner_id = client.get('/api/v1/auth/session').json()['user']['id']
    assert admin.post('/api/v1/admin/memberships', json={'user_id': owner_id, 'role': 'viewer'}, headers=ah).status_code == 403
    assert admin.patch(f'/api/v1/admin/users/{owner_id}', json={'is_active': False}, headers=ah).status_code == 403
    assert admin.post(f'/api/v1/admin/users/{owner_id}/reset-password', headers=ah).status_code == 403
    assert admin.post('/api/v1/admin/memberships', json={'user_id': 'missing', 'role': 'viewer'}, headers=ah).status_code == 404
    operator, oh, _ = as_user(client, make_user, 'operator@test.local', 'operator')
    assert operator.get('/api/v1/admin/users').status_code == 403
    assert operator.get('/api/v1/admin/settings').status_code == 403
    assert operator.get('/api/v1/admin/overview').status_code == 403


def test_memberships_are_tenant_scoped(client, owner, second_tenant, make_user):
    _, headers = owner
    acme_user = make_user('acme-analyst@acme.test', 'acme-password-long-123456', 'analyst', tenant_id=second_tenant['tenant_id'])
    emails = [u['email'] for u in client.get('/api/v1/admin/users').json()['items']]
    assert 'acme-analyst@acme.test' not in emails
    assert client.patch(f'/api/v1/admin/users/{acme_user}', json={'display_name': 'x'}, headers=headers).status_code == 404
    assert client.delete(f'/api/v1/admin/users/{acme_user}', headers=headers).status_code == 404
    assert client.post(f'/api/v1/admin/users/{acme_user}/reset-password', headers=headers).status_code == 404
    # An account that exists in another tenant cannot be attached here (that membership would allow a password
    # reset or deactivation of a user this tenant does not own), and the error does not reveal where it lives.
    added = client.post('/api/v1/admin/users', json={'email': 'acme-analyst@acme.test', 'role': 'viewer'}, headers=headers)
    assert added.status_code == 409
    assert client.post('/api/v1/admin/memberships', json={'user_id': acme_user, 'role': 'viewer'}, headers=headers).status_code == 404
    other = second_tenant['client']
    acme_roles = {u['email']: u['role'] for u in other.get('/api/v1/admin/users').json()['items']}
    assert acme_roles['acme-analyst@acme.test'] == 'analyst' and ADMIN_EMAIL not in acme_roles


# ---------------------------------------------------------------- settings


def test_tenant_settings_whitelist(client, owner, make_user):
    _, headers = owner
    current = client.get('/api/v1/admin/settings').json()
    assert current['ai_provider'] is None and current['effective_ai_provider'] == 'none' and current['actions_enabled'] is False
    assert client.patch('/api/v1/admin/settings', json={'theme': 'dark'}, headers=headers).status_code == 400
    assert client.patch('/api/v1/admin/settings', json={'ai_provider': 'skynet'}, headers=headers).status_code == 400
    assert client.patch('/api/v1/admin/settings', json={'retention_days': 3}, headers=headers).status_code == 400
    assert client.patch('/api/v1/admin/settings', json={'default_min_severity_for_notifications': 'urgent'}, headers=headers).status_code == 400
    inline = client.patch('/api/v1/admin/settings', json={'action_credentials': {'aws': 'literal:AKIAIOSFODNN7EXAMPLE'}}, headers=headers)
    assert inline.status_code == 400 and inline.json()['code'] == 'inline_secret'
    updated = client.patch('/api/v1/admin/settings', json={'ai_provider': 'ollama', 'retention_days': 365, 'default_min_severity_for_notifications': 'medium',
                                                           'action_credentials': {'aws': 'env:ARGUS_AWS_ROLE', 'okta': 'secrets:okta_token'}}, headers=headers)
    assert updated.status_code == 200, updated.text
    data = updated.json()
    assert data['effective_ai_provider'] == 'ollama' and data['retention_days'] == 365 and data['action_credentials']['okta'] == 'secrets:okta_token'
    audit = client.get('/api/v1/audit?action=admin.settings_changed').json()['items'][0]['detail']['changes']
    assert set(audit) == {'ai_provider', 'retention_days', 'default_min_severity_for_notifications', 'action_credentials'}
    assert 'AKIAIOSFODNN7EXAMPLE' not in str(client.get('/api/v1/audit').json())
    cleared = client.patch('/api/v1/admin/settings', json={'ai_provider': None, 'retention_days': None}, headers=headers).json()
    assert cleared['ai_provider'] is None and cleared['retention_days'] is None and cleared['effective_ai_provider'] == 'none'
    # actions_enabled is owner-only and reflected in the session payload.
    admin, ah, _ = as_user(client, make_user, 'admin2@test.local', 'admin')
    assert admin.get('/api/v1/admin/settings').status_code == 200
    assert admin.patch('/api/v1/admin/settings', json={'actions_enabled': True}, headers=ah).status_code == 403
    assert admin.patch('/api/v1/admin/settings', json={'retention_days': 30}, headers=ah).status_code == 200
    assert client.patch('/api/v1/admin/settings', json={'actions_enabled': True}, headers=headers).json()['actions_enabled'] is True
    assert client.get('/api/v1/auth/session').json()['tenant']['actions_enabled'] is True
    overview = client.get('/api/v1/admin/overview').json()
    assert overview['settings_keys'] == ['action_credentials', 'default_min_severity_for_notifications', 'retention_days'] and overview['members']['total'] == 2


def test_settings_are_per_tenant(owner, second_tenant):
    client, headers = owner
    client.patch('/api/v1/admin/settings', json={'retention_days': 90}, headers=headers)
    other = second_tenant['client']
    assert other.get('/api/v1/admin/settings').json()['retention_days'] is None
    assert client.get('/api/v1/admin/settings').json()['retention_days'] == 90
    assert other.get('/api/v1/admin/overview').json()['members']['total'] == 1
