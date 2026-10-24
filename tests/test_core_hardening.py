from __future__ import annotations

from app.core.config import Settings
from app.core.security import resolve_secret, secret_ref_allowed
from tests.conftest import wait_job


def _settings(tmp_path, **overrides):
    base = dict(session_secret='s' * 40, admin_password='p' * 20, secrets_dir=tmp_path / 'secrets')
    base.update(overrides)
    return Settings(**base)


def test_sec_secret_refs_restricted_to_prefix_allowlist_and_secrets_dir(tmp_path, monkeypatch):
    settings = _settings(tmp_path, secret_env_allowlist='ARGUS_AWS_ROLE')
    monkeypatch.setenv('SESSION_SECRET', 'the-session-secret')
    monkeypatch.setenv('ARGUS_SECRET_GH', 'gh-token')
    monkeypatch.setenv('ARGUS_AWS_ROLE', 'arn:aws:iam::1:role/x')
    assert resolve_secret('env:SESSION_SECRET', settings) == ''
    assert resolve_secret('env:DATABASE_URL', settings) == ''
    assert resolve_secret('env:ARGUS_SECRET_GH', settings) == 'gh-token'
    assert resolve_secret('env:ARGUS_AWS_ROLE', settings) == 'arn:aws:iam::1:role/x'
    (tmp_path / 'secrets').mkdir()
    (tmp_path / 'secrets' / 'db').write_text('pw', encoding='utf-8')
    (tmp_path / 'outside').write_text('nope', encoding='utf-8')
    assert resolve_secret(f'file:{tmp_path / "secrets" / "db"}', settings) == 'pw'
    assert resolve_secret(f'file:{tmp_path / "outside"}', settings) == ''
    assert resolve_secret(f'file:{tmp_path / "secrets" / ".." / "outside"}', settings) == ''
    assert secret_ref_allowed('file:/proc/self/environ', settings)[0] is False
    assert secret_ref_allowed('literal:x', _settings(tmp_path, allow_literal_secret_refs=False))[0] is False
    assert resolve_secret('env:ANYTHING', _settings(tmp_path, secret_env_allowlist='*')) == ''  # unset var, but allowed


def test_sec_request_body_limit(owner):
    client, headers = owner
    big = {'items': ['x' * 1024] * 9000}  # ~9 MB
    response = client.post('/api/v1/assets/import', json=big, headers=headers)
    assert response.status_code == 413 and response.json()['code'] == 'payload_too_large'


def test_sec_api_key_scopes_validated(owner):
    client, headers = owner
    assert client.post('/api/v1/auth/api-keys', json={'name': 'bad', 'role': 'viewer', 'scopes': ['*']}, headers=headers).status_code == 400
    assert client.post('/api/v1/auth/api-keys', json={'name': 'bad2', 'role': 'viewer', 'scopes': ['findings:']}, headers=headers).status_code == 400
    assert client.post('/api/v1/auth/api-keys', json={'name': 'ok', 'role': 'viewer', 'scopes': ['ingest', 'findings:*', 'events:read']}, headers=headers).status_code == 201


def test_sec_pagination_offset_clamped(owner):
    client, headers = owner
    assert client.get('/api/v1/findings?cursor=999999999999999', headers=headers).status_code == 200


def test_sec_job_results_hidden_from_viewers(app, client, make_user, owner):
    owner_client, owner_headers = owner
    queue = app.state.queue

    @queue.handler('t.secretish')
    async def secretish(job, ctx):
        return {'token': 'should-not-leak-to-viewers'}

    job = client.portal.call(lambda: queue.enqueue('t.secretish', {}, tenant_id=app.state.default_tenant_id))
    done = wait_job(owner_client, owner_headers, job.id)
    assert done['result'] == {'token': 'should-not-leak-to-viewers'}
    from tests.conftest import login

    make_user('v@test.local', 'viewer-password-long-1', 'viewer')
    viewer_headers = login(client, 'v@test.local', 'viewer-password-long-1')
    assert client.get(f'/api/v1/ops/jobs/{job.id}', headers=viewer_headers).json()['result'] is None
