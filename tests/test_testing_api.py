"""API tests for the testing harness: adapters, scopes, plans, ad-hoc scans, runs, the full
queued scan path, permission gating and cross-tenant isolation."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.models import Asset, AssetAuthorization
from app.testing.adapters import trivy
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, login, wait_job

TRIVY_REPORT = (Path(__file__).parent / 'fixtures' / 'testing' / 'trivy' / 'report.json').read_text(encoding='utf-8')


def _make_asset(app, tenant_id, *, kind='repo', target='repo', env='production', scan_root=None,
                allow_active=False, allow_intrusive=False) -> str:
    if scan_root is not None and kind == 'repo':
        (scan_root / target).mkdir(parents=True, exist_ok=True)
    with app.state.db_factory() as db:
        asset = Asset(tenant_id=tenant_id, name='app', kind=kind, target=target, environment=env, approved=True)
        db.add(asset)
        db.flush()
        db.add(AssetAuthorization(tenant_id=tenant_id, asset_id=asset.id, authorized_by='u', attestation='ok',
                                  allow_active=allow_active, allow_intrusive=allow_intrusive))
        db.commit()
        return asset.id


def _create_scope(client, headers, asset_id, tiers=('passive',)):
    resp = client.post('/api/v1/tests/scopes', json={'name': 'default-scope', 'asset_ids': [asset_id],
                                                      'allowed_tiers': list(tiers), 'max_rps': 10}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()['id']


def test_list_adapters(owner):
    client, headers = owner
    data = client.get('/api/v1/tests/adapters', headers=headers).json()
    names = {a['name'] for a in data['items']}
    assert {'web_baseline', 'trivy', 'nuclei', 'zap', 'prowler', 'caldera', 'semgrep', 'gitleaks'} <= names
    web = next(a for a in data['items'] if a['name'] == 'web_baseline')
    assert web['tier'] == 'passive' and 'web' in web['target_kinds']


def test_scope_crud_and_validation(owner):
    client, headers = owner
    # invalid tier rejected
    bad = client.post('/api/v1/tests/scopes', json={'name': 's', 'allowed_tiers': ['nope']}, headers=headers)
    assert bad.status_code == 422
    bad_window = client.post('/api/v1/tests/scopes', json={'name': 's', 'window_start': '25:00'}, headers=headers)
    assert bad_window.status_code == 422
    created = client.post('/api/v1/tests/scopes', json={'name': 's1', 'asset_ids': ['x'], 'allowed_tiers': ['passive', 'active'],
                                                        'window_start': '02:00', 'window_end': '04:00'}, headers=headers)
    assert created.status_code == 201
    sid = created.json()['id']
    assert client.get(f'/api/v1/tests/scopes/{sid}', headers=headers).json()['allowed_tiers'] == ['passive', 'active']
    assert client.get('/api/v1/tests/scopes', headers=headers).json()['items']
    assert client.post(f'/api/v1/tests/scopes/{sid}/revoke', headers=headers).status_code == 200


def test_plan_crud_and_unknown_adapter(owner):
    client, headers = owner
    sid = _create_scope(client, headers, 'asset-x')
    bad = client.post('/api/v1/tests/plans', json={'name': 'p', 'scope_id': sid, 'adapters': ['nope']}, headers=headers)
    assert bad.status_code == 422
    ok = client.post('/api/v1/tests/plans', json={'name': 'p1', 'scope_id': sid, 'adapters': ['trivy'],
                                                   'params': {'config': 'auto'}, 'schedule_minutes': 60}, headers=headers)
    assert ok.status_code == 201
    pid = ok.json()['id']
    assert client.get(f'/api/v1/tests/plans/{pid}', headers=headers).json()['adapters'] == ['trivy']


def test_viewer_cannot_create_scope_but_can_read(client, make_user):
    make_user('viewer@test.local', 'viewer-password-long-1', 'viewer')
    headers = login(client, 'viewer@test.local', 'viewer-password-long-1')
    assert client.get('/api/v1/tests/adapters', headers=headers).status_code == 200
    assert client.post('/api/v1/tests/scopes', json={'name': 's', 'allowed_tiers': ['passive']}, headers=headers).status_code == 403


def test_scan_denied_without_authorization(app, owner, settings):
    client, headers = owner
    tenant_id = app.state.default_tenant_id
    # asset with no authorization record
    (settings.scan_root / 'noauth').mkdir(parents=True, exist_ok=True)
    with app.state.db_factory() as db:
        asset = Asset(tenant_id=tenant_id, name='app', kind='repo', target='noauth', environment='production')
        db.add(asset)
        db.commit()
        asset_id = asset.id
    sid = _create_scope(client, headers, asset_id)
    resp = client.post('/api/v1/scans', json={'asset_id': asset_id, 'adapter': 'trivy', 'scope_id': sid}, headers=headers)
    assert resp.status_code == 403
    assert resp.json()['code'] == 'scope_denied'


def test_full_scan_flow(app, owner, settings, monkeypatch):
    client, headers = owner
    tenant_id = app.state.default_tenant_id

    async def fake(argv, timeout, cwd=None, env=None, stdin=None):
        return 0, TRIVY_REPORT, ''

    monkeypatch.setattr(trivy, 'run_tool', fake)
    asset_id = _make_asset(app, tenant_id, target='scanme', scan_root=settings.scan_root)
    sid = _create_scope(client, headers, asset_id)
    resp = client.post('/api/v1/scans', json={'asset_id': asset_id, 'adapter': 'trivy', 'scope_id': sid}, headers=headers)
    assert resp.status_code == 202, resp.text
    job_id = resp.json()['job_id']
    wait_job(client, headers, job_id)
    run = client.get(f"/api/v1/tests/runs/{resp.json()['id']}", headers=headers).json()
    assert run['status'] == 'completed' and run['result_count'] == 3
    assert len(run['results']) == 3
    # findings were created for the tenant
    scans = client.get('/api/v1/scans', headers=headers).json()
    assert any(s['id'] == resp.json()['id'] for s in scans['items'])


def test_plan_run_enqueues(app, owner, settings, monkeypatch):
    client, headers = owner
    tenant_id = app.state.default_tenant_id

    async def fake(argv, timeout, cwd=None, env=None, stdin=None):
        return 0, TRIVY_REPORT, ''

    monkeypatch.setattr(trivy, 'run_tool', fake)
    asset_id = _make_asset(app, tenant_id, target='planrepo', scan_root=settings.scan_root)
    sid = _create_scope(client, headers, asset_id)
    pid = client.post('/api/v1/tests/plans', json={'name': 'p', 'scope_id': sid, 'adapters': ['trivy']}, headers=headers).json()['id']
    resp = client.post(f'/api/v1/tests/plans/{pid}/run', headers=headers)
    assert resp.status_code == 202
    runs = resp.json()['items']
    assert len(runs) == 1 and runs[0]['status'] == 'queued'
    wait_job(client, headers, runs[0]['job_id'])
    got = client.get(f"/api/v1/tests/runs/{runs[0]['id']}", headers=headers).json()
    assert got['status'] == 'completed'


def test_runs_list_cross_tenant_isolation(app, owner, second_tenant, settings, monkeypatch):
    client, headers = owner
    tenant_id = app.state.default_tenant_id

    async def fake(argv, timeout, cwd=None, env=None, stdin=None):
        return 0, TRIVY_REPORT, ''

    monkeypatch.setattr(trivy, 'run_tool', fake)
    asset_id = _make_asset(app, tenant_id, target='isorepo', scan_root=settings.scan_root)
    sid = _create_scope(client, headers, asset_id)
    run_id = client.post('/api/v1/scans', json={'asset_id': asset_id, 'adapter': 'trivy', 'scope_id': sid},
                         headers=headers).json()['id']
    other, oheaders = second_tenant['client'], second_tenant['headers']
    # Second tenant sees none of the first tenant's scopes or runs.
    assert other.get('/api/v1/tests/scopes', headers=oheaders).json()['items'] == []
    assert other.get('/api/v1/tests/runs', headers=oheaders).json()['items'] == []
    assert other.get(f'/api/v1/tests/runs/{run_id}', headers=oheaders).status_code == 404
    assert other.get(f'/api/v1/scans/{run_id}', headers=oheaders).status_code == 404


def test_unauthenticated_rejected(client):
    assert client.get('/api/v1/tests/adapters').status_code == 401
    assert client.post('/api/v1/scans', json={'asset_id': 'x', 'adapter': 'trivy', 'scope_id': 's'}).status_code == 401
