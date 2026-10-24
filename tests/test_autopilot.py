"""Autonomous pentest: off by default, needs an autonomous scope, caps tiers, keeps the scope check, honours
stop and the kill switch, and is tenant scoped. Uses fake adapters (no subprocess, no network) registered under
the names redteam_plan proposes per asset kind, and non-web assets so scope.check never resolves DNS."""
from __future__ import annotations

import pytest

from app.models import Asset, AssetAuthorization, dumps, loads
from app.testing import harness
from tests.conftest import login, wait_job


class _FakeAdapter(harness.TestAdapter):
    def __init__(self, name: str, tier: str, kinds: tuple[str, ...], findings: int = 1):
        self.name, self.tier, self.target_kinds, self._findings = name, tier, kinds, findings

    def available(self, settings) -> bool:
        return True

    async def run(self, plan_params, asset, scope, ctx):
        return [harness.NormalizedFinding(rule=f'{self.name}:x{i}', title=f'{self.name} finding {i}', description='d', severity='medium')
                for i in range(self._findings)]


# Names and tiers mirror redteam_plan's ADAPTERS_BY_KIND so the planner proposes them.
_FAKES = [('trivy', 'passive', ('repo', 'host', 'cloud_account', 'k8s_cluster')), ('semgrep', 'passive', ('repo',)),
          ('gitleaks', 'passive', ('repo',)), ('nuclei', 'active', ('web', 'database', 'network')),
          ('caldera', 'intrusive', ('host', 'k8s_cluster')), ('prowler', 'passive', ('cloud_account', 'identity_provider', 'saas'))]


@pytest.fixture
def fake_adapters():
    saved = {name: harness.ADAPTERS.get(name) for name, _, _ in _FAKES}
    for name, tier, kinds in _FAKES:
        harness.ADAPTERS[name] = _FakeAdapter(name, tier, kinds)
    yield
    for name, adapter in saved.items():
        if adapter is None:
            harness.ADAPTERS.pop(name, None)
        else:
            harness.ADAPTERS[name] = adapter


def _asset(app, tenant_id, *, kind='host', target='host-prod-1', env='production', allow_active=True, allow_intrusive=False, authorize=True,
           scan_root=None) -> str:
    if kind == 'repo' and scan_root is not None:
        (scan_root / target).mkdir(parents=True, exist_ok=True)
    with app.state.db_factory() as db:
        asset = Asset(tenant_id=tenant_id, name=target, kind=kind, target=target, environment=env, approved=True)
        db.add(asset)
        db.flush()
        if authorize:
            db.add(AssetAuthorization(tenant_id=tenant_id, asset_id=asset.id, authorized_by='u', attestation='ok',
                                      allow_active=allow_active, allow_intrusive=allow_intrusive))
        db.commit()
        return asset.id


def _scope(client, headers, asset_id, *, tiers=('passive', 'active'), autonomous=True) -> str:
    created = client.post('/api/v1/tests/scopes', json={'name': 'auto-scope', 'asset_ids': [asset_id], 'allowed_tiers': list(tiers),
                                                         'autonomous': autonomous, 'max_rps': 50}, headers=headers)
    assert created.status_code == 201, created.text
    return created.json()['id']


def _enable(app, tenant_id, **cfg):
    from app.models import Tenant

    app.state.settings.autopentest_enabled = True
    with app.state.db_factory() as db:
        tenant = db.get(Tenant, tenant_id)
        data = loads(tenant.settings_json, {})
        data['autopentest'] = {'enabled': True, **cfg}
        tenant.settings_json = dumps(data)
        db.commit()


def _run(client, headers, **body) -> dict:
    response = client.post('/api/v1/tests/autopilot', json=body, headers=headers)
    assert response.status_code == 202, response.text
    run = response.json()
    job = wait_job(client, headers, run['job_id'], timeout=120)
    assert job['status'] == 'completed', job
    return client.get(f"/api/v1/tests/autopilot/{run['id']}", headers=headers).json()


def test_disabled_by_default(app, owner, default_tenant_id, fake_adapters):
    client, headers = owner
    scope_id = _scope(client, headers, _asset(app, default_tenant_id))
    response = client.post('/api/v1/tests/autopilot', json={'scope_id': scope_id}, headers=headers)
    assert response.status_code == 403 and 'disabled' in response.json()['detail']


def test_scope_must_be_marked_autonomous(app, owner, default_tenant_id, fake_adapters):
    client, headers = owner
    _enable(app, default_tenant_id)
    scope_id = _scope(client, headers, _asset(app, default_tenant_id), autonomous=False)
    response = client.post('/api/v1/tests/autopilot', json={'scope_id': scope_id}, headers=headers)
    assert response.status_code == 403 and 'autonomous' in response.json()['detail']
    assert client.post(f'/api/v1/tests/scopes/{scope_id}/autonomous', json={'autonomous': True}, headers=headers).json()['autonomous'] is True
    audit = client.get('/api/v1/audit', params={'action': 'testing.scope.autonomous'}, headers=headers).json()['items']
    assert audit and audit[0]['subject'] == scope_id


def test_full_run_launches_passive_caps_intrusive_and_stops_early(app, owner, default_tenant_id, fake_adapters):
    client, headers = owner
    _enable(app, default_tenant_id)
    # host asset: planner proposes trivy (passive) and caldera (intrusive); scope allows passive+active, so caldera is capped out.
    scope_id = _scope(client, headers, _asset(app, default_tenant_id, kind='host'))
    run = _run(client, headers, scope_id=scope_id, max_tier='active', max_rounds=2)
    assert run['status'] == 'completed'
    launched = {s['adapter'] for s in run['steps'] if s['phase'] == 'launched'}
    assert launched == {'trivy'}
    assert run['test_runs'] == 1 and run['findings_new'] >= 1
    runs = client.get('/api/v1/tests/runs', headers=headers).json()['items']
    assert len(runs) == 1 and runs[0]['triggered_by'] == f"autopilot:{run['id']}" and runs[0]['status'] == 'completed'
    assert any(s['phase'] in ('stop_early', 'round_empty') for s in run['steps'])  # round 2 re-plans, nothing new, stops
    audit = client.get('/api/v1/audit', params={'action': 'testing.autopilot.completed'}, headers=headers).json()['items']
    assert audit and audit[0]['subject'] == run['id']


def test_active_tier_launches_when_allowed(app, owner, default_tenant_id, fake_adapters):
    client, headers = owner
    _enable(app, default_tenant_id)
    scope_id = _scope(client, headers, _asset(app, default_tenant_id, kind='database', target='db-orders'))
    run = _run(client, headers, scope_id=scope_id, max_tier='active')
    assert {s['adapter'] for s in run['steps'] if s['phase'] == 'launched'} == {'nuclei'} and run['test_runs'] == 1


def test_tenant_tier_cap_drops_active(app, owner, default_tenant_id, fake_adapters):
    client, headers = owner
    _enable(app, default_tenant_id, max_tier='passive')  # even though the scope allows active
    scope_id = _scope(client, headers, _asset(app, default_tenant_id, kind='database', target='db-cap'), tiers=('passive', 'active'))
    run = _run(client, headers, scope_id=scope_id, max_tier='active')
    assert not [s for s in run['steps'] if s['phase'] == 'launched'] and run['test_runs'] == 0
    skipped = [d for s in run['steps'] if s['phase'] == 'plan' for d in s['skipped']]
    assert any(d['adapter'] == 'nuclei' and 'cap' in d['reason'] for d in skipped)


def test_scope_check_enforced_without_authorization(app, owner, default_tenant_id, fake_adapters):
    client, headers = owner
    _enable(app, default_tenant_id)
    scope_id = _scope(client, headers, _asset(app, default_tenant_id, kind='host', target='host-noauth', authorize=False))
    run = _run(client, headers, scope_id=scope_id)
    assert run['test_runs'] == 0
    plans = [s for s in run['steps'] if s['phase'] == 'plan']
    assert plans and all(s['authorized'] is False for s in plans)  # the planner refuses to plan an unauthorized asset


def test_max_test_runs_cap(app, owner, settings, default_tenant_id, fake_adapters):
    client, headers = owner
    _enable(app, default_tenant_id, max_test_runs=1)
    # repo asset: planner proposes three passive adapters (semgrep, gitleaks, trivy); the cap stops after one.
    asset = _asset(app, default_tenant_id, kind='repo', target='myrepo', scan_root=settings.scan_root)
    scope_id = _scope(client, headers, asset, tiers=('passive',))
    run = _run(client, headers, scope_id=scope_id)
    assert run['test_runs'] == 1 and any(s['phase'] == 'cap_reached' for s in run['steps'])


def test_kill_switch_blocks_start(app, owner, default_tenant_id, fake_adapters):
    client, headers = owner
    _enable(app, default_tenant_id)
    app.state.settings.autopentest_kill_switch = True
    scope_id = _scope(client, headers, _asset(app, default_tenant_id))
    try:
        response = client.post('/api/v1/tests/autopilot', json={'scope_id': scope_id}, headers=headers)
        assert response.status_code == 403 and 'kill switch' in response.json()['detail']
    finally:
        app.state.settings.autopentest_kill_switch = False


def test_stop_request(app, owner, default_tenant_id, fake_adapters):
    client, headers = owner
    _enable(app, default_tenant_id)
    scope_id = _scope(client, headers, _asset(app, default_tenant_id))
    started = client.post('/api/v1/tests/autopilot', json={'scope_id': scope_id}, headers=headers).json()
    client.post(f"/api/v1/tests/autopilot/{started['id']}/stop", headers=headers)
    assert wait_job(client, headers, started['job_id'], timeout=120)['status'] == 'completed'
    run = client.get(f"/api/v1/tests/autopilot/{started['id']}", headers=headers).json()
    assert run['status'] in ('stopped', 'completed')


def test_assets_must_be_in_scope_and_runs_are_tenant_scoped(app, owner, second_tenant, default_tenant_id, fake_adapters):
    client, headers = owner
    _enable(app, default_tenant_id)
    scope_id = _scope(client, headers, _asset(app, default_tenant_id))
    outside = client.post('/api/v1/tests/autopilot', json={'scope_id': scope_id, 'asset_ids': ['not-in-scope']}, headers=headers)
    assert outside.status_code == 403 and 'not in the scope' in outside.json()['detail']
    started = client.post('/api/v1/tests/autopilot', json={'scope_id': scope_id}, headers=headers).json()
    other, oh = second_tenant['client'], second_tenant['headers']
    assert other.get(f"/api/v1/tests/autopilot/{started['id']}", headers=oh).status_code == 404
    assert started['id'] not in [r['id'] for r in other.get('/api/v1/tests/autopilot', headers=oh).json()['items']]
    wait_job(client, headers, started['job_id'], timeout=120)


def test_analyst_cannot_start(app, client, make_user, default_tenant_id, fake_adapters):
    _enable(app, default_tenant_id)
    make_user('analyst2@test.local', 'analyst-password-long-123456', 'analyst')
    headers = login(client, 'analyst2@test.local', 'analyst-password-long-123456')
    assert client.post('/api/v1/tests/autopilot', json={'scope_id': 'x'}, headers=headers).status_code == 403
