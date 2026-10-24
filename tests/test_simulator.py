"""Agentic attack simulator: every scenario is caught by its rules, evasion variants show gaps, the sandbox is
isolated from the real tenant, and runs are tenant scoped."""
from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.core.config import Settings
from app.models import Finding, SecurityEvent, Tenant
from app.models.detections import Detection, DetectionRuleState
from app.simulator import SCENARIOS, execute, runner
from app.simulator.scenarios import Build
from tests.conftest import wait_job


def _start(client, headers, **body) -> dict:
    response = client.post('/api/v1/simulations', json=body, headers=headers)
    assert response.status_code == 202, response.text
    return response.json()


def _finish(client, headers, run: dict) -> dict:
    job = wait_job(client, headers, run['job_id'], timeout=120)
    assert job['status'] == 'completed', job
    return client.get(f"/api/v1/simulations/{run['id']}", headers=headers).json()


def test_scenario_catalog(owner):
    client, headers = owner
    items = client.get('/api/v1/simulations/scenarios', headers=headers).json()['items']
    assert {i['id'] for i in items} == set(SCENARIOS) and all(i['expected_rules'] and i['techniques'] for i in items)


@pytest.mark.parametrize('scenario_id', sorted(SCENARIOS))
def test_each_scenario_is_detected_with_default_rules(app, client, scenario_id):
    settings: Settings = app.state.settings
    with app.state.db_factory() as db:
        tenant = db.get(Tenant, app.state.default_tenant_id)
        sandbox = runner.sandbox_for(db, tenant)
        report = runner.run_scenario(db, tenant, sandbox, scenario_id, intensity='normal', evasion=False, run_id='t-run', settings=settings)
        db.commit()
    assert report['outcome'] == 'detected', (report['missed_rules'], report['fired_rules'], report['detections'])
    assert not report['rule_errors']


def test_full_run_through_the_api_reports_coverage_and_leaves_no_trace(owner, db, default_tenant_id):
    client, headers = owner
    before = {model: db.scalar(select(func.count()).select_from(model).where(model.tenant_id == default_tenant_id))
              for model in (SecurityEvent, Detection, Finding)}
    run = _finish(client, headers, _start(client, headers))
    assert run['status'] == 'completed' and run['coverage'] == 1.0
    assert run['summary']['detected'] == len(SCENARIOS) and run['summary']['gaps'] == []
    db.expire_all()
    after = {model: db.scalar(select(func.count()).select_from(model).where(model.tenant_id == default_tenant_id))
             for model in (SecurityEvent, Detection, Finding)}
    assert before == after  # nothing reached the real tenant
    sandbox = db.execute(select(Tenant).where(Tenant.slug == f'sim-{default_tenant_id[:8]}')).scalar_one()
    assert sandbox.is_active is False and sandbox.actions_enabled is False
    assert db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.tenant_id == sandbox.id)) == 0  # purged afterwards
    listed = client.get('/api/v1/simulations', headers=headers).json()['items']
    assert listed[0]['id'] == run['id'] and 'results' not in listed[0]
    audit = client.get('/api/v1/audit', params={'action': 'simulation.completed'}, headers=headers).json()['items']
    assert audit and audit[0]['subject'] == run['id']


def test_evasion_variant_reveals_gaps(owner):
    client, headers = owner
    run = _finish(client, headers, _start(client, headers, scenarios=['agent_swarm_credential_spray', 'autonomous_privilege_escalation',
                                                                      'machine_speed_recon'], evasion=True))
    outcomes = {r['scenario']: r['outcome'] for r in run['results']}
    assert outcomes['agent_swarm_credential_spray'] == 'missed'
    assert outcomes['autonomous_privilege_escalation'] == 'missed'
    assert run['coverage'] < 1.0 and run['summary']['gaps']


def test_disabled_rule_shows_as_gap(owner, db, default_tenant_id):
    client, headers = owner
    db.add(DetectionRuleState(tenant_id=default_tenant_id, rule_id='k8s.privileged_workload', enabled=False))
    db.commit()
    run = _finish(client, headers, _start(client, headers, scenarios=['rogue_k8s_agent']))
    result = run['results'][0]
    assert result['outcome'] == 'missed' and result['disabled_rules'] == ['k8s.privileged_workload']


def test_validation_permissions_and_tenancy(owner, second_tenant, make_user, app):
    client, headers = owner
    assert client.post('/api/v1/simulations', json={'scenarios': ['nope']}, headers=headers).status_code == 422
    assert client.post('/api/v1/simulations', json={'intensity': 'extreme'}, headers=headers).status_code == 422
    run = _start(client, headers, scenarios=['canary_grab'])
    other = second_tenant['client']
    assert other.get(f"/api/v1/simulations/{run['id']}", headers=second_tenant['headers']).status_code == 404
    assert run['id'] not in [r['id'] for r in other.get('/api/v1/simulations', headers=second_tenant['headers']).json()['items']]
    from fastapi.testclient import TestClient
    from tests.conftest import login

    make_user('analyst@test.local', 'analyst-password-long-123456', 'analyst')
    analyst = TestClient(app)
    ah = login(analyst, 'analyst@test.local', 'analyst-password-long-123456')
    assert analyst.post('/api/v1/simulations', json={}, headers=ah).status_code == 403  # detections:run is operator+
    assert analyst.get('/api/v1/simulations/scenarios', headers=ah).status_code == 200
    wait_job(client, headers, run['job_id'], timeout=60)


def test_purge_refuses_real_tenants(app, client):
    with app.state.db_factory() as db:
        with pytest.raises(PermissionError):
            runner.purge(db, db.get(Tenant, app.state.default_tenant_id))


def test_execute_rejects_foreign_run(app, second_tenant):
    with app.state.db_factory() as db:
        from app.models.simulation import SimulationRun

        run = SimulationRun(tenant_id=app.state.default_tenant_id, scenarios_json='["canary_grab"]')
        db.add(run)
        db.commit()
        run_id = run.id
    with pytest.raises(PermissionError):
        execute(app.state.db_factory, app.state.settings, second_tenant['tenant_id'], run_id)


def test_intensity_scales_volume():
    low = SCENARIOS['agent_swarm_credential_spray'].build(Build(run_id='x', intensity='low'))
    high = SCENARIOS['agent_swarm_credential_spray'].build(Build(run_id='x', intensity='high'))
    assert len(high.events) > len(low.events)
    assert all(e.metadata['simulation'] is True and e.metadata['user_agent'] for e in high.events)
