"""/api/v1/agents and /api/v1/evals, including queued runs with AI_PROVIDER=none and cross-tenant access."""
from __future__ import annotations

from app.models import AgentRun
from tests.conftest import login, wait_job
from tests.test_agents_support import no_network, seed_estate  # noqa: F401


def _seed(app, tenant_id, prefix='est'):
    with app.state.db_factory() as db:
        ids = seed_estate(db, tenant_id, prefix)
        db.commit()
    return ids


def test_specs_and_tools_listing(owner, make_user, client):
    c, headers = owner
    specs = c.get('/api/v1/agents/specs').json()['items']
    names = {s['name'] for s in specs}
    assert {'triage', 'investigate', 'hunt', 'redteam_plan', 'remediate', 'posture_report', 'swarm_responder'} <= names
    assert all(s['has_fallback'] and s['allowed'] and s['output_schema']['additionalProperties'] is False for s in specs)
    tools = c.get('/api/v1/agents/tools').json()['items']
    assert {t['name']: t['risk'] for t in tools}['propose_action'] == 'propose' and len(tools) >= 27
    make_user('viewer@test.local', 'viewer-password-long-1', 'viewer')
    viewer = login(client, 'viewer@test.local', 'viewer-password-long-1')
    assert client.get('/api/v1/agents/specs', headers=viewer).status_code == 200
    assert client.post('/api/v1/agents/run', json={'spec': 'triage', 'inputs': {}}, headers=viewer).status_code == 403
    assert c.get('/api/v1/agents/specs', headers={'X-API-Key': 'argus_deadbeef_notarealkey'}).status_code == 401


def test_run_triage_via_queue_with_fallback(owner, app, default_tenant_id):
    c, headers = owner
    ids = _seed(app, default_tenant_id)
    started = c.post('/api/v1/agents/run', json={'spec': 'triage', 'task': 'Triage this', 'finding_id': ids['f1']}, headers=headers)
    assert started.status_code == 202, started.text
    body = started.json()
    assert body['status'] == 'queued' and body['job_id'] and body['finding_id'] == ids['f1']
    job = wait_job(c, headers, body['job_id'])
    assert job['status'] == 'completed', job
    run = c.get(f"/api/v1/agents/runs/{body['id']}").json()
    assert run['status'] == 'completed' and run['provider'] == 'none' and run['model'] == 'rules-only'
    assert run['output']['severity_recommendation'] == 'critical' and run['output']['duplicates'] == [ids['f2']]
    assert 'steps' in run and run['inputs'] == {'finding_id': ids['f1']}
    listed = c.get('/api/v1/agents/runs', params={'spec': 'triage', 'status': 'completed', 'finding_id': ids['f1']}).json()
    assert [r['id'] for r in listed['items']] == [body['id']] and listed['next_cursor'] is None
    assert c.get('/api/v1/agents/runs', params={'spec': 'hunt'}).json()['items'] == []
    audit = c.get('/api/v1/ops/jobs').json()
    assert any(j['id'] == body['job_id'] for j in audit['items'])


def test_run_validation(owner, app, default_tenant_id, second_tenant):
    c, headers = owner
    assert c.post('/api/v1/agents/run', json={'spec': 'nope', 'inputs': {}}, headers=headers).status_code == 404
    other = _seed(app, second_tenant['tenant_id'], 'acme')
    assert c.post('/api/v1/agents/run', json={'spec': 'triage', 'finding_id': other['f1']}, headers=headers).status_code == 404
    assert c.post('/api/v1/agents/run', json={'spec': 'triage', 'inputs': {}}).status_code == 403  # CSRF
    hunt = c.post('/api/v1/agents/run', json={'spec': 'hunt', 'inputs': {'hypothesis': 'anything', 'hours': 1}}, headers=headers)
    assert hunt.status_code == 202 and wait_job(c, headers, hunt.json()['job_id'])['status'] == 'completed'


def test_runs_are_tenant_isolated(owner, app, default_tenant_id, second_tenant):
    c, headers = owner
    ids = _seed(app, default_tenant_id)
    started = c.post('/api/v1/agents/run', json={'spec': 'remediate', 'finding_id': ids['f1']}, headers=headers).json()
    wait_job(c, headers, started['job_id'])
    other, oh = second_tenant['client'], second_tenant['headers']
    assert other.get(f"/api/v1/agents/runs/{started['id']}").status_code == 404
    assert other.get('/api/v1/agents/runs').json()['items'] == []
    assert other.post(f"/api/v1/agents/runs/{started['id']}/cancel", headers=oh).status_code == 404
    # The other tenant can run its own agent and sees only its own run.
    theirs = other.post('/api/v1/agents/run', json={'spec': 'posture_report', 'inputs': {'days': 3}}, headers=oh)
    assert theirs.status_code == 202
    assert wait_job(other, oh, theirs.json()['job_id'])['status'] == 'completed'
    assert [r['id'] for r in other.get('/api/v1/agents/runs').json()['items']] == [theirs.json()['id']]


def test_cancel_run(owner, app, default_tenant_id):
    c, headers = owner
    with app.state.db_factory() as db:
        run = AgentRun(tenant_id=default_tenant_id, spec='hunt', task='stuck', status='queued', created_by='u', job_id='')
        db.add(run)
        db.commit()
        run_id = run.id
    cancelled = c.post(f'/api/v1/agents/runs/{run_id}/cancel', headers=headers)
    assert cancelled.status_code == 200 and cancelled.json()['status'] == 'cancelled'
    assert c.post(f'/api/v1/agents/runs/{run_id}/cancel', headers=headers).status_code == 409
    assert c.get(f'/api/v1/agents/runs/{run_id}').json()['status'] == 'cancelled'
    # Cancelling a queued job through the queue marks the job cancelled too.
    started = c.post('/api/v1/agents/run', json={'spec': 'hunt', 'inputs': {'hypothesis': 'x', 'hours': 1}}, headers=headers).json()
    response = c.post(f"/api/v1/agents/runs/{started['id']}/cancel", headers=headers)
    assert response.status_code in (200, 409)
    job = wait_job(c, headers, started['job_id'])
    assert job['status'] in ('cancelled', 'completed')


def test_evals_api(owner, app, default_tenant_id, second_tenant, make_user, client):
    c, headers = owner
    suites = c.get('/api/v1/evals/suites').json()['items']
    assert {s['name'] for s in suites} >= {'prompt_injection', 'triage_precision', 'hunt_recall'}
    assert c.post('/api/v1/evals/run', json={'suite': 'missing'}, headers=headers).status_code == 404
    assert c.post('/api/v1/evals/run', json={'suite': 'hunt_recall', 'spec': 'nope'}, headers=headers).status_code == 404
    started = c.post('/api/v1/evals/run', json={'suite': 'prompt_injection'}, headers=headers)
    assert started.status_code == 202, started.text
    body = started.json()
    job = wait_job(c, headers, body['job_id'], timeout=60)
    assert job['status'] == 'completed', job
    report = c.get(f"/api/v1/evals/{body['id']}").json()
    assert report['status'] == 'completed' and report['total'] >= 10 and report['failed'] == 0 and report['passed'] == report['total']
    assert all(case['passed'] for case in report['report']['cases'])
    listed = c.get('/api/v1/evals', params={'suite': 'prompt_injection'}).json()
    assert [e['id'] for e in listed['items']] == [body['id']] and 'report' not in listed['items'][0]
    assert c.get('/api/v1/evals', params={'suite': 'triage_precision'}).json()['items'] == []
    # Eval runs created agent runs that are visible and tagged.
    runs = c.get('/api/v1/agents/runs', params={'limit': 100}).json()['items']
    assert len(runs) >= report['total'] and all(r['task'].startswith('[eval prompt_injection:') for r in runs)
    # Cross-tenant and role checks.
    other = second_tenant['client']
    assert other.get(f"/api/v1/evals/{body['id']}").status_code == 404
    assert other.get('/api/v1/evals').json()['items'] == []
    make_user('viewer2@test.local', 'viewer-password-long-2', 'viewer')
    viewer = login(client, 'viewer2@test.local', 'viewer-password-long-2')
    assert client.get('/api/v1/evals/suites', headers=viewer).status_code == 200
    assert client.post('/api/v1/evals/run', json={'suite': 'hunt_recall'}, headers=viewer).status_code == 403
