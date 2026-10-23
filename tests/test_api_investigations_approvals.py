from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from app.core.findings import upsert_finding
from app.models import AgentRun, Investigation, dumps, utcnow
from tests.conftest import login


def make_finding(db, tenant_id, rule='r1'):
    finding, _ = upsert_finding(db, tenant_id, source='test', rule=rule, title='Finding', description='d', severity_name='high')
    db.commit()
    return finding


# ---------------------------------------------------------------- investigations


def test_investigations_merge_legacy_and_agent_runs(owner, db, default_tenant_id):
    client, _ = owner
    finding = make_finding(db, default_tenant_id)
    legacy = Investigation(tenant_id=default_tenant_id, finding_id=finding.id, model='rules-only', summary='Rules summary', confidence='low',
                           recommended_steps=dumps(['rotate key']), limitations=dumps(['no model']), created_at=utcnow() - timedelta(hours=2))
    run = AgentRun(tenant_id=default_tenant_id, spec='triage', task='triage it', status='completed', provider='none', model='fallback',
                   output_json=dumps({'summary': 'Agent summary', 'confidence': 'medium', 'recommended_steps': ['isolate']}), finding_id=finding.id,
                   created_at=utcnow() - timedelta(hours=1))
    hunt = AgentRun(tenant_id=default_tenant_id, spec='hunt', task='hunt', status='completed', created_at=utcnow())
    db.add_all([legacy, run, hunt])
    db.commit()
    items = client.get('/api/v1/investigations').json()['items']
    assert [i['kind'] for i in items] == ['agent_run', 'investigation'] and items[0]['summary'] == 'Agent summary'
    assert items[1]['recommended_steps'] == ['rotate key'] and items[1]['status'] == 'completed'
    assert [i['id'] for i in client.get('/api/v1/investigations?kind=investigation').json()['items']] == [legacy.id]
    assert len(client.get(f'/api/v1/investigations?finding_id={finding.id}').json()['items']) == 2
    page = client.get('/api/v1/investigations?limit=1').json()
    assert page['items'][0]['id'] == run.id and page['next_cursor'] == '1'
    assert client.get('/api/v1/investigations?limit=1&cursor=1').json()['items'][0]['id'] == legacy.id
    assert client.get(f'/api/v1/investigations/{legacy.id}').json()['model'] == 'rules-only'
    detail = client.get(f'/api/v1/investigations/{run.id}').json()
    assert detail['kind'] == 'agent_run' and detail['steps'] == [] and detail['confidence'] == 'medium'
    assert client.get(f'/api/v1/investigations/{hunt.id}').status_code == 404
    assert client.get('/api/v1/investigations/missing').status_code == 404


def test_investigations_cross_tenant(owner, second_tenant, db, default_tenant_id):
    finding = make_finding(db, default_tenant_id)
    legacy = Investigation(tenant_id=default_tenant_id, finding_id=finding.id, summary='s')
    run = AgentRun(tenant_id=default_tenant_id, spec='investigate', task='t', status='queued', finding_id=finding.id)
    db.add_all([legacy, run])
    db.commit()
    other = second_tenant['client']
    assert other.get('/api/v1/investigations').json()['items'] == []
    assert other.get(f'/api/v1/investigations/{legacy.id}').status_code == 404
    assert other.get(f'/api/v1/investigations/{run.id}').status_code == 404


# ---------------------------------------------------------------- approvals


def test_approvals_record_only_and_self_approval_blocked(client, owner, db, default_tenant_id, make_user):
    _, headers = owner
    finding = make_finding(db, default_tenant_id)
    assert client.post('/api/v1/approvals', json={'finding_id': 'missing', 'action': 'isolate_endpoint', 'rationale': 'Investigate demo host'},
                       headers=headers).status_code == 404
    created = client.post('/api/v1/approvals', json={'finding_id': finding.id, 'action': 'isolate_endpoint', 'rationale': 'Investigate demo host'}, headers=headers)
    assert created.status_code == 201, created.text
    approval = created.json()
    assert approval['status'] == 'pending' and approval['executes'] is False and '/api/v1/actions' in approval['note']
    own = client.post(f"/api/v1/approvals/{approval['id']}/decide", json={'decision': 'approved'}, headers=headers)
    assert own.status_code == 403 and own.json()['code'] == 'self_approval'
    make_user('analyst@test.local', 'analyst-password-long-1', 'analyst')
    analyst = TestClient(client.app)
    ah = login(analyst, 'analyst@test.local', 'analyst-password-long-1')
    decided = analyst.post(f"/api/v1/approvals/{approval['id']}/decide", json={'decision': 'approved', 'comment': 'ok'}, headers=ah)
    assert decided.status_code == 200 and decided.json()['status'] == 'approved' and decided.json()['executes'] is False
    assert analyst.post(f"/api/v1/approvals/{approval['id']}/decide", json={'decision': 'denied'}, headers=ah).status_code == 409
    assert client.get(f"/api/v1/approvals/{approval['id']}").json()['decided_by'] == decided.json()['decided_by']
    assert [a['id'] for a in client.get('/api/v1/approvals?status=approved').json()['items']] == [approval['id']]
    assert client.get(f'/api/v1/approvals?finding_id={finding.id}').json()['items'][0]['action'] == 'isolate_endpoint'
    audit = {e['action'] for e in client.get('/api/v1/audit?action=approvals.').json()['items']}
    assert audit == {'approvals.requested', 'approvals.decided'}
    assert client.get('/api/v1/audit/verify').json()['valid'] is True
    assert client.post('/api/v1/approvals', json={'finding_id': finding.id, 'action': 'rm -rf /', 'rationale': 'bad action name'}, headers=headers).status_code == 422


def test_approvals_rbac_and_cross_tenant(client, owner, second_tenant, db, default_tenant_id, make_user):
    _, headers = owner
    finding = make_finding(db, default_tenant_id)
    approval = client.post('/api/v1/approvals', json={'finding_id': finding.id, 'action': 'revoke_credential', 'rationale': 'Leaked token'}, headers=headers).json()
    make_user('viewer@test.local', 'viewer-password-long-1', 'viewer')
    viewer = TestClient(client.app)
    vh = login(viewer, 'viewer@test.local', 'viewer-password-long-1')
    assert viewer.get('/api/v1/approvals').status_code == 200
    assert viewer.post('/api/v1/approvals', json={'finding_id': finding.id, 'action': 'x_y', 'rationale': 'viewer tries'}, headers=vh).status_code == 403
    assert viewer.post(f"/api/v1/approvals/{approval['id']}/decide", json={'decision': 'approved'}, headers=vh).status_code == 403
    other, oh = second_tenant['client'], second_tenant['headers']
    assert other.get('/api/v1/approvals').json()['items'] == []
    assert other.get(f"/api/v1/approvals/{approval['id']}").status_code == 404
    assert other.post(f"/api/v1/approvals/{approval['id']}/decide", json={'decision': 'approved'}, headers=oh).status_code == 404
    assert other.post('/api/v1/approvals', json={'finding_id': finding.id, 'action': 'deploy_patch', 'rationale': 'cross tenant'}, headers=oh).status_code == 404
