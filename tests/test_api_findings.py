from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.findings import upsert_finding
from tests.conftest import login, wait_job


def make_finding(db, tenant_id, *, rule='r1', severity='medium', title='Sample finding', source='test', asset_id=None, **kw):
    finding, _ = upsert_finding(db, tenant_id, source=source, rule=rule, title=title, description=kw.pop('description', 'desc'),
                                severity_name=severity, asset_id=asset_id, remediation=kw.pop('remediation', 'fix it'), **kw)
    db.commit()
    return finding


def test_list_filters_sort_and_stats(owner, db, default_tenant_id):
    client, headers = owner
    make_finding(db, default_tenant_id, rule='low', severity='low', title='Low one')
    make_finding(db, default_tenant_id, rule='crit', severity='critical', title='Critical one', cve_ids=['CVE-2026-0001'], kev=True)
    make_finding(db, default_tenant_id, rule='high', severity='high', title='High one', source='nuclei')
    by_sev = client.get('/api/v1/findings?sort=severity').json()
    assert [f['severity'] for f in by_sev['items']] == ['critical', 'high', 'low']
    assert [f['title'] for f in client.get('/api/v1/findings?severity=high,critical&sort=severity').json()['items']] == ['Critical one', 'High one']
    assert [f['title'] for f in client.get('/api/v1/findings?source=nuclei').json()['items']] == ['High one']
    assert [f['title'] for f in client.get('/api/v1/findings?search=CVE-2026').json()['items']] == ['Critical one']
    assert [f['title'] for f in client.get('/api/v1/findings?rule=low').json()['items']] == ['Low one']
    assert client.get('/api/v1/findings?status=resolved').json()['items'] == []
    page = client.get('/api/v1/findings?limit=2').json()
    assert len(page['items']) == 2 and page['next_cursor'] == '2'
    stats = client.get('/api/v1/findings/stats').json()
    assert stats['open_total'] == 3 and stats['by_severity']['critical'] == 1 and stats['by_status']['open'] == 3
    assert stats['by_source'] == {'test': 2, 'nuclei': 1} and stats['aging']['<1d'] == 3 and stats['kev_open'] == 1
    assert stats['mean_time_to_resolve_hours'] is None and stats['opened_7d'] == 3


def test_lifecycle_transitions_and_audit(owner, db, default_tenant_id):
    client, headers = owner
    finding = make_finding(db, default_tenant_id)
    url = f'/api/v1/findings/{finding.id}'
    assert client.patch(url, json={'status': 'investigating'}, headers=headers).json()['status'] == 'investigating'
    assert client.patch(url, json={'status': 'investigating'}, headers=headers).status_code == 200  # no-op
    assert client.patch(url, json={'status': 'resolved', 'comment': 'patched'}, headers=headers).json()['status'] == 'resolved'
    bad = client.patch(url, json={'status': 'investigating'}, headers=headers)
    assert bad.status_code == 409 and bad.json()['code'] == 'invalid_transition'
    assert client.patch(url, json={'status': 'accepted'}, headers=headers).status_code == 409
    assert client.patch(url, json={'status': 'open'}, headers=headers).json()['status'] == 'open'
    assert client.patch(url, json={'status': 'false_positive'}, headers=headers).json()['status'] == 'false_positive'
    assert client.patch(url, json={'status': 'resolved'}, headers=headers).status_code == 409
    unknown = client.patch(url, json={'status': 'wontfix'}, headers=headers)
    assert unknown.status_code == 400 and unknown.json()['code'] == 'invalid_status'
    changes = client.get(f'/api/v1/audit?action=findings.status_changed&subject={finding.id}').json()['items']
    assert len(changes) == 4 and changes[-1]['detail'] == {'from': 'open', 'to': 'investigating', 'comment': ''}
    assert any(c['detail']['comment'] == 'patched' for c in changes)
    # Assignee must be a member of the tenant; tags are normalized.
    me = client.get('/api/v1/auth/session').json()['user']['id']
    assert client.patch(url, json={'assignee': 'nobody'}, headers=headers).status_code == 400
    updated = client.patch(url, json={'assignee': me, 'tags': ['z', ' a ', 'a']}, headers=headers).json()
    assert updated['assignee'] == me and updated['tags'] == ['a', 'z']
    assert [f['id'] for f in client.get(f'/api/v1/findings?assignee={me}').json()['items']] == [finding.id]
    assert client.patch(url, json={'assignee': ''}, headers=headers).json()['assignee'] == ''
    assert client.get('/api/v1/audit/verify').json()['valid'] is True


def test_finding_detail_shape(owner, db, default_tenant_id):
    client, headers = owner
    asset = client.post('/api/v1/assets', json={'name': 'Site', 'kind': 'web', 'target': 'https://example.org'}, headers=headers).json()
    finding = make_finding(db, default_tenant_id, asset_id=asset['id'])
    detail = client.get(f'/api/v1/findings/{finding.id}').json()
    assert detail['asset']['id'] == asset['id'] and detail['investigations'] == [] and detail['agent_runs'] == []
    assert detail['detection'] is None and detail['action_requests'] == [] and detail['evidence'] == {}
    assert client.get('/api/v1/findings/missing').status_code == 404


def test_csv_export(owner, db, default_tenant_id):
    client, headers = owner
    make_finding(db, default_tenant_id, title='HSTS not configured', severity='medium')
    make_finding(db, default_tenant_id, rule='r2', title='Resolved one', severity='low')
    response = client.get('/api/v1/findings/export.csv')
    assert response.status_code == 200 and response.headers['content-type'].startswith('text/csv')
    lines = response.text.strip().splitlines()
    assert lines[0].startswith('id,severity,status,source,rule,asset_id,asset_name,title') and len(lines) == 3
    assert 'HSTS not configured' in response.text and response.headers['x-row-count'] == '2'
    filtered = client.get('/api/v1/findings/export.csv?severity=low')
    assert filtered.headers['x-row-count'] == '1' and 'Resolved one' in filtered.text
    exported = client.get('/api/v1/audit?action=findings.exported').json()['items']
    assert len(exported) == 2 and exported[0]['detail']['filters'] == {'severity': 'low'}


def test_investigate_queues_agent_run(owner, db, default_tenant_id):
    client, headers = owner
    finding = make_finding(db, default_tenant_id, title='Suspicious login burst', severity='high')
    response = client.post(f'/api/v1/findings/{finding.id}/investigate', json={}, headers=headers)
    assert response.status_code == 202, response.text
    data = response.json()
    assert data['agent_run_id'] and data['job_id'] and data['spec'] == 'investigate'
    run = client.get(f"/api/v1/agents/runs/{data['agent_run_id']}").json()
    assert run['finding_id'] == finding.id and run['spec'] == 'investigate'
    job = wait_job(client, headers, data['job_id'])
    assert job['status'] in {'completed', 'failed'}
    listed = client.get(f'/api/v1/investigations?finding_id={finding.id}').json()['items']
    assert listed and listed[0]['kind'] == 'agent_run' and listed[0]['agent_run_id'] == data['agent_run_id']
    assert client.get(f'/api/v1/findings/{finding.id}').json()['agent_runs'][0]['id'] == data['agent_run_id']
    assert client.get('/api/v1/audit?action=findings.investigate_requested').json()['items'][0]['subject'] == finding.id


def test_investigate_unavailable_without_spec(owner, db, default_tenant_id, monkeypatch):
    client, headers = owner
    finding = make_finding(db, default_tenant_id)
    from app.agents import runtime

    monkeypatch.setitem(runtime.SPECS, 'investigate', None)
    response = client.post(f'/api/v1/findings/{finding.id}/investigate', headers=headers)
    assert response.status_code == 503 and 'investigate' in response.json()['detail']
    assert client.post('/api/v1/findings/missing/investigate', headers=headers).status_code == 404


def test_rbac_viewer_cannot_write(client, owner, db, default_tenant_id, make_user):
    finding = make_finding(db, default_tenant_id)
    make_user('viewer@test.local', 'viewer-password-long-1', 'viewer')
    viewer = TestClient(client.app)
    vh = login(viewer, 'viewer@test.local', 'viewer-password-long-1')
    assert viewer.get('/api/v1/findings').status_code == 200
    assert viewer.get('/api/v1/findings/export.csv').status_code == 200
    assert viewer.patch(f'/api/v1/findings/{finding.id}', json={'status': 'resolved'}, headers=vh).status_code == 403
    assert viewer.post(f'/api/v1/findings/{finding.id}/investigate', headers=vh).status_code == 403


def test_cross_tenant_isolation(owner, second_tenant, db, default_tenant_id):
    client, headers = owner
    finding = make_finding(db, default_tenant_id)
    other, oh = second_tenant['client'], second_tenant['headers']
    assert other.get('/api/v1/findings').json()['items'] == []
    assert other.get(f'/api/v1/findings/{finding.id}').status_code == 404
    assert other.patch(f'/api/v1/findings/{finding.id}', json={'status': 'resolved'}, headers=oh).status_code == 404
    assert other.post(f'/api/v1/findings/{finding.id}/investigate', headers=oh).status_code == 404
    assert other.get('/api/v1/findings/stats').json()['open_total'] == 0
    assert other.get('/api/v1/findings/export.csv').headers['x-row-count'] == '0'
    assert client.get('/api/v1/findings/stats').json()['open_total'] == 1
