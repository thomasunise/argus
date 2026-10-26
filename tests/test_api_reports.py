from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from app.core.findings import EventDraft, upsert_event, upsert_finding
from app.models import Finding, utcnow
from tests.conftest import login

ATTESTATION = 'I confirm that this organization owns and controls this asset and authorizes testing.'
STATUSES = {'satisfied', 'partial', 'missing', 'manual'}


def seed(client, headers, db, tenant_id):
    asset = client.post('/api/v1/assets', json={'name': 'Site', 'kind': 'web', 'target': 'https://example.org', 'environment': 'staging'}, headers=headers).json()
    client.post(f"/api/v1/assets/{asset['id']}/authorize", json={'attestation': ATTESTATION}, headers=headers)
    client.post('/api/v1/assets', json={'name': 'Account', 'kind': 'cloud_account', 'target': '123456789012'}, headers=headers)
    crit, _ = upsert_finding(db, tenant_id, source='test', rule='crit', title='Critical', description='d', severity_name='critical', asset_id=asset['id'])
    crit.created_at = utcnow() - timedelta(days=10)  # past the 7 day critical SLA
    upsert_finding(db, tenant_id, source='test', rule='med', title='Medium', description='d', severity_name='medium')
    resolved, _ = upsert_finding(db, tenant_id, source='test', rule='old', title='Resolved', description='d', severity_name='low')
    resolved.status, resolved.created_at = 'resolved', utcnow() - timedelta(days=2)
    upsert_event(db, tenant_id, EventDraft(source='wazuh', external_id='e1', title='Login', severity='low', actor='alice'))
    db.commit()
    return asset


def test_summary_shape(owner, db, default_tenant_id):
    client, headers = owner
    seed(client, headers, db, default_tenant_id)
    summary = client.get('/api/v1/reports/summary').json()
    assert summary['assets'] == {'total': 2, 'approved': 1}
    assert summary['findings']['open'] == 2 and summary['findings']['open_by_severity']['critical'] == 1 and summary['findings']['total'] == 3
    assert summary['events']['last_24h'] == 1 and summary['events']['recent'][0]['title'] == 'Login'
    assert summary['detections']['available'] is True and summary['detections']['open'] == 0
    assert summary['agent_runs_24h']['total'] == 0 and 'pending' in summary['actions']
    assert summary['collectors']['available'] is True and summary['tests']['available'] is True and summary['graph']['nodes'] >= 2
    assert summary['audit_chain']['valid'] is True and summary['ai_provider'] == 'none'


def test_posture_score_and_components(owner, db, default_tenant_id):
    client, headers = owner
    empty = client.get('/api/v1/reports/posture').json()
    assert 0 <= empty['score'] <= 100 and empty['grade'] in 'ABCDF' and empty['components']['authorization']['included'] is False
    seed(client, headers, db, default_tenant_id)
    posture = client.get('/api/v1/reports/posture').json()
    assert set(posture['components']) == {'authorization', 'open_critical_high', 'coverage', 'detection_trend', 'exposure', 'mttr'}
    auth = posture['components']['authorization']
    assert auth['included'] is True and auth['score'] == 50.0 and auth['detail']['authorized'] == 1
    crit = posture['components']['open_critical_high']
    assert crit['score'] == 84.0 and crit['detail']['critical_past_sla'] == 1
    coverage = posture['components']['coverage']
    assert coverage['included'] is True and coverage['score'] == 0.0 and coverage['detail']['value']['needed'] == ['cloud']
    assert posture['components']['mttr']['included'] is True and posture['components']['mttr']['detail']['sample'] == 1
    assert sum(posture['weights_used'].values()) == sum(c['weight'] for c in posture['components'].values() if c['included'])
    assert 0 <= posture['score'] <= 100 and posture['grade'] in 'ABCDF'


def test_compliance_frameworks(owner, db, default_tenant_id):
    client, headers = owner
    seed(client, headers, db, default_tenant_id)
    frameworks = client.get('/api/v1/reports/compliance').json()
    assert {f['framework'] for f in frameworks['items']} == {'soc2', 'nist-800-171', 'iso27001'} and 'soc2' in frameworks['catalog']
    for framework in ('soc2', 'nist-800-171', 'iso27001'):
        report = client.get(f'/api/v1/reports/compliance/{framework}').json()
        assert report['framework'] == framework and 'not a certification' in report['disclaimer']
        totals = report['totals']
        assert totals['controls'] == len(report['controls']) == sum(totals[s] for s in STATUSES)
        assert all(c['status'] in STATUSES for c in report['controls'])
        for control in report['controls']:
            if control['status'] == 'manual':
                assert all(e['ok'] is None for e in control['evidence'])
            else:
                assert any(e['ok'] is not None for e in control['evidence'])
                assert all({'key', 'ok', 'summary'} <= set(e) for e in control['evidence'])
    soc2 = {c['id']: c for c in client.get('/api/v1/reports/compliance/soc2').json()['controls']}
    cc61 = {e['key']: e for e in soc2['CC6.1']['evidence']}
    assert cc61['sso_configured']['ok'] is False and cc61['api_key_rotation']['ok'] is True and soc2['CC6.1']['status'] == 'partial'
    assert soc2['CC9.2']['status'] == 'manual' and soc2['CC9.2']['manual_guidance']
    cc74 = {e['key']: e for e in soc2['CC7.4']['evidence']}
    assert cc74['vulnerability_sla']['ok'] is False and cc74['vulnerability_sla']['value']['breaches'] == 1
    nist = {c['id']: c for c in client.get('/api/v1/reports/compliance/nist-800-171').json()['controls']}
    assert {e['key']: e['ok'] for e in nist['3.3.8']['evidence']} == {'audit_chain_valid': True, 'audit_signing': True, 'audit_external_sink': True}
    assert nist['3.3.8']['status'] == 'satisfied'
    assert client.get('/api/v1/reports/compliance/pci').status_code == 404
    assert client.get('/api/v1/audit?action=reports.compliance_generated').json()['items']


def test_trends(owner, db, default_tenant_id):
    client, headers = owner
    seed(client, headers, db, default_tenant_id)
    trends = client.get('/api/v1/reports/trends?days=7').json()
    assert trends['days'] == 7 and len(trends['series']) == 7 and trends['series'][-1]['day'] == trends['to']
    assert trends['totals']['findings_opened'] == 2 and trends['totals']['findings_closed'] == 1 and trends['totals']['events'] == 1
    assert trends['series'][-1]['events'] == 1 and trends['series'][-1]['detections'] == 0
    assert client.get('/api/v1/reports/trends?days=0').json()['days'] == 1
    assert client.get('/api/v1/reports/trends?days=5000').json()['days'] == 365


def test_viewer_can_read_and_cross_tenant(client, owner, second_tenant, db, default_tenant_id, make_user):
    _, headers = owner
    seed(client, headers, db, default_tenant_id)
    make_user('viewer@test.local', 'viewer-password-long-1', 'viewer')
    viewer = TestClient(client.app)
    login(viewer, 'viewer@test.local', 'viewer-password-long-1')
    for path in ('/api/v1/reports/summary', '/api/v1/reports/posture', '/api/v1/reports/compliance/soc2', '/api/v1/reports/trends'):
        assert viewer.get(path).status_code == 200, path
    other = second_tenant['client']
    summary = other.get('/api/v1/reports/summary').json()
    assert summary['assets'] == {'total': 0, 'approved': 0} and summary['findings']['open'] == 0 and summary['events']['total'] == 0
    assert other.get('/api/v1/reports/trends?days=7').json()['totals']['findings_opened'] == 0
    assert other.get('/api/v1/reports/posture').json()['components']['authorization']['included'] is False
    acme_soc2 = {c['id']: c for c in other.get('/api/v1/reports/compliance/soc2').json()['controls']}
    assert {e['key']: e['ok'] for e in acme_soc2['CC7.4']['evidence']}['vulnerability_sla'] is True
    assert db.query(Finding).filter(Finding.tenant_id == second_tenant['tenant_id']).count() == 0


def test_onboarding_checklist_tracks_tenant_data(owner, db, default_tenant_id, make_user, second_tenant):
    from app.models import AgentRun
    from app.models.collectors import CollectorConfig
    from app.models.detections import Detection

    client, _ = owner
    fresh = client.get('/api/v1/reports/onboarding').json()
    assert [s['id'] for s in fresh['steps']] == ['source', 'events', 'triage', 'agent', 'team']
    assert fresh['completed'] == 0 and fresh['total'] == 5
    assert all(s['href'].startswith('#/') and s['perm'] for s in fresh['steps'])

    # Rows in another tenant never count towards this one.
    other = second_tenant['tenant_id']
    db.add(CollectorConfig(tenant_id=other, name='x', collector='aws'))
    upsert_event(db, other, EventDraft(source='wazuh', external_id='o1', title='Other'))
    db.commit()
    assert client.get('/api/v1/reports/onboarding').json()['completed'] == 0

    upsert_event(db, default_tenant_id, EventDraft(source='wazuh', external_id='e1', title='Login', severity='low'))
    db.add(Detection(tenant_id=default_tenant_id, rule_id='r1', fingerprint='f1', title='Brute force', status='open'))
    db.commit()
    done = {s['id']: s['done'] for s in client.get('/api/v1/reports/onboarding').json()['steps']}
    assert done == {'source': False, 'events': True, 'triage': False, 'agent': False, 'team': False}  # an open detection is not triaged yet

    db.add(CollectorConfig(tenant_id=default_tenant_id, name='prod', collector='aws'))
    db.add(Detection(tenant_id=default_tenant_id, rule_id='r2', fingerprint='f2', title='Impossible travel', status='false_positive'))
    db.add(AgentRun(tenant_id=default_tenant_id, spec='triage', task='look'))
    db.commit()
    make_user('analyst@test.local', 'analyst-password-long-123456', 'analyst')
    final = client.get('/api/v1/reports/onboarding').json()
    assert final['completed'] == 5 and all(s['done'] for s in final['steps'])


def test_onboarding_readable_by_viewer(client, make_user):
    make_user('viewer@test.local', 'viewer-password-long-123456', 'viewer')
    login(client, 'viewer@test.local', 'viewer-password-long-123456')
    assert client.get('/api/v1/reports/onboarding').status_code == 200
