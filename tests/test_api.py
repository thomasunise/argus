import json
import time


def test_health_and_login(client):
    assert client.get('/health').json()['status']=='healthy'
    assert client.get('/api/dashboard').status_code==401
    assert client.post('/api/login',json={'password':'incorrect'}).status_code==401
    assert client.post('/api/login',json={'password':'test-password-very-long-123456'}).status_code==200
    assert client.get('/api/session').json()['authenticated'] is True
    assert client.post('/api/assets',json={'name':'Bad','kind':'web','target':'https://example.org'}).status_code==403


def test_assets_and_authorization(authed, monkeypatch):
    from app import policy
    client, headers=authed
    response=client.post('/api/assets',headers=headers,json={'name':'Test Website','kind':'web','target':'https://example.org','environment':'staging'})
    assert response.status_code==201, response.text
    asset=response.json()
    assert asset['approved'] is False
    assert client.post('/api/assets/'+asset['id']+'/approve', headers=headers,json={'attestation':False}).status_code==403
    monkeypatch.setattr(policy.socket,'getaddrinfo', lambda *args, **kwargs: [(None,None,None,None,('93.184.215.14',443))])
    approved=client.post('/api/assets/'+asset['id']+'/approve',headers=headers,json={'attestation':True})
    assert approved.status_code==200, approved.text
    assert approved.json()['approved'] is True
    assert client.get('/api/dashboard').json()['approved_assets']==1


def test_scan_and_findings(authed, monkeypatch):
    from app import policy, main
    client,headers=authed
    monkeypatch.setattr(policy.socket,'getaddrinfo', lambda *args, **kwargs: [(None,None,None,None,('93.184.215.14',443))])
    async def fake_scan(target, config):
        return [dict(rule='header:strict-transport-security',title='HSTS not configured',
                     description='A sample validated header check',remediation='Configure HSTS',
                     severity_name='medium', evidence={'header':'strict-transport-security'})]
    monkeypatch.setattr(main,'web_baseline_scan',fake_scan)
    a=client.post('/api/assets',headers=headers,json={'name':'Staging','kind':'web','target':'https://example.org'}).json()
    assert client.post('/api/scans',headers=headers,json={'asset_id':a['id'],'scanner':'web-baseline'}).status_code==403
    client.post('/api/assets/'+a['id']+'/approve',headers=headers,json={'attestation':True})
    job=client.post('/api/scans',headers=headers,json={'asset_id':a['id'],'scanner':'web-baseline'})
    assert job.status_code==202, job.text
    for _ in range(40):
        scans=client.get('/api/scans').json()
        if scans[0]['status']=='completed':break
        time.sleep(.05)
    assert scans[0]['status']=='completed',scans
    findings=client.get('/api/findings').json()
    assert len(findings)==1
    assert findings[0]['title']=='HSTS not configured'
    assert client.post('/api/findings/'+findings[0]['id']+'/investigate',headers=headers,json={}).json()['model']=='rules-only'
    r=client.patch('/api/findings/'+findings[0]['id'],headers=headers,json={'status':'resolved'})
    assert r.json()['status']=='resolved'
    report=client.get('/api/reports/findings.csv')
    assert report.status_code==200 and 'HSTS not configured' in report.text
    assert client.get('/api/audit/verify').json()['valid'] is True


def test_ingest_dedup_and_secret_redaction(client, authed):
    authed_client, csrf=authed
    ingest={'X-Ingest-Key':'ingest-key-testing-longer-than-24-characters'}
    assert client.post('/api/ingest/wazuh',json={},headers={'X-Ingest-Key':'wrong'}).status_code==401
    alert={'id':'123','rule':{'level':13,'description':'Illustrative alert','id':'500'},'agent':{'name':'example'}}
    assert client.post('/api/ingest/wazuh',json=alert,headers=ingest).json()['ingested']==1
    assert client.post('/api/ingest/wazuh',json=alert,headers=ingest).json()['ingested']==0
    findings=client.get('/api/findings').json()
    assert len(findings)==1 and findings[0]['severity']=='critical'
    trivy={'Results':[{'Target':'test-file','Secrets':[{'RuleID':'rule-1','Category':'API key','Severity':'HIGH','Match':'TOP_SECRET_VALUE'}]}]}
    result=client.post('/api/ingest/trivy',json=trivy,headers=ingest)
    assert result.json()['imported']==1
    assert 'TOP_SECRET_VALUE' not in json.dumps(client.get('/api/findings').json())
    assert 'TOP_SECRET_VALUE' not in json.dumps(client.get('/api/events').json())
    assert client.get('/api/audit/verify').json()['valid'] is True


def test_approvals_only_record(authed):
    client,headers=authed
    ingest={'X-Ingest-Key':'ingest-key-testing-longer-than-24-characters'}
    client.post('/api/ingest/falco',headers=ingest,json={'rule':'Example alert','priority':'ERROR','time':'now'})
    finding=client.get('/api/findings').json()[0]
    req=client.post('/api/approvals',headers=headers,json={'finding_id':finding['id'],
                'action':'isolate_endpoint','rationale':'Investigate isolated demo host'})
    assert req.status_code==201 and req.json()['execution']=='not_implemented'
    approved=client.post('/api/approvals/'+req.json()['id']+'/decide',headers=headers,json={'decision':'approved'})
    assert approved.json()['status']=='approved' and approved.json()['execution']=='not_implemented'
    assert client.get('/api/audit/verify').json()['valid'] is True
