"""Ingest endpoint: authentication matrix, dedupe, limits, findings for report sources, webhook
signature verification (GitHub, Okta), the Wazuh indexer pull job, batch stats and tenant isolation."""
from __future__ import annotations

import hashlib
import hmac
import json
import pathlib
from datetime import datetime, timedelta, timezone

import httpx
import respx
from sqlalchemy import select

from app.models import Asset, AuditEntry, Finding, SecurityEvent, loads
from tests.conftest import wait_job

FIXTURES = pathlib.Path(__file__).parent / 'fixtures' / 'integrations'


def load(source: str, name: str):
    return json.loads((FIXTURES / source / name).read_text(encoding='utf-8'))


def ingest(client, key: str, source: str, payload, headers: dict | None = None):
    return client.post(f'/api/v1/ingest/{source}', json=payload, headers={'X-API-Key': key, **(headers or {})})


def test_ingest_auth_matrix(owner, ingest_key, api_key):
    client, headers = owner
    payload = load('falco', 'alerts.json')
    assert ingest(client, ingest_key, 'falco', payload).status_code == 200
    assert ingest(client, api_key, 'falco', payload).status_code == 200
    assert client.post('/api/v1/ingest/falco', json=payload, headers=headers).status_code == 401          # session user
    assert client.post('/api/v1/ingest/falco', json=payload).status_code == 401                           # anonymous
    assert client.post('/api/v1/ingest/falco', json=payload, headers={'X-API-Key': 'argus_deadbeef_notarealkey'}).status_code == 401
    viewer = client.post('/api/v1/auth/api-keys', json={'name': 'ro', 'role': 'viewer', 'scopes': ['findings:read']}, headers=headers).json()['key']
    assert ingest(client, viewer, 'falco', payload).status_code == 403                                     # viewer key without ingest scope


def test_ingest_dedupe_batches_and_alert_correlation(owner, ingest_key, db, default_tenant_id):
    client, headers = owner
    payload = load('wazuh', 'alerts.json')
    first = ingest(client, ingest_key, 'wazuh', payload).json()
    assert (first['received'], first['accepted'], first['duplicates'], first['findings'], first['errors']) == (4, 4, 0, 1, [])
    assert len(first['event_ids']) == 4 and len(first['finding_ids']) == 1 and first['batch_id']
    second = ingest(client, ingest_key, 'wazuh', payload).json()
    assert (second['accepted'], second['duplicates'], second['findings']) == (0, 4, 0)
    events = db.execute(select(SecurityEvent).where(SecurityEvent.tenant_id == default_tenant_id, SecurityEvent.source == 'wazuh')).scalars().all()
    assert len(events) == 4 and sorted(e.action for e in events) == ['auth.failure', 'auth.failure', 'file.modified', 'privilege.sudo']
    stored = next(e for e in events if e.external_id == '1729687200.183726')
    assert loads(stored.metadata_json)['ip'] == '203.0.113.45' and stored.actor == 'deploy' and stored.severity == 'low'
    alert = db.execute(select(Finding).where(Finding.tenant_id == default_tenant_id, Finding.source == 'wazuh')).scalar_one()
    assert alert.rule == 'alert:1729687380.184300' and alert.severity == 'high' and alert.title.startswith('Security alert: sshd: brute force')
    batches = client.get('/api/v1/integrations/ingest/batches?source=wazuh', headers=headers).json()['items']
    assert len(batches) == 2 and batches[0]['duplicates'] == 4 and batches[1]['accepted'] == 4 and batches[1]['api_key_id']
    assert db.execute(select(AuditEntry).where(AuditEntry.action == 'integrations.ingest', AuditEntry.subject == 'wazuh')).scalars().first() is not None


def test_ingest_limits_and_errors(owner, ingest_key):
    client, _ = owner
    base = load('falco', 'alerts.json')[0]
    too_many = [dict(base, uuid=f'u-{i}') for i in range(501)]
    r = ingest(client, ingest_key, 'falco', too_many)
    assert r.status_code == 413 and r.json()['code'] == 'batch_too_large'
    big = client.post('/api/v1/ingest/falco', content=b'[' + b'{"rule":"x","output":"' + b'a' * (2 * 1024 * 1024 + 10) + b'"}]',
                      headers={'X-API-Key': ingest_key, 'Content-Type': 'application/json'})
    assert big.status_code == 413
    bad = client.post('/api/v1/ingest/falco', content=b'{not json', headers={'X-API-Key': ingest_key, 'Content-Type': 'application/json'})
    assert bad.status_code == 400 and bad.json()['code'] == 'invalid_payload'
    assert ingest(client, ingest_key, 'falco', 42).status_code == 400
    assert ingest(client, ingest_key, 'does-not-exist', base).status_code == 404
    mixed = ingest(client, ingest_key, 'falco', [base, 'nope', 7]).json()
    assert mixed['accepted'] == 1 and mixed['error_count'] == 2 and all('not a JSON object' in e for e in mixed['errors'])
    assert ingest(client, ingest_key, 'falco', base, {'X-Asset-Id': 'missing-asset'}).status_code == 404


def test_ingest_asset_header_links_events(owner, ingest_key, db, default_tenant_id, second_tenant):
    client, _ = owner
    asset = Asset(tenant_id=default_tenant_id, name='web-prod-01', kind='host', target='10.20.4.11', environment='production')
    foreign = Asset(tenant_id=second_tenant['tenant_id'], name='acme-host', kind='host', target='10.9.9.9', environment='production')
    db.add_all([asset, foreign])
    db.commit()
    result = ingest(client, ingest_key, 'wazuh', load('wazuh', 'alerts.json'), {'X-Asset-Id': asset.id}).json()
    assert result['accepted'] == 4
    events = db.execute(select(SecurityEvent).where(SecurityEvent.tenant_id == default_tenant_id, SecurityEvent.source == 'wazuh')).scalars().all()
    assert {e.asset_id for e in events} == {asset.id}
    assert ingest(client, ingest_key, 'falco', load('falco', 'alerts.json'), {'X-Asset-Id': foreign.id}).status_code == 404


def test_trivy_report_creates_findings_and_never_stores_secrets(owner, ingest_key, db, default_tenant_id):
    client, _ = owner
    report = load('trivy', 'report.json')
    result = ingest(client, ingest_key, 'trivy', report).json()
    assert (result['accepted'], result['findings'], result['findings_created']) == (1, 5, 5)
    findings = db.execute(select(Finding).where(Finding.tenant_id == default_tenant_id, Finding.source == 'trivy')).scalars().all()
    assert len(findings) == 5
    vuln = next(f for f in findings if f.rule.endswith('CVE-2024-6387'))
    assert vuln.cve_ids == 'CVE-2024-6387' and vuln.cvss == 8.1 and vuln.severity == 'high' and loads(vuln.evidence)['package'] == 'openssh-server'
    secret = next(f for f in findings if f.rule.startswith('secret:'))
    assert 'AKIAIOSFODNN7EXAMPLE' not in secret.evidence and 'AKIAIOSFODNN7EXAMPLE' not in secret.description and secret.severity == 'critical'
    event = db.execute(select(SecurityEvent).where(SecurityEvent.tenant_id == default_tenant_id, SecurityEvent.source == 'trivy')).scalar_one()
    assert event.action == 'secret_detected' and 'AKIAIOSFODNN7EXAMPLE' not in event.metadata_json
    again = ingest(client, ingest_key, 'trivy', report).json()
    assert (again['accepted'], again['duplicates'], again['findings'], again['findings_created']) == (0, 1, 5, 0)
    db.expire_all()
    assert db.get(Finding, vuln.id).occurrences == 2


def test_every_fixture_ingests_cleanly(owner, ingest_key):
    client, _ = owner
    expected = {
        ('wazuh', 'alerts.json'): (4, 1), ('wazuh', 'indexer_hits.json'): (2, 1), ('falco', 'alerts.json'): (3, 1), ('trivy', 'report.json'): (1, 5),
        ('aws_guardduty', 'findings.json'): (2, 1), ('aws_cloudtrail', 'records.json'): (6, 0), ('azure_defender', 'alerts.json'): (3, 2),
        ('gcp_scc', 'findings.json'): (3, 2), ('crowdstrike', 'detections.json'): (3, 2), ('sentinelone', 'threats.json'): (2, 1),
        ('okta_logs', 'system_log.json'): (5, 0), ('okta_logs', 'event_hook.json'): (1, 0), ('k8s_audit', 'events.json'): (5, 0),
        ('github_webhook', 'secret_scanning_alert.json'): (1, 0), ('github_webhook', 'code_scanning_alert.json'): (1, 1),
        ('github_webhook', 'dependabot_alert.json'): (1, 1), ('github_webhook', 'repository_publicized.json'): (1, 0),
        ('github_webhook', 'member_added_admin.json'): (1, 0), ('generic', 'events.json'): (2, 0),
    }
    for (source, name), (accepted, findings) in expected.items():
        response = ingest(client, ingest_key, source, load(source, name))
        assert response.status_code == 200, (source, name, response.text)
        body = response.json()
        assert body['errors'] == [] and (body['accepted'], body['findings']) == (accepted, findings), (source, name, body)
    # aliases route to the same parser and dedupe against the canonical source label
    alias = ingest(client, ingest_key, 'cloudtrail', load('aws_cloudtrail', 'records.json')).json()
    assert alias['source'] == 'aws_cloudtrail' and alias['duplicates'] == 6


def _sign(secret: str, body: bytes) -> str:
    return 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_github_signature_verification(owner, db, default_tenant_id, monkeypatch):
    client, headers = owner
    monkeypatch.setenv('GH_HOOK_SECRET', 'octocat-shared-secret')
    created = client.post('/api/v1/integrations', json={'name': 'gh', 'kind': 'github_webhook', 'secret_refs': {'webhook_secret': 'env:GH_HOOK_SECRET'}}, headers=headers)
    assert created.status_code == 201, created.text
    integration_id = created.json()['id']
    body = json.dumps(load('github_webhook', 'secret_scanning_alert.json')).encode()
    url = f'/api/v1/ingest/github_webhook/verify?integration={integration_id}'
    gh_headers = {'Content-Type': 'application/json', 'X-GitHub-Event': 'secret_scanning_alert', 'X-GitHub-Delivery': 'delivery-0001', 'User-Agent': 'GitHub-Hookshot/abc'}
    ok = client.post(url, content=body, headers={**gh_headers, 'X-Hub-Signature-256': _sign('octocat-shared-secret', body)})
    assert ok.status_code == 200 and ok.json()['accepted'] == 1, ok.text
    event = db.execute(select(SecurityEvent).where(SecurityEvent.source == 'github')).scalar_one()
    assert event.tenant_id == default_tenant_id and event.external_id == 'delivery-0001' and event.action == 'secret_detected'
    bad = client.post(url, content=body, headers={**gh_headers, 'X-Hub-Signature-256': _sign('wrong-secret', body)})
    assert bad.status_code == 401
    assert client.post(url, content=body, headers=gh_headers).status_code == 401                                     # no signature
    assert client.post(url, content=body + b' ', headers={**gh_headers, 'X-Hub-Signature-256': _sign('octocat-shared-secret', body)}).status_code == 401  # tampered body
    assert client.post('/api/v1/ingest/github_webhook/verify?integration=nope', content=body, headers=gh_headers).status_code == 404
    assert client.post(f'/api/v1/ingest/wazuh/verify?integration={integration_id}', content=body, headers=gh_headers).status_code == 400
    client.patch(f'/api/v1/integrations/{integration_id}', json={'enabled': False}, headers=headers)
    assert client.post(url, content=body, headers={**gh_headers, 'X-Hub-Signature-256': _sign('octocat-shared-secret', body)}).status_code == 404
    audit = db.execute(select(AuditEntry).where(AuditEntry.action == 'integrations.ingest', AuditEntry.subject == 'github_webhook')).scalars().first()
    assert audit is not None and audit.actor == f'webhook:{integration_id}'


def test_okta_challenge_and_shared_header(owner, db, monkeypatch):
    client, headers = owner
    monkeypatch.setenv('OKTA_HOOK_AUTH', 'okta-hook-token-123')
    created = client.post('/api/v1/integrations', json={'name': 'okta', 'kind': 'okta_logs', 'secret_refs': {'auth_header': 'env:OKTA_HOOK_AUTH'}}, headers=headers)
    assert created.status_code == 201, created.text
    integration_id = created.json()['id']
    challenge = client.get(f'/api/v1/ingest/okta_logs/verify?integration={integration_id}', headers={'X-Okta-Verification-Challenge': 'abc123'})
    assert challenge.status_code == 200 and challenge.json() == {'verification': 'abc123'}
    assert client.get(f'/api/v1/ingest/okta_logs/verify?integration={integration_id}').status_code == 400
    body = json.dumps(load('okta_logs', 'event_hook.json')).encode()
    ok = client.post(f'/api/v1/ingest/okta/verify?integration={integration_id}', content=body, headers={'Content-Type': 'application/json', 'Authorization': 'okta-hook-token-123'})
    assert ok.status_code == 200 and ok.json()['accepted'] == 1, ok.text
    assert db.execute(select(SecurityEvent).where(SecurityEvent.source == 'okta')).scalar_one().action == 'okta.user.mfa.factor.deactivate'
    bad = client.post(f'/api/v1/ingest/okta_logs/verify?integration={integration_id}', content=body, headers={'Content-Type': 'application/json', 'Authorization': 'nope'})
    assert bad.status_code == 401


def test_wazuh_sync_job_pulls_since_last_run(owner, db, default_tenant_id, monkeypatch):
    client, headers = owner
    monkeypatch.setenv('WZ_USER', 'argus-ro')
    monkeypatch.setenv('WZ_PASS', 'indexer-password-1')
    created = client.post('/api/v1/integrations', json={'name': 'wazuh indexer', 'kind': 'wazuh',
                                                        'config': {'indexer_url': 'https://indexer.test:9200', 'lookback_minutes': 30, 'page_size': 200},
                                                        'secret_refs': {'username': 'env:WZ_USER', 'password': 'env:WZ_PASS'}}, headers=headers)
    assert created.status_code == 201, created.text
    integration_id = created.json()['id']
    # Keep the fixture inside the seven-day safety bound enforced by Wazuh sync.
    # A fixed 2026 timestamp made CI fail once that date became stale.
    fixture = load('wazuh', 'indexer_hits.json')
    latest = (datetime.now(timezone.utc) - timedelta(minutes=2)).replace(microsecond=0)
    earlier = latest - timedelta(minutes=1)
    hits = fixture['hits']['hits']
    hits[0]['_source']['timestamp'] = earlier.strftime('%Y-%m-%dT%H:%M:%S.000+0000')
    hits[1]['_source']['timestamp'] = latest.strftime('%Y-%m-%dT%H:%M:%S.000+0000')
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post('https://indexer.test:9200/wazuh-alerts-*/_search').mock(return_value=httpx.Response(200, json=fixture))
        started = client.post(f'/api/v1/integrations/{integration_id}/sync', headers=headers)
        assert started.status_code == 200, started.text
        job = wait_job(client, headers, started.json()['job_id'])
        assert job['status'] == 'completed', job
        assert job['result']['accepted'] == 2 and job['result']['findings'] == 1
        request = route.calls[0].request
        assert request.headers['Authorization'].startswith('Basic ') and json.loads(request.content)['query']['range']['timestamp']['gt']
        second = wait_job(client, headers, client.post(f'/api/v1/integrations/{integration_id}/sync', headers=headers).json()['job_id'])
        assert second['status'] == 'completed' and second['result']['duplicates'] == 2 and second['result']['accepted'] == 0, second
        first_since = json.loads(route.calls[0].request.content)['query']['range']['timestamp']['gt']
        second_since = json.loads(route.calls[1].request.content)['query']['range']['timestamp']['gt']
        assert first_since != second_since and second['result']['since'] == second_since
        assert datetime.fromisoformat(second_since) == latest   # resumes from newest alert, not now - lookback
    state = client.get(f'/api/v1/integrations/{integration_id}', headers=headers).json()['state']
    assert datetime.fromisoformat(state['last_sync_at']) == latest and state['last_count'] == 2
    assert db.execute(select(SecurityEvent).where(SecurityEvent.tenant_id == default_tenant_id, SecurityEvent.source == 'wazuh')).scalars().all()
    assert client.post(f'/api/v1/integrations/{integration_id}/sync', headers=headers).status_code == 200
    plain = client.post('/api/v1/integrations', json={'name': 'plain http', 'kind': 'wazuh', 'config': {'indexer_url': 'http://indexer.test:9200'}}, headers=headers)
    assert plain.status_code == 400


def test_wazuh_sync_failure_records_error(owner, monkeypatch):
    client, headers = owner
    created = client.post('/api/v1/integrations', json={'name': 'broken', 'kind': 'wazuh', 'config': {'indexer_url': 'https://down.test:9200'}}, headers=headers)
    integration_id = created.json()['id']
    with respx.mock() as mock:
        mock.post('https://down.test:9200/wazuh-alerts-*/_search').mock(side_effect=httpx.ConnectError('refused'))
        job = wait_job(client, headers, client.post(f'/api/v1/integrations/{integration_id}/sync', headers=headers).json()['job_id'], timeout=40)
    assert job['status'] == 'failed' and 'WazuhSyncError' in job['error']
    assert 'Wazuh indexer sync failed' in client.get(f'/api/v1/integrations/{integration_id}', headers=headers).json()['last_error']


def test_ingest_cross_tenant_isolation(owner, ingest_key, second_tenant, db):
    client, headers = owner
    assert ingest(client, ingest_key, 'falco', load('falco', 'alerts.json')).json()['accepted'] == 3
    other, other_headers = second_tenant['client'], second_tenant['headers']
    assert other.get('/api/v1/integrations/ingest/batches', headers=other_headers).json()['items'] == []
    assert client.get('/api/v1/integrations/ingest/batches', headers=headers).json()['items'][0]['source'] == 'falco'
    other_key = other.post('/api/v1/auth/api-keys', json={'name': 'acme-sensor', 'role': 'viewer', 'scopes': ['ingest']}, headers=other_headers).json()['key']
    assert ingest(other, other_key, 'falco', load('falco', 'alerts.json')).json()['accepted'] == 3   # same external ids, different tenant: not duplicates
    by_tenant = {}
    for event in db.execute(select(SecurityEvent).where(SecurityEvent.source == 'falco')).scalars().all():
        by_tenant.setdefault(event.tenant_id, 0)
        by_tenant[event.tenant_id] += 1
    assert by_tenant == {second_tenant['tenant_id']: 3, client.app.state.default_tenant_id: 3}
