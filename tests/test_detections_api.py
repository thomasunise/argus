"""Router tests for /api/v1/detections and /api/v1/canaries, including cross-tenant isolation on
every list/get endpoint, permission checks, the queued run job and the public hit endpoints."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.findings import EventDraft, upsert_event
from app.detections.engine import run
from app.models.detections import CanaryHit, Detection
from tests.conftest import login, wait_job

NOW = datetime.now(timezone.utc).replace(microsecond=0)
T0 = NOW - timedelta(minutes=15)


def seed_machine_speed(db, tenant_id, actor='bot', n=25):
    for i in range(n):
        upsert_event(db, tenant_id, EventDraft(source='api-seed', external_id=f'{actor}-{i}', title='call', actor=actor, action='api.call', entity='svc',
                                               occurred_at=T0 + timedelta(milliseconds=100 * i)))
    db.commit()


def seed_detection(db, tenant_id) -> Detection:
    seed_machine_speed(db, tenant_id)
    run(db, tenant_id, rule_ids=['swarm.machine_speed_sequence'], now=NOW)
    db.commit()
    return db.query(Detection).filter(Detection.tenant_id == tenant_id).one()


# ---------------------------------------------------------------- detections


def test_list_get_patch_detection_and_cross_tenant(owner, second_tenant, db, default_tenant_id):
    client, headers = owner
    detection = seed_detection(db, default_tenant_id)
    listed = client.get('/api/v1/detections', headers=headers).json()
    assert [d['id'] for d in listed['items']] == [detection.id] and listed['next_cursor'] is None
    assert client.get('/api/v1/detections?rule_id=swarm.machine_speed_sequence&severity=high&status=open', headers=headers).json()['items']
    assert client.get('/api/v1/detections?entity=bo', headers=headers).json()['items']
    assert client.get('/api/v1/detections?entity=zzz', headers=headers).json()['items'] == []
    assert client.get('/api/v1/detections?status=resolved', headers=headers).json()['items'] == []
    one = client.get(f'/api/v1/detections/{detection.id}', headers=headers).json()
    assert one['rule_id'] == 'swarm.machine_speed_sequence' and one['evidence']['events'] == 25 and one['finding_id']
    patched = client.patch(f'/api/v1/detections/{detection.id}', json={'status': 'investigating', 'note': 'looking'}, headers=headers)
    assert patched.status_code == 200 and patched.json()['status'] == 'investigating'
    assert client.patch(f'/api/v1/detections/{detection.id}', json={'status': 'bogus'}, headers=headers).status_code == 422
    from app.models import AuditEntry

    assert db.query(AuditEntry).filter(AuditEntry.action == 'detections.status_changed').count() == 1
    other, oh = second_tenant['client'], second_tenant['headers']
    assert other.get('/api/v1/detections', headers=oh).json()['items'] == []
    assert other.get(f'/api/v1/detections/{detection.id}', headers=oh).status_code == 404
    assert other.patch(f'/api/v1/detections/{detection.id}', json={'status': 'resolved'}, headers=oh).status_code == 404
    assert other.get('/api/v1/detections/stats', headers=oh).json()['by_rule'] == {}


def test_rules_endpoint_state_and_permissions(owner, second_tenant, client, make_user):
    c, headers = owner
    rules = c.get('/api/v1/detections/rules', headers=headers).json()['items']
    assert len(rules) == 13 and all(r['enabled'] for r in rules)
    fanout = next(r for r in rules if r['id'] == 'swarm.coordinated_identity_fanout')
    assert fanout['params']['min_actors'] == 10 and fanout['category'] == 'swarm'
    patched = c.patch('/api/v1/detections/rules/swarm.coordinated_identity_fanout', json={'enabled': False, 'params': {'min_actors': 4}}, headers=headers)
    assert patched.status_code == 200 and patched.json()['enabled'] is False and patched.json()['params']['min_actors'] == 4
    assert patched.json()['overrides'] == {'min_actors': 4}
    assert c.patch('/api/v1/detections/rules/swarm.coordinated_identity_fanout', json={'params': {'bogus': 1}}, headers=headers).status_code == 400
    assert c.patch('/api/v1/detections/rules/no.such_rule', json={'enabled': True}, headers=headers).status_code == 404
    # Tenant isolation of rule state: the other tenant still sees defaults.
    other = second_tenant['client'].get('/api/v1/detections/rules', headers=second_tenant['headers']).json()['items']
    assert next(r for r in other if r['id'] == 'swarm.coordinated_identity_fanout')['enabled'] is True
    # Viewers may read rules but not change them.
    make_user('viewer@test.local', 'viewer-password-long-1', 'viewer')
    vh = login(client, 'viewer@test.local', 'viewer-password-long-1')
    assert client.get('/api/v1/detections/rules', headers=vh).status_code == 200
    assert client.patch('/api/v1/detections/rules/swarm.coordinated_identity_fanout', json={'enabled': True}, headers=vh).status_code == 403
    assert client.post('/api/v1/detections/run', json={}, headers=vh).status_code == 403


def test_run_job_and_stats(owner, db, default_tenant_id, second_tenant):
    client, headers = owner
    seed_machine_speed(db, default_tenant_id)
    assert client.post('/api/v1/detections/run', json={'rule_ids': ['nope.rule']}, headers=headers).status_code == 400
    queued = client.post('/api/v1/detections/run', json={'since_minutes': 120}, headers=headers)
    assert queued.status_code == 202, queued.text
    job = wait_job(client, headers, queued.json()['job_id'])
    assert job['status'] == 'completed', job
    assert job['result']['rules_run'] == 13 and job['result']['detections_created'] == 1 and job['result']['errors'] == []
    stats = client.get('/api/v1/detections/stats', headers=headers).json()
    assert stats['by_rule'] == {'swarm.machine_speed_sequence': 1} and stats['by_status'] == {'open': 1} and stats['open_by_severity'] == {'high': 1}
    assert stats['last_run']['trigger'] == 'job' and stats['last_run']['detections_created'] == 1 and stats['rules_registered'] == 13
    # The other tenant's run finds nothing because events are tenant scoped.
    other, oh = second_tenant['client'], second_tenant['headers']
    queued = other.post('/api/v1/detections/run', json={}, headers=oh)
    assert queued.status_code == 202
    job = wait_job(other, oh, queued.json()['job_id'])
    assert job['status'] == 'completed' and job['result']['detections_created'] == 0
    assert other.get('/api/v1/detections', headers=oh).json()['items'] == []


# ---------------------------------------------------------------- canaries


def test_canary_lifecycle_each_kind(owner, second_tenant, db):
    client, headers = owner
    created = {}
    for kind in ['token', 'url', 'credential', 'file', 'dns', 'aws_key', 'api_key', 'document']:
        response = client.post('/api/v1/canaries', json={'kind': kind, 'label': f'{kind} lure', 'placement': 'wiki/ops', 'expires_in_days': 30}, headers=headers)
        assert response.status_code == 201, response.text
        created[kind] = response.json()
    assert len(created['token']['token']) == 32 and created['token']['metadata']['value'] == created['token']['token']
    assert created['url']['metadata']['url'].endswith(f"/api/v1/canaries/{created['url']['token']}/hit")
    assert created['aws_key']['token'].startswith('AKIA') and len(created['aws_key']['token']) == 20 and len(created['aws_key']['metadata']['aws_secret_access_key']) == 40
    assert created['credential']['metadata']['username'] == created['credential']['token'] and created['credential']['metadata']['password']
    assert created['dns']['metadata']['hostname'].startswith(created['dns']['token'] + '.')
    assert created['api_key']['token'].startswith('cnry_')
    assert created['file']['metadata']['filename'].endswith('.pdf') and created['document']['metadata']['filename'].endswith('.html')
    assert all(c['expires_at'] for c in created.values())
    listed = client.get('/api/v1/canaries?limit=3', headers=headers).json()
    assert len(listed['items']) == 3 and listed['next_cursor'] == '3'
    assert len(client.get('/api/v1/canaries?kind=dns', headers=headers).json()['items']) == 1
    # Artifacts
    pdf = client.get(f"/api/v1/canaries/{created['file']['id']}/artifact", headers=headers)
    assert pdf.status_code == 200 and pdf.content.startswith(b'%PDF-1.4') and created['file']['token'].encode() in pdf.content and pdf.content.rstrip().endswith(b'%%EOF')
    html = client.get(f"/api/v1/canaries/{created['document']['id']}/artifact", headers=headers)
    assert html.status_code == 200 and b'<img src=' in html.content and created['document']['token'].encode() in html.content
    creds = client.get(f"/api/v1/canaries/{created['aws_key']['id']}/artifact", headers=headers)
    assert b'aws_access_key_id = AKIA' in creds.content
    # Revoke
    revoked = client.delete(f"/api/v1/canaries/{created['token']['id']}", headers=headers)
    assert revoked.status_code == 200 and revoked.json()['revoked_at'] and revoked.json()['active'] is False
    assert len(client.get('/api/v1/canaries', headers=headers).json()['items']) == 7
    assert len(client.get('/api/v1/canaries?include_revoked=true', headers=headers).json()['items']) == 8
    # Cross-tenant: nothing visible, nothing mutable.
    other, oh = second_tenant['client'], second_tenant['headers']
    assert other.get('/api/v1/canaries', headers=oh).json()['items'] == []
    for kind in ('url', 'file'):
        cid = created[kind]['id']
        assert other.get(f'/api/v1/canaries/{cid}/hits', headers=oh).status_code == 404
        assert other.get(f'/api/v1/canaries/{cid}/artifact', headers=oh).status_code == 404
        assert other.delete(f'/api/v1/canaries/{cid}', headers=oh).status_code == 404


def test_canary_hits_public_endpoint_then_detection(owner, second_tenant, db, default_tenant_id):
    client, headers = owner
    canary = client.post('/api/v1/canaries', json={'kind': 'url', 'label': 'payroll-link', 'placement': 'sharepoint'}, headers=headers).json()
    token = canary['token']
    # POST hit with any body, unauthenticated, from a different client.
    hit = second_tenant['client'].post(f'/api/v1/canaries/{token}/hit', content=b'{"who": "attacker", "Authorization": "Bearer abcdefghijklmnopqrstuvwxyz"}',
                                       headers={'User-Agent': 'python-requests/2.31', 'X-Forwarded-For': '203.0.113.9', 'Content-Type': 'application/json'})
    assert hit.status_code == 204
    gif = second_tenant['client'].get(f'/api/v1/canaries/{token}/hit?doc=q3', headers={'User-Agent': 'Word/16.0'})
    assert gif.status_code == 200 and gif.headers['content-type'] == 'image/gif' and gif.content.startswith(b'GIF89a')
    # Unknown or malformed tokens are silently accepted so the endpoint cannot be used to enumerate canaries.
    assert client.post('/api/v1/canaries/nope-not-a-token-here/hit', content=b'x').status_code == 204
    assert client.get('/api/v1/canaries/%3Cscript%3E/hit').status_code == 200
    hits = client.get(f"/api/v1/canaries/{canary['id']}/hits", headers=headers).json()['items']
    assert len(hits) == 2
    post_hit = next(h for h in hits if h['user_agent'].startswith('python-requests'))
    assert post_hit['source_ip'] == 'testclient' and post_hit['payload']['body']['who'] == 'attacker'  # forwarded headers are not trusted
    assert 'abcdefghijklmnopqrstuvwxyz' not in post_hit['payload']['body']['Authorization']
    assert 'cookie' not in post_hit['headers'] and 'user-agent' in post_hit['headers']
    get_hit = next(h for h in hits if h['user_agent'] == 'Word/16.0')
    assert get_hit['payload'] == {'query': {'doc': 'q3'}}
    refreshed = client.get('/api/v1/canaries', headers=headers).json()['items'][0]
    assert refreshed['hit_count'] == 2 and refreshed['last_hit_at']
    # A canary event was emitted and the tripwire rule turns it into a critical detection.
    events = client.get('/api/v1/events', headers=headers)
    if events.status_code == 200:  # events router is core-api; only assert when mounted
        assert any(e['action'] == 'canary.hit' for e in events.json()['items'])
    run(db, default_tenant_id, rule_ids=['canary.tripwire'])
    db.commit()
    detections = client.get('/api/v1/detections?rule_id=canary.tripwire', headers=headers).json()['items']
    assert len(detections) == 1 and detections[0]['severity'] == 'critical' and detections[0]['entity'] == 'payroll-link'
    assert set(detections[0]['evidence']['source_ips']) == {'testclient'}
    # Revoked canaries stop recording.
    client.delete(f"/api/v1/canaries/{canary['id']}", headers=headers)
    assert client.post(f'/api/v1/canaries/{token}/hit').status_code == 204
    assert db.query(CanaryHit).count() == 2


def test_canary_hit_rate_limit_per_token(owner):
    client, headers = owner
    token = client.post('/api/v1/canaries', json={'kind': 'token', 'label': 'rl'}, headers=headers).json()['token']
    statuses = [client.post(f'/api/v1/canaries/{token}/hit').status_code for _ in range(61)]
    assert statuses[:60] == [204] * 60 and statuses[60] == 429
    # Limits are per token: another token is unaffected.
    assert client.post('/api/v1/canaries/another-token-value-here/hit').status_code == 204


def test_canary_permissions(client, make_user, owner):
    make_user('viewer2@test.local', 'viewer-password-long-2', 'viewer')
    vh = login(client, 'viewer2@test.local', 'viewer-password-long-2')
    assert client.get('/api/v1/canaries', headers=vh).status_code == 200
    assert client.post('/api/v1/canaries', json={'kind': 'token', 'label': 'x'}, headers=vh).status_code == 403
    assert client.post('/api/v1/canaries', json={'kind': 'bogus', 'label': 'x'}, headers=owner[1]).status_code in (403, 422)
