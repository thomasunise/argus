"""Outbound channels (payload shapes via respx / monkeypatched smtplib), integration CRUD and
validation, event subscription -> delivery jobs, the retry path and tenant isolation."""
from __future__ import annotations

import hashlib
import hmac
import json
import pathlib
import smtplib

import httpx
import pytest
import respx
from sqlalchemy import select

from app.integrations.outbound import DeliveryResult, OutboundEvent, registry
from app.integrations.outbound.webhook import SIGNATURE_HEADER
from app.models import AuditEntry
from tests.conftest import login, wait_for, wait_job

FIXTURES = pathlib.Path(__file__).parent / 'fixtures' / 'integrations'


def make_event(**overrides) -> OutboundEvent:
    base = dict(topic='finding.created', tenant_id='tenant-1', tenant_name='Default', subject_kind='finding', subject_id='f-1', title='Public bucket marketing-assets-public',
                severity='high', status='open', summary='Bucket policy grants s3:GetObject to Principal *.', url='http://127.0.0.1:8080/#/findings/f-1', delivery_id='d-1',
                payload={'finding_id': 'f-1', 'source': 'aws_cloudtrail'})
    base.update(overrides)
    return OutboundEvent(**base)


# ---------------------------------------------------------------- channels


@pytest.mark.asyncio
async def test_webhook_signature_and_retry():
    calls = []

    def responder(request):
        calls.append(request)
        return httpx.Response(503, text='try later') if len(calls) == 1 else httpx.Response(200, text='ok')

    with respx.mock() as mock:
        route = mock.post('https://hooks.example.test/argus').mock(side_effect=responder)
        result = await registry.get('webhook').send(make_event(), {'url': 'https://hooks.example.test/argus', 'retry_attempts': 3, 'retry_backoff_seconds': 0,
                                                                   'headers': {'X-Env': 'prod', 'Authorization': 'must-not-pass'}}, {'signing_secret': 'shh'})
    assert result.ok and result.status_code == 200 and len(route.calls) == 2
    request = route.calls[-1].request
    expected = 'sha256=' + hmac.new(b'shh', request.content, hashlib.sha256).hexdigest()
    assert request.headers[SIGNATURE_HEADER] == expected and request.headers['X-Argus-Topic'] == 'finding.created' and request.headers['X-Env'] == 'prod'
    assert request.headers['X-Argus-Delivery'] == 'd-1' and 'Authorization' not in request.headers
    body = json.loads(request.content)
    assert body['topic'] == 'finding.created' and body['event']['title'] == 'Public bucket marketing-assets-public' and body['event']['severity'] == 'high'
    assert body['event']['payload']['finding_id'] == 'f-1' and body['id'] == 'd-1'


@pytest.mark.asyncio
async def test_webhook_gives_up_after_attempts_and_rejects_bad_url():
    with respx.mock() as mock:
        route = mock.post('https://hooks.example.test/down').mock(return_value=httpx.Response(500, text='boom'))
        result = await registry.get('webhook').send(make_event(), {'url': 'https://hooks.example.test/down', 'retry_attempts': 2, 'retry_backoff_seconds': 0}, {})
    assert not result.ok and result.retryable and result.status_code == 500 and 'boom' in result.error and len(route.calls) == 2
    assert not (await registry.get('webhook').send(make_event(), {'url': 'ftp://nope'}, {})).ok


@pytest.mark.asyncio
async def test_slack_webhook_and_bot_modes():
    with respx.mock() as mock:
        hook = mock.post('https://hooks.slack.com/services/T000/B000/XXXX').mock(return_value=httpx.Response(200, text='ok'))
        result = await registry.get('slack').send(make_event(), {'mode': 'webhook'}, {'webhook_url': 'https://hooks.slack.com/services/T000/B000/XXXX'})
        assert result.ok
        payload = json.loads(hook.calls[0].request.content)
        assert payload['text'] == '[High] Public bucket marketing-assets-public' and payload['blocks'][0]['type'] == 'header'
        fields = {f['text'].split('\n')[0] for f in payload['blocks'][1]['fields']}
        assert {'*Severity*', '*Topic*', '*Status*', '*Subject*', '*Source*'} <= fields and payload['blocks'][-1]['type'] == 'context'
        assert any('Open in Argus' in el['text'] for el in payload['blocks'][-1]['elements'])
        bot = mock.post('https://slack.com/api/chat.postMessage').mock(return_value=httpx.Response(200, json={'ok': True, 'ts': '1729687200.000100'}))
        result = await registry.get('slack').send(make_event(), {'mode': 'bot', 'channel': '#security'}, {'bot_token': 'xoxb-not-real-token-123456'})
        assert result.ok and result.external_ref == '1729687200.000100'
        request = bot.calls[0].request
        assert request.headers['Authorization'] == 'Bearer xoxb-not-real-token-123456' and json.loads(request.content)['channel'] == '#security'
        bot.mock(return_value=httpx.Response(200, json={'ok': False, 'error': 'channel_not_found'}))
        failed = await registry.get('slack').send(make_event(), {'mode': 'bot', 'channel': '#nope'}, {'bot_token': 'xoxb-not-real-token-123456'})
        assert not failed.ok and 'channel_not_found' in failed.error and not failed.retryable


@pytest.mark.asyncio
async def test_jira_create_then_comment_and_transition():
    config = {'base_url': 'https://example.atlassian.net', 'project_key': 'SEC', 'issue_type': 'Bug'}
    secrets = {'email': 'bot@example.com', 'api_token': 'atlassian-token'}
    with respx.mock() as mock:
        search = mock.get('https://example.atlassian.net/rest/api/3/search/jql').mock(return_value=httpx.Response(200, json={'issues': []}))
        create = mock.post('https://example.atlassian.net/rest/api/3/issue').mock(return_value=httpx.Response(201, json={'id': '10001', 'key': 'SEC-7'}))
        result = await registry.get('jira').send(make_event(severity='critical'), config, secrets)
        assert result.ok and result.external_ref == 'SEC-7'
        assert 'labels = "argus-finding-f-1"' in search.calls[0].request.url.params['jql']
        assert search.calls[0].request.headers['Authorization'].startswith('Basic ')
        fields = json.loads(create.calls[0].request.content)['fields']
        assert fields['project'] == {'key': 'SEC'} and fields['issuetype'] == {'name': 'Bug'} and fields['priority'] == {'name': 'Highest'}
        assert 'argus-finding-f-1' in fields['labels'] and fields['summary'].startswith('[Critical] Public bucket') and fields['description']['type'] == 'doc'
        search.mock(return_value=httpx.Response(200, json={'issues': [{'key': 'SEC-7', 'fields': {'status': {'name': 'Open'}}}]}))
        comment = mock.post('https://example.atlassian.net/rest/api/3/issue/SEC-7/comment').mock(return_value=httpx.Response(201, json={'id': '1'}))
        transitions = mock.get('https://example.atlassian.net/rest/api/3/issue/SEC-7/transitions').mock(
            return_value=httpx.Response(200, json={'transitions': [{'id': '11', 'name': 'In Progress', 'to': {'statusCategory': {'key': 'indeterminate'}}},
                                                                   {'id': '31', 'name': 'Done', 'to': {'statusCategory': {'key': 'done'}}}]}))
        transition = mock.post('https://example.atlassian.net/rest/api/3/issue/SEC-7/transitions').mock(return_value=httpx.Response(204))
        resolved = await registry.get('jira').send(make_event(topic='finding.resolved', status='resolved'), config, secrets)
        assert resolved.ok and resolved.external_ref == 'SEC-7' and resolved.detail['transition'] == 'Done'
        assert 'Status: resolved' in json.dumps(json.loads(comment.calls[0].request.content))
        assert json.loads(transition.calls[0].request.content) == {'transition': {'id': '31'}} and len(transitions.calls) == 1
    assert not (await registry.get('jira').send(make_event(), {'base_url': 'http://insecure', 'project_key': 'SEC'}, secrets)).ok


@pytest.mark.asyncio
async def test_servicenow_create_then_update():
    config = {'instance_url': 'https://dev0000.service-now.com', 'assignment_group': 'SecOps'}
    secrets = {'username': 'argus', 'password': 'snow-pass'}
    with respx.mock() as mock:
        lookup = mock.get('https://dev0000.service-now.com/api/now/table/incident').mock(return_value=httpx.Response(200, json={'result': []}))
        create = mock.post('https://dev0000.service-now.com/api/now/table/incident').mock(return_value=httpx.Response(201, json={'result': {'sys_id': 'abc123', 'number': 'INC0010001'}}))
        result = await registry.get('servicenow').send(make_event(), config, secrets)
        assert result.ok and result.external_ref == 'INC0010001'
        assert lookup.calls[0].request.url.params['sysparm_query'] == 'correlation_id=argus:finding:f-1'
        assert lookup.calls[0].request.headers['Authorization'].startswith('Basic ')
        body = json.loads(create.calls[0].request.content)
        assert body['correlation_id'] == 'argus:finding:f-1' and (body['impact'], body['urgency']) == ('2', '1') and body['assignment_group'] == 'SecOps'
        assert body['short_description'].startswith('[High] Public bucket')
        lookup.mock(return_value=httpx.Response(200, json={'result': [{'sys_id': 'abc123', 'number': 'INC0010001', 'state': '2'}]}))
        patch = mock.patch('https://dev0000.service-now.com/api/now/table/incident/abc123').mock(return_value=httpx.Response(200, json={'result': {'number': 'INC0010001'}}))
        resolved = await registry.get('servicenow').send(make_event(topic='finding.resolved', status='resolved'), config, secrets)
        assert resolved.ok and resolved.external_ref == 'INC0010001'
        patched = json.loads(patch.calls[0].request.content)
        assert patched['state'] == '6' and 'work_notes' in patched and patched['close_code']


@pytest.mark.asyncio
async def test_pagerduty_trigger_and_resolve():
    with respx.mock() as mock:
        route = mock.post('https://events.pagerduty.com/v2/enqueue').mock(return_value=httpx.Response(202, json={'status': 'success', 'dedup_key': 'argus-finding-f-1'}))
        result = await registry.get('pagerduty').send(make_event(), {'source': 'argus-prod'}, {'routing_key': 'R0UT1NGKEY'})
        assert result.ok and result.external_ref == 'argus-finding-f-1'
        body = json.loads(route.calls[0].request.content)
        assert body['routing_key'] == 'R0UT1NGKEY' and body['event_action'] == 'trigger' and body['dedup_key'] == 'argus-finding-f-1'
        assert body['payload']['severity'] == 'error' and body['payload']['source'] == 'argus-prod' and body['payload']['custom_details']['finding_id'] == 'f-1'
        assert body['links'][0]['href'].endswith('/#/findings/f-1')
        resolved = await registry.get('pagerduty').send(make_event(topic='finding.resolved', status='resolved'), {}, {'routing_key': 'R0UT1NGKEY'})
        assert resolved.ok and json.loads(route.calls[1].request.content)['event_action'] == 'resolve' and 'payload' not in json.loads(route.calls[1].request.content)
    assert not (await registry.get('pagerduty').send(make_event(), {}, {})).ok


@pytest.mark.asyncio
async def test_email_channel_with_monkeypatched_smtp(monkeypatch):
    sent: dict = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            sent['host'], sent['port'], sent['timeout'] = host, port, timeout
            sent['calls'] = []

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            sent['closed'] = True

        def ehlo(self):
            sent['calls'].append('ehlo')

        def starttls(self, context=None):
            sent['calls'].append('starttls')
            sent['tls_context'] = context is not None

        def login(self, user, password):
            sent['calls'].append('login')
            sent['login'] = (user, password)

        def send_message(self, message):
            sent['calls'].append('send')
            sent['message'] = message

    monkeypatch.setattr(smtplib, 'SMTP', FakeSMTP)
    config = {'host': 'smtp.example.test', 'port': 587, 'from': 'argus@example.test', 'to': ['soc@example.test', 'oncall@example.test'], 'subject_prefix': '[SOC]'}
    result = await registry.get('email').send(make_event(), config, {'username': 'mailer', 'password': 'mail-pass'})
    assert result.ok and result.status_code == 250 and result.external_ref.startswith('<') and result.detail['recipients'] == config['to']
    assert (sent['host'], sent['port']) == ('smtp.example.test', 587) and sent['calls'] == ['ehlo', 'starttls', 'ehlo', 'login', 'send'] and sent['tls_context']
    assert sent['login'] == ('mailer', 'mail-pass') and sent['closed']
    message = sent['message']
    assert message['To'] == 'soc@example.test, oncall@example.test' and message['From'] == 'argus@example.test'
    assert message['Subject'] == '[SOC] High: Public bucket marketing-assets-public' and message['X-Argus-Topic'] == 'finding.created'
    parts = [p.get_content_type() for p in message.walk()]
    assert 'text/plain' in parts and 'text/html' in parts and 'Open in Argus' in message.get_body(('plain',)).get_content()

    class AuthFail(FakeSMTP):
        def login(self, user, password):
            raise smtplib.SMTPAuthenticationError(535, b'bad credentials')

    monkeypatch.setattr(smtplib, 'SMTP', AuthFail)
    failed = await registry.get('email').send(make_event(), config, {'username': 'mailer', 'password': 'wrong'})
    assert not failed.ok and not failed.retryable and 'SMTPAuthenticationError' in failed.error
    assert not (await registry.get('email').send(make_event(), {'host': 'h', 'to': []}, {})).ok


# ---------------------------------------------------------------- API: CRUD, validation, test endpoint


def test_types_crud_and_validation(owner, db, monkeypatch):
    client, headers = owner
    types = client.get('/api/v1/integrations/types', headers=headers).json()
    assert {t['kind'] for t in types['outbound']} == {'webhook', 'slack', 'jira', 'servicenow', 'pagerduty', 'email'}
    assert {t['name'] for t in types['inbound']} >= {'wazuh', 'aws_cloudtrail', 'github_webhook', 'okta_logs', 'generic'}
    slack = next(t for t in types['outbound'] if t['kind'] == 'slack')
    assert slack['secret_fields'] == ['webhook_url', 'bot_token'] and slack['config_schema']['type'] == 'object'
    github = next(t for t in types['inbound'] if t['name'] == 'github_webhook')
    assert github['supports_verify'] and github['example'].endswith('secret_scanning_alert.json') and github['secret_fields'] == ['webhook_secret']

    def create(body):
        return client.post('/api/v1/integrations', json=body, headers=headers)

    assert create({'name': 'x', 'kind': 'fax'}).status_code == 400
    assert create({'name': 'x', 'kind': 'webhook', 'config': {}}).status_code == 400                                                     # url required
    assert create({'name': 'x', 'kind': 'webhook', 'config': {'url': 'https://h.test', 'signing_secret': 'inline'}}).status_code == 400  # inline secret
    assert create({'name': 'x', 'kind': 'webhook', 'config': {'url': 'https://h.test'}, 'secret_refs': {'signing_secret': 'not-a-ref'}}).status_code == 400
    assert create({'name': 'x', 'kind': 'webhook', 'config': {'url': 'https://h.test'}, 'secret_refs': {'bogus': 'env:X'}}).status_code == 400
    assert create({'name': 'x', 'kind': 'webhook', 'config': {'url': 'https://h.test'}, 'topics': ['nonsense.topic']}).status_code == 400
    assert create({'name': 'x', 'kind': 'webhook', 'config': {'url': 'https://h.test'}, 'min_severity': 'urgent'}).status_code == 400
    assert create({'name': 'x', 'kind': 'webhook', 'config': {'url': 'https://h.test', 'extra': 1}}).status_code == 400                     # additionalProperties false
    assert create({'name': 'x', 'kind': 'pagerduty', 'topics': ['testing.*']}).status_code == 400                                             # channel cannot deliver testing.*
    assert create({'name': 'x', 'kind': 'slack', 'config': {'note': 'password=SuperSecret123'}}).status_code == 400                            # credential-looking value
    created = create({'name': 'SOC hook', 'kind': 'webhook', 'config': {'url': 'https://hooks.example.test/x'}, 'secret_refs': {'signing_secret': 'env:HOOK_SECRET'}})
    assert created.status_code == 201, created.text
    row = created.json()
    assert row['direction'] == 'outbound' and row['topics'] == ['finding.*', 'detection.*', 'action.*'] and row['min_severity'] == 'low' and row['enabled']
    assert row['secret_refs'] == {'signing_secret': 'env:HOOK_SECRET'} and row['secret_fields'] == ['signing_secret']
    integration_id = row['id']
    listed = client.get('/api/v1/integrations', headers=headers).json()
    assert [i['id'] for i in listed['items']] == [integration_id] and listed['next_cursor'] is None
    assert client.get('/api/v1/integrations?direction=inbound', headers=headers).json()['items'] == []
    assert client.get('/api/v1/integrations?kind=webhook&enabled=true', headers=headers).json()['items'][0]['id'] == integration_id
    patched = client.patch(f'/api/v1/integrations/{integration_id}', json={'topics': ['finding.created'], 'min_severity': 'high', 'enabled': False, 'name': 'SOC hook v2'}, headers=headers)
    assert patched.status_code == 200 and patched.json()['topics'] == ['finding.created'] and patched.json()['min_severity'] == 'high' and not patched.json()['enabled']
    assert client.patch(f'/api/v1/integrations/{integration_id}', json={'config': {'url': 'nope'}}, headers=headers).status_code == 400
    assert client.get(f'/api/v1/integrations/{integration_id}', headers=headers).json()['name'] == 'SOC hook v2'
    inbound = create({'name': 'gh', 'kind': 'github_webhook', 'secret_refs': {'webhook_secret': 'env:GH_SECRET_MISSING'}})
    assert inbound.status_code == 201 and inbound.json()['direction'] == 'inbound' and inbound.json()['topics'] == []
    tested = client.post(f'/api/v1/integrations/{inbound.json()["id"]}/test', headers=headers).json()
    assert tested['direction'] == 'inbound' and tested['ok'] is False and tested['secrets_missing'] == ['webhook_secret'] and '/verify?integration=' in tested['ingest_url']
    monkeypatch.setenv('GH_SECRET_MISSING', 'now-present')
    assert client.post(f'/api/v1/integrations/{inbound.json()["id"]}/test', headers=headers).json()['ok'] is True
    assert client.post(f'/api/v1/integrations/{inbound.json()["id"]}/sync', headers=headers).status_code == 400   # github has no pull job
    assert client.delete(f'/api/v1/integrations/{integration_id}', headers=headers).json() == {'ok': True}
    assert client.get(f'/api/v1/integrations/{integration_id}', headers=headers).status_code == 404
    actions = {a for (a,) in db.execute(select(AuditEntry.action).where(AuditEntry.action.like('integrations.%'))).all()}
    assert {'integrations.create', 'integrations.update', 'integrations.delete', 'integrations.test'} <= actions
    make_viewer = client.post('/api/v1/auth/api-keys', json={'name': 'ro', 'role': 'viewer'}, headers=headers).json()['key']
    assert client.get('/api/v1/integrations/types', headers={'X-API-Key': make_viewer}).status_code == 200
    assert client.post('/api/v1/integrations', json={'name': 'x', 'kind': 'webhook', 'config': {'url': 'https://h.test'}}, headers={'X-API-Key': make_viewer}).status_code == 403


def test_outbound_test_endpoint_records_delivery(owner, monkeypatch):
    client, headers = owner
    monkeypatch.setenv('HOOK_SECRET', 'secret-for-signing')
    created = client.post('/api/v1/integrations', json={'name': 'hook', 'kind': 'webhook', 'config': {'url': 'https://hooks.example.test/t', 'retry_backoff_seconds': 0},
                                                        'secret_refs': {'signing_secret': 'env:HOOK_SECRET'}}, headers=headers).json()
    with respx.mock() as mock:
        route = mock.post('https://hooks.example.test/t').mock(return_value=httpx.Response(200, text='ok'))
        result = client.post(f'/api/v1/integrations/{created["id"]}/test', headers=headers).json()
    assert result['ok'] and result['status_code'] == 200 and result['direction'] == 'outbound'
    request = route.calls[0].request
    assert request.headers[SIGNATURE_HEADER] == 'sha256=' + hmac.new(b'secret-for-signing', request.content, hashlib.sha256).hexdigest()
    assert json.loads(request.content)['topic'] == 'integration.test'
    delivery = client.get(f'/api/v1/integrations/deliveries/{result["delivery_id"]}', headers=headers).json()
    assert delivery['status'] == 'sent' and delivery['topic'] == 'integration.test' and delivery['attempts'] == 1 and delivery['response_code'] == 200
    assert client.get('/api/v1/integrations/deliveries?topic=integration.test', headers=headers).json()['items'][0]['id'] == result['delivery_id']
    assert client.get(f'/api/v1/integrations/{created["id"]}', headers=headers).json()['last_delivery_at']


# ---------------------------------------------------------------- event subscription -> jobs -> deliveries


def test_event_subscription_delivers_matching_findings(owner, ingest_key, monkeypatch):
    client, headers = owner
    monkeypatch.setenv('HOOK_SECRET', 's')
    hook = client.post('/api/v1/integrations', json={'name': 'high+', 'kind': 'webhook', 'config': {'url': 'https://hooks.example.test/high', 'retry_backoff_seconds': 0},
                                                     'secret_refs': {'signing_secret': 'env:HOOK_SECRET'}, 'topics': ['finding.*'], 'min_severity': 'high'}, headers=headers).json()
    client.post('/api/v1/integrations', json={'name': 'detections only', 'kind': 'webhook', 'config': {'url': 'https://hooks.example.test/det'},
                                              'topics': ['detection.*']}, headers=headers)
    client.post('/api/v1/integrations', json={'name': 'disabled', 'kind': 'webhook', 'config': {'url': 'https://hooks.example.test/off'}, 'topics': ['finding.*'],
                                              'enabled': False}, headers=headers)
    report = json.loads((FIXTURES / 'trivy' / 'report.json').read_text(encoding='utf-8'))
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post('https://hooks.example.test/high').mock(return_value=httpx.Response(200, text='ok'))
        others = mock.post(url__regex=r'https://hooks\.example\.test/(det|off)').mock(return_value=httpx.Response(200, text='ok'))
        assert client.post('/api/v1/ingest/trivy', json=report, headers={'X-API-Key': ingest_key}).json()['findings'] == 5

        def delivered():
            items = client.get('/api/v1/integrations/deliveries?status=sent', headers=headers).json()['items']
            return items if len(items) >= 4 else None

        sent = wait_for(delivered)
    assert len(sent) == 4 and {d['integration_id'] for d in sent} == {hook['id']} and {d['topic'] for d in sent} == {'finding.created'}
    assert len(route.calls) == 4 and len(others.calls) == 0
    titles = {json.loads(c.request.content)['event']['title'] for c in route.calls}
    assert any('CVE-2024-6387' in t for t in titles) and not any('CVE-2024-35195' in t for t in titles)   # medium finding filtered by min_severity
    body = json.loads(route.calls[0].request.content)['event']
    assert body['subject_kind'] == 'finding' and body['payload']['finding_id'] and body['url'].endswith(f"/#/findings/{body['subject_id']}") and body['severity'] in {'high', 'critical'}
    all_deliveries = client.get('/api/v1/integrations/deliveries', headers=headers).json()['items']
    assert len(all_deliveries) == 4 and all(d['job_id'] for d in all_deliveries)
    jobs = client.get('/api/v1/ops/jobs', headers=headers).json()['items']
    kinds = {j['kind'] for j in jobs if j['status'] == 'completed'}
    assert {'integrations.fanout', 'integrations.deliver'} <= kinds and not [j for j in jobs if j['kind'].startswith('integrations.') and j['status'] == 'failed']


def test_delivery_retry_path(owner, ingest_key, monkeypatch):
    client, headers = owner
    hook = client.post('/api/v1/integrations', json={'name': 'flaky', 'kind': 'webhook', 'config': {'url': 'https://hooks.example.test/flaky', 'retry_attempts': 1,
                                                                                                     'retry_backoff_seconds': 0}, 'topics': ['finding.created']}, headers=headers).json()
    alerts = json.loads((FIXTURES / 'wazuh' / 'alerts.json').read_text(encoding='utf-8'))
    with respx.mock() as mock:
        route = mock.post('https://hooks.example.test/flaky').mock(return_value=httpx.Response(500, text='upstream down'))
        assert client.post('/api/v1/ingest/wazuh', json=alerts, headers={'X-API-Key': ingest_key}).json()['findings'] == 1   # one high alert -> finding.created

        def failed():
            items = client.get('/api/v1/integrations/deliveries?status=failed', headers=headers).json()['items']
            return items[0] if items else None

        delivery = wait_for(failed)
        assert delivery['attempts'] == 1 and delivery['response_code'] == 500 and 'upstream down' in delivery['last_error'] and delivery['next_attempt_at']
        assert delivery['integration_id'] == hook['id'] and delivery['max_attempts'] == 5
        assert 'upstream down' in client.get(f'/api/v1/integrations/{hook["id"]}', headers=headers).json()['last_error']
        scheduled = [j for j in client.get('/api/v1/ops/jobs?status=queued', headers=headers).json()['items'] if j['kind'] == 'integrations.deliver']
        assert scheduled, 'automatic retry should be scheduled with a delay'
        route.mock(return_value=httpx.Response(200, text='ok'))
        retried = client.post(f'/api/v1/integrations/deliveries/{delivery["id"]}/retry', headers=headers)
        assert retried.status_code == 200 and retried.json()['delivery']['status'] == 'queued'
        job = wait_job(client, headers, retried.json()['job_id'])
        assert job['status'] == 'completed' and job['result']['status'] == 'sent' and job['result']['attempts'] == 2
    final = client.get(f'/api/v1/integrations/deliveries/{delivery["id"]}', headers=headers).json()
    assert final['status'] == 'sent' and final['attempts'] == 2 and final['sent_at'] and final['last_error'] == ''
    assert client.post(f'/api/v1/integrations/deliveries/{delivery["id"]}/retry', headers=headers).status_code == 400   # already sent
    for job_id in [j['id'] for j in scheduled]:
        client.post(f'/api/v1/ops/jobs/{job_id}/cancel', headers=headers)


@pytest.mark.asyncio
async def test_deliver_handler_skips_disabled_and_enforces_tenant(app):
    from app.integrations.delivery import record_result, retry_delay
    from app.models.integrations import WebhookDelivery, IntegrationConfig

    assert [retry_delay(n) for n in (1, 2, 3, 4, 9)] == [15, 60, 300, 600, 600]
    delivery = WebhookDelivery(tenant_id='t', integration_id='i', topic='finding.created', max_attempts=2)
    integration = IntegrationConfig(tenant_id='t', name='x', kind='webhook')
    record_result(None, delivery, integration, DeliveryResult(ok=False, error='HTTP 503', status_code=503, retryable=True))
    assert delivery.status == 'failed' and delivery.attempts == 1 and delivery.next_attempt_at is not None and integration.last_error == 'HTTP 503'
    record_result(None, delivery, integration, DeliveryResult(ok=False, error='HTTP 503', status_code=503, retryable=True))
    assert delivery.attempts == 2 and delivery.next_attempt_at is None   # max attempts reached: no further retry
    record_result(None, delivery, integration, DeliveryResult(ok=True, status_code=200, external_ref='X-1'))
    assert delivery.status == 'sent' and delivery.external_ref == 'X-1' and integration.last_error == '' and delivery.sent_at is not None


# ---------------------------------------------------------------- tenant isolation on every endpoint


def test_cross_tenant_isolation_on_every_endpoint(owner, second_tenant, ingest_key, monkeypatch):
    client, headers = owner
    monkeypatch.setenv('HOOK_SECRET', 's')
    created = client.post('/api/v1/integrations', json={'name': 'mine', 'kind': 'webhook', 'config': {'url': 'https://hooks.example.test/mine'},
                                                        'secret_refs': {'signing_secret': 'env:HOOK_SECRET'}}, headers=headers).json()
    with respx.mock() as mock:
        mock.post('https://hooks.example.test/mine').mock(return_value=httpx.Response(200, text='ok'))
        delivery_id = client.post(f'/api/v1/integrations/{created["id"]}/test', headers=headers).json()['delivery_id']
    client.post('/api/v1/ingest/falco', json=json.loads((FIXTURES / 'falco' / 'alerts.json').read_text(encoding='utf-8')), headers={'X-API-Key': ingest_key})
    other, oh = second_tenant['client'], second_tenant['headers']
    assert other.get('/api/v1/integrations', headers=oh).json()['items'] == []
    assert other.get(f'/api/v1/integrations/{created["id"]}', headers=oh).status_code == 404
    assert other.patch(f'/api/v1/integrations/{created["id"]}', json={'name': 'hijack'}, headers=oh).status_code == 404
    assert other.delete(f'/api/v1/integrations/{created["id"]}', headers=oh).status_code == 404
    assert other.post(f'/api/v1/integrations/{created["id"]}/test', headers=oh).status_code == 404
    assert other.post(f'/api/v1/integrations/{created["id"]}/sync', headers=oh).status_code == 404
    assert other.get('/api/v1/integrations/deliveries', headers=oh).json()['items'] == []
    assert other.get(f'/api/v1/integrations/deliveries/{delivery_id}', headers=oh).status_code == 404
    assert other.post(f'/api/v1/integrations/deliveries/{delivery_id}/retry', headers=oh).status_code == 404
    assert other.get('/api/v1/integrations/ingest/batches', headers=oh).json()['items'] == []
    assert other.get('/api/v1/integrations/types', headers=oh).status_code == 200
    # the owner still sees everything, and a viewer in the owner's tenant can read but not write
    assert client.get(f'/api/v1/integrations/{created["id"]}', headers=headers).json()['name'] == 'mine'
    assert delivery_id in {d['id'] for d in client.get('/api/v1/integrations/deliveries', headers=headers).json()['items']}
    assert client.get('/api/v1/integrations/ingest/batches', headers=headers).json()['items'][0]['source'] == 'falco'
    # A second-tenant webhook never receives the first tenant's events.
    other.post('/api/v1/integrations', json={'name': 'theirs', 'kind': 'webhook', 'config': {'url': 'https://hooks.example.test/theirs'}, 'topics': ['finding.*']}, headers=oh)
    with respx.mock(assert_all_called=False) as mock:
        theirs = mock.post('https://hooks.example.test/theirs').mock(return_value=httpx.Response(200, text='ok'))
        assert client.post('/api/v1/ingest/wazuh', json=json.loads((FIXTURES / 'wazuh' / 'alerts.json').read_text(encoding='utf-8')),
                           headers={'X-API-Key': ingest_key}).json()['findings'] == 1
        wait_for(lambda: [j for j in client.get('/api/v1/ops/jobs', headers=headers).json()['items'] if j['kind'] == 'integrations.fanout' and j['status'] == 'completed'] or None)
    assert len(theirs.calls) == 0 and other.get('/api/v1/integrations/deliveries', headers=oh).json()['items'] == []


def test_viewer_session_can_read_but_not_write(client, make_user):
    make_user('int-viewer@test.local', 'viewer-password-long-1', 'viewer')
    headers = login(client, 'int-viewer@test.local', 'viewer-password-long-1')
    assert client.get('/api/v1/integrations', headers=headers).status_code == 200
    assert client.get('/api/v1/integrations/deliveries', headers=headers).status_code == 200
    assert client.post('/api/v1/integrations', json={'name': 'x', 'kind': 'webhook', 'config': {'url': 'https://h.test'}}, headers=headers).status_code == 403
