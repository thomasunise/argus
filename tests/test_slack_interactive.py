"""Slack interactive buttons: message blocks, signature verification, replay and timestamp checks,
user mapping, broker-enforced decisions (approve, deny, rollback), high-risk refusal, isolation."""
from __future__ import annotations

import json
import time
from urllib.parse import urlencode

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.actions import catalog
from app.api import slack as slack_api
from app.integrations.outbound import OutboundEvent
from app.integrations.outbound.slack import build_blocks
from app.models import AuditEntry
from tests.conftest import login, wait_for
from tests.test_autoresponse import Fake, FakeHigh

PW = 'operator-password-long-123456'
SECRET = 'slack-signing-secret-for-tests'


@pytest.fixture
def fakes():
    instances = {cls.name: cls() for cls in (Fake, FakeHigh)}
    for inst in instances.values():
        catalog.register(inst)
    yield instances
    for name in instances:
        catalog.unregister(name)


@pytest.fixture
def replies(monkeypatch):
    sent: list[tuple[str, str]] = []

    async def fake_reply(url, text):
        sent.append((url, text))

    monkeypatch.setattr(slack_api, '_reply', fake_reply)
    return sent


@pytest.fixture
def setup(app, owner, make_user, fakes):
    """Owner session, two operators (op1 requests, op2 is linked to Slack user U2), an interactive Slack integration."""
    client, headers = owner
    assert client.post('/api/v1/actions/kill-switch', json={'enabled': False}, headers=headers).status_code == 200
    make_user('op1@test.local', PW, 'operator')
    make_user('op2@test.local', PW, 'operator')
    make_user('viewer@test.local', PW, 'viewer')
    op1 = TestClient(app)
    h1 = login(op1, 'op1@test.local', PW)
    body = {'name': 'slack', 'kind': 'slack', 'topics': ['action.*'],
            'config': {'mode': 'webhook', 'interactive': True, 'execute_on_approve': False,
                       'user_map': {'U2': 'op2@test.local', 'U1': 'op1@test.local', 'UV': 'viewer@test.local', 'UX': 'nobody@test.local'}},
            'secret_refs': {'webhook_url': 'literal:https://hooks.slack.com/services/T0/B0/XYZ', 'signing_secret': f'literal:{SECRET}'}}
    resp = client.post('/api/v1/integrations', json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return {'client': client, 'headers': headers, 'op1': op1, 'h1': h1, 'integration_id': resp.json()['id']}


def request_action(env, action_type='test.ar.medium', target='srv-1'):
    resp = env['op1'].post('/api/v1/actions/requests', json={'action_type': action_type, 'params': {'target': target}, 'reason': 'test'},
                           headers=env['h1'])
    assert resp.status_code == 201, resp.text
    return resp.json()


def click(client, integration_id, action_id, value, user='U2', *, ts=None, secret=SECRET, signature=None, team='T0'):
    payload = {'type': 'block_actions', 'user': {'id': user}, 'team': {'id': team}, 'response_url': 'https://hooks.slack.com/actions/T0/1/abc',
               'actions': [{'action_id': action_id, 'value': value}]}
    body = urlencode({'payload': json.dumps(payload)}).encode()
    ts = ts or str(int(time.time()))
    sig = signature or slack_api.sign(secret, ts, body)
    return client.post(f'/api/v1/slack/interactions/{integration_id}', content=body,
                       headers={'x-slack-request-timestamp': ts, 'x-slack-signature': sig, 'content-type': 'application/x-www-form-urlencoded'})


def status_of(env, request_id):
    return env['client'].get(f'/api/v1/actions/requests/{request_id}', headers=env['headers']).json()['status']


# ---------------------------------------------------------------- blocks


def _event(topic, **payload):
    return OutboundEvent(topic=topic, tenant_id='t1', title='Action', payload=payload, url='https://argus.example/#/actions/r1')


def _ids(blocks):
    actions = [b for b in blocks if b['type'] == 'actions']
    return [e['action_id'] for e in actions[0]['elements']] if actions else []


def test_blocks_buttons_by_topic_and_risk():
    pending = _event('action.requested', request_id='r1', status='pending', risk='medium')
    assert _ids(build_blocks(pending)) == []  # not interactive: no buttons at all
    assert _ids(build_blocks(pending, {'interactive': True})) == ['argus_approve', 'argus_deny', 'argus_open']
    approve = next(b for b in build_blocks(pending, {'interactive': True}) if b['type'] == 'actions')['elements'][0]
    assert approve['value'] == 'r1' and approve['style'] == 'primary'
    auto = _event('action.requested', request_id='r1', status='auto_approved', risk='low')
    assert _ids(build_blocks(auto, {'interactive': True})) == ['argus_open']
    high = _event('action.requested', request_id='r1', status='pending', risk='high')
    blocks = build_blocks(high, {'interactive': True})
    assert _ids(blocks) == ['argus_open'] and any('MFA' in json.dumps(b) for b in blocks)
    assert _ids(build_blocks(high, {'interactive': True, 'allow_high_risk': True}))[:2] == ['argus_approve', 'argus_deny']
    executed = _event('action.executed', request_id='r1', run_id='run1', risk='medium', reversible=True)
    rollback = next(b for b in build_blocks(executed, {'interactive': True}) if b['type'] == 'actions')['elements'][0]
    assert rollback['action_id'] == 'argus_rollback' and rollback['value'] == 'run1' and 'confirm' in rollback
    assert _ids(build_blocks(_event('action.autonomous', run_id='run1', risk='medium', reversible=True), {'interactive': True}))[0] == 'argus_rollback'
    assert _ids(build_blocks(_event('action.executed', run_id='run1', risk='medium', reversible=False), {'interactive': True})) == ['argus_open']
    assert _ids(build_blocks(_event('finding.created'), {'interactive': True})) == []


def test_signature_helpers():
    body, ts = b'payload=%7B%7D', str(int(time.time()))
    sig = slack_api.sign(SECRET, ts, body)
    assert slack_api.verify(SECRET, ts, body, sig)
    assert not slack_api.verify(SECRET, ts, body + b'x', sig)
    assert not slack_api.verify('other', ts, body, sig)
    assert not slack_api.verify(SECRET, str(int(ts) - 301), body, slack_api.sign(SECRET, str(int(ts) - 301), body))
    assert not slack_api.verify('', ts, body, sig) and not slack_api.verify(SECRET, 'abc', body, sig)


@pytest.mark.asyncio
async def test_reply_only_to_slack_hooks():
    with respx.mock(assert_all_called=False) as mock:
        good = mock.post('https://hooks.slack.com/actions/T0/1/abc').mock(return_value=httpx.Response(200))
        evil = mock.post('https://evil.example/hook').mock(return_value=httpx.Response(200))
        await slack_api._reply('https://hooks.slack.com/actions/T0/1/abc', 'hi')
        await slack_api._reply('https://evil.example/hook', 'hi')
        await slack_api._reply('http://hooks.slack.com/actions/x', 'hi')
        assert good.call_count == 1 and evil.call_count == 0


# ---------------------------------------------------------------- endpoint


def test_approve_and_deny_from_slack(app, setup, replies, db, default_tenant_id):
    env = setup
    client, iid = env['client'], env['integration_id']
    req = request_action(env)
    resp = click(client, iid, 'argus_approve', req['id'])
    assert resp.status_code == 200, resp.text
    assert status_of(env, req['id']) == 'approved'
    assert 'Approved' in replies[-1][1] and replies[-1][0].startswith('https://hooks.slack.com/')
    detail = client.get(f'/api/v1/actions/requests/{req["id"]}', headers=env['headers']).json()
    assert detail['approvals'][0]['comment'] == 'via Slack'

    other = request_action(env, target='srv-2')
    assert click(client, iid, 'argus_deny', other['id']).status_code == 200
    assert status_of(env, other['id']) == 'rejected' and 'Denied' in replies[-1][1]
    trail = db.execute(select(AuditEntry).where(AuditEntry.tenant_id == default_tenant_id, AuditEntry.action == 'slack.interaction')).scalars().all()
    assert len(trail) == 2 and all('slack' in t.detail for t in trail)


def test_execute_on_approve_and_rollback_button(app, setup, replies):
    env = setup
    client, headers, iid = env['client'], env['headers'], env['integration_id']
    patched = client.patch(f'/api/v1/integrations/{iid}', json={'config': {'mode': 'webhook', 'interactive': True, 'execute_on_approve': True,
                                                                            'user_map': {'U2': 'op2@test.local'}}}, headers=headers)
    assert patched.status_code == 200, patched.text
    req = request_action(env)
    assert click(client, iid, 'argus_approve', req['id']).status_code == 200
    assert 'queued' in replies[-1][1], replies
    detail = wait_for(lambda: (d := client.get(f'/api/v1/actions/requests/{req["id"]}', headers=headers).json())['status'] == 'executed' and d)
    run_id = detail['runs'][0]['id']
    assert click(client, iid, 'argus_rollback', run_id).status_code == 200
    assert 'Rollback' in replies[-1][1]
    wait_for(lambda: client.get(f'/api/v1/actions/runs/{run_id}', headers=headers).json()['status'] == 'rolled_back')


def test_broker_rules_still_apply(app, setup, replies):
    env = setup
    client, iid = env['client'], env['integration_id']
    req = request_action(env)
    # the requester cannot approve their own request from Slack either
    assert click(client, iid, 'argus_approve', req['id'], user='U1').status_code == 200
    assert status_of(env, req['id']) == 'pending' and 'refused' in replies[-1][1]
    # a viewer lacks actions:approve
    assert click(client, iid, 'argus_approve', req['id'], user='UV').status_code == 200
    assert status_of(env, req['id']) == 'pending' and 'refused' in replies[-1][1]
    # unmapped and unknown users are told to link their account
    assert click(client, iid, 'argus_approve', req['id'], user='UZ').status_code == 200
    assert status_of(env, req['id']) == 'pending' and 'not linked' in replies[-1][1]
    assert click(client, iid, 'argus_approve', req['id'], user='UX').status_code == 200
    assert 'does not exist' in replies[-1][1]
    # high risk must be decided in Argus
    high = request_action(env, action_type='test.ar.high')
    assert click(client, iid, 'argus_approve', high['id']).status_code == 200
    assert status_of(env, high['id']) == 'pending' and 'MFA' in replies[-1][1]
    # unknown ids
    assert click(client, iid, 'argus_approve', 'no-such-request').status_code == 200 and 'no longer exists' in replies[-1][1]
    assert click(client, iid, 'argus_rollback', 'no-such-run').status_code == 200 and 'no longer exists' in replies[-1][1]


def test_authentication_failures(app, setup, replies):
    env = setup
    client, headers, iid = env['client'], env['headers'], env['integration_id']
    req = request_action(env)
    assert click(client, iid, 'argus_approve', req['id'], secret='wrong-secret').status_code == 401
    old = str(int(time.time()) - 600)
    assert click(client, iid, 'argus_approve', req['id'], ts=old).status_code == 401
    assert click(client, 'no-such-integration', 'argus_approve', req['id']).status_code == 401
    missing = client.post(f'/api/v1/slack/interactions/{iid}', content=b'payload=%7B%7D')
    assert missing.status_code == 401
    assert click(client, iid, 'argus_approve', req['id'], team='T-OTHER').status_code == 200  # no team_id pinned yet
    # replay of an identical signed request is refused
    ts = str(int(time.time()))
    other = request_action(env, target='srv-3')
    body_req = click(client, iid, 'argus_deny', other['id'], ts=ts)
    assert body_req.status_code == 200
    assert click(client, iid, 'argus_deny', other['id'], ts=ts).status_code == 401
    # pinned workspace and non-interactive integrations refuse
    client.patch(f'/api/v1/integrations/{iid}', json={'config': {'mode': 'webhook', 'interactive': True, 'team_id': 'T0',
                                                                 'user_map': {'U2': 'op2@test.local'}}}, headers=headers)
    third = request_action(env, target='srv-4')
    assert click(client, iid, 'argus_approve', third['id'], team='T-OTHER').status_code == 401
    client.patch(f'/api/v1/integrations/{iid}', json={'config': {'mode': 'webhook', 'interactive': False}}, headers=headers)
    assert click(client, iid, 'argus_approve', third['id']).status_code == 401
    assert status_of(env, third['id']) == 'pending'


def test_cross_tenant_ids_are_not_reachable(app, setup, second_tenant, replies, make_user):
    env = setup
    other, oh = second_tenant['client'], second_tenant['headers']
    assert other.post('/api/v1/actions/kill-switch', json={'enabled': False}, headers=oh).status_code == 200
    make_user('op9@acme.test', PW, 'operator', tenant_id=second_tenant['tenant_id'])
    op9 = TestClient(app)
    h9 = login(op9, 'op9@acme.test', PW)
    foreign = op9.post('/api/v1/actions/requests', json={'action_type': 'test.ar.medium', 'params': {'target': 'x'}, 'reason': 'r'}, headers=h9).json()
    assert click(env['client'], env['integration_id'], 'argus_approve', foreign['id']).status_code == 200
    assert 'no longer exists' in replies[-1][1]
    assert other.get(f'/api/v1/actions/requests/{foreign["id"]}', headers=oh).json()['status'] == 'pending'
