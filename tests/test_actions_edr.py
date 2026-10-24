"""Endpoint containment executors: CrowdStrike Falcon host containment and SentinelOne network disconnect."""
from __future__ import annotations

import json
import logging
from types import SimpleNamespace

import httpx
import pytest
import respx

from app.actions import catalog, load_executors
from app.actions.catalog import ActionError, ExecContext
from app.actions.executors import crowdstrike, sentinelone

load_executors()

AID = 'a' * 32
CS = 'https://api.crowdstrike.com'
S1 = 'https://acme.sentinelone.net/web/api/v2.1'


async def _hb():
    return None


def ctx(settings, platform: str) -> ExecContext:
    return ExecContext(tenant_id='t1', settings=settings, request=SimpleNamespace(id='req-1'), logger=logging.getLogger('test'), heartbeat=_hb,
                       platform=platform, actor='tester')


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv('ACTIONS_CROWDSTRIKE_CLIENT_ID', 'cs-id')
    monkeypatch.setenv('ACTIONS_CROWDSTRIKE_CLIENT_SECRET', 'cs-secret')
    monkeypatch.setenv('ACTIONS_SENTINELONE_API_URL', 'https://acme.sentinelone.net')
    monkeypatch.setenv('ACTIONS_SENTINELONE_TOKEN', 's1-token')


def _device(**extra) -> dict:
    return {'device_id': AID, 'hostname': 'WS-042', 'platform_name': 'Windows', 'status': 'normal', 'product_type_desc': 'Workstation',
            'last_seen': '2026-10-24T10:00:00Z', **extra}


def test_registered_and_governed():
    for name in ('crowdstrike.host.contain', 'sentinelone.endpoint.disconnect'):
        action = catalog.get(name)
        assert action is not None and action.reversible and action.risk == 'high' and action.category == 'containment'
    assert crowdstrike.ContainHost._plan(_device())['json'] == {'ids': [AID]}
    assert sentinelone.DisconnectEndpoint._plan({'id': '123456789'})['json'] == {'filter': {'ids': ['123456789']}}


def test_available_only_with_credentials(settings, env, monkeypatch):
    assert catalog.get('crowdstrike.host.contain').available(settings)
    monkeypatch.delenv('ACTIONS_CROWDSTRIKE_CLIENT_SECRET')
    assert not catalog.get('crowdstrike.host.contain').available(settings)


@pytest.mark.asyncio
async def test_crowdstrike_contain_lifecycle_by_hostname(settings, env):
    action = catalog.get('crowdstrike.host.contain')
    params = action.normalize({'hostname': 'WS-042'})
    with respx.mock(base_url=CS, assert_all_called=False) as mock:
        token = mock.post('/oauth2/token').mock(return_value=httpx.Response(201, json={'access_token': 'tok', 'expires_in': 1799}))
        query = mock.get('/devices/queries/devices/v1').mock(return_value=httpx.Response(200, json={'resources': [AID]}))
        mock.get('/devices/entities/devices/v2').mock(return_value=httpx.Response(200, json={'resources': [_device()]}))
        act = mock.post('/devices/entities/devices-actions/v2').mock(return_value=httpx.Response(202, json={'resources': [{'id': AID}], 'errors': []}))
        dry = await action.dry_run(params, ctx(settings, 'crowdstrike'))
        assert dry.ok and dry.entities == 1 and "hostname:'WS-042'" == query.calls.last.request.url.params['filter']
        assert token.calls.last.request.content == b'client_id=cs-id&client_secret=cs-secret'
        result = await action.execute(params, ctx(settings, 'crowdstrike'))
        request = act.calls.last.request
        assert request.url.params['action_name'] == 'contain' and json.loads(request.content) == {'ids': [AID]}
        assert request.headers['Authorization'] == 'Bearer tok'
        assert result.rollback_payload == {'device_id': AID, 'hostname': 'WS-042'}
        await action.rollback(result.rollback_payload, ctx(settings, 'crowdstrike'))
        assert act.calls.last.request.url.params['action_name'] == 'lift_containment'


@pytest.mark.asyncio
async def test_crowdstrike_refuses_servers_contained_and_ambiguous(settings, env):
    action = catalog.get('crowdstrike.host.contain')
    with respx.mock(base_url=CS, assert_all_called=False) as mock:
        mock.post('/oauth2/token').mock(return_value=httpx.Response(201, json={'access_token': 'tok'}))
        devices = mock.get('/devices/entities/devices/v2')
        devices.mock(return_value=httpx.Response(200, json={'resources': [_device(product_type_desc='Domain Controller')]}))
        refused = await action.dry_run(action.normalize({'device_id': AID}), ctx(settings, 'crowdstrike'))
        assert not refused.ok and 'allow_servers' in refused.summary
        allowed = await action.dry_run(action.normalize({'device_id': AID, 'allow_servers': True}), ctx(settings, 'crowdstrike'))
        assert allowed.ok and any('domain controller' in w for w in allowed.warnings)
        devices.mock(return_value=httpx.Response(200, json={'resources': [_device(status='contained')]}))
        assert not (await action.dry_run(action.normalize({'device_id': AID}), ctx(settings, 'crowdstrike'))).ok
        mock.get('/devices/queries/devices/v1').mock(return_value=httpx.Response(200, json={'resources': [AID, 'b' * 32]}))
        devices.mock(return_value=httpx.Response(200, json={'resources': [_device(), _device(device_id='b' * 32)]}))
        ambiguous = await action.dry_run(action.normalize({'hostname': 'WS-042'}), ctx(settings, 'crowdstrike'))
        assert not ambiguous.ok and 'device_id' in ambiguous.summary
        mock.post('/devices/entities/devices-actions/v2').mock(return_value=httpx.Response(200, json={'errors': [{'message': 'denied'}]}))
        devices.mock(return_value=httpx.Response(200, json={'resources': [_device()]}))
        with pytest.raises(ActionError, match='denied'):
            await action.execute(action.normalize({'device_id': AID}), ctx(settings, 'crowdstrike'))


@pytest.mark.asyncio
async def test_crowdstrike_base_url_is_pinned(settings, env, monkeypatch):
    monkeypatch.setenv('ACTIONS_CROWDSTRIKE_BASE_URL', 'https://evil.example.com')
    action = catalog.get('crowdstrike.host.contain')
    with pytest.raises(ActionError, match='crowdstrike.com'):
        await action.dry_run(action.normalize({'device_id': AID}), ctx(settings, 'crowdstrike'))
    assert action.validate({'device_id': 'not-hex'})  # schema rejects malformed ids


@pytest.mark.asyncio
async def test_sentinelone_disconnect_lifecycle(settings, env):
    action = catalog.get('sentinelone.endpoint.disconnect')
    agent = {'id': '1234567890', 'computerName': 'LAPTOP-7', 'networkStatus': 'connected', 'osType': 'macos', 'machineType': 'laptop'}
    params = action.normalize({'computer_name': 'LAPTOP-7'})
    with respx.mock(base_url=S1, assert_all_called=False) as mock:
        agents = mock.get('/agents').mock(return_value=httpx.Response(200, json={'data': [agent]}))
        disconnect = mock.post('/agents/actions/disconnect').mock(return_value=httpx.Response(200, json={'data': {'affected': 1}}))
        connect = mock.post('/agents/actions/connect').mock(return_value=httpx.Response(200, json={'data': {'affected': 1}}))
        dry = await action.dry_run(params, ctx(settings, 'sentinelone'))
        assert dry.ok and agents.calls.last.request.url.params['computerName'] == 'LAPTOP-7'
        assert agents.calls.last.request.headers['Authorization'] == 'ApiToken s1-token'
        result = await action.execute(params, ctx(settings, 'sentinelone'))
        assert json.loads(disconnect.calls.last.request.content) == {'filter': {'ids': ['1234567890']}}
        await action.rollback(result.rollback_payload, ctx(settings, 'sentinelone'))
        assert connect.called
        mock.get('/agents').mock(return_value=httpx.Response(200, json={'data': [dict(agent, machineType='server')]}))
        assert not (await action.dry_run(params, ctx(settings, 'sentinelone'))).ok
        mock.get('/agents').mock(return_value=httpx.Response(200, json={'data': [dict(agent, networkStatus='disconnected')]}))
        assert not (await action.dry_run(params, ctx(settings, 'sentinelone'))).ok
        mock.get('/agents').mock(return_value=httpx.Response(200, json={'data': [agent]}))
        mock.post('/agents/actions/disconnect').mock(return_value=httpx.Response(200, json={'data': {'affected': 0}}))
        with pytest.raises(ActionError):
            await action.execute(params, ctx(settings, 'sentinelone'))


@pytest.mark.asyncio
async def test_sentinelone_url_must_be_console(settings, env, monkeypatch):
    monkeypatch.setenv('ACTIONS_SENTINELONE_API_URL', 'http://acme.sentinelone.net')
    action = catalog.get('sentinelone.endpoint.disconnect')
    with pytest.raises(ActionError, match='sentinelone.net'):
        await action.dry_run(action.normalize({'agent_id': '1234567890'}), ctx(settings, 'sentinelone'))
