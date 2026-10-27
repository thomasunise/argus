"""Capture and replay: the proxy half of discovery.

A capture is what the browser already saw: method, path, status, content type, and whether an
authorization header was present. Bodies and header values are never stored. Replay re-issues one
captured request through the scope gate, with a narrow method allowlist (GET/HEAD) so a replay can
never mutate the target.
"""
from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.core import policy
from app.core.errors import NotFound, ScopeDenied
from app.core.rbac import Principal, Role, system_principal
from app.discovery import service
from app.models import Asset, AssetAuthorization, Tenant, dumps, loads
from app.models.discovery import DiscoveryRun, RequestCapture
from app.models.testing import TestScope

TARGET = 'https://app.example.test'


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    monkeypatch.setattr(policy, 'validate_target', lambda kind, target, settings, *, resolve=True: target)
    monkeypatch.setattr(service, '_target_ip', lambda target: ('203.0.113.10', 443))


@pytest.fixture
def setup(app, client):
    app.state.settings.discovery_enabled = True
    app.state.settings.discovery_image = 'ghcr.io/thomasunise/argus-recon@sha256:' + 'c' * 64
    app.state.settings.discovery_follow_up_limit = 0
    tenant_id = app.state.default_tenant_id
    with app.state.db_factory() as db:
        tenant = db.get(Tenant, tenant_id)
        data = loads(tenant.settings_json, {})
        data['discovery'] = {'enabled': True}
        tenant.settings_json = dumps(data)
        asset = Asset(tenant_id=tenant_id, name='app', kind='web', target=TARGET, environment='staging', approved=True)
        db.add(asset)
        db.flush()
        db.add(AssetAuthorization(tenant_id=tenant_id, asset_id=asset.id, authorized_by='u',
                                  attestation='I confirm that this organization owns and controls this asset.',
                                  allow_active=True))
        scope = TestScope(tenant_id=tenant_id, name='disc', asset_ids_json=dumps([asset.id]),
                          allowed_tiers_json=dumps(['passive', 'active']))
        db.add(scope)
        db.flush()
        ids = {'tenant_id': tenant_id, 'asset_id': asset.id, 'scope_id': scope.id}
        db.commit()
    return app, ids


def _principal(app, ids) -> Principal:
    return system_principal(ids['tenant_id'])


def _capture(app, ids, *, method='GET', path='/admin') -> str:
    with app.state.db_factory() as db:
        run = DiscoveryRun(tenant_id=ids['tenant_id'], asset_id=ids['asset_id'], scope_id=ids['scope_id'])
        db.add(run)
        db.flush()
        row = RequestCapture(tenant_id=ids['tenant_id'], asset_id=ids['asset_id'], run_id=run.id,
                             scope_id=ids['scope_id'], method=method, path=path, status=200,
                             content_type='text/html', has_auth=True)
        db.add(row)
        db.commit()
        return row.id


def test_parse_requests_dedupes_and_ignores_noise():
    text = '\n'.join([
        service.REQUEST_MARKER + json.dumps({'method': 'GET', 'path': '/admin', 'status': 200,
                                             'content_type': 'text/html', 'has_auth': True}),
        service.REQUEST_MARKER + json.dumps({'method': 'GET', 'path': '/admin', 'status': 200}),
        service.REQUEST_MARKER + 'not json',
        service.REQUEST_MARKER + json.dumps({'method': 'GET', 'path': '/api/users', 'status': 401}),
    ])
    rows = service.parse_requests(text)
    assert [(r['method'], r['path']) for r in rows] == [('GET', '/admin'), ('GET', '/api/users')]
    assert rows[0]['has_auth'] is True


@pytest.mark.asyncio
@respx.mock
async def test_replay_reissues_a_captured_get(setup):
    app, ids = setup
    capture_id = _capture(app, ids, path='/admin')
    route = respx.get(f'{TARGET}/admin').mock(return_value=httpx.Response(200, text='dashboard'))

    result = await service.replay(app, _principal(app, ids), capture_id)

    assert route.called and result['status'] == 200 and result['path'] == '/admin'
    assert result['method'] == 'GET' and result['bytes'] == len('dashboard')
    assert 'dashboard' not in json.dumps(result)  # the body is never returned


@pytest.mark.asyncio
@respx.mock
async def test_replay_downgrades_unsafe_methods_to_get(setup):
    app, ids = setup
    capture_id = _capture(app, ids, method='DELETE', path='/admin')
    route = respx.get(f'{TARGET}/admin').mock(return_value=httpx.Response(200, text='ok'))
    result = await service.replay(app, _principal(app, ids), capture_id)
    assert route.called and result['method'] == 'GET'


@pytest.mark.asyncio
@respx.mock
async def test_replay_rejects_a_traversal_path(setup):
    app, ids = setup
    capture_id = _capture(app, ids, path='/../../etc/passwd')
    route = respx.get(f'{TARGET}/').mock(return_value=httpx.Response(200, text='ok'))
    result = await service.replay(app, _principal(app, ids), capture_id)
    assert route.called and result['path'] == '/'


@pytest.mark.asyncio
async def test_replay_is_denied_without_an_active_authorization(setup):
    app, ids = setup
    capture_id = _capture(app, ids)
    with app.state.db_factory() as db:
        for auth in db.query(AssetAuthorization).all():
            auth.allow_active = False
        db.commit()
    with pytest.raises(ScopeDenied, match='active testing'):
        await service.replay(app, _principal(app, ids), capture_id)


@pytest.mark.asyncio
async def test_replay_is_tenant_scoped(setup, second_tenant):
    app, ids = setup
    capture_id = _capture(app, ids)
    other = Principal(tenant_id=second_tenant['tenant_id'], role=Role.owner, auth='session', user_id='other', email='o@x')
    with pytest.raises(NotFound):
        await service.replay(app, other, capture_id)
