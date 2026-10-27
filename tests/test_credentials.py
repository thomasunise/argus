"""Authenticated testing: encrypted credentials, header injection, and the API around them."""
from __future__ import annotations

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.models import Asset, AssetCredential, dumps
from app.models.testing import TestScope
from app.testing import harness
from app.testing.adapters import param_probe
from app.testing.auth import load_auth_headers
from tests.conftest import login
from tests.test_testing_adapters import _asset, _ctx, _scope

TARGET = 'https://app.example.test'
ANY = r'^https://app\.example\.test/.*$'


def _adapter_ctx(settings, headers):
    ctx = _ctx(settings, target=TARGET, tier='active')
    ctx.auth_headers = headers
    return ctx


@pytest.mark.asyncio
@respx.mock
async def test_param_probe_sends_the_asset_credentials(settings):
    seen = {}

    def capture(request):
        seen['authorization'] = request.headers.get('authorization', '')
        seen['cookie'] = request.headers.get('cookie', '')
        return httpx.Response(200, text='nothing reflected')

    respx.route(method='GET', url__regex=ANY).mock(side_effect=capture)
    await param_probe.ParamProbeAdapter().run(
        {}, _asset('web', TARGET), _scope(),
        _adapter_ctx(settings, {'Authorization': 'Bearer session-token', 'Cookie': 'sid=abc'}))
    assert seen['authorization'] == 'Bearer session-token'
    assert seen['cookie'] == 'sid=abc'


@pytest.mark.asyncio
@respx.mock
async def test_param_probe_without_credentials_sends_no_authorization(settings):
    seen = {}

    def capture(request):
        seen['authorization'] = request.headers.get('authorization', '')
        return httpx.Response(200, text='ok')

    respx.route(method='GET', url__regex=ANY).mock(side_effect=capture)
    await param_probe.ParamProbeAdapter().run({}, _asset('web', TARGET), _scope(), _ctx(settings, target=TARGET))
    assert seen['authorization'] == ''


def test_header_loading_covers_every_kind(app, default_tenant_id):
    with app.state.db_factory() as db:
        asset = Asset(tenant_id=default_tenant_id, name='app', kind='web', target=TARGET, environment='staging')
        db.add(asset)
        db.flush()
        db.add_all([
            AssetCredential(tenant_id=default_tenant_id, asset_id=asset.id, kind='header', name='X-Api-Key', secret='k-123'),
            AssetCredential(tenant_id=default_tenant_id, asset_id=asset.id, kind='bearer', name='token', secret='t-456'),
        ])
        db.commit()
        headers = load_auth_headers(db, default_tenant_id, asset.id)
    assert headers['X-Api-Key'] == 'k-123'
    assert headers['Authorization'] == 'Bearer t-456'


def test_credentials_are_encrypted_at_rest(app, default_tenant_id):
    with app.state.db_factory() as db:
        asset = Asset(tenant_id=default_tenant_id, name='app2', kind='web', target=TARGET, environment='staging')
        db.add(asset)
        db.flush()
        db.add(AssetCredential(tenant_id=default_tenant_id, asset_id=asset.id, kind='bearer', name='token', secret='super-secret-value'))
        db.commit()
        raw = db.execute(__import__('sqlalchemy').text('SELECT secret FROM asset_credentials')).scalar_one()
        row = db.query(AssetCredential).first()
        assert 'super-secret-value' not in str(raw)  # ciphertext column
        assert row.secret == 'super-secret-value'    # transparent on the ORM


def test_credential_api_never_returns_the_secret(owner, app, default_tenant_id):
    client, headers = owner
    created = client.post('/api/v1/assets', json={'name': 'App', 'kind': 'web', 'target': TARGET,
                                                  'environment': 'staging'}, headers=headers)
    asset_id = created.json()['id']
    added = client.post(f'/api/v1/assets/{asset_id}/credentials',
                        json={'kind': 'bearer', 'name': 'token', 'value': 'top-secret'},
                        headers=headers)
    assert added.status_code == 201, added.text
    assert 'top-secret' not in added.text

    listed = client.get(f'/api/v1/assets/{asset_id}/credentials', headers=headers)
    assert listed.status_code == 200 and 'top-secret' not in listed.text
    assert listed.json()['items'][0]['kind'] == 'bearer'

    credential_id = added.json()['id']
    assert client.delete(f'/api/v1/assets/{asset_id}/credentials/{credential_id}', headers=headers).status_code == 200
    with app.state.db_factory() as db:
        row = db.get(AssetCredential, credential_id)
        assert row.revoked_at is not None  # revoked, not deleted: the history stays auditable


def test_viewer_cannot_add_credentials(owner, app, make_user):
    client, headers = owner
    created = client.post('/api/v1/assets', json={'name': 'App', 'kind': 'web', 'target': TARGET,
                                                  'environment': 'staging'}, headers=headers)
    asset_id = created.json()['id']
    make_user('viewer-cred@test.local', 'viewer-password-long-123', 'viewer')
    other = TestClient(app)
    other_headers = login(other, 'viewer-cred@test.local', 'viewer-password-long-123')
    response = other.post(f'/api/v1/assets/{asset_id}/credentials',
                          json={'kind': 'bearer', 'name': 'token', 'value': 'x'}, headers=other_headers)
    assert response.status_code == 403
