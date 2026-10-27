"""Out-of-band verification: the callback listener and the SSRF probe that depends on it."""
from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models import Asset
from app.models.oob import OobToken
from app.testing import harness
from app.testing.adapters import oob_probe
from app.testing.ratelimit import RateLimiter

TARGET = 'https://app.example.test'
ANY = r'^https://app\.example\.test/.*$'


# ---- listener --------------------------------------------------------------


def test_callback_records_a_hit(app, client):
    with app.state.db_factory() as db:
        asset = Asset(tenant_id='t-oob', name='a', kind='web', target=TARGET, environment='staging')
        db.add(asset)
        db.flush()
        token = OobToken(tenant_id='t-oob', asset_id=asset.id, token='tok-123', kind='ssrf')
        db.add(token)
        db.commit()

    response = TestClient(app).get('/api/v1/oob/tok-123', headers={'user-agent': 'curl/8'})
    assert response.status_code == 200 and response.headers['content-type'].startswith('image/gif')

    with app.state.db_factory() as db:
        row = db.execute(select(OobToken).where(OobToken.token == 'tok-123')).scalar_one()
        assert row.hit_count == 1 and row.first_hit_at is not None
        assert row.user_agent.startswith('curl')

    again = TestClient(app).post('/api/v1/oob/tok-123')
    assert again.status_code == 200 and again.json()['hits'] == 2


def test_unknown_token_is_not_recorded(app, client):
    assert TestClient(app).get('/api/v1/oob/does-not-exist').status_code == 404


# ---- probe -----------------------------------------------------------------


def _ctx(app, settings):
    async def _hb():
        return None

    return harness.HarnessContext(settings=settings, tenant_id='t-oob', run_id='run-oob-1', heartbeat=_hb,
                                  rate_limiter=RateLimiter(1000), logger=harness.log, scan_root=settings.scan_root,
                                  tier='intrusive', target=TARGET, db_factory=app.state.db_factory)


@pytest.fixture
def asset(app, client, settings):  # client starts the lifespan, which creates the tables
    settings.oob_enabled = True
    settings.oob_base_url = 'https://argus.example.test'
    settings.oob_wait_seconds = 2
    with app.state.db_factory() as db:
        row = Asset(tenant_id='t-oob', name='app', kind='web', target=TARGET, environment='staging')
        db.add(row)
        db.commit()
        return SimpleNamespace(id=row.id, name='app', kind='web', target=TARGET, environment='staging')


@pytest.mark.asyncio
@respx.mock
async def test_probe_reports_a_confirmed_ssrf(app, settings, asset):
    def handler(request):
        callback = request.url.params.get('url', '')
        token = callback.rsplit('/', 1)[-1] if callback else ''
        if token:
            with app.state.db_factory() as db:
                row = db.execute(select(OobToken).where(OobToken.token == token)).scalar_one_or_none()
                if row is not None:
                    row.hit_count += 1
                    row.first_hit_at = row.created_at
                    row.source_ip = '10.0.0.5'
                    db.commit()
        return httpx.Response(200, text='ok')

    respx.route(method='GET', url__regex=ANY).mock(side_effect=handler)
    findings = await oob_probe.OobProbeAdapter().run({}, asset, None, _ctx(app, settings))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == 'oob:ssrf:url' and finding.severity == 'high'
    assert finding.evidence['source_ip'] == '10.0.0.5'


@pytest.mark.asyncio
@respx.mock
async def test_probe_is_silent_without_a_callback(app, settings, asset):
    settings.oob_wait_seconds = 1
    respx.route(method='GET', url__regex=ANY).mock(return_value=httpx.Response(200, text='ok'))
    findings = await oob_probe.OobProbeAdapter().run({}, asset, None, _ctx(app, settings))
    assert findings == []


@pytest.mark.asyncio
async def test_probe_does_nothing_when_oob_is_disabled(app, settings, asset):
    settings.oob_enabled = False
    assert await oob_probe.OobProbeAdapter().run({}, asset, None, _ctx(app, settings)) == []
