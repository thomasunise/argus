"""Browser discovery: runner helpers, and a two-phase discovery run (browser then recon)."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from app.core import policy
from app.discovery import service
from app.exploit.engine import EngineResult
from app.models import Asset, AssetAuthorization, Tenant, dumps, loads
from app.models.discovery import Discovery, DiscoveryRun, RequestCapture
from app.models.testing import TestScope

REPO = Path(__file__).resolve().parents[1]
BROWSER_IMAGE = 'ghcr.io/thomasunise/argus-browser@sha256:' + 'd' * 64
RECON_IMAGE = 'ghcr.io/thomasunise/argus-recon@sha256:' + 'c' * 64

BROWSER_OUT = '\n'.join([
    service.DISCOVERY_MARKER + json.dumps({'kind': 'endpoint', 'value': '/app/dashboard', 'source': 'browser-request'}),
    service.DISCOVERY_MARKER + json.dumps({'kind': 'endpoint', 'value': '/admin', 'source': 'browser-dom'}),
    service.TRAILER + json.dumps({'exit_code': 0, 'discoveries': 2}),
])
RECON_OUT = '\n'.join([
    service.DISCOVERY_MARKER + json.dumps({'kind': 'endpoint', 'value': '/admin', 'source': 'probe'}),
    service.DISCOVERY_MARKER + json.dumps({'kind': 'endpoint', 'value': '/login', 'source': 'probe'}),
    service.TRAILER + json.dumps({'exit_code': 0, 'discoveries': 2}),
])


def _runner():
    spec = importlib.util.spec_from_file_location('browser_runner', REPO / 'sandbox' / 'browser_runner.py')
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_same_origin_and_path_normalization():
    runner = _runner()
    assert runner.same_origin('https://app.example.com/x', 'https://app.example.com') is True
    assert runner.same_origin('https://cdn.example.com/x.js', 'https://app.example.com') is False
    assert runner.same_origin('/relative', 'https://app.example.com') is True
    assert runner.normalize_path('https://app.example.com/a?b=1', 'https://app.example.com') == '/a'


def test_links_are_filtered_to_the_asset():
    runner = _runner()
    html = ('<a href="/admin">a</a><script src="https://cdn.example.com/app.js"></script>'
            '<a href="mailto:x@y.z">m</a><form action="/login"></form>')
    links = runner.extract_links(html, 'https://app.example.com/')
    assert '/admin' in links and '/login' in links
    assert '/app.js' not in links and not any(link.startswith('mailto') for link in links)


class PhaseClient:
    """Returns a different transcript per image, and records the jobs in order."""

    def __init__(self):
        self.jobs = []

    async def run(self, job):
        self.jobs.append(job)
        stdout = BROWSER_OUT if job.image == BROWSER_IMAGE else RECON_OUT
        return EngineResult(exit_code=0, stdout=stdout, execution_id=job.name)


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    monkeypatch.setattr(policy, 'validate_target', lambda kind, target, settings, *, resolve=True: target)
    monkeypatch.setattr(service, '_target_ip', lambda target: ('203.0.113.10', 443))


@pytest.fixture
def setup(app, client):
    app.state.settings.discovery_enabled = True
    app.state.settings.discovery_image = RECON_IMAGE
    app.state.settings.discovery_browser_image = BROWSER_IMAGE
    app.state.settings.discovery_follow_up_limit = 0
    tenant_id = app.state.default_tenant_id
    with app.state.db_factory() as db:
        tenant = db.get(Tenant, tenant_id)
        data = loads(tenant.settings_json, {})
        data['discovery'] = {'enabled': True}
        tenant.settings_json = dumps(data)
        asset = Asset(tenant_id=tenant_id, name='app', kind='web', target='https://app.example.com',
                      environment='staging', approved=True)
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


def test_browser_runs_first_and_facts_are_merged(setup):
    import asyncio

    app, ids = setup
    with app.state.db_factory() as db:
        run = DiscoveryRun(tenant_id=ids['tenant_id'], asset_id=ids['asset_id'], scope_id=ids['scope_id'])
        db.add(run)
        db.commit()
        run_id = run.id

    client = PhaseClient()
    outcome = asyncio.run(service.execute_run(app, run_id, client=client))

    assert outcome['status'] == 'completed'
    assert [job.image for job in client.jobs] == [BROWSER_IMAGE, RECON_IMAGE]
    assert [job.suffix for job in client.jobs] == ['b', 'r']
    assert outcome['discoveries'] == 3  # /admin deduped across the two phases

    with app.state.db_factory() as db:
        values = sorted(row.value for row in db.query(Discovery).all())
        assert values == ['/admin', '/app/dashboard', '/login']


CAPTURE_OUT = '\n'.join([
    service.REQUEST_MARKER + json.dumps({'method': 'GET', 'path': '/admin', 'status': 200,
                                         'content_type': 'text/html', 'has_auth': True}),
    service.REQUEST_MARKER + json.dumps({'method': 'POST', 'path': '/api/login', 'status': 401,
                                         'content_type': 'application/json', 'has_auth': False}),
    service.TRAILER + json.dumps({'exit_code': 0, 'discoveries': 0}),
])


def test_browser_requests_become_captures(setup):
    import asyncio

    app, ids = setup
    app.state.settings.discovery_browser_image = ''  # one engine is enough for this assertion

    class CaptureClient:
        async def run(self, job):
            return EngineResult(exit_code=0, stdout=CAPTURE_OUT, execution_id=job.name)

    with app.state.db_factory() as db:
        run = DiscoveryRun(tenant_id=ids['tenant_id'], asset_id=ids['asset_id'], scope_id=ids['scope_id'])
        db.add(run)
        db.commit()
        run_id = run.id

    outcome = asyncio.run(service.execute_run(app, run_id, client=CaptureClient()))
    assert outcome['status'] == 'completed'

    with app.state.db_factory() as db:
        rows = db.query(RequestCapture).all()
        assert {(row.method, row.path) for row in rows} == {('GET', '/admin'), ('POST', '/api/login')}
        assert any(row.has_auth for row in rows)
