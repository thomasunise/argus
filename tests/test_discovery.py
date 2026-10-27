"""Discovery loop: parsing, dedupe, the follow-up cap, and the scope gate.

The recon engine is faked (it returns `ARGUS_DISCOVERY` lines), so these tests exercise Argus's
half of the loop: what it stores, what it refuses, and how many follow-up tests it will queue.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core import policy
from app.core.errors import ScopeDenied
from app.discovery import service
from app.models import Asset, AssetAuthorization, Tenant, dumps, loads
from app.models.discovery import Discovery, DiscoveryRun
from app.models.testing import TestScope
from app.exploit.engine import EngineResult

REPO = Path(__file__).resolve().parents[1]
STDOUT = '\n'.join([
    service.DISCOVERY_MARKER + json.dumps({'kind': 'endpoint', 'value': '/admin', 'source': 'probe'}),
    service.DISCOVERY_MARKER + json.dumps({'kind': 'endpoint', 'value': '/api/v1/users', 'source': 'crawl'}),
    service.DISCOVERY_MARKER + json.dumps({'kind': 'technology', 'value': 'server: nginx/1.24', 'source': 'headers'}),
    service.TRAILER + json.dumps({'exit_code': 0, 'discoveries': 3}),
])


class FakeClient:
    def __init__(self, stdout: str = STDOUT):
        self.stdout = stdout
        self.jobs = []

    async def run(self, job):
        self.jobs.append(job)
        return EngineResult(exit_code=0, stdout=self.stdout)


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    monkeypatch.setattr(policy, 'validate_target', lambda kind, target, settings, *, resolve=True: target)
    monkeypatch.setattr(service, '_target_ip', lambda target: ('203.0.113.10', 443))


@pytest.fixture
def setup(app, client):
    app.state.settings.discovery_enabled = True
    app.state.settings.discovery_image = 'ghcr.io/thomasunise/argus-recon@sha256:' + 'c' * 64
    app.state.settings.discovery_follow_up_limit = 1
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


def _run_row(app, ids) -> str:
    with app.state.db_factory() as db:
        run = DiscoveryRun(tenant_id=ids['tenant_id'], asset_id=ids['asset_id'], scope_id=ids['scope_id'])
        db.add(run)
        db.commit()
        return run.id


def _execute(app, run_id, *, client=None, launcher=None):
    import asyncio

    return asyncio.run(service.execute_run(app, run_id, client=client or FakeClient(), launcher=launcher))


def test_parse_discoveries_dedupes_and_bounds():
    facts = service.parse_discoveries(STDOUT)
    assert [f['value'] for f in facts] == ['/admin', '/api/v1/users', 'server: nginx/1.24']
    assert all(f['kind'] in {'endpoint', 'technology'} for f in facts)
    weird = service.DISCOVERY_MARKER + json.dumps({'kind': 'nonsense', 'value': '/x'})
    assert service.parse_discoveries(weird)[0]['kind'] == 'endpoint'
    assert service.parse_discoveries(service.DISCOVERY_MARKER + json.dumps({'kind': 'endpoint', 'value': 'x' * 600})) == []


def test_recon_path_extraction_is_same_origin_and_bounded():
    spec = importlib.util.spec_from_file_location('recon_runner', REPO / 'sandbox' / 'recon_runner.py')
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    html = '<a href="/admin">a</a><script src="https://cdn.example.com/app.js"></script>' \
           '<form action="/login"></form><a href="mailto:x@y.z">m</a>'
    paths = module.extract_paths(html, origin_host='app.example.com')
    assert '/admin' in paths and '/login' in paths
    assert '/app.js' not in paths  # a different origin's asset is not this asset's path
    assert not any(p.startswith('mailto') for p in paths)
    assert module.technologies({'server': 'nginx/1.24'}) == ['server: nginx/1.24']


def test_run_stores_facts_and_queues_capped_follow_ups(setup):
    app, ids = setup
    launched = []

    async def launcher(*args, **kwargs):
        launched.append(kwargs)
        return {'id': f'test-run-{len(launched)}'}

    outcome = _execute(app, _run_row(app, ids), launcher=launcher)
    assert outcome['status'] == 'completed' and outcome['discoveries'] == 3
    assert outcome['follow_ups'] == 1 and len(launched) == 1  # cap is 1, and only endpoints qualify
    assert launched[0]['adapter_name'] == 'nuclei'

    with app.state.db_factory() as db:
        facts = db.query(Discovery).all()
        assert len(facts) == 3
        queued = [f for f in facts if f.status == 'queued_for_test']
        assert len(queued) == 1 and queued[0].test_run_id == 'test-run-1'


def test_second_run_dedupes_and_queues_nothing_new(setup):
    app, ids = setup
    _execute(app, _run_row(app, ids), launcher=lambda *a, **k: _noop())
    outcome = _execute(app, _run_row(app, ids), launcher=lambda *a, **k: _noop())
    assert outcome['discoveries'] == 3 and outcome['follow_ups'] == 0
    with app.state.db_factory() as db:
        assert db.query(Discovery).count() == 3


def test_scope_without_active_testing_denies_the_run(setup):
    app, ids = setup
    with app.state.db_factory() as db:
        for auth in db.query(AssetAuthorization).all():
            auth.allow_active = False
        db.commit()
    outcome = _execute(app, _run_row(app, ids))
    assert outcome['status'] == 'denied'
    with app.state.db_factory() as db:
        run = db.query(DiscoveryRun).order_by(DiscoveryRun.created_at.desc()).first()
        assert run.status == 'denied' and 'active testing' in run.error


def test_kill_switch_denies_every_run(setup):
    app, ids = setup
    app.state.settings.discovery_kill_switch = True
    outcome = _execute(app, _run_row(app, ids))
    assert outcome['status'] == 'denied' and 'kill switch' in outcome['reason']


def test_tenant_must_opt_in(setup):
    app, ids = setup
    with app.state.db_factory() as db:
        tenant = db.get(Tenant, ids['tenant_id'])
        tenant.settings_json = dumps({})
        db.commit()
    outcome = _execute(app, _run_row(app, ids))
    assert outcome['status'] == 'denied' and 'opted in' in outcome['reason']


def test_the_engine_job_only_reaches_the_asset(setup):
    app, ids = setup
    client = FakeClient()
    _execute(app, _run_row(app, ids), client=client)
    job = client.jobs[0]
    assert job.egress == [('203.0.113.10', 443)] and job.target_host == 'app.example.com'
    assert '--max-endpoints' in job.argv


async def _noop():
    return {'id': 'test-run-1'}
