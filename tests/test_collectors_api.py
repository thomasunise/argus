"""API, run job, scheduler and tenant-isolation tests for the collectors package."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.collectors import Collector, CollectorContext, CollectorResult, registry
from app.collectors.runner import execute_run, is_due, scheduler_tick
from app.models import AuditEntry, SecurityEvent
from app.models.collectors import CollectorConfig, CollectorRun
from fastapi.testclient import TestClient

from tests.conftest import login, wait_for, wait_job

BASE = '/api/v1/collectors'


class FakeCollector(Collector):
    name = 'fake'
    kind = 'cloud'
    description = 'test collector'
    secret_fields = ['token']
    sdk_modules = ()
    config_schema = {'type': 'object', 'additionalProperties': False, 'required': ['account'],
                     'properties': {'account': {'type': 'string'}, 'regions': {'type': 'array', 'items': {'type': 'string'}}, 'fail_times': {'type': 'integer'}}}

    def __init__(self):
        self.calls: list[CollectorContext] = []
        self.failures = 0

    def _normalize(self, raw):
        r = CollectorResult()
        acct = r.node('asset', f"fake:account:{raw['account']}", {'provider': 'fake'}, label='Fake account', criticality='high')
        user = r.node('identity', 'fake:user:alice', {'mfa': False})
        r.edge(acct, user, 'owns')
        r.event(self.source, f"fake:{raw['account']}:no-mfa:alice", 'alice has no MFA', 'medium', 'cloud_api', actor='alice', entity=user.key, action='mfa_missing',
                metadata={'token_seen': raw.get('token_seen')})
        r.stats['accounts'] = 1
        r.warn('fake warning')
        return r

    async def collect(self, ctx):
        self.calls.append(ctx)
        if self.failures < int(ctx.config.get('fail_times') or 0):
            self.failures += 1
            raise RuntimeError('upstream unavailable')
        await ctx.heartbeat()
        return self._normalize({'account': ctx.config['account'], 'token_seen': bool(ctx.config.get('token'))})


@pytest.fixture
def fake():
    collector = FakeCollector()
    registry.register(collector)
    try:
        yield collector
    finally:
        registry.unregister('fake')


def create(client, headers, **overrides):
    body = {'name': 'prod account', 'collector': 'fake', 'config': {'account': '111', 'regions': ['eu-west-1']}, 'secret_refs': {'token': 'env:FAKE_TOKEN'}, 'schedule_minutes': 0}
    body.update(overrides)
    return client.post(BASE, json=body, headers=headers)


# ---------------------------------------------------------------- types and validation


def test_types_lists_collectors_with_schema_and_availability(owner):
    client, headers = owner
    items = {i['name']: i for i in client.get(f'{BASE}/types', headers=headers).json()['items']}
    assert {'aws', 'azure', 'gcp', 'kubernetes', 'github', 'okta', 'entra', 'osquery', 'netflow'} <= set(items)
    aws = items['aws']
    assert aws['kind'] == 'cloud' and aws['secret_fields'] == ['access_key_id', 'secret_access_key', 'session_token'] and 'regions' in aws['config_schema']['properties']
    import importlib.util

    assert aws['available'] is (importlib.util.find_spec('boto3') is not None)
    if not aws['available']:
        assert aws['install_hint'] == 'install boto3'
    assert items['netflow']['available'] is True and items['github']['secret_fields'] == ['token']
    assert client.get(f'{BASE}/types', headers={'X-API-Key': 'argus_deadbeef_notarealkey'}).status_code == 401


def test_create_rejects_inline_and_literal_secrets(owner, fake):
    client, headers = owner
    assert create(client, headers).status_code == 201
    inline = create(client, headers, config={'account': '111', 'token': 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'}, secret_refs={})
    assert inline.status_code == 400 and inline.json()['code'] == 'invalid_config' and 'token is a secret' in inline.json()['detail']
    literal = create(client, headers, secret_refs={'token': 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'})
    assert literal.status_code == 400 and 'must be a reference' in literal.json()['detail']
    assert create(client, headers, secret_refs={'token': 'literal:dev-only-token'}).status_code == 201  # explicit opt-in
    unknown_secret = create(client, headers, secret_refs={'password': 'env:X'})
    assert unknown_secret.status_code == 400 and 'unknown secret field password' in unknown_secret.json()['detail']
    looks_like_secret = create(client, headers, config={'account': 'AKIAIOSFODNN7EXAMPLE'}, secret_refs={})
    assert looks_like_secret.status_code == 400 and 'looks like a credential' in looks_like_secret.json()['detail']
    bad_schema = create(client, headers, config={'account': '111', 'regions': 'eu-west-1', 'bogus': 1})
    detail = bad_schema.json()['detail']
    assert bad_schema.status_code == 400 and 'unknown config key bogus' in detail and 'regions must be of type array' in detail
    assert create(client, headers, config={}).status_code == 400
    assert create(client, headers, collector='nope').status_code == 400
    assert create(client, headers, collector='github', config={'org': 'acme'}, secret_refs={'token': 'env:GITHUB_TOKEN'}).status_code == 201
    assert create(client, headers, collector='github', config={'org': 'acme'}, secret_refs={'token': 'env:GITHUB_TOKEN'}, schedule_minutes=99999).status_code == 422


def test_crud_and_permissions(owner, fake, app, make_user, db, default_tenant_id):
    owner_client, headers = owner
    client = TestClient(app)  # separate cookie jar for the viewer/operator sessions
    created = create(owner_client, headers).json()
    assert created['collector'] == 'fake' and created['secret_refs'] == {'token': 'env:FAKE_TOKEN'} and created['enabled'] and created['available'] is True
    assert created['schedule_minutes'] == 0 and created['config'] == {'account': '111', 'regions': ['eu-west-1']}
    listed = owner_client.get(BASE, headers=headers).json()
    assert [i['id'] for i in listed['items']] == [created['id']] and listed['next_cursor'] is None
    assert owner_client.get(f'{BASE}?collector=github', headers=headers).json()['items'] == []
    assert owner_client.get(f"{BASE}/{created['id']}", headers=headers).json()['name'] == 'prod account'
    patched = owner_client.patch(f"{BASE}/{created['id']}", json={'name': 'renamed', 'schedule_minutes': 30, 'enabled': False, 'config': {'account': '222'}}, headers=headers)
    assert patched.status_code == 200 and patched.json()['name'] == 'renamed' and patched.json()['schedule_minutes'] == 30 and patched.json()['enabled'] is False
    assert patched.json()['config'] == {'account': '222'} and patched.json()['secret_refs'] == {'token': 'env:FAKE_TOKEN'}
    assert owner_client.patch(f"{BASE}/{created['id']}", json={'secret_refs': {'token': 'plaintext-token-value'}}, headers=headers).status_code == 400
    assert owner_client.patch(f"{BASE}/{created['id']}", json={'config': {'nope': 1}}, headers=headers).status_code == 400
    # a disabled config cannot be run
    assert owner_client.post(f"{BASE}/{created['id']}/run", headers=headers).status_code == 400
    # role matrix: viewer reads only, operator can run but not write
    make_user('viewer@test.local', 'viewer-password-long-1', 'viewer')
    viewer = login(client, 'viewer@test.local', 'viewer-password-long-1')
    assert client.get(BASE, headers=viewer).status_code == 200
    assert create(client, viewer).status_code == 403
    assert client.post(f"{BASE}/{created['id']}/run", headers=viewer).status_code == 403
    make_user('operator@test.local', 'operator-password-long-1', 'operator')
    operator = login(client, 'operator@test.local', 'operator-password-long-1')
    assert create(client, operator).status_code == 403
    assert client.patch(f"{BASE}/{created['id']}", json={'name': 'x'}, headers=operator).status_code == 403
    assert client.delete(f"{BASE}/{created['id']}", headers=operator).status_code == 403
    assert owner_client.delete(f"{BASE}/{created['id']}", headers=headers).status_code == 200
    assert owner_client.get(f"{BASE}/{created['id']}", headers=headers).status_code == 404
    actions = [a for (a,) in db.execute(select(AuditEntry.action).where(AuditEntry.tenant_id == default_tenant_id)).all()]
    assert {'collectors.create', 'collectors.update', 'collectors.delete'} <= set(actions)


# ---------------------------------------------------------------- run job end to end


def test_run_job_end_to_end(owner, fake, app, db, default_tenant_id, monkeypatch):
    monkeypatch.setenv('FAKE_TOKEN', 'resolved-token-value')
    client, headers = owner
    config = create(client, headers).json()
    started = client.post(f"{BASE}/{config['id']}/run", headers=headers)
    assert started.status_code == 202, started.text
    payload = started.json()
    assert payload['status'] == 'queued' and payload['job_id'] and payload['already_queued'] is False
    job = wait_job(client, headers, payload['job_id'])
    assert job['status'] == 'completed', job
    assert job['result']['status'] == 'completed' and job['result']['stats']['nodes'] == 2 and job['result']['stats']['events'] == 1
    run = client.get(f"{BASE}/runs/{payload['run_id']}", headers=headers).json()
    assert run['status'] == 'completed' and run['stats']['accounts'] == 1 and run['stats']['events_created'] == 1 and run['started_at'] and run['finished_at']
    assert 'fake warning' in run['warnings'] and 'graph' in run['stats'] and run['triggered_by']
    runs = client.get(f"{BASE}/{config['id']}/runs", headers=headers).json()
    assert [r['id'] for r in runs['items']] == [payload['run_id']]
    refreshed = client.get(f"{BASE}/{config['id']}", headers=headers).json()
    assert refreshed['last_success_at'] and refreshed['last_run_at'] and refreshed['last_error'] == ''
    # secrets were resolved from the env reference and handed to the collector, but never stored
    ctx = fake.calls[-1]
    assert ctx.config['token'] == 'resolved-token-value' and ctx.tenant_id == default_tenant_id and ctx.since is None
    events = db.execute(select(SecurityEvent).where(SecurityEvent.tenant_id == default_tenant_id, SecurityEvent.source == 'collector:fake')).scalars().all()
    assert len(events) == 1 and events[0].action == 'mfa_missing' and events[0].external_id == 'fake:111:no-mfa:alice'
    assert 'resolved-token-value' not in events[0].metadata_json and 'resolved-token-value' not in run['stats'].__repr__()
    stored = db.get(CollectorConfig, config['id'])
    assert 'resolved-token-value' not in stored.config_json + stored.secret_refs_json
    audit = db.execute(select(AuditEntry).where(AuditEntry.tenant_id == default_tenant_id, AuditEntry.action == 'collectors.run')).scalars().all()
    assert len(audit) == 1 and 'resolved-token-value' not in audit[0].detail and audit[0].actor == 'system'
    assert any(a.action == 'collectors.run_requested' for a in db.execute(select(AuditEntry).where(AuditEntry.tenant_id == default_tenant_id)).scalars())
    # second run: dedupes the event, passes `since`, and a repeated POST while queued returns the same run
    again = client.post(f"{BASE}/{config['id']}/run", headers=headers).json()
    wait_job(client, headers, again['job_id'])
    assert fake.calls[-1].since is not None
    assert db.scalar(select(SecurityEvent.id).where(SecurityEvent.tenant_id == default_tenant_id, SecurityEvent.source == 'collector:fake').limit(2)) and \
        len(db.execute(select(SecurityEvent).where(SecurityEvent.tenant_id == default_tenant_id, SecurityEvent.source == 'collector:fake')).scalars().all()) == 1


def test_run_failure_is_recorded_and_retried(owner, fake, db):
    client, headers = owner
    config = create(client, headers, config={'account': '333', 'fail_times': 1}).json()
    started = client.post(f"{BASE}/{config['id']}/run", headers=headers).json()
    job = wait_job(client, headers, started['job_id'])
    assert job['status'] == 'completed' and job['attempts'] == 2  # first attempt failed, queue retried
    run = client.get(f"{BASE}/runs/{started['run_id']}", headers=headers).json()
    assert run['status'] == 'completed'
    assert client.get(f"{BASE}/{config['id']}", headers=headers).json()['last_error'] == ''
    assert len(fake.calls) == 2


@pytest.mark.asyncio
async def test_execute_run_handles_unknown_and_disabled_collectors(app, settings, default_tenant_id, fake):
    with app.state.db_factory() as db:
        config = CollectorConfig(tenant_id=default_tenant_id, name='ghost', collector='ghost', config_json='{}', secret_refs_json='{}')
        db.add(config)
        db.flush()
        run = CollectorRun(tenant_id=default_tenant_id, config_id=config.id)
        db.add(run)
        db.commit()
        config_id, run_id = config.id, run.id

    async def heartbeat():
        return None

    outcome = await execute_run(app, settings, app.state.db_factory, default_tenant_id, config_id, run_id, heartbeat)
    assert outcome['status'] == 'failed'  # not retryable: no exception, run marked failed
    with app.state.db_factory() as db:
        assert db.get(CollectorRun, run_id).status == 'failed' and 'unknown collector' in db.get(CollectorConfig, config_id).last_error
    with pytest.raises(LookupError):
        await execute_run(app, settings, app.state.db_factory, 'other-tenant', config_id, run_id, heartbeat)
    # missing secret => warning, timeout => failed run
    with app.state.db_factory() as db:
        config = db.get(CollectorConfig, config_id)
        config.collector, config.config_json, config.secret_refs_json = 'fake', '{"account": "1"}', '{"token": "env:DEFINITELY_NOT_SET_ARGUS"}'
        run = CollectorRun(tenant_id=default_tenant_id, config_id=config.id)
        db.add(run)
        db.commit()
        run_id = run.id
    await execute_run(app, settings, app.state.db_factory, default_tenant_id, config_id, run_id, heartbeat)
    with app.state.db_factory() as db:
        run = db.get(CollectorRun, run_id)
        assert run.status == 'completed' and 'secret reference for token resolved to an empty value' in run.warnings_json
    slow = settings.model_copy(update={'test_tool_timeout_seconds': 0.05})

    async def hang(ctx):
        await asyncio.sleep(5)

    original = fake.collect
    fake.collect = hang  # type: ignore[method-assign]
    try:
        with app.state.db_factory() as db:
            run = CollectorRun(tenant_id=default_tenant_id, config_id=config_id)
            db.add(run)
            db.commit()
            run_id = run.id
        with pytest.raises(RuntimeError, match='timed out'):
            await execute_run(app, slow, app.state.db_factory, default_tenant_id, config_id, run_id, heartbeat)
    finally:
        fake.collect = original  # type: ignore[method-assign]
    with app.state.db_factory() as db:
        assert db.get(CollectorRun, run_id).status == 'failed' and 'timed out' in db.get(CollectorConfig, config_id).last_error


def test_run_rejects_unavailable_collector(owner, monkeypatch):
    from app.collectors import base as base_mod

    client, headers = owner
    config = create(client, headers, collector='aws', config={'regions': ['us-east-1']}, secret_refs={'secret_access_key': 'env:AWS_SECRET_ACCESS_KEY'}).json()
    monkeypatch.setattr(base_mod, 'modules_available', lambda *names: False)
    response = client.post(f"{BASE}/{config['id']}/run", headers=headers)
    assert response.status_code == 503 and 'install boto3' in response.json()['detail']


# ---------------------------------------------------------------- scheduler


def test_is_due_logic():
    now = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)
    cfg = CollectorConfig(tenant_id='t', name='n', collector='fake', enabled=True, schedule_minutes=60)
    assert is_due(cfg, now) is True  # never ran
    cfg.last_run_at = now - timedelta(minutes=59)
    assert is_due(cfg, now) is False
    cfg.last_run_at = now - timedelta(minutes=60)
    assert is_due(cfg, now) is True
    cfg.last_run_at = (now - timedelta(minutes=120)).replace(tzinfo=None)  # naive timestamps from SQLite
    assert is_due(cfg, now) is True
    cfg.enabled = False
    assert is_due(cfg, now) is False
    cfg.enabled, cfg.schedule_minutes = True, 0
    assert is_due(cfg, now) is False


def test_scheduler_tick_enqueues_due_configs_across_tenants(owner, fake, app, second_tenant, default_tenant_id, monkeypatch):
    import threading

    client, headers = owner
    # Keep the in-process worker off the SQLite file until the tick has committed: a job that starts writing while
    # the tick's read transaction upgrades to a write gets an immediate 'database is locked' on SQLite (WAL snapshot
    # rule, not subject to busy_timeout). Production runs on PostgreSQL where this cannot happen.
    gate = threading.Event()
    original = app.state.queue._handlers['collectors.run']

    async def gated(job, ctx):
        while not gate.is_set():
            await asyncio.sleep(0.05)
        return await original(job, ctx)

    monkeypatch.setitem(app.state.queue._handlers, 'collectors.run', gated)
    due = create(client, headers, schedule_minutes=15).json()
    create(client, headers, name='manual only', schedule_minutes=0)
    other = second_tenant['client'].post(BASE, json={'name': 'acme', 'collector': 'fake', 'config': {'account': 'acme'}, 'schedule_minutes': 5}, headers=second_tenant['headers'])
    assert other.status_code == 201
    enqueued = client.portal.call(lambda: scheduler_tick(app))
    assert enqueued == 2
    assert client.portal.call(lambda: scheduler_tick(app)) == 0  # last_run_at set at enqueue time
    gate.set()

    def finished():
        runs = client.get(f"{BASE}/{due['id']}/runs", headers=headers).json()['items']
        return runs if runs and runs[0]['status'] in {'completed', 'failed'} else None

    runs = wait_for(finished)
    assert runs[0]['triggered_by'] == 'scheduler' and runs[0]['status'] == 'completed'
    acme_runs = wait_for(lambda: [r for r in second_tenant['client'].get(f"{BASE}/{other.json()['id']}/runs", headers=second_tenant['headers']).json()['items']
                                  if r['status'] == 'completed'] or None)
    assert len(acme_runs) == 1
    tenants = {c.tenant_id for c in fake.calls}
    assert tenants == {default_tenant_id, second_tenant['tenant_id']}
    with app.state.db_factory() as db:
        refreshed = db.get(CollectorConfig, due['id'])
        assert refreshed.last_success_at is not None
        refreshed.last_run_at = datetime.now(timezone.utc) - timedelta(minutes=16)
        db.commit()
    assert client.portal.call(lambda: scheduler_tick(app)) == 1


def test_scheduler_loop_is_registered_as_startup_hook(app, client):
    assert any(getattr(h, '__name__', '') == 'start_scheduler' for h in app.state.startup_hooks)
    assert 'collectors.run' in app.state.queue.kinds
    assert any('scheduler_loop' in repr(t.get_coro()) for t in app.state.background_tasks)  # spawned by lifespan when workers run in-process


# ---------------------------------------------------------------- cross-tenant isolation


def test_cross_tenant_isolation_on_every_endpoint(owner, fake, second_tenant):
    client, headers = owner
    config = create(client, headers).json()
    started = client.post(f"{BASE}/{config['id']}/run", headers=headers).json()
    wait_job(client, headers, started['job_id'])
    other, oh = second_tenant['client'], second_tenant['headers']
    assert other.get(BASE, headers=oh).json()['items'] == []
    assert other.get(f"{BASE}/{config['id']}", headers=oh).status_code == 404
    assert other.patch(f"{BASE}/{config['id']}", json={'name': 'hijack'}, headers=oh).status_code == 404
    assert other.delete(f"{BASE}/{config['id']}", headers=oh).status_code == 404
    assert other.post(f"{BASE}/{config['id']}/run", headers=oh).status_code == 404
    assert other.get(f"{BASE}/{config['id']}/runs", headers=oh).status_code == 404
    assert other.get(f"{BASE}/runs/{started['run_id']}", headers=oh).status_code == 404
    assert other.get(f"/api/v1/ops/jobs/{started['job_id']}", headers=oh).status_code == 404
    assert client.get(f"{BASE}/{config['id']}", headers=headers).json()['name'] == 'prod account'
    assert client.get(f"{BASE}/runs/{started['run_id']}", headers=headers).status_code == 200


def test_literal_secret_refs_are_masked_in_responses_and_kept_on_patch(owner, fake, db):
    client, headers = owner
    created = create(client, headers, secret_refs={'token': 'literal:dev-only-token'})
    assert created.status_code == 201, created.text
    cid = created.json()['id']
    assert created.json()['secret_refs'] == {'token': 'literal:[set]'}
    assert 'dev-only-token' not in client.get(BASE, headers=headers).text
    assert 'dev-only-token' not in client.get(f'{BASE}/{cid}', headers=headers).text
    # A client editing the config sends the masked view back; the stored literal must survive.
    patched = client.patch(f'{BASE}/{cid}', json={'secret_refs': {'token': 'literal:[set]'}, 'name': 'renamed'}, headers=headers)
    assert patched.status_code == 200, patched.text
    row = db.execute(select(CollectorConfig).where(CollectorConfig.id == cid)).scalar_one()
    db.refresh(row)
    assert 'literal:dev-only-token' in row.secret_refs_json
    # A new reference replaces it.
    assert client.patch(f'{BASE}/{cid}', json={'secret_refs': {'token': 'env:FAKE_TOKEN'}}, headers=headers).status_code == 200
    db.refresh(row)
    assert 'dev-only-token' not in row.secret_refs_json
