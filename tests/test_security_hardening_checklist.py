"""Regression and security hardening tests for the P0-P5 checklist and 10-step implementation roadmap."""
from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
import respx
from app.actions import broker, catalog, credentials, policy
from app.actions.catalog import ActionType, DryRunResult, ExecResult
from app.agents.providers import Provider
from app.agents.runtime import AgentRuntime, AgentSpec
from app.core.db import pool_stats, set_tenant_context
from app.core.errors import Conflict
from app.core.queue import JobQueue
from app.core.rbac import Principal, Role
from app.detections.benchmark import run_benchmark
from app.models import Asset, Tenant
from app.models.ai import AIGatewayRequest
from app.ops import backup as bk
from sqlalchemy import text


def test_structured_health_and_ready_include_pool_and_checks(client):
    health = client.get('/health').json()
    assert health['status'] == 'healthy'
    assert 'pool' in health and 'dialect' in health['pool']

    ready = client.get('/ready').json()
    assert ready['status'] == 'ready'
    assert ready['checks']['database'] == 'ok'
    assert 'pool' in ready


def test_set_tenant_context_and_pool_stats(db, app, default_tenant_id):
    set_tenant_context(db, default_tenant_id)
    assert db.info['tenant_id'] == default_tenant_id
    stats = pool_stats(app.state.engine)
    assert stats['dialect'] in ('sqlite', 'postgresql')


def test_action_credentials_tenant_isolation(settings, monkeypatch, tmp_path):
    monkeypatch.setenv('ACTIONS_GITHUB_TOKEN', 'ghp_global_fallback')
    assert credentials.resolve('github', 'token', settings, {}) == 'ghp_global_fallback'

    # Tenant opts into strict credential isolation: global env vars must not be used.
    isolated = {'isolate_action_credentials': True}
    assert credentials.resolve('github', 'token', settings, isolated) == ''

    policy_isolated = {'action_policy': {'isolate_credentials': True}}
    assert credentials.resolve('github', 'token', settings, policy_isolated) == ''

    # Settings-level disable of env fallback.
    strict_settings = settings.model_copy(update={'allow_env_action_credentials': False})
    assert credentials.resolve('github', 'token', strict_settings, {}) == ''

    # Tenant-specific secret reference still resolves when isolated.
    secret_file = tmp_path / 'secrets' / 'gh_tok'
    secret_file.parent.mkdir(parents=True, exist_ok=True)
    secret_file.write_text('ghp_tenant_isolated', encoding='utf-8')
    isolated_with_ref = {
        'isolate_action_credentials': True,
        'action_credentials': {'github': {'token': f'file:{secret_file}'}},
    }
    assert credentials.resolve('github', 'token', strict_settings, isolated_with_ref) == 'ghp_tenant_isolated'


def test_inactive_tenant_blocks_actions(settings):
    inactive = Tenant(id='t-inactive', slug='inactive', name='Inactive', is_active=False, actions_enabled=True, settings_json='{}')
    assert policy.tenant_kill_switch(inactive) is True


@pytest.mark.asyncio
async def test_agent_require_known_price_blocks_unpriced_model(app, db, default_tenant_id):
    class UnpricedProvider(Provider):
        name = 'custom'
        model = 'unknown-model-v1'

        def price(self):
            return None

        async def complete(self, system, messages, tools, max_tokens=16000):  # pragma: no cover
            raise AssertionError('unpriced model should not be called when agent_require_known_price=True')

    spec = AgentSpec(
        name='test_price_guard',
        description='Test price guard',
        system_prompt='Test',
        tools=[],
        output_schema={'type': 'object', 'properties': {'ok': {'type': 'boolean'}}, 'required': ['ok'], 'additionalProperties': False},
    )
    strict_settings = app.state.settings.model_copy(update={'agent_require_known_price': True, 'agent_cost_ceiling_usd': 5.0})
    runtime = AgentRuntime(strict_settings, provider=UnpricedProvider(), app=app)
    principal = Principal(tenant_id=default_tenant_id, role=Role.operator, user_id='u1', email='u1@test.local')
    result = await runtime.run(spec, 'check price', {}, principal, app.state.db_factory)
    assert result.status == 'budget_exhausted'
    assert 'no price configured' in result.error


@pytest.mark.asyncio
async def test_concurrent_rollback_claims_only_once(app, default_tenant_id, db):
    class ConcurrentRollbackAction(ActionType):
        name = 'test.concurrent.rollback'
        description = 'Test rollback race'
        risk = 'low'
        reversible = True
        platforms = ['argus']
        params_schema = {'type': 'object', 'properties': {'target': {'type': 'string'}}, 'required': ['target'], 'additionalProperties': False}

        async def dry_run(self, params, ctx):
            return DryRunResult(ok=True, summary='ok', blast_radius={'kind': 'host', 'entities': 1, 'ids': ['h1']})

        async def execute(self, params, ctx):
            return ExecResult(ok=True, summary='done', rollback_payload={'host': 'h1'})

        async def rollback(self, payload, ctx):
            await asyncio.sleep(0.05)
            return ExecResult(ok=True, summary='undone')

    catalog.register(ConcurrentRollbackAction)
    try:
        tenant = db.get(Tenant, default_tenant_id)
        tenant.actions_enabled = True
        db.commit()

        requester = Principal(tenant_id=default_tenant_id, role=Role.operator, user_id='req-user', email='req@test.local')
        approver = Principal(tenant_id=default_tenant_id, role=Role.admin, user_id='app-user', email='app@test.local')

        req = await broker.request(db, requester, 'test.concurrent.rollback', {'target': 'h1'}, 'race test', settings=app.state.settings)
        db.commit()
        broker.approve(db, approver, req.id, 'approve', 'lgtm')
        db.commit()
        run = await broker.execute(app, approver, req.id, db=db)

        for _ in range(40):
            db.expire_all()
            refreshed = broker.get_run(db, approver, run.id)
            if refreshed.status == 'executed':
                break
            await asyncio.sleep(0.05)
        assert broker.get_run(db, approver, run.id).status == 'executed'

        results = await asyncio.gather(
            broker.rollback(app, approver, run.id),
            broker.rollback(app, approver, run.id),
            return_exceptions=True,
        )
        conflicts = [r for r in results if isinstance(r, Conflict)]
        successes = [r for r in results if not isinstance(r, Exception)]
        assert len(successes) == 1
        assert len(conflicts) == 1

        for _ in range(40):
            db.expire_all()
            refreshed = broker.get_run(db, approver, run.id)
            if refreshed.status == 'rolled_back':
                break
            await asyncio.sleep(0.05)
        assert broker.get_run(db, approver, run.id).status == 'rolled_back'
    finally:
        catalog.unregister('test.concurrent.rollback')


@pytest.mark.asyncio
async def test_failed_rollback_can_be_retried(app, default_tenant_id, db):
    attempts = {'n': 0}

    class FlakyRollbackAction(ActionType):
        name = 'test.flaky.rollback'
        description = 'Test rollback retry after transient failure'
        risk = 'low'
        reversible = True
        platforms = ['argus']
        params_schema = {'type': 'object', 'properties': {'target': {'type': 'string'}}, 'required': ['target'], 'additionalProperties': False}

        async def dry_run(self, params, ctx):
            return DryRunResult(ok=True, summary='ok', blast_radius={'kind': 'host', 'entities': 1, 'ids': ['h1']})

        async def execute(self, params, ctx):
            return ExecResult(ok=True, summary='done', rollback_payload={'host': 'h1'})

        async def rollback(self, payload, ctx):
            attempts['n'] += 1
            if attempts['n'] == 1:
                return ExecResult(ok=False, summary='transient provider error')
            return ExecResult(ok=True, summary='rollback succeeded on retry')

    catalog.register(FlakyRollbackAction)
    try:
        tenant = db.get(Tenant, default_tenant_id)
        tenant.actions_enabled = True
        db.commit()

        requester = Principal(tenant_id=default_tenant_id, role=Role.operator, user_id='req-1', email='req1@test.local')
        approver = Principal(tenant_id=default_tenant_id, role=Role.admin, user_id='app-1', email='app1@test.local')

        req = await broker.request(db, requester, 'test.flaky.rollback', {'target': 'h1'}, 'retry test', settings=app.state.settings)
        db.commit()
        broker.approve(db, approver, req.id, 'approve', 'ok')
        db.commit()
        run = await broker.execute(app, approver, req.id, db=db)

        for _ in range(40):
            db.expire_all()
            if broker.get_run(db, approver, run.id).status == 'executed':
                break
            await asyncio.sleep(0.05)

        await broker.rollback(app, approver, run.id)
        for _ in range(40):
            db.expire_all()
            if broker.get_run(db, approver, run.id).status == 'rollback_failed':
                break
            await asyncio.sleep(0.05)
        assert broker.get_run(db, approver, run.id).status == 'rollback_failed'

        # Retry rollback after transient failure: must succeed and transition to rolled_back.
        await broker.rollback(app, approver, run.id)
        for _ in range(40):
            db.expire_all()
            if broker.get_run(db, approver, run.id).status == 'rolled_back':
                break
            await asyncio.sleep(0.05)
        assert broker.get_run(db, approver, run.id).status == 'rolled_back'
        assert attempts['n'] == 2
    finally:
        catalog.unregister('test.flaky.rollback')


@pytest.mark.asyncio
async def test_emergency_rollback_not_blocked_by_action_kill_switch(app, db, default_tenant_id):
    """Operator-authorized recovery must remain possible during a response freeze."""
    class RecoverableAction(ActionType):
        name = 'test.emergency.rollback'
        description = 'Recovery kill switch regression'
        risk = 'low'
        reversible = True
        platforms = ['argus']
        params_schema = {'type': 'object', 'properties': {}, 'additionalProperties': False}

        async def dry_run(self, params, ctx):
            return DryRunResult(ok=True, summary='ok', blast_radius={'kind': 'host', 'entities': 1, 'ids': ['h1']})

        async def execute(self, params, ctx):
            return ExecResult(ok=True, summary='applied', rollback_payload={'host': 'h1'})

        async def rollback(self, payload, ctx):
            return ExecResult(ok=True, summary='restored')

    catalog.register(RecoverableAction)
    try:
        tenant = db.get(Tenant, default_tenant_id)
        tenant.actions_enabled = True
        db.commit()
        requester = Principal(tenant_id=default_tenant_id, role=Role.operator, user_id='emerg-req')
        approver = Principal(tenant_id=default_tenant_id, role=Role.admin, user_id='emerg-admin')
        req = await broker.request(db, requester, 'test.emergency.rollback', {}, 'recovery', settings=app.state.settings)
        db.commit()
        broker.approve(db, approver, req.id, 'approve')
        db.commit()
        run = await broker.execute(app, approver, req.id, db=db)
        for _ in range(80):
            db.expire_all()
            if broker.get_run(db, approver, run.id).status == 'executed':
                break
            await asyncio.sleep(0.05)
        assert broker.get_run(db, approver, run.id).status == 'executed'
        app.state.settings.actions_kill_switch = True
        await broker.rollback(app, approver, run.id)
        for _ in range(80):
            db.expire_all()
            if broker.get_run(db, approver, run.id).status == 'rolled_back':
                break
            await asyncio.sleep(0.05)
        assert broker.get_run(db, approver, run.id).status == 'rolled_back'
    finally:
        app.state.settings.actions_kill_switch = False
        catalog.unregister('test.emergency.rollback')


@respx.mock
def test_streaming_gateway_sets_tenant_context_and_meters_usage(app, owner):
    client, headers = owner
    app.state.settings.ai_gateway_enabled = True
    app.state.settings.ai_gateway_openai_api_key = 'upstream-openai-key'
    app.state.settings.ai_gateway_model_prices = 'gpt-test=1:2'

    key_resp = client.post('/api/v1/auth/api-keys', json={'name': 'gw-stream', 'role': 'analyst', 'scopes': ['ai_gateway:use']}, headers=headers)
    assert key_resp.status_code == 201
    gw_key = key_resp.json()['key']

    client.put('/api/v1/ai-gateway/policy', json={'monthly_budget_usd': 5.0}, headers=headers)

    sse = (
        b'data: {"id":"c1","choices":[{"delta":{"content":"Hi"}}]}\n\n'
        b'data: {"id":"c1","choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":500}}\n\n'
        b'data: [DONE]\n\n'
    )
    respx.post('https://api.openai.com/v1/chat/completions').mock(
        return_value=httpx.Response(200, content=sse, headers={'content-type': 'text/event-stream'})
    )
    resp = client.post(
        '/api/v1/ai-gateway/openai/v1/chat/completions',
        json={'model': 'gpt-test', 'stream': True, 'messages': [{'role': 'user', 'content': 'hello'}]},
        headers={'Authorization': f'Bearer {gw_key}'},
    )
    assert resp.status_code == 200
    req_id = resp.headers['x-argus-gateway-request-id']
    with app.state.db_factory() as session:
        row = session.get(AIGatewayRequest, req_id)
        assert row is not None
        assert row.status == 'allowed'
        assert row.input_tokens == 1000 and row.output_tokens == 500
        assert row.cost_usd == pytest.approx(0.002)


@pytest.mark.asyncio
async def test_concurrent_ai_gateway_budget_reservation(app, owner):
    client, headers = owner
    app.state.settings.ai_gateway_enabled = True
    app.state.settings.ai_gateway_openai_api_key = 'upstream-openai-key'
    app.state.settings.ai_gateway_model_prices = 'gpt-test=1:2'

    key_resp = client.post('/api/v1/auth/api-keys', json={'name': 'gw-budget', 'role': 'analyst', 'scopes': ['ai_gateway:use']}, headers=headers)
    gw_key = key_resp.json()['key']

    # Set budget to $0.002 so only one in-flight request (reserving $0.002) can proceed at a time.
    client.put('/api/v1/ai-gateway/policy', json={'monthly_budget_usd': 0.002, 'requests_per_minute': 100}, headers=headers)

    async def slow_upstream(request):
        await asyncio.sleep(0.08)
        return httpx.Response(
            200,
            json={
                'id': 'chatcmpl-1',
                'object': 'chat.completion',
                'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'ok'}}],
                'usage': {'prompt_tokens': 1000, 'completion_tokens': 500, 'total_tokens': 1500},
            },
        )

    with respx.mock:
        respx.post('https://api.openai.com/v1/chat/completions').mock(side_effect=slow_upstream)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url='http://testserver') as ac:
            responses = await asyncio.gather(
                *[
                    ac.post(
                        '/api/v1/ai-gateway/openai/v1/chat/completions',
                        json={'model': 'gpt-test', 'max_tokens': 500, 'messages': [{'role': 'user', 'content': 'hello'}]},
                        headers={'Authorization': f'Bearer {gw_key}'},
                    )
                    for _ in range(3)
                ]
            )
    codes = sorted(r.status_code for r in responses)
    assert codes == [200, 429, 429]


@pytest.mark.asyncio
async def test_worker_shutdown_requeues_running_job_without_burning_attempt(settings):
    q = JobQueue(settings.model_copy(update={'redis_url': ''}))
    started = asyncio.Event()

    @q.handler('test.interrupted')
    async def _handle(job, ctx):
        q._loop.call_soon_threadsafe(started.set)
        await asyncio.sleep(10)
        return {'ok': True}

    await q.start(concurrency=1)
    job = await q.enqueue('test.interrupted', {'x': 1}, tenant_id='t1')
    await asyncio.wait_for(started.wait(), timeout=5)
    await q.stop()

    saved = q._backend.jobs[job.id]
    assert saved.status == 'queued'
    assert saved.attempts == 0
    assert saved.error == 'worker shutdown'


def test_backup_verify_tenant_integrity_and_restore_drill(owner, second_tenant, app, settings, tmp_path):
    client, headers = owner
    r1 = client.post('/api/v1/assets', json={'name': 't1-web', 'kind': 'host', 'target': '10.10.0.1', 'environment': 'staging'}, headers=headers)
    assert r1.status_code in (200, 201)
    r2 = second_tenant['client'].post(
        '/api/v1/assets',
        json={'name': 't2-db', 'kind': 'host', 'target': '10.20.0.1', 'environment': 'production'},
        headers=second_tenant['headers'],
    )
    assert r2.status_code in (200, 201)

    t1_integrity = bk.verify_tenant_integrity(app.state.engine, app.state.default_tenant_id)
    t2_integrity = bk.verify_tenant_integrity(app.state.engine, second_tenant['tenant_id'])
    assert t1_integrity['ok'] and t1_integrity['table_counts'].get('assets', 0) >= 1
    assert t2_integrity['ok'] and t2_integrity['table_counts'].get('assets', 0) == 1

    s = settings.model_copy(update={'backup_dir': tmp_path / 'bk', 'backup_min_free_mb': 1})
    dump_res = bk.dump(app.state.engine, s, Path(s.backup_dir))
    restored_url = f"sqlite:///{tmp_path / 'restored_drill.db'}"
    restored = bk.restore(dump_res.path, restored_url, s)
    assert restored['checks']['ok']
    assert app.state.default_tenant_id in restored['checks']['tenant_integrity']
    assert second_tenant['tenant_id'] in restored['checks']['tenant_integrity']


def test_detection_benchmark_precision_recall_and_zero_fpr(db, default_tenant_id):
    report = run_benchmark(db, default_tenant_id)
    assert report['recall'] == 1.0
    assert report['precision'] == 1.0
    assert report['false_positive_rate'] == 0.0
    assert set(report['techniques_covered']) == {'T1078', 'T1098', 'T1530'}


def test_postgres_rls_enforces_tenant_isolation_under_restricted_role(app, default_tenant_id, second_tenant):
    if app.state.engine.dialect.name != 'postgresql':
        pytest.skip('PostgreSQL-only RLS enforcement test')

    t1 = default_tenant_id
    t2 = second_tenant['tenant_id']
    with app.state.db_factory() as db:
        db.add(Asset(tenant_id=t1, name='rls-t1', kind='host', target='10.0.1.1', environment='staging'))
        db.add(Asset(tenant_id=t2, name='rls-t2', kind='host', target='10.0.2.1', environment='staging'))
        db.commit()

    with app.state.engine.begin() as conn:
        conn.exec_driver_sql('ALTER TABLE assets ENABLE ROW LEVEL SECURITY')
        conn.exec_driver_sql('ALTER TABLE assets FORCE ROW LEVEL SECURITY')
        conn.exec_driver_sql('DROP POLICY IF EXISTS argus_tenant_isolation ON assets')
        conn.exec_driver_sql(
            "CREATE POLICY argus_tenant_isolation ON assets "
            "USING (tenant_id = current_setting('app.tenant_id', true)) "
            "WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"
        )
        conn.exec_driver_sql(
            "DO $$ BEGIN "
            "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_rls_test_user') THEN "
            "CREATE ROLE argus_rls_test_user NOLOGIN NOSUPERUSER NOBYPASSRLS; "
            "END IF; END $$;"
        )
        conn.exec_driver_sql('GRANT SELECT ON assets TO argus_rls_test_user')

    with app.state.db_factory() as db:
        db.execute(text('SET LOCAL ROLE argus_rls_test_user'))
        set_tenant_context(db, t1)
        names_t1 = [r[0] for r in db.execute(text('SELECT name FROM assets')).all()]
        assert names_t1 == ['rls-t1']

    with app.state.db_factory() as db:
        db.execute(text('SET LOCAL ROLE argus_rls_test_user'))
        set_tenant_context(db, t2)
        names_t2 = [r[0] for r in db.execute(text('SELECT name FROM assets')).all()]
        assert names_t2 == ['rls-t2']
