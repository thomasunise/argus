"""Regression and security hardening tests for the P0-P5 checklist."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.actions import broker, catalog, credentials, policy
from app.actions.catalog import ActionType, DryRunResult, ExecResult
from app.agents.providers import Provider, Usage
from app.agents.runtime import AgentRuntime, AgentSpec
from app.core.db import pool_stats, set_tenant_context
from app.core.errors import Conflict
from app.core.rbac import Principal, Role
from app.models import Tenant


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
async def test_concurrent_rollback_claims_only_once(app, db, default_tenant_id):
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

        # Wait on the worker's terminal state rather than an arbitrary 2s window.
        job = await app.state.queue.wait(run.job_id, timeout=30)
        assert job is not None and job.status == 'completed', getattr(job, 'error', 'job missing')
        db.expire_all()
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
    finally:
        catalog.unregister('test.concurrent.rollback')

