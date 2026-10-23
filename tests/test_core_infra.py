from __future__ import annotations

import asyncio
import json

import pytest

from app.core.audit import record_audit, verify_chain
from app.core.queue import JobQueue
from app.core.rbac import Principal, Role, has
from app.models import AuditEntry
from tests.conftest import wait_job


def test_rbac_matrix():
    viewer = Principal(tenant_id='t', role=Role.viewer)
    operator = Principal(tenant_id='t', role=Role.operator)
    owner = Principal(tenant_id='t', role=Role.owner)
    assert has(viewer, 'findings:read') and not has(viewer, 'findings:write')
    assert has(operator, 'tests:run') and not has(operator, 'admin:users')
    assert has(owner, 'admin:tenant')
    scoped = Principal(tenant_id='t', role=Role.operator, auth='api_key', scopes=frozenset({'findings:*'}))
    assert has(scoped, 'findings:write') and not has(scoped, 'tests:run')


def test_audit_chain_and_sink(db, settings, default_tenant_id):
    principal = Principal(tenant_id=default_tenant_id, role=Role.owner, user_id='u1', email='a@b')
    record_audit(db, principal, 'test.one', 'subj', {'token': 'Bearer abcdefghijklmnopqrstuvwxyz'})
    record_audit(db, principal, 'test.two', 'subj2', {'n': 2})
    db.commit()
    assert verify_chain(db, default_tenant_id)['valid'] is True
    entry = db.query(AuditEntry).filter(AuditEntry.action == 'test.one').one()
    assert 'abcdefghijklmnopqrstuvwxyz' not in entry.detail and entry.signature
    # Tamper detection
    entry.detail = '{"changed":true}'
    db.commit()
    assert verify_chain(db, default_tenant_id)['valid'] is False
    lines = open(settings.audit_jsonl_path, encoding='utf-8').read().splitlines()
    assert any(json.loads(line)['action'] == 'test.two' for line in lines)


@pytest.mark.asyncio
async def test_memory_queue_retry_and_cancel(settings):
    queue = JobQueue(settings.model_copy(update={'queue_max_attempts': 2}))
    calls = {'n': 0}

    @queue.handler('t.flaky')
    async def flaky(job, ctx):
        calls['n'] += 1
        if calls['n'] == 1:
            raise RuntimeError('boom')
        return 'ok'

    @queue.handler('t.slow')
    async def slow(job, ctx):
        for _ in range(100):
            await asyncio.sleep(0.05)
            await ctx.heartbeat()
        return 'done'

    await queue.start(concurrency=2)
    try:
        job = await queue.enqueue('t.flaky', {}, tenant_id='t')
        done = await queue.wait(job.id, timeout=10)
        assert done.status == 'completed' and done.result == 'ok' and done.attempts == 2
        slow_job = await queue.enqueue('t.slow', {}, tenant_id='t')
        await asyncio.sleep(0.2)
        assert await queue.cancel(slow_job.id)
        done = await queue.wait(slow_job.id, timeout=10)
        assert done.status == 'cancelled'
        dup1 = await queue.enqueue('t.slow', {}, tenant_id='t', idempotency_key='same')
        dup2 = await queue.enqueue('t.slow', {}, tenant_id='t', idempotency_key='same')
        assert dup1.id == dup2.id
        await queue.cancel(dup1.id)
        with pytest.raises(KeyError):
            await queue.enqueue('t.unknown', {}, tenant_id='t')
    finally:
        await queue.stop()


def test_ops_jobs_endpoint_tenant_scoped(app, owner, second_tenant):
    client, headers = owner
    queue = app.state.queue

    @queue.handler('t.noop')
    async def noop(job, ctx):
        return {'ok': True}

    job = client.portal.call(lambda: queue.enqueue('t.noop', {}, tenant_id=app.state.default_tenant_id))
    done = wait_job(client, headers, job.id)
    assert done['status'] == 'completed' and done['result'] == {'ok': True}
    assert second_tenant['client'].get(f'/api/v1/ops/jobs/{job.id}', headers=second_tenant['headers']).status_code == 404

