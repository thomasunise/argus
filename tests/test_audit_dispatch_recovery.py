"""Durable audit mirroring and action-dispatch recovery regression tests."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.actions import broker
from app.core import audit
from app.models import AuditEntry, Tenant, dumps
from app.models.actions import ActionRequest, ActionRun
from app.models.audit import AuditSinkDelivery


class FlakySink(audit.AuditSink):
    name = 'flaky'

    def __init__(self):
        self.fail = True
        self.records = []

    def write(self, record):
        if self.fail:
            raise RuntimeError('sink offline')
        self.records.append(record)


def test_external_audit_failure_survives_commit_and_retries(db, default_tenant_id, monkeypatch):
    sink = FlakySink()
    monkeypatch.setattr(audit, '_sinks', [sink])
    audit.record_audit(db, 'system', 'test.outbox', 'target', tenant_id=default_tenant_id)
    db.commit()
    obligations = db.query(AuditSinkDelivery).filter(AuditSinkDelivery.sink == sink.name).all()
    assert len(obligations) == 1
    assert obligations[0].status == 'pending'
    sink.fail = False
    result = audit.replay_audit_deliveries(db)
    db.commit()
    assert result['delivered'] == 1
    db.refresh(obligations[0])
    assert obligations[0].status == 'delivered'
    assert len(sink.records) == 1
    assert sink.records[0]['action'] == 'test.outbox'


@pytest.mark.asyncio
async def test_action_dispatch_can_be_recovered_from_committed_run(db, app, default_tenant_id, monkeypatch):
    request = ActionRequest(tenant_id=default_tenant_id, action_type='argus.isolate',
                            params_json='{}', reason='recovery test', status='executing',
                            risk='low', requested_by='operator', policy_json=dumps({'auto_approve': False}))
    db.add(request)
    db.flush()
    run = ActionRun(tenant_id=default_tenant_id, request_id=request.id,
                    status='queued', job_id='', executed_by='operator')
    db.add(run)
    db.commit()
    calls = []

    async def accept(kind, payload, **kwargs):
        calls.append((kind, payload, kwargs))
        return SimpleNamespace(id='recovered-job-id')

    monkeypatch.setattr(app.state.queue, 'enqueue', accept)
    result = await broker.recover_pending_dispatches(app)
    assert result == {'recovered': 1, 'deferred': 0}
    db.expire_all()
    assert db.get(ActionRun, run.id).job_id == 'recovered-job-id'
    assert calls[0][0] == 'actions.execute'
    assert calls[0][1]['run_id'] == run.id
