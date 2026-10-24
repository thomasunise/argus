"""Autonomous response: templates, policy guardrails, shadow and enforce modes, automatic rollback,
keep, caps, simulation skip, event-bus wiring, API permissions and tenant isolation."""
from __future__ import annotations

from datetime import timedelta
from functools import partial
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.actions import autoresponse, broker, catalog, policy
from app.actions.catalog import ActionType, DryRunResult, ExecResult, entities
from app.core import events
from app.core.errors import Forbidden
from app.core.rbac import Principal, Role
from app.models import AuditEntry, dumps, uid, utcnow
from app.models.actions import ActionRequest, ActionRun
from app.models.autoresponse import AutoresponseExecution
from app.models.detections import Detection
from tests.conftest import login, wait_for, wait_job

PW = 'operator-password-long-123456'


class Fake(ActionType):
    name = 'test.ar.medium'
    description = 'fake reversible action for autonomous-response tests'
    params_schema = {'properties': {'target': {'type': 'string', 'minLength': 1}, 'count': {'type': 'integer', 'minimum': 0, 'default': 1}},
                     'required': ['target']}
    risk = 'medium'
    reversible = True
    platforms = ['argus']
    category = 'containment'

    def __init__(self):
        super().__init__()
        self.calls = []

    async def dry_run(self, params, ctx):
        self.calls.append(('dry_run', dict(params)))
        if params['target'] == 'missing':
            return DryRunResult(ok=False, summary='target missing')
        return DryRunResult(ok=True, summary=f'would block {params["target"]}', blast_radius=entities(params.get('count', 1), 'ip', [params['target']]))

    async def execute(self, params, ctx):
        self.calls.append(('execute', dict(params)))
        return ExecResult(ok=True, summary=f'blocked {params["target"]}', rollback_payload={'target': params['target']})

    async def rollback(self, payload, ctx):
        self.calls.append(('rollback', dict(payload)))
        return ExecResult(ok=True, summary=f'unblocked {payload["target"]}')


class FakeHigh(Fake):
    name = 'test.ar.high'
    risk = 'high'


class FakeCritical(Fake):
    name = 'test.ar.critical'
    risk = 'critical'


class FakeIrreversible(Fake):
    name = 'test.ar.irreversible'
    risk = 'high'
    reversible = False


@pytest.fixture
def settings(settings):
    settings.autoresponse_enabled = True
    return settings


@pytest.fixture
def fakes():
    instances = {cls.name: cls() for cls in (Fake, FakeHigh, FakeCritical, FakeIrreversible)}
    for inst in instances.values():
        catalog.register(inst)
    yield instances
    for name in instances:
        catalog.unregister(name)


# ---------------------------------------------------------------- helpers


def enable(client, headers, *, actions=True, tenant=True):
    if actions:
        assert client.post('/api/v1/actions/kill-switch', json={'enabled': False}, headers=headers).status_code == 200
    if tenant:
        resp = client.put('/api/v1/autoresponse/settings', json={'enabled': True}, headers=headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()['effective'] is True


def playbook(client, headers, **overrides):
    body = {'name': 'block canary sources', 'mode': 'enforce', 'rule_ids': ['canary_tripwire'], 'min_severity': 'high', 'min_confidence': 0.8,
            'action_type': 'test.ar.medium', 'params_template': {'target': '{{evidence.src_ip}}'}, 'rollback_after_minutes': 30}
    body.update(overrides)
    resp = client.post('/api/v1/autoresponse/playbooks', json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def detection(app, tenant_id, *, rule_id='canary_tripwire', severity='critical', confidence=0.95, evidence=None, tags=None, entity='canary-1'):
    with app.state.db_factory() as db:
        row = Detection(tenant_id=tenant_id, rule_id=rule_id, fingerprint=uid().replace('-', ''), title=f'{rule_id} fired', severity=severity,
                        confidence=confidence, entity=entity, entity_kind='canary', evidence_json=dumps(evidence if evidence is not None else {'src_ip': '203.0.113.9'}),
                        tags_json=dumps(tags or []))
        db.add(row)
        db.commit()
        return row.id


def evaluate(client, headers, app, tenant_id, detection_id) -> list[dict]:
    job = client.portal.call(partial(app.state.queue.enqueue, autoresponse.JOB_KIND, {'detection_id': detection_id}, tenant_id=tenant_id))
    done = wait_job(client, headers, job.id)
    assert done['status'] == 'completed', done
    return client.get('/api/v1/autoresponse/executions', params={'detection_id': detection_id}, headers=headers).json()['items']


def run_status(app, run_id):
    with app.state.db_factory() as db:
        run = db.get(ActionRun, run_id)
        return run.status if run else None


# ---------------------------------------------------------------- units


def test_render_templates_and_matching():
    ctx = {'id': 'd1', 'rule_id': 'r', 'severity': 'high', 'confidence': 0.9, 'entity': 'host-1', 'entity_kind': 'host',
           'evidence': {'src_ip': '198.51.100.7', 'n': 3, 'nested': {'x': 'y'}, 'list': ['a']}, 'tags': []}
    assert autoresponse.render({'ip': '{{ evidence.src_ip }}', 'n': '{{evidence.n}}', 'msg': 'seen {{entity}} ({{severity}})', 'k': 5}, ctx) == \
        {'ip': '198.51.100.7', 'n': 3, 'msg': 'seen host-1 (high)', 'k': 5}
    assert autoresponse.render(['{{evidence.list.0}}'], ctx) == ['a']
    for bad in ('{{evidence.missing}}', '{{evidence.nested}}', '{{__class__}}', '{{evidence.__dict__}}'):
        with pytest.raises(autoresponse.MissingValue):
            autoresponse.render({'x': bad}, ctx)
    assert autoresponse.placeholders({'a': ['{{entity}} {{evidence.ip}}']}) == ['entity', 'evidence.ip']
    pb = SimpleNamespace(rule_ids_json='["r"]', min_severity='high', min_confidence=0.8, entity_kind='')
    assert autoresponse.matches(pb, ctx)
    assert not autoresponse.matches(SimpleNamespace(**{**pb.__dict__, 'min_severity': 'critical'}), ctx)
    assert not autoresponse.matches(SimpleNamespace(**{**pb.__dict__, 'min_confidence': 0.95}), ctx)
    assert not autoresponse.matches(SimpleNamespace(**{**pb.__dict__, 'rule_ids_json': '["other"]'}), ctx)
    assert not autoresponse.matches(SimpleNamespace(**{**pb.__dict__, 'entity_kind': 'identity'}), ctx)
    assert autoresponse.is_simulation({'tags': ['simulation'], 'evidence': {}})
    assert autoresponse.is_simulation({'tags': [], 'evidence': {'simulation': True}})
    assert not autoresponse.is_simulation(ctx)


def test_policy_autonomous_guardrails(settings, fakes):
    tenant = SimpleNamespace(id='t1', actions_enabled=True, settings_json='{}')
    system = Principal(tenant_id='t1', role=Role.owner, auth='system')
    ok = DryRunResult(ok=True, summary='', blast_radius=entities(1, 'ip'))
    auto = {'playbook': 'p', 'max_risk': 'medium', 'max_entities': 1}

    def decide(name, dry=ok, **extra):
        return policy.evaluate(None, tenant, settings, catalog.get(name), {}, system, dry_run=dry, autonomous={**auto, **extra})

    medium = decide('test.ar.medium')
    assert medium.auto_approve and medium.required_approvals == 0
    assert not decide('test.ar.high').auto_approve
    high = decide('test.ar.high', max_risk='high')
    assert high.auto_approve and high.required_approvals == 0
    assert not decide('test.ar.critical', max_risk='critical').auto_approve
    assert not decide('test.ar.irreversible', max_risk='high').auto_approve
    assert not decide('test.ar.medium', dry=DryRunResult(ok=False, summary='x')).auto_approve
    assert not decide('test.ar.medium', dry=DryRunResult(ok=True, summary='', blast_radius=entities(3, 'ip'))).auto_approve
    assert decide('test.ar.medium', dry=DryRunResult(ok=True, summary='', blast_radius=entities(3, 'ip')), max_entities=3).auto_approve
    agent = policy.evaluate(None, tenant, settings, catalog.get('test.ar.medium'), {}, system, dry_run=ok, autonomous=auto, agent_originated=True)
    assert not agent.auto_approve
    killed = policy.evaluate(None, SimpleNamespace(id='t1', actions_enabled=False, settings_json='{}'), settings, catalog.get('test.ar.medium'), {},
                             system, dry_run=ok, autonomous=auto)
    assert killed.denied and not killed.auto_approve


@pytest.mark.asyncio
async def test_broker_refuses_autonomous_flag_from_humans_and_agents(app, client, fakes, default_tenant_id):
    human = Principal(tenant_id=default_tenant_id, role=Role.owner, auth='session', user_id='u1')
    with app.state.db_factory() as db:
        with pytest.raises(Forbidden):
            await broker.request(db, human, 'test.ar.medium', {'target': 'x'}, 'r', autonomous={'playbook': 'p'})
        with pytest.raises(Forbidden):
            await broker.request(db, autoresponse.autoresponse_principal(default_tenant_id), 'test.ar.medium', {'target': 'x'}, 'r',
                                 agent_run_id='run-1', autonomous={'playbook': 'p'})


# ---------------------------------------------------------------- API and flows


def test_playbook_validation_and_permissions(app, owner, make_user, fakes):
    client, headers = owner
    bad = [{'action_type': 'test.ar.critical'}, {'action_type': 'test.ar.irreversible', 'allow_high_risk': True}, {'action_type': 'test.ar.high'},
           {'action_type': 'nope.nope'}, {'params_template': {'target': '{{password}}'}}]
    for override in bad:
        body = {'name': 'x', 'action_type': 'test.ar.medium', 'params_template': {'target': '{{entity}}'}, **override}
        assert client.post('/api/v1/autoresponse/playbooks', json=body, headers=headers).status_code == 422, override
    created = playbook(client, headers, action_type='test.ar.high', allow_high_risk=True)
    assert created['mode'] == 'enforce' and created['allow_high_risk'] is True
    assert client.patch(f'/api/v1/autoresponse/playbooks/{created["id"]}', json={'allow_high_risk': False}, headers=headers).status_code == 422
    patched = client.patch(f'/api/v1/autoresponse/playbooks/{created["id"]}', json={'mode': 'shadow', 'max_per_hour': 2}, headers=headers).json()
    assert patched['mode'] == 'shadow' and patched['max_per_hour'] == 2
    default_mode = client.post('/api/v1/autoresponse/playbooks', json={'name': 'd', 'action_type': 'test.ar.medium',
                                                                        'params_template': {'target': '{{entity}}'}}, headers=headers).json()
    assert default_mode['mode'] == 'shadow'  # new playbooks only observe until someone switches them to enforce

    make_user('viewer@test.local', PW, 'viewer')
    make_user('op@test.local', PW, 'operator')
    from fastapi.testclient import TestClient

    viewer = TestClient(app)
    vh = login(viewer, 'viewer@test.local', PW)
    assert viewer.get('/api/v1/autoresponse/playbooks', headers=vh).status_code == 200
    assert viewer.get('/api/v1/autoresponse/status', headers=vh).status_code == 200
    assert viewer.post('/api/v1/autoresponse/playbooks', json={'name': 'x', 'action_type': 'test.ar.medium'}, headers=vh).status_code == 403
    operator = TestClient(app)
    oh = login(operator, 'op@test.local', PW)
    assert operator.put('/api/v1/autoresponse/settings', json={'enabled': True}, headers=oh).status_code == 403
    assert operator.delete(f'/api/v1/autoresponse/playbooks/{created["id"]}', headers=oh).status_code == 403
    assert client.delete(f'/api/v1/autoresponse/playbooks/{created["id"]}', headers=headers).status_code == 200
    assert client.get(f'/api/v1/autoresponse/playbooks/{created["id"]}', headers=headers).status_code == 404


def test_nothing_happens_until_tenant_opts_in(app, owner, fakes, default_tenant_id):
    client, headers = owner
    enable(client, headers, tenant=False)
    playbook(client, headers)
    status = client.get('/api/v1/autoresponse/status', headers=headers).json()
    assert status['global_enabled'] is True and status['tenant_enabled'] is False and status['effective'] is False
    assert evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id)) == []
    assert fakes['test.ar.medium'].calls == []


def test_shadow_mode_records_without_acting(app, owner, fakes, db, default_tenant_id):
    client, headers = owner
    enable(client, headers)
    playbook(client, headers, mode='shadow')
    items = evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id))
    assert len(items) == 1 and items[0]['outcome'] == 'shadow', items
    assert 'would execute autonomously' in items[0]['reason'] and items[0]['dry_run']['ok'] is True
    assert items[0]['params'] == {'target': '203.0.113.9', 'count': 1}
    assert [c[0] for c in fakes['test.ar.medium'].calls] == ['dry_run']
    assert db.execute(select(ActionRequest)).scalars().all() == []


def test_enforce_executes_then_rolls_back_automatically(app, owner, fakes, db, default_tenant_id):
    client, headers = owner
    enable(client, headers)
    pb = playbook(client, headers)
    did = detection(app, default_tenant_id)
    items = evaluate(client, headers, app, default_tenant_id, did)
    assert len(items) == 1 and items[0]['outcome'] == 'enforced', items
    execution = items[0]
    assert execution['rollback_state'] == 'pending' and execution['rollback_due_at'] and execution['action_run_id']
    wait_for(lambda: run_status(app, execution['action_run_id']) == 'executed')
    req = client.get(f'/api/v1/actions/requests/{execution["action_request_id"]}', headers=headers).json()
    assert req['status'] == 'executed' and req['requested_by'] == 'system' and req['detection_id'] == did and req['required_approvals'] == 0
    assert any('autonomous' in r for r in req['policy']['reasons'])
    assert ('execute', {'target': '203.0.113.9', 'count': 1}) in fakes['test.ar.medium'].calls

    # re-delivery of the same detection does nothing new
    assert len(evaluate(client, headers, app, default_tenant_id, did)) == 1
    # before the deadline the sweep leaves it alone
    assert client.portal.call(autoresponse.sweep_rollbacks, app)['requested'] == 0
    later = utcnow() + timedelta(minutes=31)
    assert client.portal.call(autoresponse.sweep_rollbacks, app, later)['requested'] == 1
    wait_for(lambda: run_status(app, execution['action_run_id']) == 'rolled_back')
    assert client.portal.call(autoresponse.sweep_rollbacks, app, later)['done'] == 1
    final = client.get(f'/api/v1/autoresponse/executions/{execution["id"]}', headers=headers).json()
    assert final['rollback_state'] == 'done' and final['rolled_back_at']
    assert fakes['test.ar.medium'].calls[-1] == ('rollback', {'target': '203.0.113.9'})
    trail = [a.action for a in db.execute(select(AuditEntry).where(AuditEntry.tenant_id == default_tenant_id)).scalars().all()]
    for action in ('autoresponse.settings', 'autoresponse.playbook_created', 'actions.requested', 'autoresponse.decision', 'actions.executed',
                   'autoresponse.rollback_requested', 'actions.rolled_back'):
        assert action in trail, action
    assert client.get(f'/api/v1/autoresponse/playbooks/{pb["id"]}', headers=headers).json()['last_triggered_at']


def test_keep_cancels_automatic_rollback_and_manual_rollback(app, owner, fakes, default_tenant_id):
    client, headers = owner
    enable(client, headers)
    playbook(client, headers)
    first = evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id))[0]
    wait_for(lambda: run_status(app, first['action_run_id']) == 'executed')
    kept = client.post(f'/api/v1/autoresponse/executions/{first["id"]}/keep', headers=headers)
    assert kept.status_code == 200 and kept.json()['rollback_state'] == 'kept' and kept.json()['kept_by']
    assert client.post(f'/api/v1/autoresponse/executions/{first["id"]}/keep', headers=headers).status_code == 409
    assert client.portal.call(autoresponse.sweep_rollbacks, app, utcnow() + timedelta(days=1))['requested'] == 0
    assert run_status(app, first['action_run_id']) == 'executed'
    manual = client.post(f'/api/v1/autoresponse/executions/{first["id"]}/rollback', headers=headers)
    assert manual.status_code == 202 and manual.json()['rollback_state'] == 'requested'
    wait_for(lambda: run_status(app, first['action_run_id']) == 'rolled_back')


def test_guardrails_skip_escalate_cap_and_deny(app, owner, fakes, db, default_tenant_id):
    client, headers = owner
    enable(client, headers)
    playbook(client, headers, max_per_hour=2)
    # simulation detections are never acted on
    sim = evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id, tags=['simulation']))
    assert sim[0]['outcome'] == 'skipped' and 'simulator' in sim[0]['reason']
    # a missing template value skips
    missing = evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id, evidence={'other': 1}))
    assert missing[0]['outcome'] == 'skipped' and 'evidence.src_ip' in missing[0]['reason']
    # below the confidence threshold: no match, no record
    assert evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id, confidence=0.5)) == []
    # a failing dry run escalates to an ordinary pending request for humans
    esc = evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id, evidence={'src_ip': 'missing'}))
    assert esc[0]['outcome'] == 'escalated', esc
    pending = client.get(f'/api/v1/actions/requests/{esc[0]["action_request_id"]}', headers=headers).json()
    assert pending['status'] == 'pending' and pending['required_approvals'] == 1
    # one enforced, then the playbook hourly cap (2: escalated + enforced) stops the next
    ok = evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id))
    assert ok[0]['outcome'] == 'enforced'
    capped = evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id))
    assert capped[0]['outcome'] == 'skipped' and 'hourly' in capped[0]['reason']


def test_blast_radius_and_tenant_cap_and_kill_switch(app, owner, fakes, default_tenant_id):
    client, headers = owner
    enable(client, headers)
    playbook(client, headers, name='wide', params_template={'target': '{{evidence.src_ip}}', 'count': 5})
    wide = evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id))
    assert wide[0]['outcome'] == 'escalated' and '5 entities' in wide[0]['reason']
    client.patch(f'/api/v1/autoresponse/playbooks/{wide[0]["playbook_id"]}', json={'enabled': False}, headers=headers)

    playbook(client, headers, name='narrow')
    assert client.put('/api/v1/autoresponse/settings', json={'max_per_hour': 0}, headers=headers).json()['max_per_hour'] == 0
    capped = evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id))
    assert capped[0]['outcome'] == 'skipped' and 'tenant hourly' in capped[0]['reason']
    client.put('/api/v1/autoresponse/settings', json={'max_per_hour': 50}, headers=headers)
    assert client.get('/api/v1/autoresponse/status', headers=headers).json()['max_per_hour'] == 20  # cannot exceed the global cap

    assert client.post('/api/v1/actions/kill-switch', json={'enabled': True}, headers=headers).status_code == 200
    denied = evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id))
    assert denied[0]['outcome'] == 'denied' and 'kill switch' in denied[0]['reason']


def test_high_risk_needs_explicit_opt_in(app, owner, fakes, default_tenant_id):
    client, headers = owner
    enable(client, headers)
    playbook(client, headers, action_type='test.ar.high', allow_high_risk=True)
    items = evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id))
    assert items[0]['outcome'] == 'enforced', items


def test_detection_event_triggers_evaluation(app, owner, fakes, default_tenant_id):
    client, headers = owner
    enable(client, headers)
    playbook(client, headers, mode='shadow')
    did = detection(app, default_tenant_id)
    client.portal.call(events.publish, 'detection.created', {'tenant_id': default_tenant_id, 'detection_id': did, 'rule_id': 'canary_tripwire'})
    found = wait_for(lambda: client.get('/api/v1/autoresponse/executions', params={'detection_id': did}, headers=headers).json()['items'])
    assert found[0]['outcome'] == 'shadow'


def test_globally_disabled_ignores_events(app, owner, fakes, default_tenant_id):
    client, headers = owner
    enable(client, headers)
    playbook(client, headers, mode='shadow')
    app.state.settings.autoresponse_enabled = False
    try:
        assert evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id)) == []
    finally:
        app.state.settings.autoresponse_enabled = True


def test_cross_tenant_isolation(app, owner, second_tenant, fakes, default_tenant_id):
    client, headers = owner
    enable(client, headers)
    pb = playbook(client, headers)
    execution = evaluate(client, headers, app, default_tenant_id, detection(app, default_tenant_id))[0]
    other, oh = second_tenant['client'], second_tenant['headers']
    assert other.get('/api/v1/autoresponse/playbooks', headers=oh).json()['items'] == []
    assert other.get('/api/v1/autoresponse/executions', headers=oh).json()['items'] == []
    assert other.get(f'/api/v1/autoresponse/playbooks/{pb["id"]}', headers=oh).status_code == 404
    assert other.patch(f'/api/v1/autoresponse/playbooks/{pb["id"]}', json={'enabled': False}, headers=oh).status_code == 404
    assert other.delete(f'/api/v1/autoresponse/playbooks/{pb["id"]}', headers=oh).status_code == 404
    assert other.get(f'/api/v1/autoresponse/executions/{execution["id"]}', headers=oh).status_code == 404
    assert other.post(f'/api/v1/autoresponse/executions/{execution["id"]}/keep', headers=oh).status_code == 404
    assert other.post(f'/api/v1/autoresponse/executions/{execution["id"]}/rollback', headers=oh).status_code == 404
    assert other.get('/api/v1/autoresponse/status', headers=oh).json()['tenant_enabled'] is False
    # the other tenant's job cannot evaluate this tenant's detection
    other_tid = second_tenant['tenant_id']
    job = client.portal.call(partial(app.state.queue.enqueue, autoresponse.JOB_KIND, {'detection_id': execution['detection_id']}, tenant_id=other_tid))
    wait_job(other, oh, job.id)
    with app.state.db_factory() as db:
        assert db.execute(select(AutoresponseExecution).where(AutoresponseExecution.tenant_id == other_tid)).scalars().all() == []
