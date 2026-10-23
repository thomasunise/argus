"""Action broker: policy matrix, full lifecycle through the API with a fake action type,
kill switch, approvals, agent-originated proposals, cross-tenant isolation, permissions."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.actions import broker, catalog, credentials, policy
from app.actions.catalog import ActionError, ActionType, DryRunResult, ExecResult, entities
from app.actions.schema import validate
from app.core.rbac import Principal, Role
from app.models import AuditEntry, Tenant, dumps, loads
from app.models.actions import ActionRequest
from tests.conftest import login, wait_job

PW = 'operator-password-long-123456'


# ---------------------------------------------------------------- fake action types


class FakeAction(ActionType):
    name = 'test.fake.high'
    description = 'fake reversible high-risk action for tests'
    params_schema = {'properties': {'target': {'type': 'string', 'minLength': 1}, 'count': {'type': 'integer', 'minimum': 0, 'default': 1}},
                     'required': ['target']}
    risk = 'high'
    reversible = True
    platforms = ['sentinel']
    category = 'containment'
    calls: list

    def __init__(self):
        super().__init__()
        self.calls = []

    async def dry_run(self, params, ctx):
        self.calls.append(('dry_run', dict(params), ctx.dry_run))
        if params['target'] == 'missing':
            return DryRunResult(ok=False, summary='target missing', blast_radius=entities(0, 'thing'))
        return DryRunResult(ok=True, summary=f'would touch {params["target"]}', blast_radius=entities(params.get('count', 1), 'thing', [params['target']]),
                            warnings=['fake warning'])

    async def execute(self, params, ctx):
        self.calls.append(('execute', dict(params), ctx.actor))
        if params['target'] == 'boom':
            raise ActionError('executor exploded with password=SuperSecret123')
        return ExecResult(ok=True, summary=f'touched {params["target"]}', rollback_payload={'target': params['target'], 'token': 'password=SuperSecret123'})

    async def rollback(self, payload, ctx):
        self.calls.append(('rollback', dict(payload), ctx.actor))
        return ExecResult(ok=True, summary=f'untouched {payload["target"]}')


class FakeLow(FakeAction):
    name = 'test.fake.low'
    risk = 'low'


class FakeMedium(FakeAction):
    name = 'test.fake.medium'
    risk = 'medium'


class FakeCritical(FakeAction):
    name = 'test.fake.critical'
    risk = 'critical'


class FakeIrreversible(FakeAction):
    name = 'test.fake.irreversible'
    risk = 'high'
    reversible = False


@pytest.fixture
def fakes():
    instances = {cls.name: cls() for cls in (FakeAction, FakeLow, FakeMedium, FakeCritical, FakeIrreversible)}
    for inst in instances.values():
        catalog.register(inst)
    yield instances
    for name in instances:
        catalog.unregister(name)


# ---------------------------------------------------------------- helpers


def _tenant(actions_enabled=True, **policy_overrides):
    return SimpleNamespace(id='t1', actions_enabled=actions_enabled, settings_json=dumps({'action_policy': policy_overrides} if policy_overrides else {}))


def _principal(role=Role.operator, user_id='u1'):
    return Principal(tenant_id='t1', role=role, user_id=user_id, email=f'{user_id}@test.local')


def as_user(app, email: str, password: str) -> tuple[TestClient, dict]:
    client = TestClient(app)
    return client, login(client, email, password)


def enable_actions(client, headers):
    resp = client.post('/api/v1/actions/kill-switch', json={'enabled': False, 'reason': 'tests'}, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()['actions_enabled'] is True


def set_tenant_policy(app, tenant_id: str, **overrides):
    with app.state.db_factory() as db:
        tenant = db.get(Tenant, tenant_id)
        data = loads(tenant.settings_json, {})
        data['action_policy'] = overrides
        tenant.settings_json = dumps(data)
        db.commit()


def make_request(client, headers, action_type='test.fake.high', target='srv-1', **extra):
    resp = client.post('/api/v1/actions/requests', json={'action_type': action_type, 'params': {'target': target, **extra}, 'reason': 'contain it'}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def audit_actions(db, tenant_id: str) -> list[str]:
    rows = db.execute(select(AuditEntry).where(AuditEntry.tenant_id == tenant_id).order_by(AuditEntry.id.asc())).scalars().all()
    return [r.action for r in rows if r.action.startswith('actions.')]


# ---------------------------------------------------------------- schema validator


def test_schema_validator_subset():
    schema = {'type': 'object', 'additionalProperties': False, 'required': ['name'],
              'properties': {'name': {'type': 'string', 'minLength': 2, 'pattern': '^[a-z]+$'}, 'n': {'type': 'integer', 'minimum': 1, 'maximum': 5},
                             'kind': {'type': 'string', 'enum': ['a', 'b']}, 'tags': {'type': 'array', 'items': {'type': 'string'}, 'maxItems': 2}}}
    assert validate(schema, {'name': 'abc', 'n': 3, 'kind': 'a', 'tags': ['x']}) == []
    problems = validate(schema, {'name': 'A', 'n': 9, 'kind': 'z', 'tags': ['x', 'y', 'z'], 'extra': 1})
    assert len(problems) == 6
    assert validate(schema, {'n': True}) and validate(schema, 'nope')


def test_action_type_contract_enforced():
    class Bad(ActionType):
        name = 'bad'
        risk = 'low'
        reversible = False

    with pytest.raises(ValueError):
        Bad()
    for action in catalog.all():
        assert action.params_schema['additionalProperties'] is False
        assert action.reversible or action.risk in {'high', 'critical'}, action.name


# ---------------------------------------------------------------- credentials


def test_credentials_resolution(settings, monkeypatch, tmp_path):
    monkeypatch.delenv('ACTIONS_GITHUB_TOKEN', raising=False)
    assert credentials.configured('github', settings) is False
    monkeypatch.setenv('ACTIONS_GITHUB_TOKEN', 'ghp_plainvalue')
    assert credentials.resolve('github', 'token', settings) == 'ghp_plainvalue'
    # env value may itself be a reference
    monkeypatch.setenv('GH_SECRET', 'ghp_fromref')
    monkeypatch.setenv('ACTIONS_GITHUB_TOKEN', 'env:GH_SECRET')
    assert credentials.resolve('github', 'token', settings) == 'ghp_fromref'
    # tenant override must be a ref; literal values are ignored
    secret_file = tmp_path / 'tok'
    secret_file.write_text('ghp_tenant', encoding='utf-8')
    tenant_settings = {'action_credentials': {'github': {'token': f'file:{secret_file}'}}}
    assert credentials.resolve('github', 'token', settings, tenant_settings) == 'ghp_tenant'
    assert credentials.resolve('github', 'token', settings, {'action_credentials': {'github': {'token': 'literalvalue'}}}) == 'ghp_fromref'
    # entra falls back to azure
    monkeypatch.setenv('ACTIONS_AZURE_TENANT_ID', 'tid')
    assert credentials.resolve('entra', 'tenant_id', settings) == 'tid'
    assert credentials.configured('aws', settings) is False
    monkeypatch.setenv('ACTIONS_AWS_ROLE_ARN', 'arn:aws:iam::123456789012:role/sentinel')
    assert credentials.configured('aws', settings) is True


# ---------------------------------------------------------------- policy matrix


def test_policy_matrix_by_risk(settings, fakes):
    tenant = _tenant()
    good = DryRunResult(ok=True, summary='', blast_radius=entities(1, 'x'))
    crit = policy.evaluate(None, tenant, settings, fakes['test.fake.critical'], {}, _principal(), dry_run=good)
    assert (crit.required_approvals, crit.owner_required, crit.denied) == (2, True, False)
    high = policy.evaluate(None, tenant, settings, fakes['test.fake.high'], {}, _principal(), dry_run=good)
    assert high.required_approvals == 2 and not high.owner_required
    settings_one = settings.model_copy(update={'actions_require_two_for_high': False})
    assert policy.evaluate(None, tenant, settings_one, fakes['test.fake.high'], {}, _principal(), dry_run=good).required_approvals == 1
    assert policy.evaluate(None, _tenant(require_two_for_high=False), settings, fakes['test.fake.high'], {}, _principal(), dry_run=good).required_approvals == 1
    med = policy.evaluate(None, tenant, settings, fakes['test.fake.medium'], {}, _principal(), dry_run=good)
    assert med.required_approvals == 1 and not med.auto_approve
    # low: not auto-approved by default
    low = policy.evaluate(None, tenant, settings, fakes['test.fake.low'], {}, _principal(), dry_run=good)
    assert low.required_approvals == 1 and not low.auto_approve
    auto_settings = settings.model_copy(update={'actions_auto_approve_low': True})
    low = policy.evaluate(None, tenant, auto_settings, fakes['test.fake.low'], {}, _principal(), dry_run=good)
    assert low.auto_approve and low.required_approvals == 0
    # blast radius too large, failed dry run, no dry run, agent-originated, irreversible: no auto approval
    big = DryRunResult(ok=True, summary='', blast_radius=entities(2, 'x'))
    assert not policy.evaluate(None, tenant, auto_settings, fakes['test.fake.low'], {}, _principal(), dry_run=big).auto_approve
    assert not policy.evaluate(None, tenant, auto_settings, fakes['test.fake.low'], {}, _principal(), dry_run=DryRunResult(ok=False, summary='')).auto_approve
    assert not policy.evaluate(None, tenant, auto_settings, fakes['test.fake.low'], {}, _principal()).auto_approve
    agent = policy.evaluate(None, tenant, auto_settings, fakes['test.fake.low'], {}, _principal(), dry_run=good, agent_originated=True)
    assert not agent.auto_approve and any('agent' in r for r in agent.reasons)
    fakes['test.fake.low'].reversible = False
    try:
        assert not policy.evaluate(None, tenant, auto_settings, fakes['test.fake.low'], {}, _principal(), dry_run=good).auto_approve
    finally:
        fakes['test.fake.low'].reversible = True


def test_policy_kill_switch_and_deny_list(settings, fakes):
    action = fakes['test.fake.medium']
    assert policy.evaluate(None, _tenant(), settings.model_copy(update={'actions_kill_switch': True}), action, {}, _principal()).denied
    assert policy.evaluate(None, _tenant(actions_enabled=False), settings, action, {}, _principal()).denied
    assert policy.evaluate(None, None, settings, action, {}, _principal()).denied
    denied = policy.evaluate(None, _tenant(deny=['test.fake.*']), settings, action, {}, _principal())
    assert denied.denied and 'denied by tenant policy' in denied.deny_reason
    assert not policy.evaluate(None, _tenant(deny=['aws.*']), settings, action, {}, _principal()).denied
    viewer = policy.evaluate(None, _tenant(), settings, action, {}, _principal(role=Role.viewer))
    assert viewer.denied and 'actions:request' in viewer.deny_reason


def test_policy_maintenance_window(settings, fakes):
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    inside = settings.model_copy(update={'actions_maintenance_window': '11:00-13:00'})
    outside = settings.model_copy(update={'actions_maintenance_window': '02:00-04:00'})
    wrap = settings.model_copy(update={'actions_maintenance_window': '23:00-01:00'})
    high, medium = fakes['test.fake.high'], fakes['test.fake.medium']
    assert policy.evaluate(None, _tenant(), inside, high, {}, _principal(), now=now, phase='execute').within_window is True
    requested = policy.evaluate(None, _tenant(), outside, high, {}, _principal(), now=now)
    assert not requested.denied and requested.within_window is False  # request allowed, execution gated
    assert policy.evaluate(None, _tenant(), outside, high, {}, _principal(), now=now, phase='execute').denied
    assert not policy.evaluate(None, _tenant(), outside, medium, {}, _principal(), now=now, phase='execute').denied  # window only for high/critical
    assert policy.in_window('23:00-01:00', datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc)) is True
    assert policy.evaluate(None, _tenant(), wrap, high, {}, _principal(), now=now, phase='execute').denied
    assert policy.in_window('garbage') is None
    malformed = policy.evaluate(None, _tenant(maintenance_window='25:99-xx'), settings, high, {}, _principal(), now=now, phase='execute')
    assert not malformed.denied and any('malformed' in r for r in malformed.reasons)


# ---------------------------------------------------------------- API: catalog and kill switch


def test_catalog_lists_real_actions(owner):
    client, headers = owner
    data = client.get('/api/v1/actions/catalog', headers=headers).json()
    names = {a['name'] for a in data['items']}
    expected = {'aws.iam.disable_access_key', 'aws.iam.detach_policy', 'aws.s3.block_public_access', 'aws.ec2.revoke_sg_ingress', 'aws.ec2.isolate_instance',
                'aws.iam.attach_deny_all_boundary', 'azure.nsg.remove_rule', 'azure.storage.disable_public_blob_access', 'azure.ad.revoke_user_sessions',
                'azure.ad.disable_user', 'gcp.firewall.disable_rule', 'gcp.storage.remove_public_binding', 'gcp.iam.remove_binding',
                'kubernetes.network_policy.isolate_pod', 'kubernetes.scale_to_zero', 'kubernetes.delete_pod', 'okta.user.suspend', 'okta.user.clear_sessions',
                'entra.user.disable', 'github.branch_protection.enable', 'github.secret_scanning.enable', 'github.open_fix_pr', 'cloudflare.waf.block_ip',
                'sentinel.finding.update_status', 'sentinel.asset.revoke_authorization'}
    assert expected <= names
    by_name = {a['name']: a for a in data['items']}
    assert by_name['aws.iam.attach_deny_all_boundary']['risk'] == 'critical'
    assert by_name['kubernetes.delete_pod']['reversible'] is False and by_name['kubernetes.delete_pod']['risk'] == 'high'
    assert by_name['sentinel.finding.update_status']['available'] is True
    assert by_name['aws.iam.disable_access_key']['available'] is False  # no boto3 / credentials in tests
    assert all(a['params_schema']['additionalProperties'] is False for a in data['items'])


def test_kill_switch_default_blocks_and_toggle(owner, fakes, db, default_tenant_id):
    client, headers = owner
    state = client.get('/api/v1/actions/kill-switch', headers=headers).json()
    assert state['actions_enabled'] is False and state['effective'] is True
    denied = client.post('/api/v1/actions/requests', json={'action_type': 'test.fake.medium', 'params': {'target': 'x'}, 'reason': 'r'}, headers=headers)
    assert denied.status_code == 403 and denied.json()['code'] == 'policy_denied'
    enable_actions(client, headers)
    assert client.get('/api/v1/actions/kill-switch', headers=headers).json()['effective'] is False
    assert client.post('/api/v1/actions/requests', json={'action_type': 'test.fake.medium', 'params': {'target': 'x'}, 'reason': 'r'}, headers=headers).status_code == 201
    engaged = client.post('/api/v1/actions/kill-switch', json={'enabled': True, 'reason': 'incident'}, headers=headers).json()
    assert engaged['tenant_engaged'] is True and engaged['detail']['reason'] == 'incident'
    assert 'actions.kill_switch' in audit_actions(db, default_tenant_id)


def test_global_kill_switch(app, owner, fakes):
    client, headers = owner
    enable_actions(client, headers)
    app.state.settings.actions_kill_switch = True
    try:
        resp = client.post('/api/v1/actions/requests', json={'action_type': 'test.fake.medium', 'params': {'target': 'x'}, 'reason': 'r'}, headers=headers)
        assert resp.status_code == 403 and 'global' in resp.json()['detail']
        assert client.get('/api/v1/actions/kill-switch', headers=headers).json()['global'] is True
    finally:
        app.state.settings.actions_kill_switch = False


def test_kill_switch_requires_admin(app, client, make_user, fakes):
    make_user('op@test.local', PW, 'operator')
    op, op_headers = as_user(app, 'op@test.local', PW)
    assert op.post('/api/v1/actions/kill-switch', json={'enabled': False}, headers=op_headers).status_code == 403
    make_user('adm@test.local', PW, 'admin')
    adm, adm_headers = as_user(app, 'adm@test.local', PW)
    assert adm.post('/api/v1/actions/kill-switch', json={'enabled': False}, headers=adm_headers).status_code == 200


# ---------------------------------------------------------------- API: request validation and dry run


def test_request_validation_and_dry_run_stored(owner, fakes, db, default_tenant_id):
    client, headers = owner
    enable_actions(client, headers)
    assert client.post('/api/v1/actions/requests', json={'action_type': 'nope.nothing', 'params': {}, 'reason': 'r'}, headers=headers).status_code == 404
    bad = client.post('/api/v1/actions/requests', json={'action_type': 'test.fake.high', 'params': {'target': 'x', 'bogus': 1}, 'reason': 'r'}, headers=headers)
    assert bad.status_code == 422 and bad.json()['code'] == 'invalid_params'
    missing = client.post('/api/v1/actions/requests', json={'action_type': 'test.fake.high', 'params': {}, 'reason': 'r'}, headers=headers)
    assert missing.status_code == 422
    unknown_finding = client.post('/api/v1/actions/requests', json={'action_type': 'test.fake.high', 'params': {'target': 'x'}, 'reason': 'r', 'finding_id': 'nope'}, headers=headers)
    assert unknown_finding.status_code == 404
    created = make_request(client, headers, target='srv-9', count=3)
    assert created['status'] == 'pending' and created['required_approvals'] == 2 and created['risk'] == 'high'
    assert created['dry_run']['ok'] is True and created['dry_run']['blast_radius']['entities'] == 3 and created['dry_run']['warnings'] == ['fake warning']
    assert created['params'] == {'target': 'srv-9', 'count': 3} and created['policy']['required_approvals'] == 2
    assert created['expires_at'] is not None and created['approvals'] == [] and created['runs'] == []
    # a failed dry run is stored too, the request still exists for humans to look at
    failed = make_request(client, headers, target='missing')
    assert failed['dry_run']['ok'] is False and failed['status'] == 'pending'
    assert fakes['test.fake.high'].calls[0][2] is True  # dry_run flag on ctx
    assert audit_actions(db, default_tenant_id).count('actions.requested') == 2
    listing = client.get('/api/v1/actions/requests', headers=headers).json()
    assert len(listing['items']) == 2 and listing['next_cursor'] is None
    assert len(client.get('/api/v1/actions/requests?action_type=test.fake.high&status=pending', headers=headers).json()['items']) == 2
    assert client.get('/api/v1/actions/requests?status=executed', headers=headers).json()['items'] == []


# ---------------------------------------------------------------- API: full lifecycle


def test_full_lifecycle_request_approve_twice_execute_rollback(app, owner, make_user, fakes, db, default_tenant_id):
    client, headers = owner
    enable_actions(client, headers)
    make_user('op1@test.local', PW, 'operator')
    make_user('op2@test.local', PW, 'operator')
    op1, h1 = as_user(app, 'op1@test.local', PW)
    op2, h2 = as_user(app, 'op2@test.local', PW)

    created = make_request(op1, h1, target='srv-1')
    rid = created['id']
    # cannot execute before approval
    assert op1.post(f'/api/v1/actions/requests/{rid}/execute', headers=h1).status_code == 409
    # requester cannot approve own request
    self_approve = op1.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=h1)
    assert self_approve.status_code == 403
    # first approval
    first = op2.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve', 'comment': 'lgtm'}, headers=h2).json()
    assert first['status'] == 'pending' and first['approval_count'] == 1
    assert op2.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=h2).status_code == 409
    assert op1.post(f'/api/v1/actions/requests/{rid}/execute', headers=h1).status_code == 409
    # second approval by the owner satisfies high (2)
    second = client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=headers).json()
    assert second['status'] == 'approved' and second['approval_count'] == 2 and second['decided_at']
    assert client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=headers).status_code == 409

    # execute
    accepted = op1.post(f'/api/v1/actions/requests/{rid}/execute', headers=h1)
    assert accepted.status_code == 202, accepted.text
    run_id, job_id = accepted.json()['run']['id'], accepted.json()['job_id']
    assert accepted.json()['request']['status'] == 'executing'
    job = wait_job(op1, h1, job_id)
    assert job['status'] == 'completed', job
    detail = op1.get(f'/api/v1/actions/requests/{rid}', headers=h1).json()
    assert detail['status'] == 'executed' and len(detail['runs']) == 1 and detail['runs'][0]['status'] == 'executed'
    run = op1.get(f'/api/v1/actions/runs/{run_id}', headers=h1).json()
    assert run['has_rollback_payload'] is True and run['result']['execution']['summary'] == 'touched srv-1'
    assert run['result']['dry_run']['ok'] is True and run['executed_by']
    assert run['rollback_payload']['target'] == 'srv-1' and 'SuperSecret123' not in run['rollback_payload']['token']  # stored redacted
    # executor saw a dry run and then an execute
    kinds = [c[0] for c in fakes['test.fake.high'].calls]
    assert kinds[-2:] == ['dry_run', 'execute']
    # cannot execute again or roll back twice
    assert op1.post(f'/api/v1/actions/requests/{rid}/execute', headers=h1).status_code == 409

    # rollback
    rb = client.post(f'/api/v1/actions/runs/{run_id}/rollback', headers=headers)
    assert rb.status_code == 202, rb.text
    assert wait_job(client, headers, rb.json()['job_id'])['status'] == 'completed'
    run = client.get(f'/api/v1/actions/runs/{run_id}', headers=headers).json()
    assert run['status'] == 'rolled_back' and run['rolled_back_at'] and run['rolled_back_by']
    assert client.get(f'/api/v1/actions/requests/{rid}', headers=headers).json()['status'] == 'rolled_back'
    assert client.post(f'/api/v1/actions/runs/{run_id}/rollback', headers=headers).status_code == 409
    assert fakes['test.fake.high'].calls[-1][0] == 'rollback'
    runs = client.get('/api/v1/actions/runs', headers=headers).json()['items']
    assert [r['id'] for r in runs] == [run_id]
    # audit trail covers the whole lifecycle
    trail = audit_actions(db, default_tenant_id)
    for action in ('actions.requested', 'actions.approval_recorded', 'actions.approved', 'actions.execute_requested', 'actions.executed',
                   'actions.rollback_requested', 'actions.rolled_back'):
        assert action in trail, (action, trail)


def test_execution_failure_marks_request_failed(app, owner, make_user, fakes):
    client, headers = owner
    enable_actions(client, headers)
    make_user('op1@test.local', PW, 'operator')
    op1, h1 = as_user(app, 'op1@test.local', PW)
    created = make_request(op1, h1, action_type='test.fake.medium', target='boom')
    rid = created['id']
    assert client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=headers).json()['status'] == 'approved'
    accepted = client.post(f'/api/v1/actions/requests/{rid}/execute', headers=headers).json()
    wait_job(client, headers, accepted['job_id'])
    detail = client.get(f'/api/v1/actions/requests/{rid}', headers=headers).json()
    assert detail['status'] == 'failed' and detail['runs'][0]['status'] == 'failed'
    assert 'exploded' in detail['runs'][0]['error'] and 'SuperSecret123' not in detail['runs'][0]['error']
    assert client.post(f'/api/v1/actions/runs/{detail["runs"][0]["id"]}/rollback', headers=headers).status_code == 409


def test_pre_execution_dry_run_failure(app, owner, make_user, fakes):
    client, headers = owner
    enable_actions(client, headers)
    make_user('op1@test.local', PW, 'operator')
    op1, h1 = as_user(app, 'op1@test.local', PW)
    rid = make_request(op1, h1, action_type='test.fake.medium', target='srv-2')['id']
    client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=headers)
    # the target disappears between approval and execution
    with app.state.db_factory() as session:
        req = session.get(ActionRequest, rid)
        req.params_json = dumps({'target': 'missing', 'count': 1})
        session.commit()
    accepted = client.post(f'/api/v1/actions/requests/{rid}/execute', headers=headers).json()
    wait_job(client, headers, accepted['job_id'])
    detail = client.get(f'/api/v1/actions/requests/{rid}', headers=headers).json()
    assert detail['status'] == 'failed' and 'dry run failed' in detail['runs'][0]['error']
    assert [c[0] for c in fakes['test.fake.medium'].calls].count('execute') == 0


def test_reject_and_cancel(app, owner, make_user, fakes):
    client, headers = owner
    enable_actions(client, headers)
    make_user('op1@test.local', PW, 'operator')
    make_user('an@test.local', PW, 'analyst')
    op1, h1 = as_user(app, 'op1@test.local', PW)
    an, ha = as_user(app, 'an@test.local', PW)
    rid = make_request(op1, h1, action_type='test.fake.medium')['id']
    rejected = client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'reject', 'comment': 'no'}, headers=headers).json()
    assert rejected['status'] == 'rejected' and rejected['approvals'][0]['decision'] == 'reject'
    assert client.post(f'/api/v1/actions/requests/{rid}/execute', headers=headers).status_code == 409
    rid2 = make_request(op1, h1, action_type='test.fake.medium')['id']
    assert an.post(f'/api/v1/actions/requests/{rid2}/cancel', json={'reason': 'x'}, headers=ha).status_code == 403  # analyst is neither requester nor approver
    assert op1.post(f'/api/v1/actions/requests/{rid2}/cancel', json={'reason': 'changed mind'}, headers=h1).json()['status'] == 'cancelled'
    assert client.post(f'/api/v1/actions/requests/{rid2}/approve', json={'decision': 'approve'}, headers=headers).status_code == 409
    assert client.post(f'/api/v1/actions/requests/{rid2}/cancel', headers=headers).status_code == 409


def test_expired_request_cannot_be_approved(app, owner, make_user, fakes):
    client, headers = owner
    enable_actions(client, headers)
    make_user('op1@test.local', PW, 'operator')
    op1, h1 = as_user(app, 'op1@test.local', PW)
    rid = make_request(op1, h1, action_type='test.fake.medium')['id']
    with app.state.db_factory() as session:
        session.get(ActionRequest, rid).expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        session.commit()
    resp = client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=headers)
    assert resp.status_code == 409 and 'expired' in resp.json()['detail']
    assert client.get(f'/api/v1/actions/requests/{rid}', headers=headers).json()['status'] == 'cancelled'


# ---------------------------------------------------------------- approvals: critical, kill switch at execution, maintenance window


def test_critical_needs_two_including_owner(app, owner, make_user, fakes):
    client, headers = owner
    enable_actions(client, headers)
    for i in (1, 2, 3):
        make_user(f'op{i}@test.local', PW, 'operator')
    op1, h1 = as_user(app, 'op1@test.local', PW)
    op2, h2 = as_user(app, 'op2@test.local', PW)
    op3, h3 = as_user(app, 'op3@test.local', PW)
    created = make_request(op1, h1, action_type='test.fake.critical')
    assert created['required_approvals'] == 2 and created['owner_approval_required'] is True
    rid = created['id']
    op2.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=h2)
    third = op3.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=h3).json()
    assert third['status'] == 'pending' and third['approval_count'] == 2  # two operators are not enough: no owner slot
    assert op1.post(f'/api/v1/actions/requests/{rid}/execute', headers=h1).status_code == 409
    final = client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=headers).json()
    assert final['status'] == 'approved' and any(a['can_approve_critical'] for a in final['approvals'])


def test_kill_switch_blocks_execution_of_approved_request(app, owner, make_user, fakes):
    client, headers = owner
    enable_actions(client, headers)
    make_user('op1@test.local', PW, 'operator')
    op1, h1 = as_user(app, 'op1@test.local', PW)
    rid = make_request(op1, h1, action_type='test.fake.medium')['id']
    client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=headers)
    client.post('/api/v1/actions/kill-switch', json={'enabled': True, 'reason': 'stop'}, headers=headers)
    resp = client.post(f'/api/v1/actions/requests/{rid}/execute', headers=headers)
    assert resp.status_code == 403 and resp.json()['code'] == 'policy_denied'
    assert client.get(f'/api/v1/actions/requests/{rid}', headers=headers).json()['status'] == 'approved'
    enable_actions(client, headers)
    assert client.post(f'/api/v1/actions/requests/{rid}/execute', headers=headers).status_code == 202


def test_maintenance_window_gates_high_execution(app, owner, make_user, fakes, default_tenant_id):
    client, headers = owner
    enable_actions(client, headers)
    make_user('op1@test.local', PW, 'operator')
    op1, h1 = as_user(app, 'op1@test.local', PW)
    now = datetime.now(timezone.utc)
    closed = f'{(now + timedelta(hours=2)).strftime("%H:%M")}-{(now + timedelta(hours=3)).strftime("%H:%M")}'
    open_ = f'{(now - timedelta(hours=1)).strftime("%H:%M")}-{(now + timedelta(hours=1)).strftime("%H:%M")}'
    set_tenant_policy(app, default_tenant_id, maintenance_window=closed, require_two_for_high=False)
    created = make_request(op1, h1, target='srv-3')
    assert created['status'] == 'pending' and created['policy']['within_window'] is False and created['required_approvals'] == 1
    rid = created['id']
    assert client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=headers).json()['status'] == 'approved'
    gated = client.post(f'/api/v1/actions/requests/{rid}/execute', headers=headers)
    assert gated.status_code == 403 and 'maintenance window' in gated.json()['detail']
    set_tenant_policy(app, default_tenant_id, maintenance_window=open_, require_two_for_high=False)
    accepted = client.post(f'/api/v1/actions/requests/{rid}/execute', headers=headers)
    assert accepted.status_code == 202
    wait_job(client, headers, accepted.json()['job_id'])
    assert client.get(f'/api/v1/actions/requests/{rid}', headers=headers).json()['status'] == 'executed'


def test_handler_recheck_denies_when_switch_flips_after_enqueue(app, owner, make_user, fakes, monkeypatch):
    """The queue handler re-evaluates policy itself; a job is not a grant."""
    client, headers = owner
    enable_actions(client, headers)
    make_user('op1@test.local', PW, 'operator')
    op1, h1 = as_user(app, 'op1@test.local', PW)
    rid = make_request(op1, h1, action_type='test.fake.medium')['id']
    client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=headers)
    original = broker.policy.evaluate
    seen = {'execute_phase_calls': 0}

    def flip(db, tenant, settings, action_type, params, requester, **kw):
        if kw.get('phase') == 'execute':
            seen['execute_phase_calls'] += 1
            if seen['execute_phase_calls'] == 2:  # 1 = endpoint pre-check passes; 2 = the queue handler sees the switch flipped
                settings.actions_kill_switch = True
        return original(db, tenant, settings, action_type, params, requester, **kw)

    monkeypatch.setattr(broker.policy, 'evaluate', flip)
    accepted = client.post(f'/api/v1/actions/requests/{rid}/execute', headers=headers)
    assert accepted.status_code == 202
    wait_job(client, headers, accepted.json()['job_id'])
    app.state.settings.actions_kill_switch = False
    detail = client.get(f'/api/v1/actions/requests/{rid}', headers=headers).json()
    assert detail['status'] == 'approved' and detail['runs'][0]['status'] == 'failed' and 'kill switch' in detail['runs'][0]['error']
    assert not any(c[0] == 'execute' for c in fakes['test.fake.medium'].calls)


# ---------------------------------------------------------------- auto approval and agent-originated requests


def test_low_risk_auto_approval_and_agent_requests(app, owner, make_user, fakes, default_tenant_id):
    client, headers = owner
    enable_actions(client, headers)
    set_tenant_policy(app, default_tenant_id, auto_approve_low=True)
    make_user('op1@test.local', PW, 'operator')
    op1, h1 = as_user(app, 'op1@test.local', PW)
    auto = make_request(op1, h1, action_type='test.fake.low', target='one', count=1)
    assert auto['status'] == 'auto_approved' and auto['required_approvals'] == 0 and auto['decided_at']
    accepted = op1.post(f'/api/v1/actions/requests/{auto["id"]}/execute', headers=h1)
    assert accepted.status_code == 202
    wait_job(op1, h1, accepted.json()['job_id'])
    assert op1.get(f'/api/v1/actions/requests/{auto["id"]}', headers=h1).json()['status'] == 'executed'
    wide = make_request(op1, h1, action_type='test.fake.low', target='many', count=5)
    assert wide['status'] == 'pending' and wide['required_approvals'] == 1
    failed_dry = make_request(op1, h1, action_type='test.fake.low', target='missing')
    assert failed_dry['status'] == 'pending'


@pytest.mark.asyncio
async def test_agent_originated_request_never_auto_approved(app, client, owner, fakes, default_tenant_id):
    _, headers = owner
    enable_actions(client, headers)
    set_tenant_policy(app, default_tenant_id, auto_approve_low=True)
    principal = Principal(tenant_id=default_tenant_id, role=Role.operator, user_id='agent-user', email='agent@test.local')
    with app.state.db_factory() as session:
        human = await broker.request(session, principal, 'test.fake.low', {'target': 'one'}, 'human asks', settings=app.state.settings)
        agent = await broker.request(session, principal, 'test.fake.low', {'target': 'one'}, 'agent asks', agent_run_id='run-123', settings=app.state.settings)
        session.commit()
        assert human.status == 'auto_approved'
        assert agent.status == 'pending' and agent.required_approvals == 1 and agent.agent_run_id == 'run-123'
        assert any('agent' in r for r in loads(agent.policy_json)['reasons'])
    listing = client.get('/api/v1/actions/requests?agent_only=true', headers=headers).json()['items']
    assert [r['id'] for r in listing] == [agent.id] and listing[0]['agent_originated'] is True


@pytest.mark.asyncio
async def test_propose_action_tool_creates_pending_request(app, client, owner, fakes, default_tenant_id):
    """The agents' propose_action tool reaches the broker and only ever creates a pending request."""
    from app.agents.tools import actions as tool_module
    from app.agents.tools.registry import ToolContext

    _, headers = owner
    enable_actions(client, headers)
    principal = Principal(tenant_id=default_tenant_id, role=Role.operator, user_id='agent-user', email='agent@test.local')
    with app.state.db_factory() as session:
        ctx = ToolContext(db=session, principal=principal, settings=app.state.settings, run_id='run-9', spec_name='investigate', app=app)
        result = await tool_module.propose_action.invoke({'action_type': 'test.fake.medium', 'params': {'target': 'srv-7'}, 'reason': 'evidence e1'}, ctx)
        session.commit()
    assert result['created'] is True and result['status'] == 'pending'
    detail = client.get(f'/api/v1/actions/requests/{result["request_id"]}', headers=headers).json()
    assert detail['agent_run_id'] == 'run-9' and detail['status'] == 'pending'
    assert not any(c[0] == 'execute' for c in fakes['test.fake.medium'].calls)


# ---------------------------------------------------------------- permissions and cross-tenant isolation


def test_permissions(app, client, make_user, owner, fakes):
    oc, oh = owner
    enable_actions(oc, oh)
    make_user('viewer@test.local', PW, 'viewer')
    make_user('an@test.local', PW, 'analyst')
    make_user('op@test.local', PW, 'operator')
    viewer, vh = as_user(app, 'viewer@test.local', PW)
    analyst, ah = as_user(app, 'an@test.local', PW)
    op, oph = as_user(app, 'op@test.local', PW)
    assert viewer.get('/api/v1/actions/catalog', headers=vh).status_code == 200
    assert viewer.post('/api/v1/actions/requests', json={'action_type': 'test.fake.medium', 'params': {'target': 'x'}, 'reason': 'r'}, headers=vh).status_code == 403
    assert analyst.post('/api/v1/actions/requests', json={'action_type': 'test.fake.medium', 'params': {'target': 'x'}, 'reason': 'r'}, headers=ah).status_code == 403
    rid = make_request(op, oph, action_type='test.fake.medium')['id']
    assert analyst.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=ah).status_code == 403
    assert viewer.post(f'/api/v1/actions/requests/{rid}/execute', headers=vh).status_code == 403
    assert viewer.get(f'/api/v1/actions/requests/{rid}', headers=vh).status_code == 200
    assert TestClient(app).get('/api/v1/actions/requests').status_code == 401


def test_cross_tenant_isolation_on_every_endpoint(app, owner, make_user, second_tenant, fakes):
    client, headers = owner
    enable_actions(client, headers)
    make_user('op1@test.local', PW, 'operator')
    op1, h1 = as_user(app, 'op1@test.local', PW)
    rid = make_request(op1, h1, action_type='test.fake.medium')['id']
    client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=headers)
    accepted = client.post(f'/api/v1/actions/requests/{rid}/execute', headers=headers).json()
    wait_job(client, headers, accepted['job_id'])
    run_id = accepted['run']['id']
    other, oh = second_tenant['client'], second_tenant['headers']
    assert other.get('/api/v1/actions/requests', headers=oh).json()['items'] == []
    assert other.get('/api/v1/actions/runs', headers=oh).json()['items'] == []
    assert other.get(f'/api/v1/actions/requests/{rid}', headers=oh).status_code == 404
    assert other.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=oh).status_code == 404
    assert other.post(f'/api/v1/actions/requests/{rid}/execute', headers=oh).status_code == 404
    assert other.post(f'/api/v1/actions/requests/{rid}/cancel', headers=oh).status_code == 404
    assert other.get(f'/api/v1/actions/runs/{run_id}', headers=oh).status_code == 404
    assert other.post(f'/api/v1/actions/runs/{run_id}/rollback', headers=oh).status_code == 404
    # kill switch state is per tenant: enabling the default tenant did nothing for acme
    assert other.get('/api/v1/actions/kill-switch', headers=oh).json()['actions_enabled'] is False
    other.post('/api/v1/actions/kill-switch', json={'enabled': False}, headers=oh)
    theirs = other.post('/api/v1/actions/requests', json={'action_type': 'test.fake.medium', 'params': {'target': 'acme'}, 'reason': 'r'}, headers=oh)
    assert theirs.status_code == 201
    assert theirs.json()['id'] not in {r['id'] for r in client.get('/api/v1/actions/requests', headers=headers).json()['items']}
    # the second tenant's job cannot touch the first tenant's rows
    with app.state.db_factory() as session:
        rows = session.execute(select(ActionRequest).where(ActionRequest.tenant_id == second_tenant['tenant_id'])).scalars().all()
        assert [r.id for r in rows] == [theirs.json()['id']]


def test_api_key_can_request_and_counts_as_distinct_actor(app, owner, api_key, make_user, fakes):
    client, headers = owner
    enable_actions(client, headers)
    key_headers = {'X-API-Key': api_key}
    created = client.post('/api/v1/actions/requests', json={'action_type': 'test.fake.medium', 'params': {'target': 'k'}, 'reason': 'r'}, headers=key_headers)
    assert created.status_code == 201 and created.json()['requested_by'].startswith('api_key:')
    rid = created.json()['id']
    assert client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=key_headers).status_code == 403  # self
    # The key was minted by the owner, so the owner is the same human as the requester and cannot approve either (security review).
    assert client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=headers).status_code == 403
    make_user('op9@test.local', PW, 'operator')
    op9, h9 = as_user(app, 'op9@test.local', PW)
    assert op9.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=h9).json()['status'] == 'approved'


def test_irreversible_action_has_no_rollback(app, owner, make_user, fakes):
    client, headers = owner
    enable_actions(client, headers)
    make_user('op1@test.local', PW, 'operator')
    make_user('op2@test.local', PW, 'operator')
    op1, h1 = as_user(app, 'op1@test.local', PW)
    op2, h2 = as_user(app, 'op2@test.local', PW)
    rid = make_request(op1, h1, action_type='test.fake.irreversible')['id']
    op2.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=h2)
    client.post(f'/api/v1/actions/requests/{rid}/approve', json={'decision': 'approve'}, headers=headers)
    accepted = client.post(f'/api/v1/actions/requests/{rid}/execute', headers=headers).json()
    wait_job(client, headers, accepted['job_id'])
    run = client.get(f'/api/v1/actions/runs/{accepted["run"]["id"]}', headers=headers).json()
    assert run['status'] == 'executed' and run['has_rollback_payload'] is False
    resp = client.post(f'/api/v1/actions/runs/{run["id"]}/rollback', headers=headers)
    assert resp.status_code == 409 and 'not reversible' in resp.json()['detail']
