"""Data retention: preview, tenant overrides, pruning that spares live rows and other tenants, audit, access."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select

from app.models import AuditEntry, Base, Tenant, uid, utcnow
from app.ops import retention
from conftest import wait_job

OLD = utcnow() - timedelta(days=400)
RECENT = utcnow() - timedelta(days=2)


def _insert(db, table: str, **values) -> str:
    values.setdefault('id', uid())
    db.execute(Base.metadata.tables[table].insert().values(**values))
    return values['id']


def _count(db, table: str, tenant_id: str, **where) -> int:
    t = Base.metadata.tables[table]
    query = select(func.count()).select_from(t).where(t.c.tenant_id == tenant_id)
    for column, value in where.items():
        query = query.where(t.c[column] == value)
    return db.execute(query).scalar()


def _seed(db, tenant_id: str) -> None:
    for i, when in enumerate([OLD, OLD, OLD, RECENT]):
        _insert(db, 'events', tenant_id=tenant_id, source='netflow', external_id=f'{tenant_id}-e{i}', title='conn', received_at=when)
    _insert(db, 'detections', tenant_id=tenant_id, rule_id='r', fingerprint=f'{tenant_id}-d1', title='old resolved', status='resolved', last_seen_at=OLD)
    _insert(db, 'detections', tenant_id=tenant_id, rule_id='r', fingerprint=f'{tenant_id}-d2', title='old open', status='open', last_seen_at=OLD)
    run = _insert(db, 'agent_runs', tenant_id=tenant_id, spec='triage', task='t', status='completed', finished_at=OLD)
    for i in range(3):
        _insert(db, 'agent_steps', run_id=run, index=i, kind='model')
    _insert(db, 'agent_runs', tenant_id=tenant_id, spec='triage', task='still running', status='running')
    integration = _insert(db, 'integration_configs', tenant_id=tenant_id, name='hook', kind='webhook')
    _insert(db, 'webhook_deliveries', tenant_id=tenant_id, integration_id=integration, topic='x', status='sent', created_at=OLD)
    _insert(db, 'webhook_deliveries', tenant_id=tenant_id, integration_id=integration, topic='x', status='queued', created_at=OLD)
    _insert(db, 'detection_runs', tenant_id=tenant_id, since=OLD, started_at=OLD, finished_at=OLD)
    db.commit()


def test_preview_run_and_tenant_override(owner, second_tenant, db, default_tenant_id):
    client, headers = owner
    _seed(db, default_tenant_id)
    _seed(db, second_tenant['tenant_id'])

    state = client.get('/api/v1/retention', headers=headers).json()
    due = {p['key']: p['due'] for p in state['policies']}
    assert state['scheduled'] is False and state['last_run_at'] is None
    assert due['events_days'] == 3 and due['detections_days'] == 1 and due['agent_runs_days'] == 1
    assert due['deliveries_days'] == 1 and due['runs_days'] == 1

    # The second tenant keeps events forever and agent runs for longer than the seed's age.
    other = second_tenant
    r = other['client'].put('/api/v1/retention', json={'overrides': {'events_days': 0, 'agent_runs_days': 1000}}, headers=other['headers'])
    assert r.status_code == 200, r.text
    policies = {p['key']: p for p in r.json()['policies']}
    assert policies['events_days']['days'] == 0 and policies['events_days']['overridden'] and policies['events_days']['due'] == 0

    run = client.post('/api/v1/retention/run', headers=headers)
    assert run.status_code == 202, run.text
    job = wait_job(client, headers, run.json()['job_id'])
    assert job['status'] == 'completed', job
    assert job['result']['deleted'] == {'events': 3, 'detections': 1, 'agent_runs': 1, 'webhook_deliveries': 1, 'detection_runs': 1}

    db.expire_all()
    me = default_tenant_id
    assert _count(db, 'events', me) == 1
    assert _count(db, 'detections', me) == 1 and _count(db, 'detections', me, status='open') == 1
    assert _count(db, 'agent_runs', me) == 1 and _count(db, 'agent_runs', me, status='running') == 1
    steps = Base.metadata.tables['agent_steps']
    assert db.execute(select(func.count()).select_from(steps)).scalar() == 3  # only the other tenant's run is left
    assert _count(db, 'webhook_deliveries', me) == 1 and _count(db, 'webhook_deliveries', me, status='queued') == 1
    # Nothing in the other tenant was touched by this tenant's run.
    assert _count(db, 'events', other['tenant_id']) == 4 and _count(db, 'agent_runs', other['tenant_id']) == 2

    audit = db.execute(select(AuditEntry).where(AuditEntry.tenant_id == me, AuditEntry.action == 'retention.pruned')).scalar_one()
    assert '"rows":7' in audit.detail
    assert client.get('/api/v1/retention', headers=headers).json()['last_run_at']

    # The other tenant's own run honours its overrides.
    job = wait_job(other['client'], other['headers'], other['client'].post('/api/v1/retention/run', headers=other['headers']).json()['job_id'])
    assert job['result']['deleted'] == {'detections': 1, 'webhook_deliveries': 1, 'detection_runs': 1}
    db.expire_all()
    assert _count(db, 'events', other['tenant_id']) == 4 and _count(db, 'agent_runs', other['tenant_id']) == 2


def test_overrides_are_validated_and_removable(owner, db, default_tenant_id):
    client, headers = owner
    assert client.put('/api/v1/retention', json={'overrides': {'nope_days': 5}}, headers=headers).status_code == 422
    assert client.put('/api/v1/retention', json={'overrides': {'events_days': 99999}}, headers=headers).status_code == 422
    assert client.put('/api/v1/retention', json={'overrides': {'events_days': -1}}, headers=headers).status_code == 422
    assert client.put('/api/v1/retention', json={'overrides': {'events_days': 7}}, headers=headers).status_code == 200
    r = client.put('/api/v1/retention', json={'overrides': {'events_days': None}}, headers=headers)
    events = next(p for p in r.json()['policies'] if p['key'] == 'events_days')
    assert events['days'] == events['default_days'] == 90 and not events['overridden']
    db.expire_all()
    actions = list(db.execute(select(AuditEntry.action).where(AuditEntry.action == 'retention.policy_updated')).scalars())
    assert len(actions) == 2


def test_retention_needs_admin_settings(api_key, client):
    auth = {'Authorization': f'Bearer {api_key}'}  # operator
    assert client.get('/api/v1/retention', headers=auth).status_code == 403
    assert client.post('/api/v1/retention/run', headers=auth).status_code == 403


def test_batches_commit_and_finish(app, db, default_tenant_id):
    for i in range(23):
        _insert(db, 'events', tenant_id=default_tenant_id, source='s', external_id=f'b{i}', title='t', received_at=OLD)
    db.commit()
    deleted = retention.prune(app.state.db_factory, app.state.settings, default_tenant_id, batch=5)
    assert deleted == {'events': 23}
    db.expire_all()
    assert _count(db, 'events', default_tenant_id) == 0


def test_zero_keeps_forever(app, db, default_tenant_id):
    _insert(db, 'events', tenant_id=default_tenant_id, source='s', external_id='z', title='t', received_at=OLD)
    db.commit()
    tenant = db.get(Tenant, default_tenant_id)
    retention.set_overrides(db, tenant, {key: 0 for key in retention.KEYS})
    db.commit()
    assert retention.prune(app.state.db_factory, app.state.settings, default_tenant_id) == {}
