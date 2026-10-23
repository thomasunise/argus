"""Engine and rule tests: synthesized event histories trigger each rule once and stay quiet on a
negative case; dedupe, baselines, rule state and canary tripwire are covered directly."""
from __future__ import annotations

import json
import statistics
from datetime import datetime, timedelta, timezone

import pytest

from app.core.findings import EventDraft, upsert_event
from app.detections import canaries as canary_svc
from app.detections.engine import (DetectionDraft, RuleContext, registry, run, update_baselines, validate_params, welford_update)
from app.models import Finding, dumps
from app.models.detections import Baseline, CanaryHit, Detection, DetectionRuleState, DetectionRun

NOW = datetime.now(timezone.utc).replace(microsecond=0)
T0 = NOW - timedelta(minutes=20)  # inside the default 60-minute lookback


def mk(db, tenant_id, n, *, actor='', action='', entity='', at=None, category='', source='synthetic', metadata=None, asset_id=None,
       severity='low', title=''):
    draft = EventDraft(source=source, external_id=f'{source}-{n}', title=title or f'{actor} {action} {entity}', severity=severity, category=category,
                       actor=actor, entity=entity, action=action, asset_id=asset_id, occurred_at=at or T0, metadata=metadata or {})
    event, _ = upsert_event(db, tenant_id, draft)
    return event


def detections_for(db, tenant_id, rule_id):
    return db.query(Detection).filter(Detection.tenant_id == tenant_id, Detection.rule_id == rule_id).all()


def run_rule(db, tenant_id, rule_id):
    result = run(db, tenant_id, rule_ids=[rule_id], now=NOW)
    assert not result['errors'], result['errors']
    return result, detections_for(db, tenant_id, rule_id)


# ---------------------------------------------------------------- registry and params


def test_registry_has_all_rules_with_categories():
    ids = registry.ids()
    for expected in ['swarm.coordinated_identity_fanout', 'swarm.novel_action_burst', 'swarm.synchronized_multi_asset_access',
                     'swarm.machine_speed_sequence', 'identity.impossible_velocity', 'identity.privilege_escalation_chain', 'canary.tripwire',
                     'anomaly.rate_spike', 'cloud.public_exposure_change', 'k8s.privileged_workload', 'code.secret_committed',
                     'agentic.tool_abuse_pattern']:
        assert expected in ids
    for rule in registry.all():
        assert rule.id.split('.')[0] == rule.category and rule.default_params and rule.description


def test_validate_params_rejects_unknown_and_wrong_types():
    rule = registry.get('swarm.coordinated_identity_fanout')
    assert validate_params(rule, {'min_actors': 3, 'baseline_sigma': 2}) == {'min_actors': 3, 'baseline_sigma': 2.0}
    with pytest.raises(ValueError):
        validate_params(rule, {'nope': 1})
    with pytest.raises(ValueError):
        validate_params(rule, {'min_actors': 'ten'})
    with pytest.raises(ValueError):
        validate_params(rule, {'ignore_actions': [1, 2]})


# ---------------------------------------------------------------- swarm rules


def test_coordinated_identity_fanout(db, default_tenant_id):
    tid = default_tenant_id
    for i in range(12):  # 12 distinct actors, same action and entity class, inside 5 minutes
        mk(db, tid, i, actor=f'user{i}', action='s3.get_object', entity=f'bucket:data-{i % 3}', at=T0 + timedelta(seconds=10 * i))
    result, found = run_rule(db, tid, 'swarm.coordinated_identity_fanout')
    assert result['detections_created'] == 1 and len(found) == 1
    d = found[0]
    assert d.severity == 'high' and d.entity == 's3.get_object on bucket' and d.entity_kind == 'action'
    evidence = json.loads(d.evidence_json)
    assert evidence['distinct_actors'] == 12 and len(evidence['event_ids']) == 12 and evidence['actors_sample']
    assert d.finding_id and db.get(Finding, d.finding_id).source == 'detection'


def test_coordinated_identity_fanout_negative_few_actors_or_normal_baseline(db, default_tenant_id):
    tid = default_tenant_id
    for i in range(6):
        mk(db, tid, i, actor=f'user{i}', action='s3.get_object', entity='bucket:data', at=T0 + timedelta(seconds=i))
    _, found = run_rule(db, tid, 'swarm.coordinated_identity_fanout')
    assert found == []
    # 12 actors but the action has a mature baseline that covers this volume: normal fan-out (e.g. a login page).
    for i in range(12):
        mk(db, tid, 100 + i, actor=f'login{i}', action='auth.login', entity='idp:okta', at=T0 + timedelta(seconds=i))
    db.add(Baseline(tenant_id=tid, dimension='action_rate', key='auth.login', window_minutes=5, mean=40.0, variance=25.0, samples=50))
    db.flush()
    _, found = run_rule(db, tid, 'swarm.coordinated_identity_fanout')
    assert found == []


def test_novel_action_burst(db, default_tenant_id):
    tid = default_tenant_id
    history = T0 - timedelta(days=2)
    for i, action in enumerate(['iam.list_users', 'iam.list_roles']):  # known actions for alice
        mk(db, tid, 1000 + i, actor='alice', action=action, entity='acct', at=history)
    for i, action in enumerate(['iam.list_users', 'sts.get_caller_identity', 'ec2.describe_instances', 'secretsmanager.list_secrets',
                                'lambda.list_functions', 'kms.list_keys', 'rds.describe_db_instances']):
        mk(db, tid, i, actor='alice', action=action, entity='acct', at=T0 + timedelta(seconds=20 * i))
    result, found = run_rule(db, tid, 'swarm.novel_action_burst')
    assert len(found) == 1 and found[0].entity == 'alice' and found[0].entity_kind == 'identity'
    assert json.loads(found[0].evidence_json)['novel_actions'] == 6  # iam.list_users was already known


def test_novel_action_burst_negative_known_actions(db, default_tenant_id):
    tid = default_tenant_id
    actions = ['a.one', 'a.two', 'a.three', 'a.four', 'a.five', 'a.six']
    for i, action in enumerate(actions):
        mk(db, tid, 1000 + i, actor='bob', action=action, entity='x', at=T0 - timedelta(days=1))
    for i, action in enumerate(actions):
        mk(db, tid, i, actor='bob', action=action, entity='x', at=T0 + timedelta(seconds=i))
    _, found = run_rule(db, tid, 'swarm.novel_action_burst')
    assert found == []


def test_synchronized_multi_asset_access(db, default_tenant_id):
    tid = default_tenant_id
    assets = [('bucket:a', 'bucket'), ('db:orders', 'db'), ('bucket:b', 'bucket'), ('host:web-1', 'host'), ('db:users', 'db'), ('bucket:c', 'bucket')]
    for i, (entity, _) in enumerate(assets):
        mk(db, tid, i, actor='svc-x', action='read', entity=entity, at=T0 + timedelta(milliseconds=200 * i))
    _, found = run_rule(db, tid, 'swarm.synchronized_multi_asset_access')
    assert len(found) == 1
    evidence = json.loads(found[0].evidence_json)
    assert evidence['distinct_assets'] == 6 and set(evidence['asset_kinds']) == {'bucket', 'db', 'host'} and evidence['median_gap_ms'] < 1000


def test_synchronized_multi_asset_access_negative_human_pace(db, default_tenant_id):
    tid = default_tenant_id
    for i, entity in enumerate(['bucket:a', 'db:orders', 'bucket:b', 'host:web-1', 'db:users', 'bucket:c']):
        mk(db, tid, i, actor='human', action='read', entity=entity, at=T0 + timedelta(seconds=5 * i))
    _, found = run_rule(db, tid, 'swarm.synchronized_multi_asset_access')
    assert found == []


def test_machine_speed_sequence(db, default_tenant_id):
    tid = default_tenant_id
    for i in range(25):
        mk(db, tid, i, actor='bot', action=f'api.call{i % 4}', entity='svc', at=T0 + timedelta(milliseconds=100 * i))
    _, found = run_rule(db, tid, 'swarm.machine_speed_sequence')
    assert len(found) == 1
    evidence = json.loads(found[0].evidence_json)
    assert evidence['events'] == 25 and evidence['median_gap_ms'] == 100.0


def test_machine_speed_sequence_negative(db, default_tenant_id):
    tid = default_tenant_id
    for i in range(25):
        mk(db, tid, i, actor='person', action='api.call', entity='svc', at=T0 + timedelta(seconds=2 * i))
    _, found = run_rule(db, tid, 'swarm.machine_speed_sequence')
    assert found == []


# ---------------------------------------------------------------- identity rules


def test_impossible_velocity(db, default_tenant_id):
    tid = default_tenant_id
    mk(db, tid, 1, actor='carol', action='auth.login', entity='idp', at=T0, metadata={'src_ip': '203.0.113.5', 'geo': {'lat': 40.71, 'lon': -74.0, 'country': 'US'}})
    mk(db, tid, 2, actor='carol', action='auth.login', entity='idp', at=T0 + timedelta(minutes=10),
       metadata={'src_ip': '198.51.100.9', 'geo': {'lat': 51.5, 'lon': -0.12, 'country': 'GB'}})
    _, found = run_rule(db, tid, 'identity.impossible_velocity')
    assert len(found) == 1 and found[0].entity == 'carol'
    evidence = json.loads(found[0].evidence_json)
    assert evidence['distance_km'] > 5000 and evidence['speed_kmh'] > 900 and evidence['from']['country'] == 'US' and evidence['to']['country'] == 'GB'


def test_impossible_velocity_negative_and_skip_without_geo(db, default_tenant_id):
    tid = default_tenant_id
    mk(db, tid, 1, actor='dave', action='auth.login', entity='idp', at=T0, metadata={'geo': {'lat': 40.71, 'lon': -74.0, 'country': 'US'}})
    mk(db, tid, 2, actor='dave', action='auth.login', entity='idp', at=T0 + timedelta(minutes=10), metadata={'geo': {'lat': 40.73, 'lon': -74.17, 'country': 'US'}})
    mk(db, tid, 3, actor='erin', action='auth.login', entity='idp', at=T0, metadata={'src_ip': '1.1.1.1'})
    mk(db, tid, 4, actor='erin', action='auth.login', entity='idp', at=T0 + timedelta(seconds=1), metadata={'src_ip': '8.8.8.8'})
    _, found = run_rule(db, tid, 'identity.impossible_velocity')
    assert found == []


def test_privilege_escalation_chain(db, default_tenant_id):
    tid = default_tenant_id
    mk(db, tid, 1, actor='frank', action='sts.assume_role', entity='role/Admin', at=T0, metadata={'role': 'Admin'})
    mk(db, tid, 2, actor='frank', action='iam.attach_user_policy', entity='user/frank', at=T0 + timedelta(minutes=3))
    mk(db, tid, 3, actor='frank', action='s3.get_object', entity='bucket:payroll', at=T0 + timedelta(minutes=5))
    _, found = run_rule(db, tid, 'identity.privilege_escalation_chain')
    assert len(found) == 1 and found[0].severity == 'critical' and found[0].entity == 'frank'
    chain = json.loads(found[0].evidence_json)['chain']
    assert [c['stage'] for c in chain] == ['assume', 'grant', 'access']


def test_privilege_escalation_chain_negative_missing_stage_or_out_of_window(db, default_tenant_id):
    tid = default_tenant_id
    mk(db, tid, 1, actor='gina', action='iam.attach_user_policy', entity='user/gina', at=T0)
    mk(db, tid, 2, actor='gina', action='s3.get_object', entity='bucket:x', at=T0 + timedelta(minutes=1))
    mk(db, tid, 3, actor='hank', action='sts.assume_role', entity='role/Admin', at=T0 - timedelta(minutes=50))
    mk(db, tid, 4, actor='hank', action='iam.attach_user_policy', entity='user/hank', at=T0 + timedelta(minutes=1))
    mk(db, tid, 5, actor='hank', action='s3.get_object', entity='bucket:x', at=T0 + timedelta(minutes=2))
    _, found = run_rule(db, tid, 'identity.privilege_escalation_chain')
    assert found == []


# ---------------------------------------------------------------- canary, anomaly


def test_canary_tripwire(db, default_tenant_id, settings):
    tid = default_tenant_id
    canary = canary_svc.create_canary(db, tid, kind='url', label='finance-share', placement='\\\\fs01\\finance\\README.txt', settings=settings)
    assert canary_svc.record_hit(db, canary, source_ip='203.0.113.77', user_agent='curl/8.0', headers={'Cookie': 'secret', 'Accept': '*/*'},
                                 received_at=NOW - timedelta(minutes=1)) is not None  # inside the rule's horizon even in a long suite run
    _, found = run_rule(db, tid, 'canary.tripwire')
    assert len(found) == 1
    d = found[0]
    evidence = json.loads(d.evidence_json)
    assert d.severity == 'critical' and d.entity == 'finance-share' and d.entity_kind == 'canary'
    assert evidence['source_ips'] == ['203.0.113.77'] and evidence['hits'] == 1
    hit = db.query(CanaryHit).one()
    assert 'cookie' not in hit.headers_json.lower() and 'accept' in hit.headers_json


def test_canary_tripwire_negative_and_revoked(db, default_tenant_id, settings):
    tid = default_tenant_id
    canary = canary_svc.create_canary(db, tid, kind='token', label='quiet', settings=settings)
    canary_svc.revoke_canary(db, canary)
    assert canary_svc.record_hit(db, canary, source_ip='1.2.3.4') is None
    _, found = run_rule(db, tid, 'canary.tripwire')
    assert found == []


def test_rate_spike_against_baseline(db, default_tenant_id):
    tid = default_tenant_id
    db.add(Baseline(tenant_id=tid, dimension='actor_rate', key='noisy', window_minutes=5, mean=2.0, variance=1.0, samples=40))
    db.add(Baseline(tenant_id=tid, dimension='actor_rate', key='young', window_minutes=5, mean=2.0, variance=1.0, samples=5))
    db.flush()
    for i in range(30):
        mk(db, tid, i, actor='noisy', action='api.read', entity='x', at=NOW - timedelta(seconds=10 + i))
        mk(db, tid, 100 + i, actor='young', action='api.read', entity='x', at=NOW - timedelta(seconds=10 + i))
    _, found = run_rule(db, tid, 'anomaly.rate_spike')
    assert len(found) == 1 and found[0].entity == 'noisy'
    evidence = json.loads(found[0].evidence_json)
    assert evidence['count'] == 30 and evidence['threshold'] == 6.0 and evidence['z_score'] == 28.0


def test_rate_spike_negative_within_baseline(db, default_tenant_id):
    tid = default_tenant_id
    db.add(Baseline(tenant_id=tid, dimension='actor_rate', key='steady', window_minutes=5, mean=20.0, variance=16.0, samples=60))
    db.flush()
    for i in range(25):
        mk(db, tid, i, actor='steady', action='api.read', entity='x', at=NOW - timedelta(seconds=10 + i))
    _, found = run_rule(db, tid, 'anomaly.rate_spike')
    assert found == []


# ---------------------------------------------------------------- cloud, k8s, code, agentic


def test_public_exposure_change(db, default_tenant_id):
    tid = default_tenant_id
    policy = {'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': 's3:GetObject'}]}
    mk(db, tid, 1, actor='ops', action='s3.put_bucket_policy', entity='bucket:public-site', category='cloud_api', metadata={'policy': policy, 'region': 'us-east-1'})
    mk(db, tid, 2, actor='ops', action='ec2.authorize_security_group_ingress', entity='sg-123', category='cloud_api', metadata={'cidr': '0.0.0.0/0', 'port': 22})
    mk(db, tid, 3, actor='ops', action='s3.put_bucket_policy', entity='bucket:private', category='cloud_api',
       metadata={'policy': {'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::123456789012:root'}}]}})
    _, found = run_rule(db, tid, 'cloud.public_exposure_change')
    assert {d.entity for d in found} == {'bucket:public-site', 'sg-123'}
    assert all(d.severity == 'high' for d in found)


def test_privileged_workload(db, default_tenant_id):
    tid = default_tenant_id
    mk(db, tid, 1, actor='deployer', action='pod.create', entity='pod/miner', category='k8s',
       metadata={'namespace': 'prod', 'spec': {'hostPID': True, 'containers': [{'image': 'x/miner', 'securityContext': {'privileged': True}}]}})
    mk(db, tid, 2, actor='deployer', action='pod.create', entity='pod/web', category='k8s',
       metadata={'namespace': 'prod', 'spec': {'containers': [{'image': 'x/web', 'securityContext': {'privileged': False}}]}})
    mk(db, tid, 3, actor='deployer', action='pod.create', entity='pod/kube-proxy', category='k8s', metadata={'namespace': 'kube-system', 'spec': {'hostNetwork': True}})
    _, found = run_rule(db, tid, 'k8s.privileged_workload')
    assert len(found) == 1 and found[0].entity == 'pod/miner' and found[0].severity == 'critical'
    assert json.loads(found[0].evidence_json)['flags'] == ['hostPID', 'privileged']


def test_secret_committed_never_stores_the_secret(db, default_tenant_id):
    tid = default_tenant_id
    secret = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD'
    mk(db, tid, 1, actor='dev', action='secret_detected', entity='repo:payments', category='code',
       metadata={'secret_type': 'github_pat', 'file': 'config/.env', 'commit': 'deadbeef', 'match': secret, 'line': 3})
    mk(db, tid, 2, actor='dev', action='lint_warning', entity='repo:payments', category='code', metadata={'rule': 'style'})
    _, found = run_rule(db, tid, 'code.secret_committed')
    assert len(found) == 1 and found[0].severity == 'critical'
    assert secret not in found[0].evidence_json and 'config/.env' in found[0].evidence_json
    finding = db.get(Finding, found[0].finding_id)
    assert secret not in finding.evidence


def test_tool_abuse_pattern(db, default_tenant_id):
    tid = default_tenant_id
    services = ['s3', 'iam', 'ec2', 'lambda']
    for i in range(60):
        mk(db, tid, i, actor='key:AKIA_BOT', action=f'{services[i % 4]}.op{i}', entity='acct', at=T0 + timedelta(seconds=5 * i),
           metadata={'user_agent': 'python-requests/2.31'})
    for i in range(60):
        mk(db, tid, 100 + i, actor='key:HUMAN', action=f'{services[i % 4]}.op{i}', entity='acct', at=T0 + timedelta(seconds=5 * i),
           metadata={'user_agent': 'Mozilla/5.0 (Windows NT 10.0) Chrome/120'})
    _, found = run_rule(db, tid, 'agentic.tool_abuse_pattern')
    assert len(found) == 1 and found[0].entity == 'key:AKIA_BOT'
    evidence = json.loads(found[0].evidence_json)
    assert evidence['distinct_actions'] == 60 and set(evidence['services']) == set(services) and evidence['automated_events'] == 60


# ---------------------------------------------------------------- engine behaviour


def test_dedupe_within_window_and_update_on_new_evidence(db, default_tenant_id):
    tid = default_tenant_id
    for i in range(25):
        mk(db, tid, i, actor='bot', action='api.call', entity='svc', at=T0 + timedelta(milliseconds=100 * i))
    first = run(db, tid, rule_ids=['swarm.machine_speed_sequence'], now=NOW)
    second = run(db, tid, rule_ids=['swarm.machine_speed_sequence'], now=NOW)
    assert first['detections_created'] == 1 and second['detections_created'] == 0 and second['detections_updated'] == 0
    assert second['detections_unchanged'] == 1
    mk(db, tid, 25, actor='bot', action='api.call', entity='svc', at=T0 + timedelta(milliseconds=2500))
    third = run(db, tid, rule_ids=['swarm.machine_speed_sequence'], now=NOW)
    assert third['detections_created'] == 0 and third['detections_updated'] == 1
    d = detections_for(db, tid, 'swarm.machine_speed_sequence')[0]
    assert d.occurrences == 2
    finding = db.get(Finding, d.finding_id)
    assert finding.detection_id == d.id and finding.rule == 'swarm.machine_speed_sequence'
    # A false positive stays suppressed; a resolved detection reopens.
    d.status = 'false_positive'
    db.flush()
    mk(db, tid, 26, actor='bot', action='api.call', entity='svc', at=T0 + timedelta(milliseconds=2600))
    assert run(db, tid, rule_ids=['swarm.machine_speed_sequence'], now=NOW)['detections_suppressed'] == 1
    d.status = 'resolved'
    db.flush()
    mk(db, tid, 27, actor='bot', action='api.call', entity='svc', at=T0 + timedelta(milliseconds=2700))
    run(db, tid, rule_ids=['swarm.machine_speed_sequence'], now=NOW)
    assert db.get(Detection, d.id).status == 'open'
    assert db.query(DetectionRun).filter(DetectionRun.tenant_id == tid).count() == 5


def test_fingerprint_formula():
    import hashlib

    draft = DetectionDraft(rule_id='x.y', title='t', description='d', severity='low', confidence=0.5, entity='bob', entity_kind='identity',
                           fingerprint_parts=['bob'], window_bucket='123')
    assert draft.fingerprint('tenant') == hashlib.sha256(b'tenant|x.y|bob|123').hexdigest()


def test_rule_state_disable_and_param_override(db, default_tenant_id):
    tid = default_tenant_id
    for i in range(5):
        mk(db, tid, i, actor=f'u{i}', action='s3.get_object', entity='bucket:data', at=T0 + timedelta(seconds=i))
    assert run(db, tid, rule_ids=['swarm.coordinated_identity_fanout'], now=NOW)['detections_created'] == 0
    db.add(DetectionRuleState(tenant_id=tid, rule_id='swarm.coordinated_identity_fanout', enabled=True, params_json=dumps({'min_actors': 3})))
    db.flush()
    assert run(db, tid, rule_ids=['swarm.coordinated_identity_fanout'], now=NOW)['detections_created'] == 1
    state = db.query(DetectionRuleState).one()
    state.enabled = False
    db.flush()
    result = run(db, tid, rule_ids=['swarm.coordinated_identity_fanout'], now=NOW)
    assert result['rules_run'] == 0


def test_rule_failure_is_isolated(db, default_tenant_id, monkeypatch):
    tid = default_tenant_id
    rule = registry.get('code.secret_committed')

    def boom(ctx):
        raise RuntimeError('kaboom')

    monkeypatch.setattr(rule, 'evaluate', boom)
    result = run(db, tid, now=NOW)
    assert result['errors'] == [{'rule_id': 'code.secret_committed', 'error': 'RuntimeError: kaboom'}]
    assert result['rules_run'] == len(registry.all())


def test_rule_context_events_are_bounded_and_graph_is_optional(db, default_tenant_id, settings):
    tid = default_tenant_id
    for i in range(10):
        mk(db, tid, i, actor='a', action='x', entity='e', at=T0 + timedelta(seconds=i), category='auth')
    mk(db, tid, 99, actor='a', action='x', entity='e', at=NOW - timedelta(hours=5), category='auth')
    ctx = RuleContext(db, tid, NOW - timedelta(hours=1), NOW, {}, settings, max_events=5)
    assert len(ctx.events()) == 5 and ctx.events_scanned == 5
    assert len(ctx.events(category='nope')) == 0
    assert ctx.graph() is None or hasattr(ctx.graph(), 'upsert_node')


# ---------------------------------------------------------------- baselines


def test_welford_matches_batch_statistics():
    values = [3, 5, 7, 2, 9, 4, 4, 6]
    mean = var = 0.0
    n = 0
    for v in values:
        mean, var, n = welford_update(mean, var, n, float(v))
    assert n == len(values)
    assert mean == pytest.approx(statistics.mean(values)) and var == pytest.approx(statistics.pvariance(values))


def test_update_baselines_rolls_windows_and_is_idempotent(db, default_tenant_id):
    tid = default_tenant_id
    base = NOW.replace(minute=(NOW.minute // 5) * 5, second=0, microsecond=0) - timedelta(minutes=30)
    counts = [3, 5, 7]
    n = 0
    for w, count in enumerate(counts):
        for i in range(count):
            mk(db, tid, n, actor='alice', action=f'act{w}.{i}', entity='thing', at=base + timedelta(minutes=5 * w, seconds=i))
            n += 1
    for w in range(3):
        result = update_baselines(db, tid, now=base + timedelta(minutes=5 * (w + 1), seconds=30))
        assert result['events'] == counts[w]
    actor = db.query(Baseline).filter(Baseline.dimension == 'actor_rate', Baseline.key == 'alice').one()
    assert actor.samples == 3 and actor.mean == pytest.approx(5.0) and actor.variance == pytest.approx(statistics.pvariance(counts))
    novel = db.query(Baseline).filter(Baseline.dimension == 'actor_novel_actions', Baseline.key == 'alice').one()
    assert novel.samples == 3 and novel.last_value == 7.0  # every action name in the last window was new
    entity = db.query(Baseline).filter(Baseline.dimension == 'entity_rate', Baseline.key == 'thing').one()
    assert entity.samples == 3 and entity.mean == pytest.approx(5.0)
    again = update_baselines(db, tid, now=base + timedelta(minutes=15, seconds=30))
    assert again['updated'] == 0 and again['skipped'] >= 3
    # An idle window records a zero sample for known keys, pulling the mean down.
    update_baselines(db, tid, now=base + timedelta(minutes=20, seconds=30))
    db.refresh(actor)
    assert actor.samples == 4 and actor.mean == pytest.approx(3.75) and actor.last_value == 0.0
