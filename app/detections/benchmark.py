"""Repeatable detection benchmark runner measuring recall, precision, false-positive rate,
time-to-detect, and coverage across rule categories and MITRE ATT&CK techniques."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.findings import EventDraft, upsert_event
from ..models.detections import Detection
from .engine import run as run_detections


@dataclass
class BenchmarkScenario:
    id: str
    category: str
    technique: str
    expected_rule: str | None  # None = benign activity (must not trigger any alert)
    events: list[dict[str, Any]] = field(default_factory=list)


def default_scenarios(now: datetime | None = None) -> list[BenchmarkScenario]:
    t0 = (now or datetime.now(UTC).replace(microsecond=0)) - timedelta(minutes=15)
    return [
        BenchmarkScenario(
            id='attack_cloud_public_s3',
            category='cloud',
            technique='T1530',
            expected_rule='cloud.public_exposure_change',
            events=[
                {
                    'source': 'aws.cloudtrail',
                    'external_id': 'bench-attack-1',
                    'actor': 'arn:aws:iam::123456789012:user/compromised-ops',
                    'action': 's3.put_bucket_policy',
                    'entity': 'arn:aws:s3:::prod-customer-exports',
                    'category': 'cloud',
                    'severity': 'high',
                    'occurred_at': t0,
                    'metadata': {'policy': {'Principal': '*'}, 'region': 'us-east-1'},
                }
            ],
        ),
        BenchmarkScenario(
            id='attack_identity_privesc_chain',
            category='identity',
            technique='T1098',
            expected_rule='identity.privilege_escalation_chain',
            events=[
                {
                    'source': 'aws.cloudtrail',
                    'external_id': 'bench-attack-2a',
                    'actor': 'svc-deploy@corp.example',
                    'action': 'sts.assume_role',
                    'entity': 'arn:aws:iam::123456789012:role/deploy',
                    'category': 'identity',
                    'severity': 'medium',
                    'occurred_at': t0,
                    'metadata': {'source_ip': '198.51.100.44'},
                },
                {
                    'source': 'aws.cloudtrail',
                    'external_id': 'bench-attack-2b',
                    'actor': 'svc-deploy@corp.example',
                    'action': 'iam.attach_role_policy',
                    'entity': 'arn:aws:iam::123456789012:role/deploy',
                    'category': 'identity',
                    'severity': 'high',
                    'occurred_at': t0 + timedelta(seconds=20),
                    'metadata': {'source_ip': '198.51.100.44'},
                },
                {
                    'source': 'aws.cloudtrail',
                    'external_id': 'bench-attack-2c',
                    'actor': 'svc-deploy@corp.example',
                    'action': 'secretsmanager.get_secret_value',
                    'entity': 'prod/db/master',
                    'category': 'data_access',
                    'severity': 'high',
                    'occurred_at': t0 + timedelta(seconds=45),
                    'metadata': {'source_ip': '198.51.100.44'},
                },
            ],
        ),
        BenchmarkScenario(
            id='attack_cross_source_lateral_chain',
            category='agentic',
            technique='T1078',
            expected_rule='agentic.cross_source_attack_chain',
            events=[
                {
                    'source': 'okta.system_log',
                    'external_id': 'bench-attack-3a',
                    'actor': 'contractor@corp.example',
                    'action': 'user.session.login',
                    'entity': 'okta:contractor',
                    'category': 'auth',
                    'severity': 'low',
                    'occurred_at': t0,
                    'metadata': {},
                },
                {
                    'source': 'aws.cloudtrail',
                    'external_id': 'bench-attack-3b',
                    'actor': 'contractor@corp.example',
                    'action': 'iam.grant_permission',
                    'entity': 'role:analytics-admin',
                    'category': 'identity',
                    'severity': 'high',
                    'occurred_at': t0 + timedelta(seconds=30),
                    'metadata': {},
                },
                {
                    'source': 'snowflake.query_history',
                    'external_id': 'bench-attack-3c',
                    'actor': 'contractor@corp.example',
                    'action': 'db.export_table',
                    'entity': 'customers_pii',
                    'category': 'data',
                    'severity': 'high',
                    'occurred_at': t0 + timedelta(seconds=60),
                    'metadata': {},
                },
            ],
        ),
        BenchmarkScenario(
            id='benign_private_s3_encryption_update',
            category='cloud',
            technique='BENIGN',
            expected_rule=None,
            events=[
                {
                    'source': 'aws.cloudtrail',
                    'external_id': 'bench-benign-1',
                    'actor': 'arn:aws:iam::123456789012:user/platform-terraform',
                    'action': 's3.put_bucket_policy',
                    'entity': 'arn:aws:s3:::internal-logs-private',
                    'category': 'cloud',
                    'severity': 'low',
                    'occurred_at': t0,
                    'metadata': {'policy': '{"Principal": {"AWS": "123456789012"}}', 'region': 'us-east-1'},
                }
            ],
        ),
        BenchmarkScenario(
            id='benign_routine_login_and_read',
            category='identity',
            technique='BENIGN',
            expected_rule=None,
            events=[
                {
                    'source': 'okta.system_log',
                    'external_id': 'bench-benign-2',
                    'actor': 'analyst@corp.example',
                    'action': 'user.session.login',
                    'entity': 'okta:analyst',
                    'category': 'auth',
                    'severity': 'low',
                    'occurred_at': t0,
                    'metadata': {'country': 'US'},
                }
            ],
        ),
        BenchmarkScenario(
            id='attack_cloud_open_security_group_ssh',
            category='cloud',
            technique='T1530',
            expected_rule='cloud.public_exposure_change',
            events=[
                {
                    'source': 'aws.cloudtrail',
                    'external_id': 'bench-attack-4',
                    'actor': 'arn:aws:iam::123456789012:user/compromised-netops',
                    'action': 'ec2.authorize_security_group_ingress',
                    'entity': 'sg-0abc1234def567890',
                    'category': 'cloud_api',
                    'severity': 'high',
                    'occurred_at': t0,
                    'metadata': {'cidr': '0.0.0.0/0', 'port': 22, 'region': 'us-west-2'},
                }
            ],
        ),
        BenchmarkScenario(
            id='attack_identity_impossible_travel_okta',
            category='identity',
            technique='T1078',
            expected_rule='identity.impossible_velocity',
            events=[
                {
                    'source': 'okta.system_log',
                    'external_id': 'bench-attack-5a',
                    'actor': 'exec@corp.example',
                    'action': 'auth.login',
                    'entity': 'okta:exec',
                    'category': 'auth',
                    'severity': 'medium',
                    'occurred_at': t0,
                    'metadata': {'src_ip': '198.51.100.10', 'geo': {'lat': 37.77, 'lon': -122.41, 'country': 'US'}},
                },
                {
                    'source': 'okta.system_log',
                    'external_id': 'bench-attack-5b',
                    'actor': 'exec@corp.example',
                    'action': 'auth.login',
                    'entity': 'okta:exec',
                    'category': 'auth',
                    'severity': 'high',
                    'occurred_at': t0 + timedelta(minutes=8),
                    'metadata': {'src_ip': '203.0.113.88', 'geo': {'lat': 35.68, 'lon': 139.69, 'country': 'JP'}},
                },
            ],
        ),
        BenchmarkScenario(
            id='attack_identity_iam_user_policy_privesc',
            category='identity',
            technique='T1098',
            expected_rule='identity.privilege_escalation_chain',
            events=[
                {
                    'source': 'aws.cloudtrail',
                    'external_id': 'bench-attack-6a',
                    'actor': 'dev-temp@corp.example',
                    'action': 'sts.assume_role',
                    'entity': 'arn:aws:iam::123456789012:role/ci-runner',
                    'category': 'identity',
                    'severity': 'medium',
                    'occurred_at': t0,
                    'metadata': {'source_ip': '198.51.100.77'},
                },
                {
                    'source': 'aws.cloudtrail',
                    'external_id': 'bench-attack-6b',
                    'actor': 'dev-temp@corp.example',
                    'action': 'iam.attach_user_policy',
                    'entity': 'arn:aws:iam::123456789012:user/dev-temp',
                    'category': 'identity',
                    'severity': 'high',
                    'occurred_at': t0 + timedelta(seconds=15),
                    'metadata': {'source_ip': '198.51.100.77'},
                },
                {
                    'source': 'aws.cloudtrail',
                    'external_id': 'bench-attack-6c',
                    'actor': 'dev-temp@corp.example',
                    'action': 's3.get_object',
                    'entity': 'bucket:prod-payroll-vault',
                    'category': 'data_access',
                    'severity': 'high',
                    'occurred_at': t0 + timedelta(seconds=40),
                    'metadata': {'source_ip': '198.51.100.77'},
                },
            ],
        ),
        BenchmarkScenario(
            id='benign_zeek_internal_dns_lookup',
            category='network',
            technique='BENIGN',
            expected_rule=None,
            events=[
                {
                    'source': 'zeek.dns',
                    'external_id': 'bench-benign-3',
                    'actor': 'host:10.10.4.21',
                    'action': 'dns.query',
                    'entity': 'internal.corp.example',
                    'category': 'network',
                    'severity': 'low',
                    'occurred_at': t0,
                    'metadata': {'qtype': 'A', 'rcode': 'NOERROR', 'proto': 'udp'},
                }
            ],
        ),
        BenchmarkScenario(
            id='benign_zeek_routine_https_egress',
            category='network',
            technique='BENIGN',
            expected_rule=None,
            events=[
                {
                    'source': 'zeek.conn',
                    'external_id': 'bench-benign-4',
                    'actor': 'host:10.10.4.22',
                    'action': 'net.connection',
                    'entity': '198.51.100.200:443',
                    'category': 'network',
                    'severity': 'low',
                    'occurred_at': t0,
                    'metadata': {'service': 'ssl', 'orig_bytes': 1240, 'resp_bytes': 4820},
                }
            ],
        ),
        BenchmarkScenario(
            id='benign_okta_same_city_session_refresh',
            category='identity',
            technique='BENIGN',
            expected_rule=None,
            events=[
                {
                    'source': 'okta.system_log',
                    'external_id': 'bench-benign-5a',
                    'actor': 'sre@corp.example',
                    'action': 'auth.login',
                    'entity': 'okta:sre',
                    'category': 'auth',
                    'severity': 'low',
                    'occurred_at': t0,
                    'metadata': {'src_ip': '198.51.100.12', 'geo': {'lat': 40.71, 'lon': -74.00, 'country': 'US'}},
                },
                {
                    'source': 'okta.system_log',
                    'external_id': 'bench-benign-5b',
                    'actor': 'sre@corp.example',
                    'action': 'auth.login',
                    'entity': 'okta:sre',
                    'category': 'auth',
                    'severity': 'low',
                    'occurred_at': t0 + timedelta(minutes=12),
                    'metadata': {'src_ip': '198.51.100.13', 'geo': {'lat': 40.73, 'lon': -73.99, 'country': 'US'}},
                },
            ],
        ),
        BenchmarkScenario(
            id='benign_cloudtrail_readonly_describe',
            category='cloud',
            technique='BENIGN',
            expected_rule=None,
            events=[
                {
                    'source': 'aws.cloudtrail',
                    'external_id': 'bench-benign-6',
                    'actor': 'arn:aws:iam::123456789012:role/monitoring-readonly',
                    'action': 'ec2.describe_instances',
                    'entity': 'region:us-east-1',
                    'category': 'cloud_api',
                    'severity': 'low',
                    'occurred_at': t0,
                    'metadata': {'region': 'us-east-1'},
                }
            ],
        ),
    ]


def run_benchmark(db: Session, tenant_id: str, scenarios: list[BenchmarkScenario] | None = None) -> dict[str, Any]:
    """Evaluate each labeled scenario in an isolated, rolled-back savepoint.

    Unlike a rule-union score, an alert for scenario A cannot count as a hit
    for scenario B. Benchmark events and detections never persist in customer
    data; results are smoke-test evidence, not production attack coverage.
    """
    now = datetime.now(UTC).replace(microsecond=0)
    suite = scenarios if scenarios is not None else default_scenarios(now)
    seen_ids: set[str] = set()
    case_results: list[dict[str, Any]] = []
    total_latency = 0.0
    engine_summaries: list[dict[str, Any]] = []
    true_positives = false_negatives = false_positives = 0
    by_category: dict[str, dict[str, int]] = {}

    for sc in suite:
        if sc.id in seen_ids:
            raise ValueError(f'duplicate scenario id {sc.id}')
        seen_ids.add(sc.id)
        # A nested transaction protects the calling tenant even when it already
        # has legitimate security data and lets each scenario run separately.
        tx = db.begin_nested()
        try:
            for ev in sc.events:
                draft = EventDraft(
                    source=ev['source'],
                    external_id=ev['external_id'],
                    title=ev.get('title') or f"{ev.get('actor', '')} {ev.get('action', '')} {ev.get('entity', '')}",
                    severity=ev.get('severity', 'low'),
                    category=ev.get('category', ''),
                    actor=ev.get('actor', ''),
                    entity=ev.get('entity', ''),
                    action=ev.get('action', ''),
                    occurred_at=ev.get('occurred_at') or now,
                    metadata=ev.get('metadata') or {},
                )
                upsert_event(db, tenant_id, draft)
            db.flush()
            existing_ids = set(db.execute(select(Detection.id).where(Detection.tenant_id == tenant_id)).scalars())
            started = time.perf_counter()
            summary = run_detections(db, tenant_id, now=now, trigger='benchmark')
            latency = round((time.perf_counter() - started) * 1000, 2)
            total_latency += latency
            engine_summaries.append(summary)
            observed = list(db.execute(select(Detection).where(
                Detection.tenant_id == tenant_id, Detection.id.notin_(existing_ids)
            )).scalars())
            rules = {row.rule_id for row in observed}
            matched = sc.expected_rule in rules if sc.expected_rule else False
            if sc.expected_rule:
                category = by_category.setdefault(sc.category, {'total': 0, 'detected': 0})
                category['total'] += 1
                if matched:
                    true_positives += 1
                    category['detected'] += 1
                else:
                    false_negatives += 1
            else:
                false_positives += len(observed)
            case_results.append({'id': sc.id, 'category': sc.category, 'technique': sc.technique,
                                 'expected_rule': sc.expected_rule, 'fired_rules': sorted(rules),
                                 'detected': matched, 'alerts': len(observed), 'engine_latency_ms': latency})
        finally:
            tx.rollback()
            db.expire_all()

    attacks = sum(s.expected_rule is not None for s in suite)
    benign = len(suite) - attacks
    return {
        'scenarios_total': len(suite),
        'attack_scenarios': attacks,
        'benign_scenarios': benign,
        'true_positives': true_positives,
        'false_negatives': false_negatives,
        'false_positives': false_positives,
        'recall': round(true_positives / max(1, attacks), 4),
        'precision': round(true_positives / max(1, true_positives + false_positives), 4),
        'false_positive_rate': round(false_positives / max(1, benign), 4),
        'time_to_detect_ms': round(total_latency, 2),  # engine execution time, not real-world detection latency
        'techniques_covered': sorted({case['technique'] for case in case_results if case['detected']}),
        'by_category': by_category,
        'scenario_results': case_results,
        'engine_summary': {'runs': engine_summaries},
    }
