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
    ]


def run_benchmark(db: Session, tenant_id: str, scenarios: list[BenchmarkScenario] | None = None) -> dict[str, Any]:
    """Execute the detection benchmark dataset against `tenant_id` and return precision/recall/FPR metrics."""
    now = datetime.now(UTC).replace(microsecond=0)
    suite = scenarios if scenarios is not None else default_scenarios(now)
    for sc in suite:
        for ev in sc.events:
            draft = EventDraft(
                source=ev['source'],
                external_id=ev['external_id'],
                title=ev.get('title') or f"{ev['actor']} {ev['action']} {ev['entity']}",
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

    started = time.perf_counter()
    engine_summary = run_detections(db, tenant_id, now=now, trigger='benchmark')
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

    detections = list(db.execute(select(Detection).where(Detection.tenant_id == tenant_id)).scalars().all())
    fired_rules = {d.rule_id for d in detections}

    attack_scenarios = [s for s in suite if s.expected_rule is not None]
    benign_scenarios = [s for s in suite if s.expected_rule is None]
    benign_actors = {ev.get('actor') for s in benign_scenarios for ev in s.events if ev.get('actor')}
    benign_entities = {ev.get('entity') for s in benign_scenarios for ev in s.events if ev.get('entity')}

    true_positives = sum(1 for s in attack_scenarios if s.expected_rule in fired_rules)
    false_negatives = len(attack_scenarios) - true_positives
    false_positives = sum(
        1 for d in detections if d.entity in benign_actors or d.entity in benign_entities
    )

    recall = round(true_positives / max(1, len(attack_scenarios)), 4)
    precision = round(true_positives / max(1, true_positives + false_positives), 4)
    false_positive_rate = round(false_positives / max(1, len(benign_scenarios)), 4)

    by_category: dict[str, dict[str, int]] = {}
    for s in attack_scenarios:
        bucket = by_category.setdefault(s.category, {'total': 0, 'detected': 0})
        bucket['total'] += 1
        if s.expected_rule in fired_rules:
            bucket['detected'] += 1

    return {
        'scenarios_total': len(suite),
        'attack_scenarios': len(attack_scenarios),
        'benign_scenarios': len(benign_scenarios),
        'true_positives': true_positives,
        'false_negatives': false_negatives,
        'false_positives': false_positives,
        'recall': recall,
        'precision': precision,
        'false_positive_rate': false_positive_rate,
        'time_to_detect_ms': elapsed_ms,
        'techniques_covered': sorted({s.technique for s in attack_scenarios if s.expected_rule in fired_rules}),
        'by_category': by_category,
        'engine_summary': engine_summary,
    }
