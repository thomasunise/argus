"""Cross-provider ordered incident correlation."""
from datetime import datetime, timedelta, timezone

from app.core.findings import EventDraft, upsert_event
from app.detections.engine import run
from app.models.detections import Detection


def _seed(db, tenant, suffix, actor, source, category, action, at):
    upsert_event(db, tenant, EventDraft(source=source, external_id=suffix, title=action,
                                        severity='low', category=category, actor=actor,
                                        entity='resource', action=action, occurred_at=at))


def test_cross_source_attack_chain_positive_and_negative(db, default_tenant_id):
    now = datetime.now(timezone.utc)
    tenant = default_tenant_id
    _seed(db, tenant, '1', 'attacker', 'okta', 'identity', 'user.login', now - timedelta(minutes=8))
    _seed(db, tenant, '2', 'attacker', 'aws', 'cloud_api', 'iam.attach_role', now - timedelta(minutes=7))
    _seed(db, tenant, '3', 'attacker', 'aws', 'cloud_api', 's3.get_object', now - timedelta(minutes=6))
    _seed(db, tenant, '4', 'normal', 'okta', 'identity', 'user.login', now - timedelta(minutes=8))
    _seed(db, tenant, '5', 'normal', 'aws', 'cloud_api', 's3.get_object', now - timedelta(minutes=7))
    result = run(db, tenant, rule_ids=['agentic.cross_source_attack_chain'], now=now)
    assert not result['errors']
    found = db.query(Detection).filter(Detection.tenant_id == tenant,
        Detection.rule_id == 'agentic.cross_source_attack_chain').all()
    assert len(found) == 1
    assert found[0].entity == 'attacker'
