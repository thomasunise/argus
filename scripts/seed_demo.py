"""Seed an isolated DEMO tenant with synthetic records.

Creates a tenant `demo` with its own owner login, assets of several kinds (two of them with
authorization records), synthetic security events shaped to trip the detection rules
`cloud.public_exposure_change` and `swarm.machine_speed_sequence`, a few findings, one canary,
one completed agent-run record with steps, and an audit entry. Every record is labelled DEMO.

The script never touches the network: no scans, no model calls, no sinks beyond what your
.env already configures. It only writes to DATABASE_URL.

    python scripts/seed_demo.py                 # seed and print the login
    python scripts/seed_demo.py --password ...  # choose the demo owner password
    python scripts/seed_demo.py --no-detect     # do not run the detection engine after seeding

Do not run this against a production database. To remove the data, drop the tenant rows or
use a fresh database.
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault('ARGUS_LAZY_APP', '1')

from sqlalchemy import select  # noqa: E402

from app.core import audit as audit_module  # noqa: E402
from app.core.audit import record_audit  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.db import make_engine, make_session_factory, session_scope  # noqa: E402
from app.core.findings import EventDraft, refresh_open_metrics, upsert_event, upsert_finding  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models import AgentRun, AgentStep, Asset, AssetAuthorization, Base, Finding, Membership, Tenant, User, dumps  # noqa: E402

DEMO_SLUG = 'demo'
DEMO_EMAIL = 'demo-owner@argus.local'
DEMO_ACCOUNT = '123456789012'
DEMO_ACTOR_CI = f'arn:aws:iam::{DEMO_ACCOUNT}:user/demo-ci-deployer'
DEMO_ACTOR_SWARM = f'arn:aws:iam::{DEMO_ACCOUNT}:role/demo-recon-agent'


def _out(line: str = '') -> None:
    sys.stdout.write(line + '\n')


def _assets(db, tenant_id: str, owner_id: str, now: datetime) -> dict[str, Asset]:
    specs = [
        # key, name, kind, target, environment, criticality, tags
        ('web_prod', 'DEMO - Customer portal', 'web', 'https://portal.demo.example', 'production', 'high', ['demo', 'internet-facing']),
        ('web_staging', 'DEMO - Customer portal (staging)', 'web', 'https://staging-portal.demo.example', 'staging', 'medium', ['demo']),
        ('aws', 'DEMO - AWS production account', 'cloud_account', f'aws:{DEMO_ACCOUNT}', 'production', 'critical', ['demo', 'aws']),
        ('k8s_lab', 'DEMO - Lab Kubernetes cluster', 'k8s_cluster', 'k8s:demo-lab', 'lab', 'low', ['demo', 'k8s']),
        ('db', 'DEMO - Orders database', 'database', 'postgres://orders-db.internal.demo.example:5432', 'production', 'critical', ['demo', 'pii']),
        ('idp', 'DEMO - Okta tenant', 'identity_provider', 'https://demo.okta.example', 'production', 'critical', ['demo', 'identity']),
        ('host', 'DEMO - Bastion host', 'host', 'bastion-01.internal.demo.example', 'production', 'medium', ['demo', 'linux']),
        ('bucket', 'DEMO - Customer exports bucket', 'cloud_account', f'arn:aws:s3:::demo-customer-exports-{DEMO_ACCOUNT}', 'production', 'high', ['demo', 'aws', 's3']),
    ]
    assets: dict[str, Asset] = {}
    for key, name, kind, target, environment, criticality, tags in specs:
        asset = Asset(tenant_id=tenant_id, name=name, kind=kind, target=target, environment=environment, criticality=criticality,
                      owner='DEMO platform team', tags_json=dumps(tags), source='manual', last_seen_at=now)
        db.add(asset)
        assets[key] = asset
    db.flush()

    # Authorizations: passive + active testing on the staging portal; intrusive allowed only in the lab cluster.
    db.add(AssetAuthorization(tenant_id=tenant_id, asset_id=assets['web_staging'].id, authorized_by=owner_id,
                              attestation='DEMO attestation: the demo team controls staging-portal.demo.example (synthetic).',
                              allow_active=True, allow_intrusive=False, scope_document_ref='DEMO-SCOPE-001',
                              expires_at=now + timedelta(days=90)))
    db.add(AssetAuthorization(tenant_id=tenant_id, asset_id=assets['k8s_lab'].id, authorized_by=owner_id,
                              attestation='DEMO attestation: isolated lab cluster, adversary emulation permitted (synthetic).',
                              allow_active=True, allow_intrusive=True, scope_document_ref='DEMO-SCOPE-002',
                              expires_at=now + timedelta(days=30)))
    assets['web_staging'].approved = True
    assets['k8s_lab'].approved = True
    db.flush()
    return assets


def _events(db, tenant_id: str, assets: dict[str, Asset], now: datetime) -> int:
    created = 0

    def add(draft: EventDraft) -> None:
        nonlocal created
        _, was_created = upsert_event(db, tenant_id, draft)
        created += int(was_created)

    # --- benign background: a human logging in, a deploy
    add(EventDraft(source='demo-okta', external_id='demo-login-1', title='[DEMO] Successful SSO login', severity='informational',
                   category='auth', actor='alice@demo.example', entity='user:alice@demo.example', action='user.session.start',
                   asset_id=assets['idp'].id, occurred_at=now - timedelta(minutes=40),
                   metadata={'client_ip': '198.51.100.24', 'user_agent': 'Mozilla/5.0', 'country': 'US', 'demo': True}))
    add(EventDraft(source='demo-cloudtrail', external_id='demo-deploy-1', title='[DEMO] ECS service updated by CI', severity='low',
                   category='cloud_api', actor=DEMO_ACTOR_CI, entity='service:portal-api', action='ecs.update_service',
                   asset_id=assets['aws'].id, occurred_at=now - timedelta(minutes=35),
                   metadata={'sourceIPAddress': '203.0.113.10', 'userAgent': 'aws-cli/2.15.0', 'awsRegion': 'us-east-1', 'demo': True}))

    # --- trips cloud.public_exposure_change: a bucket policy change with public markers
    add(EventDraft(source='demo-cloudtrail', external_id='demo-public-bucket-1', title='[DEMO] Bucket policy changed to allow public read',
                   severity='high', category='cloud_api', actor=DEMO_ACTOR_CI, entity=f'bucket:demo-customer-exports-{DEMO_ACCOUNT}',
                   action='s3.put_bucket_policy', asset_id=assets['bucket'].id, occurred_at=now - timedelta(minutes=12),
                   metadata={'sourceIPAddress': '203.0.113.10', 'userAgent': 'aws-cli/2.15.0', 'awsRegion': 'us-east-1',
                             'account': DEMO_ACCOUNT, 'public': True, 'cidr': '0.0.0.0/0',
                             'policy_summary': 'Allow s3:GetObject to everyone (synthetic DEMO event)', 'demo': True}))

    # --- trips swarm.machine_speed_sequence: one identity, 24 enumeration calls 180 ms apart
    recon_actions = ['iam.list_users', 'iam.list_roles', 'iam.list_policies', 'iam.get_account_authorization_details', 's3.list_buckets',
                     's3.get_bucket_policy', 'ec2.describe_instances', 'ec2.describe_security_groups', 'secretsmanager.list_secrets',
                     'kms.list_keys', 'rds.describe_db_instances', 'lambda.list_functions']
    start = now - timedelta(minutes=8)
    for index in range(24):
        action = recon_actions[index % len(recon_actions)]
        add(EventDraft(source='demo-cloudtrail', external_id=f'demo-recon-{index:03d}', title=f'[DEMO] {action} by automated client',
                       severity='low', category='cloud_api', actor=DEMO_ACTOR_SWARM, entity=f'{action.split(".")[0]}:{DEMO_ACCOUNT}',
                       action=action, asset_id=assets['aws'].id, occurred_at=start + timedelta(milliseconds=180 * index),
                       metadata={'sourceIPAddress': '192.0.2.77', 'userAgent': 'python-requests/2.32 agent-swarm/0.1', 'awsRegion': 'us-east-1',
                                 'account': DEMO_ACCOUNT, 'headers': {'x-agent-id': 'swarm-node-3'}, 'demo': True}))
    return created


def _findings(db, tenant_id: str, assets: dict[str, Asset]) -> int:
    rows = [
        dict(source='demo-fixture', rule='demo.tls_expiry', asset_id=assets['web_prod'].id, severity_name='high',
             title='[DEMO] TLS certificate expires in 9 days',
             description='Synthetic finding. No connection to portal.demo.example was made.',
             remediation='Renew the certificate and confirm the renewal automation runs before expiry.',
             evidence={'not_after': '2026-11-01T00:00:00Z', 'issuer': 'DEMO CA', 'demo': True}),
        dict(source='demo-fixture', rule='demo.public_bucket', asset_id=assets['bucket'].id, severity_name='critical',
             title='[DEMO] Customer exports bucket is publicly readable',
             description='Synthetic finding derived from the DEMO bucket-policy event. No cloud account was inspected.',
             remediation='Restore the bucket policy, enable Block Public Access, and review access logs for the exposure window.',
             evidence={'bucket': f'demo-customer-exports-{DEMO_ACCOUNT}', 'policy_change_by': DEMO_ACTOR_CI, 'demo': True}),
        dict(source='demo-fixture', rule='demo.vulnerable_package', asset_id=assets['host'].id, severity_name='medium',
             title='[DEMO] openssh-server has a known vulnerability',
             description='Synthetic finding. The bastion host was not scanned.',
             remediation='Upgrade the package to the fixed version and restart the service.',
             evidence={'package': 'openssh-server', 'installed': '9.2p1-2', 'fixed': '9.2p1-2+deb12u3', 'demo': True},
             cve_ids=['CVE-2024-6387'], cvss=8.1, epss=0.42, kev=False),
        dict(source='demo-fixture', rule='demo.k8s_privileged', asset_id=assets['k8s_lab'].id, severity_name='low',
             title='[DEMO] Lab workload runs privileged',
             description='Synthetic finding for the isolated lab cluster.',
             remediation='Drop privileged mode and use a restricted pod security standard.',
             evidence={'namespace': 'lab', 'workload': 'deploy/attack-sim', 'demo': True}),
    ]
    created = 0
    for row in rows:
        _, was_created = upsert_finding(db, tenant_id, tags=['demo'], **row)
        created += int(was_created)
    return created


def _canary(db, tenant_id: str, owner_id: str, settings) -> str:
    try:
        from app.detections.canaries import create_canary
    except ImportError:  # detections package not present in this checkout
        return 'skipped (detections package not installed)'
    canary = create_canary(db, tenant_id, kind='aws_key', label='DEMO - fake AWS key in ~/.aws/credentials on bastion',
                           placement='DEMO placement: bastion-01 /home/deploy/.aws/credentials (synthetic, never deployed)',
                           metadata={'demo': True}, created_by=owner_id, settings=settings)
    return f'{canary.kind} {canary.token[:8]}... ({canary.label})'


def _agent_run(db, tenant_id: str, owner_id: str, finding_id: str | None, now: datetime) -> AgentRun:
    output = {'severity': 'critical', 'summary': '[DEMO] The exports bucket policy was opened to the internet by the CI deployer identity. '
                                                 'Treat as exposure until access logs are reviewed.',
              'recommended_actions': [{'action_type': 's3.block_public_access', 'reason': 'DEMO: reversible containment'}],
              'confidence': 'high', 'demo': True}
    run = AgentRun(tenant_id=tenant_id, spec='triage', task='[DEMO] Triage the public bucket finding', inputs_json=dumps({'finding_id': finding_id}),
                   status='completed', provider='none', model='fallback', output_json=dumps(output), steps_count=2, input_tokens=0, output_tokens=0,
                   cost_estimate_usd=0.0, finding_id=finding_id, created_by=owner_id, created_at=now - timedelta(minutes=5),
                   started_at=now - timedelta(minutes=5), finished_at=now - timedelta(minutes=4))
    db.add(run)
    db.flush()
    db.add(AgentStep(run_id=run.id, index=0, kind='tool', name='get_finding', input_json=dumps({'finding_id': finding_id}),
                     output_json=dumps({'demo': True, 'severity': 'critical'}), latency_ms=12))
    db.add(AgentStep(run_id=run.id, index=1, kind='model', name='submit_result', input_json=dumps({'demo': True}), output_json=dumps(output),
                     latency_ms=3))
    db.flush()
    return run


def _run_detections(db, tenant_id: str, settings) -> dict | None:
    try:
        from app.detections import engine
    except ImportError:
        return None
    return engine.run(db, tenant_id, settings=settings, trigger='api')


def _detection_rules(db, tenant_id: str) -> list[tuple[str, str]]:
    try:
        from app.models.detections import Detection
    except ImportError:
        return []
    rows = db.execute(select(Detection.rule_id, Detection.title).where(Detection.tenant_id == tenant_id).order_by(Detection.rule_id)).all()
    return [(r[0], r[1]) for r in rows]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--password', default='', help='demo owner password (default: random)')
    parser.add_argument('--no-detect', action='store_true', help='skip running the detection engine after seeding')
    args = parser.parse_args(argv)

    settings = get_settings()
    if settings.is_production:
        sys.stderr.write('refusing to seed demo data with APP_ENV=production\n')
        return 2
    audit_module.configure(settings)
    engine = make_engine(settings)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    password = args.password or secrets.token_urlsafe(18)
    now = datetime.now(timezone.utc)

    with session_scope(factory) as db:
        if db.execute(select(Tenant).where(Tenant.slug == DEMO_SLUG)).scalar_one_or_none():
            _out(f'tenant "{DEMO_SLUG}" already exists; nothing seeded. Use a fresh database to reseed.')
            return 0
        tenant = Tenant(slug=DEMO_SLUG, name='DEMO Corp (synthetic)', actions_enabled=False)
        db.add(tenant)
        db.flush()
        user = db.execute(select(User).where(User.email == DEMO_EMAIL)).scalar_one_or_none()
        if not user:
            user = User(email=DEMO_EMAIL, display_name='DEMO Owner', password_hash=hash_password(password))
            db.add(user)
            db.flush()
        else:
            user.password_hash = hash_password(password)
        db.add(Membership(user_id=user.id, tenant_id=tenant.id, role='owner'))
        db.flush()

        assets = _assets(db, tenant.id, user.id, now)
        events = _events(db, tenant.id, assets, now)
        findings = _findings(db, tenant.id, assets)
        canary = _canary(db, tenant.id, user.id, settings)
        bucket_finding = db.execute(select(Finding).where(Finding.tenant_id == tenant.id, Finding.rule == 'demo.public_bucket')).scalar_one()
        run = _agent_run(db, tenant.id, user.id, bucket_finding.id, now)
        counts = refresh_open_metrics(db, tenant.id)
        record_audit(db, 'system', 'demo.seeded', tenant.id,
                     {'assets': len(assets), 'events': events, 'findings': findings, 'agent_run': run.id, 'note': 'synthetic DEMO records'},
                     tenant_id=tenant.id)
        detection_result = None if args.no_detect else _run_detections(db, tenant.id, settings)
        detection_rules = _detection_rules(db, tenant.id) if detection_result else []
        tenant_id = tenant.id

    _out('Seeded synthetic DEMO data. These records are NOT real telemetry or scan results.')
    _out(f'  tenant      {DEMO_SLUG} ({tenant_id})')
    _out(f'  assets      {len(assets)} (2 with authorization records)')
    _out(f'  events      {events}')
    _out(f'  findings    {findings} open by severity: ' + ', '.join(f'{k}={v}' for k, v in counts.items() if v))
    _out(f'  canary      {canary}')
    _out(f'  agent run   {run.id} (spec=triage, status=completed, provider=none)')
    if detection_result is not None:
        _out(f'  detections  created={detection_result["detections_created"]} rules_run={detection_result["rules_run"]} '
             f'events_scanned={detection_result["events_scanned"]} errors={len(detection_result["errors"])}')
        for rule_id, title in detection_rules:
            _out(f'              {rule_id}: {title}')
    _out()
    _out('Login:')
    _out(f'  URL       {settings.base_url}')
    _out(f'  tenant    {DEMO_SLUG}')
    _out(f'  email     {DEMO_EMAIL}')
    _out(f'  password  {password}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
