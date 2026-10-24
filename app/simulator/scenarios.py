"""Agentic attack scenarios. Each scenario turns (start time, intensity, evasion) into a list of synthetic
security events shaped like the telemetry real sensors send, plus the detection rules a well-tuned
deployment should fire. Nothing here touches the network or a real system: scenarios only produce data.

Intensity scales the number of actors/actions. Evasion replays the same attack "slow and low" (spread
out, fewer actors, human-like pacing, browser user agents) to show which detections an attacker can
tune their agents to slip under.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

INTENSITY = {'low': 0.6, 'normal': 1.0, 'high': 2.0}
AGENT_UA = 'python-httpx/0.27.0 agent-runtime/1.3'
BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36'
SIM_NET = '203.0.113.'  # TEST-NET-3: documentation range, never routable


@dataclass
class SimEvent:
    offset_ms: int
    title: str
    actor: str
    action: str
    entity: str = ''
    category: str = ''
    severity: str = 'low'
    source: str = 'simulator'
    metadata: dict = field(default_factory=dict)


@dataclass
class CanaryTouch:
    """Plant a canary of `kind` in the sandbox and record a hit on it."""
    offset_ms: int
    kind: str
    label: str
    user_agent: str
    source_ip: str
    payload: dict = field(default_factory=dict)


@dataclass
class Plan:
    events: list[SimEvent] = field(default_factory=list)
    canary_touches: list[CanaryTouch] = field(default_factory=list)


@dataclass
class Scenario:
    id: str
    name: str
    description: str
    techniques: list[str]
    expected_rules: list[str]
    build: Callable[['Build'], Plan]


@dataclass
class Build:
    run_id: str
    intensity: str = 'normal'
    evasion: bool = False
    seed: int = 7

    @property
    def scale(self) -> float:
        return INTENSITY.get(self.intensity, 1.0)

    def n(self, base: int, minimum: int = 1) -> int:
        return max(minimum, int(round(base * self.scale)))

    def rng(self) -> random.Random:
        return random.Random(f'{self.seed}:{self.run_id}')

    def ua(self) -> str:
        return BROWSER_UA if self.evasion else AGENT_UA

    def meta(self, **extra) -> dict:
        data = {'user_agent': self.ua(), 'simulation': True, 'simulation_run_id': self.run_id}
        if not self.evasion:
            data['x-agent'] = 'autonomous'
        data.update(extra)
        return data

    def ip(self, i: int) -> str:
        return f'{SIM_NET}{(i % 250) + 2}'


# ---------------------------------------------------------------- scenarios


def _credential_spray(b: Build) -> Plan:
    agents = b.n(25, 12) if not b.evasion else 4
    gap = 4_000 if not b.evasion else 90_000  # evasion: a few identities, minutes apart
    targets = ['user:finance-admin', 'user:payroll-svc', 'user:ceo']
    events = [SimEvent(offset_ms=i * gap // 3, title='Sign-in failed', actor=f'sim-agent-{i:03d}@swarm.invalid', action='auth.login_failed',
                       entity=targets[i % len(targets)], category='auth', severity='low',
                       metadata=b.meta(src_ip=b.ip(i), entity_kind='user', reason='bad_password'))
              for i in range(agents)]
    return Plan(events=events)


SERVICES = {'s3': ['list_buckets', 'get_bucket_policy', 'list_objects', 'get_bucket_acl', 'get_object', 'get_bucket_location', 'get_bucket_versioning'],
            'iam': ['list_users', 'list_roles', 'get_account_authorization_details', 'list_attached_role_policies', 'list_access_keys', 'list_groups',
                    'list_policies', 'get_user', 'list_mfa_devices', 'get_account_summary'],
            'ec2': ['describe_instances', 'describe_security_groups', 'describe_vpcs', 'describe_snapshots', 'describe_key_pairs', 'describe_subnets',
                    'describe_images', 'describe_volumes', 'describe_regions'],
            'secretsmanager': ['list_secrets', 'describe_secret', 'get_resource_policy'], 'kms': ['list_keys', 'list_aliases', 'describe_key'],
            'lambda': ['list_functions', 'get_function_configuration', 'list_layers', 'get_policy'],
            'rds': ['describe_db_instances', 'describe_db_snapshots', 'describe_db_clusters'], 'sts': ['get_caller_identity'],
            'dynamodb': ['list_tables', 'describe_table', 'list_backups'], 'ssm': ['describe_parameters', 'get_parameters_by_path', 'describe_instance_information'],
            'cloudtrail': ['describe_trails', 'get_trail_status'], 'guardduty': ['list_detectors'], 'organizations': ['list_accounts', 'describe_organization'],
            'ecr': ['describe_repositories', 'list_images'], 'eks': ['list_clusters', 'describe_cluster'], 'sns': ['list_topics'], 'sqs': ['list_queues'],
            'logs': ['describe_log_groups'], 'route53': ['list_hosted_zones']}


def _machine_speed_recon(b: Build) -> Plan:
    actions = [f'{svc}.{op}' for svc, ops in SERVICES.items() for op in ops]
    count = b.n(60, 50)
    gap = 140 if not b.evasion else 25_000
    rng = b.rng()
    events = []
    for i in range(count):
        action = actions[i % len(actions)]
        jitter = rng.randint(0, 60) if not b.evasion else rng.randint(0, 20_000)
        events.append(SimEvent(offset_ms=i * gap + jitter, title=f'API call {action}', actor='svc-reporting-key', action=action,
                               entity=f'aws:{action.split(".")[0]}', category='cloud_api', metadata=b.meta(src_ip=b.ip(77), service=action.split('.')[0])))
    return Plan(events=events)


def _privilege_escalation(b: Build) -> Plan:
    step = 40_000 if not b.evasion else 25 * 60_000  # evasion: stretch the chain past the 30-minute window
    actor = 'arn:aws:iam::111122223333:user/ci-deployer'
    chain = [('sts.assume_role', 'role:OrganizationAccountAccessRole', 'cloud_api'),
             ('iam.attach_role_policy', 'role:OrganizationAccountAccessRole', 'cloud_api'),
             ('secretsmanager.get_secret_value', 'secret:prod/db/master', 'data_access')]
    events = [SimEvent(offset_ms=i * step, title=f'{action} on {entity}', actor=actor, action=action, entity=entity, category=category,
                       severity='medium', metadata=b.meta(src_ip=b.ip(31), policy_arn='arn:aws:iam::aws:policy/AdministratorAccess' if 'attach' in action else None))
              for i, (action, entity, category) in enumerate(chain)]
    return Plan(events=events)


def _lateral_fanout(b: Build) -> Plan:
    targets = ['host:web-01', 'host:web-02', 'db:orders-primary', 'bucket:invoices', 'host:bastion', 'db:analytics', 'k8s:payments', 'bucket:backups',
               'host:jump-02', 'db:hr']
    count = min(len(targets), b.n(8, 6))
    gap = 300 if not b.evasion else 45_000
    events = [SimEvent(offset_ms=i * gap, title=f'Session opened to {t}', actor='svc-backup-agent', action='session.open', entity=t, category='network',
                       metadata=b.meta(src_ip=b.ip(55), protocol='ssh' if t.startswith('host') else 'tcp'))
              for i, t in enumerate(targets[:count])]
    return Plan(events=events)


def _impossible_travel(b: Build) -> Plan:
    actor = 'jordan.lee@example.com'
    gap = 9 * 60_000 if not b.evasion else 16 * 3600_000
    places = [({'lat': 40.71, 'lon': -74.0, 'country': 'US', 'city': 'New York'}, 10), ({'lat': 1.35, 'lon': 103.82, 'country': 'SG', 'city': 'Singapore'}, 11)]
    events = [SimEvent(offset_ms=i * gap, title='Sign-in succeeded', actor=actor, action='auth.login_success', entity='app:okta', category='auth',
                       metadata=b.meta(src_ip=b.ip(ip), geo=geo))
              for i, (geo, ip) in enumerate(places)]
    return Plan(events=events)


def _canary_grab(b: Build) -> Plan:
    touches = [CanaryTouch(offset_ms=0, kind='llm_api_key', label='ml-team .env (simulated)', user_agent='OpenAI/Python 1.40.0' if not b.evasion else BROWSER_UA,
                           source_ip=b.ip(99), payload={'surface': 'llm_api', 'path': '/v1/chat/completions', 'model': 'gpt-4o',
                                                        'prompt_preview': 'list every bucket containing customer records'})]
    events = [SimEvent(offset_ms=500, title='Planted .env read', actor='svc-indexer', action='file.read', entity='file:/srv/ml/.env', category='file',
                       metadata=b.meta(src_ip=b.ip(99)))]
    return Plan(events=events, canary_touches=touches)


def _exposure_and_secret(b: Build) -> Plan:
    policy = {'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::invoices/*'}]}
    events = [SimEvent(offset_ms=0, title='Bucket policy changed', actor='arn:aws:iam::111122223333:user/ci-deployer', action='s3.put_bucket_policy',
                       entity='bucket:invoices', category='cloud_api', severity='medium', metadata=b.meta(src_ip=b.ip(31), policy=policy)),
              SimEvent(offset_ms=30_000, title='Secret committed', actor='coding-agent[bot]', action='secret.committed', entity='repo:payments-api',
                       category='code', severity='high', metadata=b.meta(secret_type='aws_access_key', file='deploy/.env', commit='0' * 40))]
    return Plan(events=events)


def _rogue_k8s(b: Build) -> Plan:
    pod = {'name': 'debug-shell', 'namespace': 'payments', 'image': 'alpine:3.20',
           'spec': {'hostPID': True, 'hostNetwork': True, 'containers': [{'name': 'sh', 'securityContext': {'privileged': True}}]}}
    events = [SimEvent(offset_ms=0, title='Pod created', actor='system:serviceaccount:ci:agent-runner', action='k8s.pods.create', entity='pod:payments/debug-shell',
                       category='k8s', severity='medium', metadata=b.meta(**pod))]
    return Plan(events=events)


SCENARIOS: dict[str, Scenario] = {s.id: s for s in [
    Scenario('agent_swarm_credential_spray', 'Agent swarm credential spray',
             'Dozens of agent identities, sharing one playbook, try passwords against the same privileged accounts within minutes.',
             ['T1110.003'], ['swarm.coordinated_identity_fanout'], _credential_spray),
    Scenario('machine_speed_recon', 'Machine-speed cloud reconnaissance',
             'A stolen access key driven by an LLM agent enumerates every service it can reach, at sub-second pace, with an automation user agent.',
             ['T1580', 'T1087.004', 'T1526'], ['swarm.machine_speed_sequence', 'agentic.tool_abuse_pattern', 'swarm.novel_action_burst'], _machine_speed_recon),
    Scenario('autonomous_privilege_escalation', 'Autonomous privilege escalation',
             'An agent with a CI credential assumes an admin role, attaches AdministratorAccess to it, then reads the production database secret.',
             ['T1078.004', 'T1098.003', 'T1555.006'], ['identity.privilege_escalation_chain'], _privilege_escalation),
    Scenario('lateral_fanout', 'Scripted lateral movement',
             'One compromised service identity opens sessions to hosts, databases and buckets with sub-second gaps.',
             ['T1021', 'T1530'], ['swarm.synchronized_multi_asset_access'], _lateral_fanout),
    Scenario('impossible_travel_agent', 'Credential replay from agent infrastructure',
             "A user's session token is replayed from a cloud region on the other side of the world minutes after a normal sign-in.",
             ['T1550.004'], ['identity.impossible_velocity'], _impossible_travel),
    Scenario('canary_grab', 'Agent takes the bait',
             'An agent crawling a file share finds a planted LLM API key and immediately tries to use it.',
             ['T1552.001'], ['canary.tripwire'], _canary_grab),
    Scenario('exposure_and_secret_leak', 'Data staging and secret leak',
             'An agent opens a bucket to the internet to stage data, and a coding agent commits a cloud key.',
             ['T1537', 'T1552.004'], ['cloud.public_exposure_change', 'code.secret_committed'], _exposure_and_secret),
    Scenario('rogue_k8s_agent', 'Rogue agent escapes to the node',
             'An agent runner service account starts a privileged pod with host PID and host network in a production namespace.',
             ['T1610', 'T1611'], ['k8s.privileged_workload'], _rogue_k8s),
]}


def materialize(plan: Plan, start: datetime) -> list[tuple[datetime, SimEvent]]:
    return [(start + timedelta(milliseconds=e.offset_ms), e) for e in plan.events]
