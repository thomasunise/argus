"""Pure normalizer tests: every collector's _normalize() against fixture JSON, plus the base helpers."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.collectors import load_builtin, registry
from app.collectors.aws import summarize_policy
from app.collectors.base import CollectorResult, is_private_ip, is_secret_ref, jsonable, parse_time, validate_config
from app.collectors.netflow import _beacon_score, _read_flows, normalize_flow
from app.collectors.osquery import _read_directory

FIXTURES = Path(__file__).parent / 'fixtures' / 'collectors'


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name / 'raw.json').read_text(encoding='utf-8'))


def by_kind(result: CollectorResult) -> dict[str, int]:
    out: dict[str, int] = {}
    for node in result.nodes:
        out[node.kind] = out.get(node.kind, 0) + 1
    return out


def actions(result: CollectorResult) -> list[str]:
    return sorted(e.action for e in result.events)


def node(result: CollectorResult, kind: str, key: str):
    match = next((n for n in result.nodes if n.kind == kind and n.key == key), None)
    assert match is not None, f'missing node {kind}:{key}'
    return match


def has_edge(result: CollectorResult, src: tuple[str, str], dst: tuple[str, str], rel: str) -> bool:
    return any(e.src == src and e.dst == dst and e.rel == rel for e in result.edges)


@pytest.fixture(autouse=True)
def _load():
    load_builtin()


# ---------------------------------------------------------------- base helpers


def test_registry_lists_all_builtin_collectors():
    names = registry.names()
    assert names == ['aws', 'azure', 'entra', 'gcp', 'github', 'kubernetes', 'netflow', 'okta', 'osquery']
    for collector in registry.all():
        desc = collector.describe()
        assert desc['kind'] in ('cloud', 'identity', 'code', 'endpoint', 'network', 'k8s')
        assert desc['config_schema']['type'] == 'object' and isinstance(desc['available'], bool)
        for secret in collector.secret_fields:
            assert secret not in collector.config_schema['properties'], f'{collector.name}: secret {secret} must not be in the non-secret schema'
    assert registry.get('netflow').available() is True
    with pytest.raises(KeyError):
        registry.get('crowdstrike')


def test_validate_config_subset():
    schema = {'type': 'object', 'additionalProperties': False, 'required': ['org'],
              'properties': {'org': {'type': 'string', 'pattern': r'^[a-z]+$'}, 'n': {'type': 'integer', 'minimum': 1}, 'mode': {'type': 'string', 'enum': ['a', 'b']},
                             'tags': {'type': 'array', 'items': {'type': 'string'}}}}
    assert validate_config(schema, {'org': 'acme', 'n': 3, 'mode': 'a', 'tags': ['x']}) == []
    errors = validate_config(schema, {'org': 'ACME', 'n': 0, 'mode': 'z', 'tags': [1], 'extra': True})
    assert any('unknown config key extra' in e for e in errors)
    assert any('org does not match' in e for e in errors)
    assert any('n must be >= 1' in e for e in errors)
    assert any('mode must be one of' in e for e in errors)
    assert any('tags[0] must be of type string' in e for e in errors)
    assert validate_config(schema, {}) == ['missing required config key org']
    assert validate_config(schema, {'org': 'acme', 'n': True}) == ['n must be of type integer']


def test_secret_ref_and_time_helpers():
    assert is_secret_ref('env:AWS_SECRET') and is_secret_ref('file:/run/secrets/x') and is_secret_ref('secrets:okta') and is_secret_ref('literal:abc')
    assert not is_secret_ref('AKIAIOSFODNN7EXAMPLE') and not is_secret_ref('env:') and not is_secret_ref(123)
    assert parse_time('2026-10-23T12:00:00Z') == datetime(2026, 10, 23, 12, tzinfo=timezone.utc)
    assert parse_time(1761220800) == datetime(2025, 10, 23, 12, tzinfo=timezone.utc)
    assert parse_time('1761220800') == datetime(2025, 10, 23, 12, tzinfo=timezone.utc)
    assert parse_time(1761220800000) == datetime(2025, 10, 23, 12, tzinfo=timezone.utc)  # milliseconds
    assert parse_time('2026-10-23T12:00:00.1234567+00:00').microsecond == 123456
    assert parse_time('garbage') is None and parse_time(None) is None
    assert is_private_ip('10.1.2.3') and is_private_ip('192.168.0.1') and is_private_ip('127.0.0.1') and is_private_ip('fe80::1') and is_private_ip('100.64.0.9')
    assert not is_private_ip('203.0.113.5') and not is_private_ip('8.8.8.8') and not is_private_ip('nope')
    assert is_private_ip('203.0.113.5', ['203.0.113.0/24'])
    assert jsonable({'when': datetime(2026, 1, 1, tzinfo=timezone.utc), 'b': b'x', 's': {1, 2}}) == {'when': '2026-01-01T00:00:00+00:00', 'b': '<bytes>', 's': [1, 2]}


def test_result_dedupes_nodes_edges_and_events():
    r = CollectorResult()
    a = r.node('asset', 'x', {'a': 1}, label='X', criticality='low')
    b = r.node('asset', 'x', {'b': 2}, criticality='high')
    assert a is b and a.props == {'a': 1, 'b': 2} and a.criticality == 'high' and a.label == 'X'
    r.edge(a, ('identity', 'y'), 'owns', {'p': 1})
    r.edge(('asset', 'x'), ('identity', 'y'), 'owns', {'q': 2})
    assert len(r.edges) == 1 and r.edges[0].props == {'p': 1, 'q': 2} and r.edges[0].src == ('asset', 'x')
    assert r.event('collector:t', 'e1', 'one') is not None and r.event('collector:t', 'e1', 'dup') is None
    with pytest.raises(ValueError):
        r.node('galaxy', 'x')
    with pytest.raises(ValueError):
        r.edge(a, a, 'loves')
    assert r.finalize().stats == {'nodes': 1, 'edges': 1, 'events': 1, 'warnings': 0}


def test_summarize_policy_flags():
    admin = summarize_policy({'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]})
    assert admin['admin'] and admin['wildcard']
    scoped = summarize_policy({'Statement': [{'Effect': 'Allow', 'Action': ['s3:GetObject'], 'Resource': 'arn:aws:s3:::b/*'}]})
    assert not scoped['admin'] and not scoped['wildcard'] and scoped['services'] == ['s3']
    passrole = summarize_policy({'Statement': [{'Effect': 'Allow', 'Action': 'iam:PassRole', 'Resource': '*'}, {'Effect': 'Deny', 'Action': '*', 'Resource': '*'}]})
    assert passrole['wildcard'] and passrole.get('privilege_escalation') and not passrole['admin'] and passrole['statements'] == 1
    not_action = summarize_policy({'Statement': [{'Effect': 'Allow', 'NotAction': 'iam:*', 'Resource': '*'}]})
    assert not_action['admin'] and not_action['not_action']
    assert summarize_policy(None)['statements'] == 0


# ---------------------------------------------------------------- normalizers


def test_aws_normalize():
    r = registry.get('aws')._normalize(fixture('aws'))
    assert r.stats['iam_users'] == 3 and r.stats['iam_roles'] == 3 and r.stats['instances'] == 2 and r.stats['buckets'] == 2 and r.stats['eks'] == 1
    assert by_kind(r) == {'asset': 5, 'permission': 7, 'identity': 4, 'role': 4, 'exposure': 6, 'network': 2, 'data_store': 3}
    assert actions(r) == ['access_key_stale', 'bucket_public', 'database_public', 'k8s_api_public', 'mfa_missing', 'role_trust_open', 'root_mfa_missing']
    alice = node(r, 'identity', 'aws:iam:user:arn:aws:iam::123456789012:user/alice')
    assert alice.props['admin'] is True and alice.props['mfa'] is True and alice.criticality == 'critical'
    assert has_edge(r, alice.ref, ('permission', 'aws:policy:arn:aws:iam::aws:policy/AdministratorAccess'), 'has_permission')
    bot = node(r, 'identity', 'aws:iam:user:arn:aws:iam::123456789012:user/deploy-bot')
    assert bot.props['console_access'] is False  # no console => no MFA event even without an MFA device
    inline = node(r, 'permission', 'aws:inline:arn:aws:iam::123456789012:user/deploy-bot/s3-wildcard')
    assert inline.props['wildcard'] and not inline.props['admin']
    stale = next(e for e in r.events if e.action == 'access_key_stale')
    assert stale.metadata['key_suffix'] == 'Y001' and 'AKIAEXAMPLEDEPLOY001' not in stale.title and stale.metadata['age_days'] > 90
    # EC2: open SG rules become exposures, attached instance exposes them and can assume its instance-profile role
    web = node(r, 'asset', 'aws:ec2:i-0123')
    assert web.props['public_ip'] == '54.1.2.3' and web.props['imdsv2_required'] is False
    assert has_edge(r, web.ref, ('exposure', 'aws:exposure:sg:sg-0aaa:tcp:22'), 'exposes')
    assert has_edge(r, web.ref, ('role', 'aws:iam:role:arn:aws:iam::123456789012:role/AppServerRole'), 'can_assume')
    assert node(r, 'exposure', 'aws:exposure:sg:sg-0aaa:tcp:22').criticality == 'critical'
    assert not any(n.key.startswith('aws:exposure:sg:sg-0bbb') for n in r.nodes)
    # cross-account trust with external id, role trusting everyone, public bucket and RDS
    assert has_edge(r, ('identity', 'aws:account:999988887777:root'), ('role', 'aws:iam:role:arn:aws:iam::123456789012:role/CrossAccountAudit'), 'can_assume')
    assert node(r, 'role', 'aws:iam:role:arn:aws:iam::123456789012:role/OpenRole').props['trusts_anyone'] is True
    assert node(r, 'data_store', 'aws:s3:acme-public-assets').props['public'] is True
    assert node(r, 'data_store', 'aws:s3:acme-data-lake').props['public'] is False
    assert has_edge(r, ('data_store', 'aws:rds:us-east-1:orders-db'), ('exposure', 'aws:exposure:rds:orders-db'), 'exposes')
    assert has_edge(r, ('asset', 'aws:lambda:arn:aws:lambda:us-east-1:123456789012:function:image-resizer'),
                    ('role', 'aws:iam:role:arn:aws:iam::123456789012:role/AppServerRole'), 'can_assume')
    assert all(e.source == 'collector:aws' for e in r.events)


def test_azure_normalize():
    r = registry.get('azure')._normalize(fixture('azure'))
    assert r.stats == {**r.stats, 'subscriptions': 1, 'resource_groups': 2, 'vms': 1, 'nsgs': 1, 'storage_accounts': 2, 'role_assignments': 3, 'aks': 1}
    assert actions(r) == ['k8s_api_public', 'nsg_rule_open', 'privileged_role_assignment', 'storage_http_allowed', 'storage_public']
    nsg_key = 'azure:nsg:/subscriptions/sub-0001/resourcegroups/rg-web/providers/microsoft.network/networksecuritygroups/web-nsg'
    nsg = node(r, 'network', nsg_key)
    assert [rule['name'] for rule in nsg.props['open_ingress']] == ['allow-https', 'allow-rdp']  # VirtualNetwork source and Deny rules excluded
    vm = node(r, 'asset', 'azure:vm:/subscriptions/sub-0001/resourcegroups/rg-web/providers/microsoft.compute/virtualmachines/web-vm')
    assert vm.props['public_ip'] == '20.1.2.3' and vm.criticality == 'high'
    assert has_edge(r, vm.ref, ('exposure', f'{nsg_key.replace("azure:nsg:", "azure:exposure:nsg:")}:allow-rdp'), 'exposes')
    assert has_edge(r, vm.ref, ('identity', 'azure:principal:mi-00000001'), 'can_assume')
    owner = node(r, 'identity', 'azure:principal:user-0001')
    assert owner.props['privileged'] is True and owner.criticality == 'critical'
    assert has_edge(r, owner.ref, ('permission', 'azure:role:Owner@/subscriptions/sub-0001'), 'has_permission')
    contributor_rg = node(r, 'permission', 'azure:role:Contributor@/subscriptions/sub-0001/resourcegroups/rg-web')
    assert contributor_rg.props['subscription_scope'] is False
    assert node(r, 'role', 'azure:principal:grp-0003').props['type'] == 'group'
    storage = node(r, 'data_store', 'azure:storage:/subscriptions/sub-0001/resourcegroups/rg-web/providers/microsoft.storage/storageaccounts/acmepublic')
    assert storage.props['allow_blob_public_access'] is True and storage.criticality == 'critical'
    event = next(e for e in r.events if e.action == 'nsg_rule_open')
    assert event.external_id == 'azure:sub-0001:nsg-open:web-nsg:allow-rdp' and event.metadata['ports'] == '3389'


def test_gcp_normalize():
    r = registry.get('gcp')._normalize(fixture('gcp'))
    assert r.stats['instances'] == 2 and r.stats['firewalls'] == 2 and r.stats['buckets'] == 2 and r.stats['gke_clusters'] == 1
    assert actions(r) == ['bucket_public', 'firewall_rule_open', 'k8s_api_public', 'primitive_role_binding', 'primitive_role_binding', 'primitive_role_binding']
    web = node(r, 'asset', 'gcp:instance:acme-prod:us-central1-a:web-1')
    assert web.props['public_ips'] == ['34.1.2.3'] and web.props['cloud_platform_scope'] is True
    assert has_edge(r, web.ref, ('exposure', 'gcp:exposure:firewall:acme-prod:default-allow-ssh'), 'exposes')  # tag ssh matches
    assert has_edge(r, web.ref, ('exposure', 'gcp:exposure:firewall:acme-prod:allow-https'), 'exposes')
    batch = node(r, 'asset', 'gcp:instance:acme-prod:us-central1-b:batch-1')
    assert not has_edge(r, batch.ref, ('exposure', 'gcp:exposure:firewall:acme-prod:default-allow-ssh'), 'exposes')  # no ssh tag
    assert not any(n.key.endswith('old-open-rdp') for n in r.nodes)  # disabled rule ignored
    assert not any(n.key.endswith('allow-internal') for n in r.nodes)  # internal source range ignored
    bucket = node(r, 'data_store', 'gcp:bucket:acme-prod-public-site')
    assert bucket.props['public'] is True and bucket.props['public_roles'] == ['roles/storage.objectViewer']
    assert node(r, 'data_store', 'gcp:bucket:acme-prod-backups').props['public'] is False
    owner = node(r, 'permission', 'gcp:role:roles/owner@acme-prod')
    assert owner.props['admin'] and owner.props['primitive']
    assert has_edge(r, ('identity', 'gcp:member:user:cto@acme.com'), owner.ref, 'has_permission')
    assert has_edge(r, ('role', 'gcp:member:group:eng@acme.com'), ('permission', 'gcp:role/viewer@acme-prod'.replace('gcp:role/', 'gcp:role:roles/')), 'has_permission')
    assert has_edge(r, web.ref, ('identity', 'gcp:sa:123456789-compute@developer.gserviceaccount.com'), 'can_assume')
    gke = node(r, 'asset', 'gcp:gke:acme-prod:us-central1:prod-gke')
    assert gke.props['private_endpoint'] is False and gke.props['workload_identity'] is True


def test_kubernetes_normalize():
    r = registry.get('kubernetes')._normalize(fixture('kubernetes'))
    assert r.stats['namespaces'] == 3 and r.stats['workloads'] == 3 and r.stats['pods'] == 3 and r.stats['secrets'] == 2 and r.stats['privileged_workloads'] == 2
    assert actions(r) == ['cluster_admin_binding', 'cluster_admin_binding', 'privileged_workload', 'privileged_workload']
    sev = {e.external_id: e.severity for e in r.events}
    assert sev['k8s:prod-eks:cluster-admin:Group::system:authenticated'] == 'critical'
    assert sev['k8s:prod-eks:cluster-admin:ServiceAccount:prod:api'] == 'high'
    assert 'k8s:prod-eks:cluster-admin:Group::system:masters' not in sev
    agent = node(r, 'asset', 'k8s:daemonset:prod-eks/kube-system/node-agent')
    assert agent.props['privileged'] and agent.props['host_pid'] and agent.props['host_network'] and agent.props['host_path'] and agent.criticality == 'high'
    api = node(r, 'asset', 'k8s:deployment:prod-eks/prod/api')
    assert api.props['privileged'] is False and api.props['run_as_root'] is False and api.props['pods'] == 2
    assert has_edge(r, api.ref, ('identity', 'k8s:sa:prod-eks/prod/api'), 'can_assume')
    assert has_edge(r, ('identity', 'k8s:sa:prod-eks/prod/api'), ('permission', 'k8s:clusterrole:prod-eks/cluster-admin'), 'has_permission')
    assert has_edge(r, api.ref, ('exposure', 'k8s:exposure:svc:prod-eks/prod/api'), 'exposes')  # selector app=api matched the deployment
    assert has_edge(r, ('asset', 'k8s:node:prod-eks/ip-10-0-1-11.ec2.internal'), api.ref, 'runs')
    assert has_edge(r, ('asset', 'k8s:ns:prod-eks/prod'), ('exposure', 'k8s:exposure:svc:prod-eks/prod/metrics'), 'exposes')  # no matching workload
    postgres = node(r, 'asset', 'k8s:statefulset:prod-eks/prod/postgres')
    assert postgres.props['run_as_root'] is True
    debug = node(r, 'asset', 'k8s:pod:prod-eks/default/debug')
    assert debug.props['privileged'] and debug.props['host_network']
    secret = node(r, 'secret', 'k8s:secret:prod-eks/prod/db-creds')
    assert secret.props['keys'] == ['password', 'username'] and 'data' not in secret.props
    assert not any(n.key.endswith('default-token-x9z2k') for n in r.nodes)
    assert not any('ClusterIP' in n.label for n in r.nodes if n.kind == 'exposure')


def test_github_normalize_never_keeps_secret_values():
    raw = fixture('github')
    r = registry.get('github')._normalize(raw)
    assert r.stats == {**r.stats, 'repos': 2, 'public_repos': 1, 'unprotected_default_branches': 1, 'dependabot_alerts': 1, 'secret_scanning_alerts': 1,
                       'code_scanning_alerts': 1, 'admin_collaborators': 2}
    assert actions(r) == ['branch_unprotected', 'code_scanning_alert', 'dependency_vulnerable', 'org_2fa_not_required', 'secret_detected']
    secret_event = next(e for e in r.events if e.action == 'secret_detected')
    assert secret_event.category == 'code' and secret_event.severity == 'critical' and secret_event.actor == 'bob'
    leaked = raw['repos'][1]['secret_scanning_alerts'][0]['secret']
    blob = json.dumps([[e.title, e.entity, e.metadata] for e in r.events] + [n.props for n in r.nodes], default=str)
    assert leaked not in blob
    web = node(r, 'asset', 'github:repo:acme/web')
    assert web.props['visibility'] == 'public' and web.props['branch_protected'] is False and web.criticality == 'high'
    assert has_edge(r, web.ref, ('exposure', 'github:exposure:public-repo:acme/web'), 'exposes')
    api = node(r, 'asset', 'github:repo:acme/api')
    assert api.props['branch_protected'] is True and api.props['required_reviews'] == 2 and api.props['open_alerts'] == {'dependabot': 1, 'secret_scanning': 1, 'code_scanning': 1}
    vuln = node(r, 'vuln', 'github:vuln:GHSA-9wx4-h78v-vm56:pip:requests')
    assert vuln.props['cve_ids'] == ['CVE-2024-35195'] and vuln.props['severity'] == 'high' and vuln.props['patched_version'] == '2.32.0'
    assert has_edge(r, api.ref, vuln.ref, 'affected_by')
    assert has_edge(r, ('identity', 'github:user:alice'), ('permission', 'github:perm:admin:acme/api'), 'has_permission')
    assert not any(n.key == 'github:user:bob' for n in r.nodes)


def test_okta_normalize():
    r = registry.get('okta')._normalize(fixture('okta'))
    assert r.stats == {**r.stats, 'users': 4, 'users_without_mfa': 1, 'groups': 2, 'apps': 2, 'admins': 2, 'log_events': 3}
    assert actions(r) == ['admin_privilege_granted', 'mfa_factor_reset', 'mfa_missing', 'sign_in_failure']
    alice = node(r, 'identity', 'okta:user:00u1alice')
    assert alice.props['phishing_resistant_mfa'] is True and alice.props['admin_roles'] == ['SUPER_ADMIN'] and alice.criticality == 'critical'
    assert has_edge(r, alice.ref, ('permission', 'okta:role:acme.okta.com:SUPER_ADMIN:Super Organization Administrator'), 'has_permission')
    bob = node(r, 'identity', 'okta:user:00u2bob')
    assert bob.props['mfa_enrolled'] is False
    assert node(r, 'identity', 'okta:user:00u4dave').props['status'] == 'SUSPENDED'
    failure = next(e for e in r.events if e.action == 'sign_in_failure')
    assert failure.actor == 'bob@acme.com' and failure.metadata['ip'] == '203.0.113.45' and failure.metadata['user_agent'] == 'Mozilla/5.0'
    assert failure.metadata['reason'] == 'INVALID_CREDENTIALS' and failure.occurred_at == datetime(2026, 10, 23, 6, tzinfo=timezone.utc)
    grant = next(e for e in r.events if e.action == 'admin_privilege_granted')
    assert grant.actor == 'alice@acme.com' and grant.entity == 'carol@acme.com' and grant.external_id == 'okta:log:e1-0004'
    assert not any(e.external_id == 'okta:log:e1-0002' for e in r.events)  # successful sign-in is not an event
    assert not any(e.external_id == 'okta:log:e1-0005' for e in r.events)  # unmapped event type ignored


def test_entra_normalize():
    r = registry.get('entra')._normalize(fixture('entra'))
    assert r.stats == {**r.stats, 'users': 3, 'guests': 1, 'groups': 2, 'global_admins': 2, 'service_principals': 2, 'sp_with_credentials': 1,
                       'conditional_access_policies': 1, 'risky_sign_ins': 1, 'audit_events': 1}
    assert actions(r) == ['admin_privilege_granted', 'conditional_access_missing', 'global_admin_risky_member', 'risky_sign_in', 'sp_long_lived_secret']
    alice = node(r, 'identity', 'entra:user:u-alice')
    assert alice.props['admin_roles'] == ['Global Administrator'] and alice.criticality == 'critical'
    ga = node(r, 'permission', 'entra:role:72f988bf-86f1-41af-91ab-2d7cd011db47:62e90394-69f5-4237-9190-012177145e10')
    assert ga.props['admin'] is True
    assert has_edge(r, ('identity', 'entra:sp:sp-automation'), ga.ref, 'has_permission')
    assert has_edge(r, ('identity', 'entra:user:u-bob'), ('permission', 'entra:role:72f988bf-86f1-41af-91ab-2d7cd011db47:fe930be7-5e62-47db-91af-98c3a49a38b1'), 'has_permission')
    assert node(r, 'role', 'entra:group:g-pim').props['role_assignable'] is True and node(r, 'role', 'entra:group:g-pim').criticality == 'high'
    tenant = node(r, 'asset', 'entra:tenant:72f988bf-86f1-41af-91ab-2d7cd011db47')
    assert tenant.props['conditional_access_enabled'] == 0
    signin = next(e for e in r.events if e.action == 'risky_sign_in')
    assert signin.severity == 'high' and signin.actor == 'bob@acme.com' and signin.metadata['ip'] == '203.0.113.77' and signin.metadata['country'] == 'NG'
    audit = next(e for e in r.events if e.action == 'admin_privilege_granted')
    assert audit.actor == 'alice@acme.com' and audit.entity == 'bob@acme.com' and audit.metadata['role'] == 'Global Administrator' and audit.severity == 'high'


def test_osquery_normalize():
    r = registry.get('osquery')._normalize(fixture('osquery'))
    assert r.stats == {**r.stats, 'hosts': 2, 'listening_ports': 5, 'sudo_users': 4, 'packages': 3, 'suspicious_processes': 2}
    assert actions(r) == ['suspicious_child_process', 'suspicious_child_process']
    web = node(r, 'asset', 'host:web-01')
    assert web.props['hostname'] == 'web-01.acme.internal' and web.props['package_count'] == 2 and web.props['packages'][0] == {'name': 'openssl', 'version': '3.0.2-0ubuntu1.15', 'source': 'deb'}
    assert has_edge(r, web.ref, ('exposure', 'host:web-01:port:tcp/6379'), 'exposes')
    assert node(r, 'exposure', 'host:web-01:port:tcp/6379').criticality == 'high' and node(r, 'exposure', 'host:web-01:port:tcp/443').criticality == 'low'
    assert not any(n.key == 'host:web-01:port:tcp/5432' for n in r.nodes)  # loopback-only listener skipped
    assert node(r, 'identity', 'host:web-01:user:deploy').props['sudo'] is True  # via sudoers
    assert node(r, 'identity', 'host:web-01:user:ubuntu').props['sudo'] is True  # via sudo group
    assert not any(n.key == 'host:web-01:user:www-data' for n in r.nodes)  # system account
    assert has_edge(r, ('identity', 'host:web-01:user:root'), ('permission', 'host:web-01:sudo'), 'has_permission')
    dc = node(r, 'asset', 'host:WIN-DC01')
    assert dc.props['public_ip'] == '203.0.113.200' and dc.criticality == 'high'
    assert node(r, 'identity', 'host:WIN-DC01:user:Administrator').props['sudo'] is True
    win = next(e for e in r.events if 'WIN-DC01' in e.external_id)
    assert win.metadata['parent_name'] == 'w3wp.exe' and win.metadata['process'] == 'powershell.exe' and win.category == 'process'


def test_osquery_directory_reader():
    raw = _read_directory(FIXTURES / 'osquery' / 'results', logging.getLogger('test'))
    assert raw['warnings'] == [] and len(raw['hosts']) == 1
    host = raw['hosts'][0]
    assert host['hostname'] == 'web-01.acme.internal' and host['primary_ip'] == '10.0.1.20' and host['osquery_version'] == '5.12.1'
    assert host['os_version'].startswith('Ubuntu 22.04.4') and host['platform'] == 'ubuntu'
    assert [p['port'] for p in host['listening_ports']] == ['22', '443', '6379', '5432']  # the "removed" row is dropped
    assert [u['username'] for u in host['users']] == ['root', 'ubuntu', 'www-data', 'deploy'] and host['users'][1]['groups'] == ['ubuntu', 'sudo']
    assert [p['name'] for p in host['packages']] == ['openssl', 'nginx'] and host['packages'][0]['source'] == 'deb'
    r = registry.get('osquery')._normalize(raw)
    assert r.stats['listening_ports'] == 3 and r.stats['sudo_users'] == 3 and actions(r) == ['suspicious_child_process']
    assert 'dev/tcp' in r.events[0].metadata['cmdline']
    assert _read_directory(FIXTURES / 'osquery' / 'missing', logging.getLogger('test'))['warnings'] == ['directory not found: missing']


def test_netflow_normalize_from_zeek_and_nfdump_files():
    raw = _read_flows(FIXTURES / 'netflow' / 'flows', {}, logging.getLogger('test'))
    assert len(raw['flows']) == 21 and raw['files'] == 2 and raw['warnings'] == []
    raw['config'] = {}
    r = registry.get('netflow')._normalize(raw)
    assert r.stats == {**r.stats, 'flows_internal': 1, 'flows_external': 20, 'internal_hosts': 3, 'external_hosts': 5, 'pairs': 5, 'beacons': 1}
    assert actions(r) == ['beaconing', 'inbound_sensitive_service', 'large_egress']
    beacon = next(e for e in r.events if e.action == 'beaconing')
    assert beacon.actor == '10.0.1.20' and beacon.entity == '203.0.113.50' and 59 <= beacon.metadata['interval_seconds'] <= 61 and beacon.metadata['connections'] == 12
    egress = next(e for e in r.events if e.action == 'large_egress')
    assert egress.actor == '10.0.1.30' and egress.metadata['top_destination'] == '198.51.100.7' and egress.metadata['bytes_out'] == 600 * 1024 * 1024
    inbound = next(e for e in r.events if e.action == 'inbound_sensitive_service')
    assert inbound.actor == '203.0.113.99' and inbound.entity == '10.0.1.20' and inbound.metadata['services'] == ['ssh']
    edge = next(e for e in r.edges if e.rel == 'connects_to' and e.src == ('network', 'ip:10.0.1.20') and e.dst == ('network', 'ip:203.0.113.50'))
    assert edge.props['count'] == 12 and edge.props['beacon']['jitter'] < 0.2 and edge.props['ports'] == [443]
    dns = next(e for e in r.edges if e.rel == 'connects_to' and e.dst == ('network', 'ip:8.8.8.8'))
    assert 'beacon' not in dns.props
    assert has_edge(r, ('network', 'ip:10.0.2.5'), ('network', 'ip:192.0.2.10'), 'connects_to')  # nfdump record
    assert has_edge(r, ('network', 'ip:10.0.1.20'), ('exposure', 'netflow:exposure:10.0.1.20'), 'exposes')
    assert not any(n.key == 'ip:10.0.1.30' and n.props.get('type') == 'external_host' for n in r.nodes)
    assert not has_edge(r, ('network', 'ip:10.0.1.20'), ('network', 'ip:10.0.1.30'), 'connects_to')  # east-west excluded


def test_netflow_helpers():
    assert normalize_flow({'id.orig_h': '10.0.0.1', 'id.resp_h': '1.1.1.1', 'id.resp_p': 53, 'ts': 1.0})['dst'] == '1.1.1.1'
    assert normalize_flow({'src4_addr': '10.0.0.1', 'dst4_addr': '1.1.1.1', 'dst_port': 80, 'in_bytes': 5})['orig_bytes'] == 5
    assert normalize_flow({'src_ip': '10.0.0.1', 'dst_ip': '1.1.1.1', 'dst_port': 80, 'bytes': 5}, 'generic')['dport'] == 80
    assert normalize_flow({'foo': 1}) is None and normalize_flow('x') is None
    regular = [1000.0 + 30 * i for i in range(10)]
    assert _beacon_score(regular, 8, 0.2)['interval_seconds'] == 30.0
    assert _beacon_score(regular[:5], 8, 0.2) is None
    assert _beacon_score([1000.0, 1003.0, 1200.0, 1201.0, 1900.0, 2500.0, 2501.0, 2502.0, 4000.0], 8, 0.2) is None
    with_outlier = regular + [regular[-1] + 600]
    assert _beacon_score(with_outlier, 8, 0.2) is not None
