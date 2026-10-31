"""Inbound parsers against realistic fixtures: counts, exact normalized fields, action vocabulary,
redaction and metadata bounding. No app or database needed."""
from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone

import pytest

from app.integrations.inbound import ParseContext, clean_metadata, parse_time, registry
from app.integrations.inbound._common import scan_markers, snake
from app.integrations.schema import (is_secret_ref, severity_at_least, topic_matches, validate_no_inline_secrets, validate_schema, validate_secret_refs,
                                     validate_topics)
from app.models import dumps

FIXTURES = pathlib.Path(__file__).parent / 'fixtures' / 'integrations'
UTC = timezone.utc


def load(source: str, name: str):
    return json.loads((FIXTURES / source / name).read_text(encoding='utf-8'))


def parse(source: str, name: str, headers: dict | None = None):
    parser = registry.get(source)
    ctx = ParseContext(tenant_id='t1', source=source, headers=headers or {})
    payload = load(source, name)
    events = parser.parse(payload, ctx)
    findings = parser.findings(payload, ctx) if parser.kind in {'both', 'findings'} else []
    assert ctx.errors == [], ctx.errors
    return events, findings


def test_registry_names_aliases_and_examples():
    assert registry.names() == ['aws_cloudtrail', 'aws_guardduty', 'azure_defender', 'crowdstrike', 'falco', 'gcp_scc', 'generic', 'github_webhook',
                                'k8s_audit', 'okta_logs', 'sentinelone', 'suricata', 'trivy', 'wazuh', 'zeek']
    assert registry.resolve('cloudtrail') == 'aws_cloudtrail' and registry.resolve('guardduty') == 'aws_guardduty'
    assert registry.resolve('okta') == 'okta_logs' and registry.resolve('github') == 'github_webhook' and registry.resolve('K8S') == 'k8s_audit'
    assert not registry.has('nope')
    for parser in registry.all():
        assert parser.source and len(parser.source) <= 30
        assert (pathlib.Path(__file__).parent.parent / parser.example).is_file(), parser.example


def test_wazuh_alerts():
    events, _ = parse('wazuh', 'alerts.json')
    assert [e.action for e in events] == ['auth.failure', 'file.modified', 'privilege.sudo', 'auth.failure']
    assert [e.severity for e in events] == ['low', 'medium', 'low', 'high']
    assert [e.category for e in events] == ['auth', 'file', 'process', 'auth']
    first = events[0]
    assert first.source == 'wazuh' and first.external_id == '1729687200.183726'
    assert first.actor == 'deploy' and first.entity == 'web-prod-01'
    assert first.occurred_at == datetime(2026, 10, 23, 12, 40, 0, 512000, tzinfo=UTC)
    assert first.metadata['ip'] == '203.0.113.45' and first.metadata['rule_id'] == '5760' and first.metadata['rule_level'] == 5
    assert first.metadata['geo'] == {'lat': 52.3824, 'lon': 4.8995, 'country': 'NL', 'city': 'Amsterdam'}
    assert first.metadata['mitre_ids'] == ['T1110.001'] and 'full_log' in first.metadata and 'previous_output' not in first.metadata
    assert events[1].metadata['file'] == '/etc/sudoers.d/90-cloud-init-users' and events[1].metadata['syscheck_event'] == 'modified'
    assert events[2].metadata['command'] == '/usr/bin/cat /etc/shadow'


def test_wazuh_indexer_hits_shape():
    events, _ = parse('wazuh', 'indexer_hits.json')
    assert [e.action for e in events] == ['host.rootcheck', 'malware.detected']
    assert events[0].external_id == 'kQ7xZ5IBz1q-indexer-0001' and events[0].severity == 'medium' and events[0].entity == 'db-prod-02'
    assert events[1].external_id == '1729687900.200001' and events[1].severity == 'critical' and events[1].actor == 'svc_backup'
    assert events[1].category == 'endpoint'


def test_falco_alerts():
    events, _ = parse('falco', 'alerts.json')
    assert [e.action for e in events] == ['falco.terminal_shell_in_container', 'falco.launch_privileged_container', 'falco.read_sensitive_file_untrusted']
    assert [e.severity for e in events] == ['low', 'medium', 'high']
    assert [e.category for e in events] == ['k8s', 'k8s', 'process']
    shell, priv, sensitive = events
    assert shell.actor == 'root' and shell.entity == 'payments/checkout-api-7d9f8c6b5-x2k4q'
    assert shell.occurred_at == datetime(2026, 10, 23, 12, 45, 1, 812345, tzinfo=UTC)
    assert shell.metadata['namespace'] == 'payments' and shell.metadata['image'] == 'registry.internal/payments/checkout-api'
    assert priv.metadata['privileged'] is True and priv.metadata['pod'] == 'debug-tools' and priv.metadata['namespace'] == 'default'
    assert sensitive.metadata['file'] == '/etc/shadow' and sensitive.actor == 'www-data' and sensitive.external_id == '2f6c1b0a-6f21-4d4e-9b0f-falco-000003'


def test_trivy_report_findings_and_secret_event_without_values():
    events, findings = parse('trivy', 'report.json')
    assert len(events) == 1 and len(findings) == 5
    secret_event = events[0]
    assert secret_event.action == 'secret_detected' and secret_event.category == 'code' and secret_event.severity == 'critical'
    assert secret_event.metadata['secret_type'] == 'aws-access-key-id' and secret_event.metadata['file'] == 'app/config/settings.py' and secret_event.metadata['line'] == 14
    assert secret_event.occurred_at == datetime(2026, 10, 23, 12, 30, 0, tzinfo=UTC)
    rules = {f.rule for f in findings}
    assert 'misconfig:Dockerfile:DS002' in rules and 'secret:app/config/settings.py:aws-access-key-id' in rules and 'vuln:app/requirements.txt:CVE-2024-35195' in rules
    regresshion = next(f for f in findings if 'CVE-2024-6387' in f.rule)
    assert regresshion.cve_ids == ['CVE-2024-6387'] and regresshion.cvss == 8.1 and regresshion.severity == 'high' and regresshion.evidence['package'] == 'openssh-server'
    assert next(f for f in findings if 'CVE-2023-4911' in f.rule).severity == 'critical'
    everything = dumps([e.__dict__ for e in events]) + dumps([f.__dict__ for f in findings])
    assert 'AKIAIOSFODNN7EXAMPLE' not in everything and 'Match' not in everything


def test_cloudtrail_records_action_vocabulary_and_exposure_markers():
    events, _ = parse('aws_cloudtrail', 'records.json')
    assert [e.action for e in events] == ['sts.assume_role', 'iam.attach_user_policy', 's3.get_object', 's3.put_bucket_policy',
                                          'ec2.authorize_security_group_ingress', 'ec2.describe_instances']
    assert [e.severity for e in events] == ['low', 'medium', 'low', 'high', 'high', 'informational']
    assert [e.category for e in events] == ['identity', 'identity', 'data_access', 'cloud_api', 'cloud_api', 'cloud_api']
    assume, attach, get, policy, sg, describe = events
    assert assume.actor == 'arn:aws:iam::123456789012:user/ci-deployer' and assume.entity == 'arn:aws:iam::123456789012:role/PaymentsAdmin'
    assert assume.external_id == 'ct-0001-assume-role' and assume.occurred_at == datetime(2026, 10, 23, 12, 0, 5, tzinfo=UTC)
    assert assume.metadata['ip'] == '198.51.100.23' and assume.metadata['user_agent'] == 'python-requests/2.32.3'
    assert assume.metadata['account'] == '123456789012' and assume.metadata['region'] == 'eu-west-1' and assume.metadata['service'] == 'sts'
    assert 'FwoGZXIvYXdzEExample' not in dumps(assume.metadata) and 'sessionToken' not in dumps(assume.metadata)
    assert attach.entity == 'ci-deployer' and attach.metadata['role'] == 'arn:aws:iam::123456789012:role/PaymentsAdmin' and attach.metadata['mfa'] == 'false'
    assert get.entity == 'payments-card-exports' and get.metadata['read_only'] is True
    assert policy.metadata['public'] is True and 'Principal:*' in policy.metadata['markers'] and policy.entity == 'marketing-assets-public'
    assert sg.metadata['markers'] == ['0.0.0.0/0'] and sg.entity == 'sg-0123456789abcdef0' and sg.metadata['request_parameters']['groupId'] == 'sg-0123456789abcdef0'
    assert describe.metadata['read_only'] is True and 'public' not in describe.metadata


def test_guardduty_raw_and_eventbridge_shapes():
    events, _ = parse('aws_guardduty', 'findings.json')
    exfil, probe = events
    assert exfil.action == 'guardduty.unauthorized_access' and exfil.severity == 'high' and exfil.category == 'cloud'
    assert exfil.actor == 'payments-api-instance-role' and exfil.entity == 'payments-api-instance-role'
    assert exfil.external_id == '6ab1c2d3e4f5a6b7c8d9e0f1a2b3c4d5' and exfil.occurred_at == datetime(2026, 10, 23, 12, 20, 9, tzinfo=UTC)
    assert exfil.metadata['ip'] == '198.51.100.23' and exfil.metadata['geo'] == {'lat': 6.4541, 'lon': 3.3947, 'country': 'NG', 'city': 'Lagos'}
    assert exfil.metadata['finding_type'] == 'UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS' and exfil.metadata['api'] == 'sts.get_caller_identity'
    assert exfil.metadata['region'] == 'eu-west-1' and exfil.metadata['account'] == '123456789012'
    assert probe.action == 'guardduty.recon' and probe.severity == 'low' and probe.entity == 'i-0fedcba9876543210'
    assert probe.external_id == '8cb2d1e0f9a8b7c6d5e4f3a2b1c0d9e8' and probe.metadata['resource_type'] == 'Instance'


def test_azure_defender_alert_and_activity_log():
    events, _ = parse('azure_defender', 'alerts.json')
    alert, nsg, role = events
    assert alert.action == 'defender.vm_suspicious_account_creation' and alert.severity == 'high' and alert.category == 'cloud'
    assert alert.actor == 'svc-backup2' and alert.entity == 'vm-payments-app-01' and alert.metadata['ip'] == '203.0.113.77'
    assert alert.external_id == 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d' and alert.metadata['subscription'] == '3b1f8c2e-4d5a-4e6f-9a7b-8c9d0e1f2a3b'
    assert alert.occurred_at == datetime(2026, 10, 23, 11, 58, 40, 123000, tzinfo=UTC)
    assert nsg.action == 'az.network.nsg.rule.write' and nsg.severity == 'high' and nsg.category == 'cloud_api'
    assert nsg.actor == 'bob.ops@contoso.example' and nsg.metadata['public'] is True and 'Internet' in nsg.metadata['markers']
    assert nsg.metadata['ip'] == '203.0.113.90' and nsg.metadata['resource_group'].lower() == 'rg-payments-prod' and nsg.metadata['region'] == 'westeurope'
    assert role.action == 'az.role_assignment.write' and role.category == 'identity' and role.severity == 'medium'


def test_gcp_scc_finding_and_audit_logs():
    events, _ = parse('gcp_scc', 'findings.json')
    finding, iam, impersonate = events
    assert finding.action == 'scc.public_bucket_acl' and finding.severity == 'high' and finding.category == 'cloud'
    assert finding.entity == '//storage.googleapis.com/payments-exports-eu' and finding.metadata['public'] is True and finding.metadata['project'] == 'payments-prod-412905'
    assert finding.external_id.startswith('organizations/987654321098/sources/')
    assert iam.action == 'storage.set_iam_policy' and iam.severity == 'high' and iam.category == 'identity'
    assert iam.actor == 'carol.data@example.com' and 'allUsers' in iam.metadata['markers'] and iam.metadata['ip'] == '203.0.113.120'
    assert iam.external_id == '-5q2zb1e3m8f9' and iam.metadata['project'] == 'payments-prod-412905' and iam.metadata['service'] == 'storage'
    assert impersonate.action == 'gcp.iam.impersonate' and impersonate.category == 'identity' and impersonate.metadata['impersonated'] is True
    assert impersonate.metadata['user_agent'].startswith('google-api-python-client')


def test_crowdstrike_detection_and_event_streams():
    events, _ = parse('crowdstrike', 'detections.json')
    detect, stream, audit = events
    assert detect.action == 'crowdstrike.execution' and detect.severity == 'high' and detect.category == 'endpoint'
    assert detect.actor == 'jdoe' and detect.entity == 'FIN-LT-0427' and detect.external_id == 'ldt:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d:4295032834'
    assert detect.metadata['ip'] == '203.0.113.201' and detect.metadata['technique'] == 'PowerShell' and detect.metadata['tactic'] == 'Execution'
    assert detect.metadata['parent'] == 'WINWORD.EXE' and detect.metadata['sha256'].startswith('9f914d42')
    assert stream.action == 'crowdstrike.credential_access' and stream.severity == 'critical' and stream.actor == 'svc_ansible' and stream.entity == 'ops-jump-03'
    assert stream.occurred_at == datetime(2026, 10, 23, 12, 16, 50, tzinfo=UTC) and stream.metadata['detect_name'] == 'CredentialDumpingViaLsass'
    assert audit.action == 'crowdstrike.console.create_api_client' and audit.category == 'auth' and audit.severity == 'medium'
    assert audit.actor == 'admin@example.com' and audit.metadata['ip'] == '203.0.113.5'


def test_sentinelone_threats():
    events, _ = parse('sentinelone', 'threats.json')
    malware, pua = events
    assert malware.action == 'sentinelone.threat.malware' and malware.severity == 'critical' and malware.category == 'endpoint'
    assert malware.actor == 'mike.r' and malware.entity == 'MKT-WS-0088' and malware.external_id == '2157203419586210873'
    assert malware.metadata['ip'] == '203.0.113.150' and malware.metadata['mitigation_status'] == 'not_mitigated' and 'Credential Access' in malware.metadata['tactics']
    assert malware.metadata['sha256'].startswith('f6d5c4b3') and malware.occurred_at == datetime(2026, 10, 23, 12, 30, 59, 998000, tzinfo=UTC)
    assert pua.action == 'sentinelone.threat.pua' and pua.severity == 'medium' and pua.entity == 'ci-runner-12' and pua.actor == 'build-agent'


def test_okta_system_log_geo_and_privilege_vocabulary():
    events, _ = parse('okta_logs', 'system_log.json')
    assert [e.action for e in events] == ['okta.user.session.start', 'okta.user.session.start', 'permission_added', 'permission_added', 'okta.user.session.start']
    assert [e.severity for e in events] == ['informational', 'informational', 'high', 'high', 'medium']
    assert [e.category for e in events] == ['auth', 'auth', 'identity', 'identity', 'auth']
    nyc, london, grant, group, failed = events
    assert nyc.source == 'okta' and nyc.actor == 'dana.k@example.com' and nyc.external_id == '0f6b8f2e-0a1b-4c2d-9e3f-okta00000001'
    assert nyc.metadata['ip'] == '198.51.100.40' and nyc.metadata['user_agent'].startswith('Mozilla/5.0 (Macintosh')
    assert nyc.metadata['geo'] == {'lat': 40.7484, 'lon': -73.9967, 'country': 'United States', 'city': 'New York'}
    assert london.metadata['geo']['country'] == 'United Kingdom' and london.metadata['is_proxy'] is True and london.metadata['threat_suspected'] == 'true'
    assert nyc.occurred_at == datetime(2026, 10, 23, 12, 0, tzinfo=UTC) and london.occurred_at == datetime(2026, 10, 23, 12, 12, tzinfo=UTC)
    assert grant.entity == 'svc-automation@example.com' and grant.metadata['event_type'] == 'user.account.privilege.grant'
    assert group.entity == 'svc-automation@example.com' and group.metadata['event_type'] == 'group.user_membership.add' and len(group.metadata['targets']) == 2
    assert failed.metadata['outcome'] == 'FAILURE' and failed.metadata['outcome_reason'] == 'INVALID_CREDENTIALS' and failed.actor == 'sam.t@example.com'


def test_okta_event_hook_envelope():
    events, _ = parse('okta_logs', 'event_hook.json')
    assert len(events) == 1 and events[0].action == 'okta.user.mfa.factor.deactivate' and events[0].severity == 'medium' and events[0].category == 'identity'


def test_k8s_audit_events_flags_and_vocabulary():
    events, _ = parse('k8s_audit', 'events.json')
    assert [e.action for e in events] == ['k8s.pods.create', 'k8s.secrets.get', 'k8s.clusterrolebinding.create', 'k8s.pods.exec', 'k8s.configmaps.list']
    assert [e.severity for e in events] == ['critical', 'low', 'medium', 'medium', 'informational']
    pod, secret, crb, exec_, cm = events
    assert pod.category == 'k8s' and pod.actor == 'ci-deployer@example.com' and pod.entity == 'payments/node-debugger-x7k2p'
    assert pod.metadata['privileged'] is True and pod.metadata['hostPID'] is True and pod.metadata['hostNetwork'] is True and 'hostIPC' not in pod.metadata
    assert pod.metadata['flags'] == ['hostNetwork', 'hostPID', 'privileged'] and pod.metadata['images'] == ['docker.io/library/ubuntu:24.04']
    assert pod.metadata['namespace'] == 'payments' and pod.metadata['ip'] == '10.20.9.14' and pod.metadata['user_agent'].startswith('kubectl')
    assert pod.external_id == '8d0e1f2a-3b4c-4d5e-9f6a-k8s000000001' and pod.occurred_at == datetime(2026, 10, 23, 12, 22, 0, 412000, tzinfo=UTC)
    assert secret.category == 'data_access' and secret.entity == 'payments/stripe-api-key' and secret.metadata['response_code'] == 200
    assert crb.actor == 'system:serviceaccount:payments:default' and crb.metadata['role_ref'] == 'cluster-admin' and crb.metadata['subjects'] == ['ServiceAccount:payments/default']
    assert exec_.metadata['subresource'] == 'exec' and cm.metadata['verb'] == 'list'


def test_github_webhooks():
    secret, _ = parse('github_webhook', 'secret_scanning_alert.json')
    assert len(secret) == 1 and secret[0].action == 'secret_detected' and secret[0].severity == 'critical' and secret[0].category == 'code'
    assert secret[0].source == 'github' and secret[0].entity == 'example-org/payments-api' and secret[0].actor == 'contractor-dev'
    assert secret[0].metadata['secret_type'] == 'aws_access_key_id' and secret[0].metadata['verified'] is True and secret[0].metadata['repo'] == 'example-org/payments-api'
    assert 'AKIAIOSFODNN7EXAMPLE' not in dumps(secret[0].metadata) and 'secret' not in secret[0].metadata
    code, code_findings = parse('github_webhook', 'code_scanning_alert.json')
    assert code[0].action == 'github.code_scanning_alert.created' and code[0].severity == 'high' and code[0].metadata['rule_id'] == 'py/sql-injection'
    assert code[0].metadata['file'] == 'app/reports/export.py' and code[0].metadata['line'] == 88
    assert len(code_findings) == 1 and code_findings[0].rule == 'code_scanning:example-org/payments-api:app/reports/export.py:py/sql-injection' and code_findings[0].severity == 'high'
    dep, dep_findings = parse('github_webhook', 'dependabot_alert.json')
    assert dep[0].action == 'github.dependabot_alert.created' and dep[0].metadata['package'] == 'cryptography' and dep[0].metadata['cve_id'] == 'CVE-2024-26130'
    assert len(dep_findings) == 1 and dep_findings[0].cve_ids == ['CVE-2024-26130'] and dep_findings[0].cvss == 7.5 and dep_findings[0].severity == 'high'
    assert dep_findings[0].rule == 'dependabot:example-org/payments-api:app/requirements.txt:GHSA-h4gh-qq45-vh27'
    public, _ = parse('github_webhook', 'repository_publicized.json')
    assert public[0].action == 'github.repository.publicized' and public[0].severity == 'high' and public[0].metadata['public'] is True
    assert public[0].entity == 'example-org/internal-tooling'
    member, _ = parse('github_webhook', 'member_added_admin.json')
    assert member[0].action == 'permission_added' and member[0].severity == 'high' and member[0].category == 'identity'
    assert member[0].actor == 'dana-k' and member[0].entity == 'example-org/payments-api:contractor-dev' and member[0].metadata['permission'] == 'admin'
    header_ctx = ParseContext(tenant_id='t1', source='github_webhook', headers={'X-GitHub-Event': 'ping', 'X-GitHub-Delivery': 'd-1'})
    assert registry.get('github_webhook').parse({'zen': 'Keep it logically awesome.', 'hook_id': 1}, header_ctx) == []
    delivery_ctx = ParseContext(tenant_id='t1', source='github_webhook', headers={'X-GitHub-Event': 'member', 'X-GitHub-Delivery': 'delivery-abc'})
    assert registry.get('github_webhook').parse(load('github_webhook', 'member_added_admin.json'), delivery_ctx)[0].external_id == 'delivery-abc'


def test_generic_ocsf_and_flat_events_drop_tokens():
    events, _ = parse('generic', 'events.json')
    ocsf, flat = events
    assert ocsf.action == 'authentication.logon' and ocsf.category == 'identity' and ocsf.severity == 'medium'
    assert ocsf.actor == 'ops-admin@example.com' and ocsf.entity == 'vpn-gw-01.example.com' and ocsf.external_id == 'ocsf-7b1c9d0e-0001'
    assert ocsf.metadata['ip'] == '192.0.2.44' and ocsf.metadata['geo'] == {'lat': 50.4501, 'lon': 30.5234, 'country': 'UA', 'city': 'Kyiv'}
    assert ocsf.metadata['user_agent'] == 'GlobalProtect/6.2.3' and ocsf.metadata['product'] == 'PAN-OS' and ocsf.occurred_at == datetime(2026, 10, 23, 12, 20, tzinfo=UTC)
    assert flat.action == 'data_access' and flat.category == 'data_access' and flat.actor == 'terraform-ci@example.com' and flat.entity == 'vault:kv/payments/stripe'
    assert flat.metadata['repo'] == 'example-org/infra' and flat.metadata['namespace'] == 'payments' and flat.metadata['service'] == 'vault'
    assert 'token' not in flat.metadata and 'hvs.CAESIJ0' not in dumps(flat.metadata)


def test_clean_metadata_bounds_and_redacts():
    big = 'x' * 3000
    data = {'ip': '1.2.3.4', 'raw_body': big, 'password': 'hunter22', 'nested': {'token': 'abc', 'keep': 'v', 'deep': {'a': {'b': {'c': {'d': 'too deep'}}}}},
            'key_text': 'AKIAIOSFODNN7EXAMPLE used', 'items': list(range(100)), 'none': None, 'empty': ''}
    out = clean_metadata(data)
    assert out['ip'] == '1.2.3.4' and 'raw_body' not in out and 'password' not in out and 'token' not in out['nested']
    assert out['nested']['keep'] == 'v' and 'AKIAIOSFODNN7EXAMPLE' not in dumps(out) and len(out['items']) == 50
    assert 'none' not in out and 'empty' not in out and 'd' not in dumps(out['nested'])
    huge = {f'k{i}': 'y' * 1500 for i in range(10)}
    bounded = clean_metadata(huge)
    assert len(dumps(bounded)) <= 6000 and bounded['truncated_keys']


def test_parse_time_variants():
    assert parse_time('2026-10-23T12:45:01.812345678Z') == datetime(2026, 10, 23, 12, 45, 1, 812345, tzinfo=UTC)
    assert parse_time('2026-10-23T12:45:00.000+0000') == datetime(2026, 10, 23, 12, 45, tzinfo=UTC)
    assert parse_time(1792757810) == datetime(2026, 10, 23, 12, 16, 50, tzinfo=UTC)
    assert parse_time(1792757810000) == datetime(2026, 10, 23, 12, 16, 50, tzinfo=UTC)
    assert parse_time('2026-10-23 12:45:00') == datetime(2026, 10, 23, 12, 45, tzinfo=UTC)
    assert parse_time('not a date') is None and parse_time(None) is None and parse_time('') is None


def test_snake_and_markers():
    assert snake('PutBucketPolicy') == 'put_bucket_policy' and snake('AuthorizeSecurityGroupIngress') == 'authorize_security_group_ingress'
    assert snake('Launch Privileged Container') == 'launch_privileged_container' and snake('VM_SuspiciousActivity') == 'vm_suspicious_activity'
    assert scan_markers({'policy': {'Statement': [{'Principal': '*'}]}}) == ['Principal:*']
    assert scan_markers({'cidr': '0.0.0.0/0', 'members': ['allUsers']}) == ['0.0.0.0/0', 'allUsers']
    assert scan_markers({'cidr': '10.0.0.0/8'}) == []


def test_schema_helpers():
    schema = {'type': 'object', 'additionalProperties': False, 'required': ['url'],
              'properties': {'url': {'type': 'string', 'format': 'uri'}, 'n': {'type': 'integer', 'minimum': 1, 'maximum': 5}, 'mode': {'type': 'string', 'enum': ['a', 'b']},
                             'to': {'type': 'array', 'items': {'type': 'string'}, 'minItems': 1}}}
    assert validate_schema(schema, {'url': 'https://x.test', 'n': 2, 'mode': 'a', 'to': ['a@b.c']}) == []
    errors = validate_schema(schema, {'n': 9, 'mode': 'z', 'extra': 1, 'to': []})
    assert any('url is required' in e for e in errors) and any('<= 5' in e for e in errors) and any('one of a, b' in e for e in errors)
    assert any('unknown key' in e for e in errors) and any('at least 1' in e for e in errors)
    assert validate_schema(schema, {'url': 'not a url'}) and validate_schema(schema, 'nope')
    assert is_secret_ref('env:X') and is_secret_ref('file:/run/secret') and not is_secret_ref('plain-value') and not is_secret_ref('env:')
    assert validate_secret_refs({'token': 'env:T'}, ['token']) == [] and validate_secret_refs({'token': 'literal'}, ['token'])
    assert validate_secret_refs({'other': 'env:T'}, ['token'])
    assert validate_no_inline_secrets({'api_token': 'x'}, ['api_token']) and validate_no_inline_secrets({'note': 'password=SuperSecret123'}, [])
    assert validate_no_inline_secrets({'url': 'https://x'}, ['api_token']) == []
    assert validate_topics(['finding.*', 'detection.created', '*']) == [] and validate_topics(['bogus.thing']) and validate_topics(['Finding.Created'])
    assert topic_matches(['finding.*'], 'finding.created') and topic_matches(['*'], 'agent.finished') and not topic_matches(['finding.created'], 'finding.resolved')
    assert severity_at_least('high', 'medium') and severity_at_least('medium', 'medium') and not severity_at_least('low', 'high') and severity_at_least('', 'high')


@pytest.mark.parametrize('source,name', [('wazuh', 'alerts.json'), ('falco', 'alerts.json'), ('aws_cloudtrail', 'records.json'), ('okta_logs', 'system_log.json'),
                                         ('k8s_audit', 'events.json'), ('generic', 'events.json')])
def test_parsers_tolerate_bad_items(source, name):
    parser = registry.get(source)
    payload = load(source, name)
    items = payload if isinstance(payload, list) else parser.items(payload)
    ctx = ParseContext(tenant_id='t1', source=source)
    drafts = parser.parse(list(items) + ['not-an-object', 42], ctx)
    assert len(drafts) >= 1 and len(ctx.errors) == 2 and all('not a JSON object' in e for e in ctx.errors)
    assert all(len(d.external_id) <= 128 and len(d.source) <= 30 and len(d.action) <= 120 and len(d.category) <= 40 for d in drafts)
    assert all(d.severity in {'critical', 'high', 'medium', 'low', 'informational'} for d in drafts)
