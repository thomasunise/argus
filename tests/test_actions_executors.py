"""Executor tests. No network and no cloud SDKs: boto3 and kubernetes clients are replaced by
recording fakes through the module-level factories, HTTP executors run against respx, and
token exchange helpers are monkeypatched. Each action type gets its pure `_plan()` checked
on fixture input plus dry_run/execute/rollback through the fakes."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import respx

from app.actions import catalog, load_executors
from app.actions.catalog import ActionError, ExecContext
from app.actions.executors import aws, azure, cloudflare, entra, gcp, github, kubernetes, okta, argus
from app.models import Asset, AssetAuthorization, Finding

FIX = Path(__file__).parent / 'fixtures' / 'actions'
load_executors()


def _fixture(name: str) -> dict:
    return json.loads((FIX / name).read_text(encoding='utf-8'))


async def _hb():
    return None


def ctx(settings, platform: str, *, db=None, dry_run=False) -> ExecContext:
    return ExecContext(tenant_id='t1', settings=settings, request=SimpleNamespace(id='req-0001'), logger=logging.getLogger('test'), heartbeat=_hb,
                       platform=platform, db=db, actor='tester', dry_run=dry_run)


class SdkError(Exception):
    """Stands in for botocore ClientError / kubernetes ApiException."""

    def __init__(self, code: str | int):
        super().__init__(str(code))
        if isinstance(code, int):
            self.status = code
        else:
            self.response = {'Error': {'Code': code}}


class FakeApi:
    """Records every method call; responses map method name -> value | Exception | callable(kwargs)."""

    def __init__(self, responses: dict | None = None):
        self.calls: list[tuple[str, tuple, dict]] = []
        self.responses = responses or {}

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)

        def call(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            value = self.responses.get(name)
            if isinstance(value, Exception):
                raise value
            if callable(value):
                return value(*args, **kwargs)
            return {} if value is None else value

        return call

    def names(self) -> list[str]:
        return [c[0] for c in self.calls]


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv('ACTIONS_AWS_ACCESS_KEY_ID', 'AKIATESTTESTTESTTEST')
    monkeypatch.setenv('ACTIONS_AWS_SECRET_ACCESS_KEY', 'secret')
    monkeypatch.setenv('ACTIONS_AZURE_TENANT_ID', 'tid')
    monkeypatch.setenv('ACTIONS_AZURE_CLIENT_ID', 'cid')
    monkeypatch.setenv('ACTIONS_AZURE_CLIENT_SECRET', 'csecret')
    monkeypatch.setenv('ACTIONS_AZURE_SUBSCRIPTION_ID', '00000000-0000-0000-0000-000000000001')
    monkeypatch.setenv('ACTIONS_GCP_ACCESS_TOKEN', 'ya29.test')
    monkeypatch.setenv('ACTIONS_K8S_KUBECONFIG', '/tmp/kubeconfig')
    monkeypatch.setenv('ACTIONS_OKTA_ORG_URL', 'https://acme.okta.com')
    monkeypatch.setenv('ACTIONS_OKTA_TOKEN', 'okta-token')
    monkeypatch.setenv('ACTIONS_GITHUB_TOKEN', 'ghp_testtoken')
    monkeypatch.setenv('ACTIONS_CLOUDFLARE_TOKEN', 'cf-token')


# ======================================================================== AWS


def _aws(monkeypatch, clients: dict[str, FakeApi]):
    monkeypatch.setattr(aws, '_client', lambda ctx, service: clients[service])


def test_aws_disable_access_key_plan():
    plan = aws.DisableAccessKey._plan({'user_name': 'deploy', 'access_key_id': 'AKIAIOSFODNN7EXAMPLE'})
    assert plan['call'] == 'UpdateAccessKey' and plan['kwargs'] == {'UserName': 'deploy', 'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'Status': 'Inactive'}
    assert plan['blast_radius']['entities'] == 1


@pytest.mark.asyncio
async def test_aws_disable_access_key_lifecycle(settings, env, monkeypatch):
    iam = FakeApi({'list_access_keys': {'AccessKeyMetadata': [{'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'Status': 'Active'}]}})
    _aws(monkeypatch, {'iam': iam})
    action = catalog.get('aws.iam.disable_access_key')
    params = {'user_name': 'deploy', 'access_key_id': 'AKIAIOSFODNN7EXAMPLE'}
    dry = await action.dry_run(params, ctx(settings, 'aws'))
    assert dry.ok and dry.blast_radius['entities'] == 1 and dry.details['current_status'] == 'Active'
    result = await action.execute(params, ctx(settings, 'aws'))
    assert result.ok and ('update_access_key', (), {'UserName': 'deploy', 'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'Status': 'Inactive'}) in iam.calls
    rb = await action.rollback(result.rollback_payload, ctx(settings, 'aws'))
    assert rb.ok and iam.calls[-1][2]['Status'] == 'Active'
    # missing user / key
    iam2 = FakeApi({'list_access_keys': SdkError('NoSuchEntity')})
    _aws(monkeypatch, {'iam': iam2})
    assert (await action.dry_run(params, ctx(settings, 'aws'))).ok is False
    assert action.validate({'user_name': 'deploy', 'access_key_id': 'lowercase'}) and not action.validate(params)


@pytest.mark.asyncio
async def test_aws_detach_policy(settings, env, monkeypatch):
    arn = 'arn:aws:iam::aws:policy/AdministratorAccess'
    plan = aws.DetachPolicy._plan({'principal_type': 'role', 'principal_name': 'ci', 'policy_arn': arn})
    assert plan['call'] == 'DetachRolePolicy' and plan['detach'] == 'detach_role_policy' and plan['kwargs'] == {'RoleName': 'ci', 'PolicyArn': arn}
    iam = FakeApi({'list_attached_role_policies': {'AttachedPolicies': [{'PolicyArn': arn, 'PolicyName': 'AdministratorAccess'}]}})
    _aws(monkeypatch, {'iam': iam})
    action = catalog.get('aws.iam.detach_policy')
    params = {'principal_type': 'role', 'principal_name': 'ci', 'policy_arn': arn}
    dry = await action.dry_run(params, ctx(settings, 'aws'))
    assert dry.ok and dry.warnings
    result = await action.execute(params, ctx(settings, 'aws'))
    assert ('detach_role_policy', (), {'RoleName': 'ci', 'PolicyArn': arn}) in iam.calls
    await action.rollback(result.rollback_payload, ctx(settings, 'aws'))
    assert iam.calls[-1][0] == 'attach_role_policy'
    iam.responses['list_attached_role_policies'] = {'AttachedPolicies': []}
    assert (await action.dry_run(params, ctx(settings, 'aws'))).ok is False


@pytest.mark.asyncio
async def test_aws_s3_block_public_access(settings, env, monkeypatch):
    plan = aws.BlockPublicAccess._plan({'bucket': 'my-bucket', 'block_public_acls': True, 'ignore_public_acls': False, 'block_public_policy': True, 'restrict_public_buckets': True})
    assert plan['kwargs']['PublicAccessBlockConfiguration']['IgnorePublicAcls'] is False
    s3 = FakeApi({'head_bucket': {}, 'get_public_access_block': SdkError('NoSuchPublicAccessBlockConfiguration')})
    _aws(monkeypatch, {'s3': s3})
    action = catalog.get('aws.s3.block_public_access')
    params = action.normalize({'bucket': 'my-bucket'})
    dry = await action.dry_run(params, ctx(settings, 'aws'))
    assert dry.ok and dry.details['previous'] is None
    result = await action.execute(params, ctx(settings, 'aws'))
    put = next(c for c in s3.calls if c[0] == 'put_public_access_block')
    assert put[2]['PublicAccessBlockConfiguration'] == {'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True}
    await action.rollback(result.rollback_payload, ctx(settings, 'aws'))
    assert s3.calls[-1][0] == 'delete_public_access_block'  # nothing existed before
    previous = {'BlockPublicAcls': False, 'IgnorePublicAcls': False, 'BlockPublicPolicy': False, 'RestrictPublicBuckets': False}
    await action.rollback({'bucket': 'my-bucket', 'previous': previous}, ctx(settings, 'aws'))
    assert s3.calls[-1][0] == 'put_public_access_block' and s3.calls[-1][2]['PublicAccessBlockConfiguration'] == previous
    s3.responses['head_bucket'] = SdkError('NoSuchBucket')
    assert (await action.dry_run(params, ctx(settings, 'aws'))).ok is False


@pytest.mark.asyncio
async def test_aws_revoke_sg_ingress(settings, env, monkeypatch):
    params = {'group_id': 'sg-0web00000000001', 'ip_protocol': 'tcp', 'from_port': 22, 'to_port': 22, 'cidr_ipv4': '0.0.0.0/0'}
    plan = aws.RevokeSgIngress._plan(params)
    assert plan['kwargs'] == {'GroupId': 'sg-0web00000000001', 'IpPermissions': [{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]}
    with pytest.raises(ActionError):
        aws.RevokeSgIngress._plan({'group_id': 'sg-0web00000000001', 'ip_protocol': 'tcp', 'from_port': 22, 'to_port': 22})
    with pytest.raises(ActionError):
        aws.RevokeSgIngress._plan({'group_id': 'sg-0web00000000001', 'ip_protocol': 'tcp', 'cidr_ipv4': '0.0.0.0/0'})
    assert aws.RevokeSgIngress._plan({'group_id': 'sg-0web00000000001', 'ip_protocol': '-1', 'source_group_id': 'sg-0ssh00000000002'})['kwargs']['IpPermissions'][0] == \
        {'IpProtocol': '-1', 'UserIdGroupPairs': [{'GroupId': 'sg-0ssh00000000002'}]}
    ec2 = FakeApi({'describe_security_groups': _fixture('aws_describe_sg_rules.json'),
                   'describe_network_interfaces': {'NetworkInterfaces': [{'NetworkInterfaceId': 'eni-1'}, {'NetworkInterfaceId': 'eni-2'}]}})
    _aws(monkeypatch, {'ec2': ec2})
    action = catalog.get('aws.ec2.revoke_sg_ingress')
    dry = await action.dry_run(params, ctx(settings, 'aws'))
    assert dry.ok and dry.blast_radius['attached_interfaces'] == 2 and dry.warnings
    result = await action.execute(params, ctx(settings, 'aws'))
    assert ec2.calls[-1][0] == 'revoke_security_group_ingress' and ec2.calls[-1][2] == plan['kwargs']
    await action.rollback(result.rollback_payload, ctx(settings, 'aws'))
    assert ec2.calls[-1][0] == 'authorize_security_group_ingress' and ec2.calls[-1][2] == plan['kwargs']
    absent = dict(params, from_port=3389, to_port=3389)
    assert (await action.dry_run(absent, ctx(settings, 'aws'))).ok is False


@pytest.mark.asyncio
async def test_aws_isolate_instance(settings, env, monkeypatch):
    instance = _fixture('aws_describe_instances.json')['Reservations'][0]['Instances'][0]
    quarantine = _fixture('aws_quarantine_sg.json')['SecurityGroups'][0]
    plan = aws.IsolateInstance._plan(instance, quarantine)
    assert len(plan['calls']) == 2 and plan['calls'][0]['kwargs'] == {'NetworkInterfaceId': 'eni-0aaa111', 'Groups': ['sg-0quarantine00009']}
    assert plan['interfaces'][0]['groups'] == ['sg-0web00000000001', 'sg-0ssh00000000002']
    assert any('egress' in w for w in plan['warnings']) and plan['blast_radius']['interfaces'] == 2
    with pytest.raises(ActionError):
        aws.IsolateInstance._plan(instance, dict(quarantine, VpcId='vpc-other'))
    ec2 = FakeApi({'describe_instances': _fixture('aws_describe_instances.json'), 'describe_security_groups': _fixture('aws_quarantine_sg.json')})
    _aws(monkeypatch, {'ec2': ec2})
    action = catalog.get('aws.ec2.isolate_instance')
    params = {'instance_id': 'i-0abc123def4567890', 'quarantine_sg_id': 'sg-0quarantine00009'}
    assert (await action.dry_run(params, ctx(settings, 'aws'))).ok
    result = await action.execute(params, ctx(settings, 'aws'))
    mods = [c for c in ec2.calls if c[0] == 'modify_network_interface_attribute']
    assert [m[2]['Groups'] for m in mods] == [['sg-0quarantine00009'], ['sg-0quarantine00009']]
    await action.rollback(result.rollback_payload, ctx(settings, 'aws'))
    restored = [c for c in ec2.calls if c[0] == 'modify_network_interface_attribute'][2:]
    assert [m[2]['Groups'] for m in restored] == [['sg-0web00000000001', 'sg-0ssh00000000002'], ['sg-0db000000000003']]
    ec2.responses['describe_instances'] = {'Reservations': []}
    assert (await action.dry_run(params, ctx(settings, 'aws'))).ok is False


@pytest.mark.asyncio
async def test_aws_attach_deny_all_boundary(settings, env, monkeypatch):
    arn = 'arn:aws:iam::123456789012:policy/ArgusDenyAll'
    params = {'principal_type': 'user', 'principal_name': 'mallory', 'boundary_policy_arn': arn}
    plan = aws.AttachDenyAllBoundary._plan(params)
    assert plan['call'] == 'PutUserPermissionsBoundary' and plan['kwargs'] == {'UserName': 'mallory', 'PermissionsBoundary': arn}
    iam = FakeApi({'get_policy': {'Policy': {'Arn': arn}}, 'get_user': {'User': {'UserName': 'mallory', 'PermissionsBoundary': {'PermissionsBoundaryArn': 'arn:aws:iam::123456789012:policy/Old'}}}})
    _aws(monkeypatch, {'iam': iam})
    action = catalog.get('aws.iam.attach_deny_all_boundary')
    assert action.risk == 'critical'
    dry = await action.dry_run(params, ctx(settings, 'aws'))
    assert dry.ok and any('replaced' in w for w in dry.warnings)
    result = await action.execute(params, ctx(settings, 'aws'))
    assert iam.calls[-1][0] == 'put_user_permissions_boundary' and result.rollback_payload['previous_boundary'].endswith('/Old')
    await action.rollback(result.rollback_payload, ctx(settings, 'aws'))
    assert iam.calls[-1][0] == 'put_user_permissions_boundary' and iam.calls[-1][2]['PermissionsBoundary'].endswith('/Old')
    await action.rollback({'principal_type': 'role', 'principal_name': 'r', 'previous_boundary': None}, ctx(settings, 'aws'))
    assert iam.calls[-1][0] == 'delete_role_permissions_boundary'
    iam.responses['get_policy'] = SdkError('NoSuchEntity')
    assert (await action.dry_run(params, ctx(settings, 'aws'))).ok is False


# ======================================================================== Azure / Entra


@pytest.fixture
def azure_token(monkeypatch):
    async def fake_token(ctx, scope, platform=None):
        return 'azure-token'

    monkeypatch.setattr(azure, 'token', fake_token)


@pytest.mark.asyncio
async def test_azure_token_exchange(settings, env):
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post('https://login.microsoftonline.com/tid/oauth2/v2.0/token').mock(return_value=httpx.Response(200, json={'access_token': 'abc'}))
        assert await azure.token(ctx(settings, 'azure'), azure.ARM_SCOPE) == 'abc'
        sent = route.calls.last.request
        assert b'client_secret=csecret' in sent.content and b'grant_type=client_credentials' in sent.content


@pytest.mark.asyncio
async def test_azure_nsg_remove_rule(settings, env, azure_token):
    params = {'resource_group': 'rg', 'nsg_name': 'web-nsg', 'rule_name': 'allow-ssh-any'}
    plan = azure.RemoveNsgRule._plan(params, 'sub-1')
    assert plan['path'] == '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/web-nsg/securityRules/allow-ssh-any'
    rule = _fixture('azure_nsg_rule.json')
    base = 'https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/web-nsg'
    action = catalog.get('azure.nsg.remove_rule')
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f'{base}/securityRules/allow-ssh-any').mock(return_value=httpx.Response(200, json=rule))
        mock.get(base).mock(return_value=httpx.Response(200, json={'properties': {'subnets': [{}], 'networkInterfaces': [{}, {}]}}))
        delete = mock.delete(f'{base}/securityRules/allow-ssh-any').mock(return_value=httpx.Response(202))
        put = mock.put(f'{base}/securityRules/allow-ssh-any').mock(return_value=httpx.Response(201, json=rule))
        dry = await action.dry_run(params, ctx(settings, 'azure'))
        assert dry.ok and dry.blast_radius['attached_nics'] == 2 and 'Inbound Allow Tcp' in dry.summary
        result = await action.execute(params, ctx(settings, 'azure'))
        assert delete.called and result.rollback_payload['properties']['destinationPortRange'] == '22'
        assert 'provisioningState' not in result.rollback_payload['properties']
        assert delete.calls.last.request.headers['Authorization'] == 'Bearer azure-token'
        await action.rollback(result.rollback_payload, ctx(settings, 'azure'))
        assert json.loads(put.calls.last.request.content)['properties']['access'] == 'Allow'
        mock.get(f'{base}/securityRules/allow-ssh-any').mock(return_value=httpx.Response(404, json={'error': {'code': 'NotFound'}}))
        assert (await action.dry_run(params, ctx(settings, 'azure'))).ok is False


@pytest.mark.asyncio
async def test_azure_storage_disable_public_blob_access(settings, env, azure_token):
    params = {'resource_group': 'rg', 'account_name': 'acmestore'}
    plan = azure.DisablePublicBlobAccess._plan(params, 'sub')
    assert plan['json'] == {'properties': {'allowBlobPublicAccess': False}} and plan['path'].endswith('/storageAccounts/acmestore')
    url = 'https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acmestore'
    action = catalog.get('azure.storage.disable_public_blob_access')
    with respx.mock(assert_all_called=False) as mock:
        mock.get(url).mock(return_value=httpx.Response(200, json={'properties': {'allowBlobPublicAccess': True}}))
        patch = mock.patch(url).mock(return_value=httpx.Response(200, json={}))
        dry = await action.dry_run(params, ctx(settings, 'azure'))
        assert dry.ok and dry.details['previous'] is True
        result = await action.execute(params, ctx(settings, 'azure'))
        assert json.loads(patch.calls.last.request.content) == {'properties': {'allowBlobPublicAccess': False}}
        await action.rollback(result.rollback_payload, ctx(settings, 'azure'))
        assert json.loads(patch.calls.last.request.content) == {'properties': {'allowBlobPublicAccess': True}}


@pytest.mark.asyncio
async def test_azure_ad_revoke_sessions_and_disable_user(settings, env, azure_token):
    user = {'id': 'u-123', 'userPrincipalName': 'mallory@acme.com', 'accountEnabled': True}
    assert azure.RevokeUserSessions._plan(user)['path'] == '/users/u-123/revokeSignInSessions'
    assert azure.DisableUser._plan(user)['json'] == {'accountEnabled': False}
    revoke, disable = catalog.get('azure.ad.revoke_user_sessions'), catalog.get('azure.ad.disable_user')
    assert revoke.reversible is False and revoke.risk == 'high'
    with respx.mock(assert_all_called=False) as mock:
        mock.get('https://graph.microsoft.com/v1.0/users/mallory@acme.com').mock(return_value=httpx.Response(200, json=user))
        post = mock.post('https://graph.microsoft.com/v1.0/users/u-123/revokeSignInSessions').mock(return_value=httpx.Response(200, json={'value': True}))
        patch = mock.patch('https://graph.microsoft.com/v1.0/users/u-123').mock(return_value=httpx.Response(204))
        assert (await revoke.dry_run({'user': 'mallory@acme.com'}, ctx(settings, 'azure'))).ok
        result = await revoke.execute({'user': 'mallory@acme.com'}, ctx(settings, 'azure'))
        assert result.ok and post.called and result.rollback_payload is None
        rb = await revoke.rollback({}, ctx(settings, 'azure'))
        assert rb.ok is False
        result = await disable.execute({'user': 'mallory@acme.com'}, ctx(settings, 'azure'))
        assert json.loads(patch.calls.last.request.content) == {'accountEnabled': False} and result.rollback_payload == {'id': 'u-123', 'previous_enabled': True}
        await disable.rollback(result.rollback_payload, ctx(settings, 'azure'))
        assert json.loads(patch.calls.last.request.content) == {'accountEnabled': True}
        mock.get('https://graph.microsoft.com/v1.0/users/ghost').mock(return_value=httpx.Response(404, json={'error': {'code': 'Request_ResourceNotFound'}}))
        assert (await disable.dry_run({'user': 'ghost'}, ctx(settings, 'azure'))).ok is False


@pytest.mark.asyncio
async def test_entra_disable_user_uses_entra_credentials(settings, env, monkeypatch):
    seen = {}

    async def fake_token(ctx, scope, platform=None):
        seen['platform'] = platform
        seen['tenant'] = ctx.require_credential('tenant_id', platform)
        return 'entra-token'

    monkeypatch.setattr(azure, 'token', fake_token)
    monkeypatch.setenv('ACTIONS_ENTRA_TENANT_ID', 'entra-tenant')
    action = catalog.get('entra.user.disable')
    assert isinstance(action, entra.EntraDisableUser) and action.platform == 'entra'
    with respx.mock(assert_all_called=True) as mock:
        mock.get('https://graph.microsoft.com/v1.0/users/u-9').mock(return_value=httpx.Response(200, json={'id': 'u-9', 'userPrincipalName': 'x@y', 'accountEnabled': True}))
        mock.patch('https://graph.microsoft.com/v1.0/users/u-9').mock(return_value=httpx.Response(204))
        result = await action.execute({'user': 'u-9'}, ctx(settings, 'entra'))
    assert result.ok and seen == {'platform': 'entra', 'tenant': 'entra-tenant'}


# ======================================================================== GCP


@pytest.mark.asyncio
async def test_gcp_firewall_disable_rule(settings, env):
    params = {'project': 'acme-prod', 'name': 'allow-all-ssh'}
    plan = gcp.DisableFirewallRule._plan(params)
    assert plan['url'] == 'https://compute.googleapis.com/compute/v1/projects/acme-prod/global/firewalls/allow-all-ssh' and plan['json'] == {'disabled': True}
    action = catalog.get('gcp.firewall.disable_rule')
    with respx.mock(assert_all_called=False) as mock:
        mock.get(plan['url']).mock(return_value=httpx.Response(200, json={'name': 'allow-all-ssh', 'disabled': False, 'direction': 'INGRESS', 'network': 'global/networks/default', 'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}]}))
        patch = mock.patch(plan['url']).mock(return_value=httpx.Response(200, json={'kind': 'compute#operation'}))
        dry = await action.dry_run(params, ctx(settings, 'gcp'))
        assert dry.ok and dry.blast_radius['network'] == 'default'
        result = await action.execute(params, ctx(settings, 'gcp'))
        assert patch.calls.last.request.headers['Authorization'] == 'Bearer ya29.test' and json.loads(patch.calls.last.request.content) == {'disabled': True}
        await action.rollback(result.rollback_payload, ctx(settings, 'gcp'))
        assert json.loads(patch.calls.last.request.content) == {'disabled': False}
        mock.get(plan['url']).mock(return_value=httpx.Response(404, json={'error': {'code': 404}}))
        assert (await action.dry_run(params, ctx(settings, 'gcp'))).ok is False


def test_gcp_storage_remove_public_binding_plan():
    policy = _fixture('gcp_bucket_policy.json')
    plan = gcp.RemovePublicBucketBinding._plan(policy, ['allUsers', 'allAuthenticatedUsers'])
    assert [r['member'] for r in plan['removed']] == ['allUsers', 'allAuthenticatedUsers']
    roles = {b['role']: b['members'] for b in plan['bindings']}
    assert roles == {'roles/storage.objectViewer': ['user:alice@example.com'], 'roles/storage.admin': ['user:alice@example.com']}
    assert gcp._restore(plan['bindings'], plan['removed']) == sorted(gcp._restore(plan['bindings'], plan['removed']), key=lambda b: 0)  # stable
    restored = {b['role']: sorted(b['members']) for b in gcp._restore(plan['bindings'], plan['removed'])}
    assert restored['roles/storage.objectViewer'] == ['allUsers', 'user:alice@example.com'] and restored['roles/storage.legacyBucketReader'] == ['allAuthenticatedUsers']


@pytest.mark.asyncio
async def test_gcp_storage_remove_public_binding(settings, env):
    policy = _fixture('gcp_bucket_policy.json')
    action = catalog.get('gcp.storage.remove_public_binding')
    params = action.normalize({'bucket': 'acme-public'})
    url = 'https://storage.googleapis.com/storage/v1/b/acme-public/iam'
    with respx.mock(assert_all_called=False) as mock:
        mock.get(url).mock(return_value=httpx.Response(200, json=policy))
        put = mock.put(url).mock(return_value=httpx.Response(200, json={}))
        dry = await action.dry_run(params, ctx(settings, 'gcp'))
        assert dry.ok and dry.blast_radius['bindings_removed'] == 2
        result = await action.execute(params, ctx(settings, 'gcp'))
        sent = json.loads(put.calls.last.request.content)
        assert sent['etag'] == 'CAE=' and not any(m in ('allUsers', 'allAuthenticatedUsers') for b in sent['bindings'] for m in b['members'])
        await action.rollback(result.rollback_payload, ctx(settings, 'gcp'))
        sent = json.loads(put.calls.last.request.content)
        assert any('allUsers' in b['members'] for b in sent['bindings'])


@pytest.mark.asyncio
async def test_gcp_iam_remove_binding(settings, env):
    policy = _fixture('gcp_project_policy.json')
    plan = gcp.RemoveIamBinding._plan(policy, 'roles/editor', 'user:mallory@example.com')
    assert plan['removed'] == [{'role': 'roles/editor', 'member': 'user:mallory@example.com', 'condition': None}]
    assert next(b for b in plan['bindings'] if b['role'] == 'roles/editor')['members'] == ['serviceAccount:ci@proj.iam.gserviceaccount.com']
    conditional = gcp.RemoveIamBinding._plan(policy, 'roles/viewer', 'user:mallory@example.com')
    assert conditional['removed'][0]['condition']['title'] == 'temp' and not any(b['role'] == 'roles/viewer' for b in conditional['bindings'])
    last_owner = gcp.RemoveIamBinding._plan({'bindings': [{'role': 'roles/owner', 'members': ['user:solo@example.com']}]}, 'roles/owner', 'user:solo@example.com')
    assert last_owner['warnings']
    assert gcp.RemoveIamBinding._plan(policy, 'roles/editor', 'user:nobody@example.com')['removed'] == []
    action = catalog.get('gcp.iam.remove_binding')
    params = {'project': 'acme-prod', 'role': 'roles/editor', 'member': 'user:mallory@example.com'}
    get_url, set_url = gcp.RemoveIamBinding._urls('acme-prod')
    with respx.mock(assert_all_called=False) as mock:
        mock.post(get_url).mock(return_value=httpx.Response(200, json=policy))
        setp = mock.post(set_url).mock(return_value=httpx.Response(200, json={}))
        assert (await action.dry_run(params, ctx(settings, 'gcp'))).ok
        result = await action.execute(params, ctx(settings, 'gcp'))
        sent = json.loads(setp.calls.last.request.content)['policy']
        assert sent['etag'] == 'BwX123' and 'user:mallory@example.com' not in next(b for b in sent['bindings'] if b['role'] == 'roles/editor')['members']
        await action.rollback(result.rollback_payload, ctx(settings, 'gcp'))
        sent = json.loads(setp.calls.last.request.content)['policy']
        assert 'user:mallory@example.com' in next(b for b in sent['bindings'] if b['role'] == 'roles/editor')['members']
        mock.post(get_url).mock(return_value=httpx.Response(403, json={'error': {'code': 403}}))
        assert (await action.dry_run(params, ctx(settings, 'gcp'))).ok is False


# ======================================================================== Kubernetes


def _pod(name='web-abc12', labels=None, owner=True):
    refs = [SimpleNamespace(kind='ReplicaSet', name='web-5d4f')] if owner else []
    return SimpleNamespace(metadata=SimpleNamespace(name=name, namespace='prod', labels=labels or {'app': 'web'}, owner_references=refs))


def _k8s(monkeypatch, core=None, apps=None, networking=None):
    fake = SimpleNamespace(core=core or FakeApi(), apps=apps or FakeApi(), networking=networking or FakeApi())
    monkeypatch.setattr(kubernetes, '_clients', lambda ctx: fake)
    return fake


def test_k8s_isolate_pod_plan():
    plan = kubernetes.IsolatePod._plan('prod', 'web-abc12')
    manifest = plan['manifest']
    assert manifest['kind'] == 'NetworkPolicy' and manifest['metadata']['name'] == 'argus-isolate-web-abc12'
    assert manifest['spec'] == {'podSelector': {'matchLabels': {'argus.io/isolated': 'web-abc12'}}, 'policyTypes': ['Ingress', 'Egress']}
    assert 'ingress' not in manifest['spec'] and 'egress' not in manifest['spec']  # deny-all
    long_name = 'p' * 70
    assert len(kubernetes.IsolatePod._plan('prod', long_name)['policy_name']) <= 63


@pytest.mark.asyncio
async def test_k8s_isolate_pod_lifecycle(settings, env, monkeypatch):
    core = FakeApi({'read_namespaced_pod': _pod()})
    networking = FakeApi({'read_namespaced_network_policy': SdkError(404)})
    _k8s(monkeypatch, core=core, networking=networking)
    action = catalog.get('kubernetes.network_policy.isolate_pod')
    params = {'namespace': 'prod', 'pod': 'web-abc12'}
    dry = await action.dry_run(params, ctx(settings, 'kubernetes'))
    assert dry.ok and dry.blast_radius['owner'] == 'ReplicaSet/web-5d4f'
    result = await action.execute(params, ctx(settings, 'kubernetes'))
    assert core.calls[-1][0] == 'patch_namespaced_pod' and core.calls[-1][1][2] == {'metadata': {'labels': {'argus.io/isolated': 'web-abc12'}}}
    assert networking.names()[-1] == 'create_namespaced_network_policy' and networking.calls[-1][1][0] == 'prod'
    assert result.rollback_payload['created_policy'] is True and result.rollback_payload['previous_label'] is None
    await action.rollback(result.rollback_payload, ctx(settings, 'kubernetes'))
    assert networking.names()[-1] == 'delete_namespaced_network_policy' and networking.calls[-1][1] == ('argus-isolate-web-abc12', 'prod')
    assert core.calls[-1][1][2] == {'metadata': {'labels': {'argus.io/isolated': None}}}
    core.responses['read_namespaced_pod'] = SdkError(404)
    assert (await action.dry_run(params, ctx(settings, 'kubernetes'))).ok is False


@pytest.mark.asyncio
async def test_k8s_scale_to_zero(settings, env, monkeypatch):
    plan = kubernetes.ScaleToZero._plan({'namespace': 'prod', 'kind': 'statefulset', 'name': 'db'})
    assert plan['scale'] == 'patch_namespaced_stateful_set_scale' and plan['body'] == {'spec': {'replicas': 0}}
    apps = FakeApi({'read_namespaced_deployment': SimpleNamespace(spec=SimpleNamespace(replicas=3))})
    _k8s(monkeypatch, apps=apps)
    action = catalog.get('kubernetes.scale_to_zero')
    params = {'namespace': 'prod', 'kind': 'deployment', 'name': 'web'}
    dry = await action.dry_run(params, ctx(settings, 'kubernetes'))
    assert dry.ok and dry.blast_radius['replicas'] == 3 and any('3 running' in w for w in dry.warnings)
    result = await action.execute(params, ctx(settings, 'kubernetes'))
    assert apps.calls[-1] == ('patch_namespaced_deployment_scale', ('web', 'prod', {'spec': {'replicas': 0}}), {})
    await action.rollback(result.rollback_payload, ctx(settings, 'kubernetes'))
    assert apps.calls[-1] == ('patch_namespaced_deployment_scale', ('web', 'prod', {'spec': {'replicas': 3}}), {})


@pytest.mark.asyncio
async def test_k8s_delete_pod(settings, env, monkeypatch):
    plan = kubernetes.DeletePod._plan({'namespace': 'prod', 'pod': 'bare', 'grace_period_seconds': 5})
    assert plan['args'] == ('bare', 'prod') and plan['kwargs'] == {'grace_period_seconds': 5} and 'permanent' in plan['warnings'][0]
    core = FakeApi({'read_namespaced_pod': _pod(owner=False)})
    _k8s(monkeypatch, core=core)
    action = catalog.get('kubernetes.delete_pod')
    assert action.reversible is False and action.risk == 'high'
    params = action.normalize({'namespace': 'prod', 'pod': 'web-abc12'})
    dry = await action.dry_run(params, ctx(settings, 'kubernetes'))
    assert dry.ok and 'permanent' in dry.warnings[0]
    result = await action.execute(params, ctx(settings, 'kubernetes'))
    assert result.ok and core.calls[-1] == ('delete_namespaced_pod', ('web-abc12', 'prod'), {'grace_period_seconds': 30})
    assert (await action.rollback({}, ctx(settings, 'kubernetes'))).ok is False


# ======================================================================== GitHub


def test_github_branch_protection_plan_and_normalize():
    plan = github.EnableBranchProtection._plan({'owner': 'acme', 'repo': 'app', 'branch': 'main', 'required_approving_review_count': 2, 'required_status_checks': ['ci/build']})
    assert plan['path'] == '/repos/acme/app/branches/main/protection'
    assert plan['json']['required_pull_request_reviews']['required_approving_review_count'] == 2
    assert plan['json']['required_status_checks'] == {'strict': True, 'contexts': ['ci/build']} and plan['json']['enforce_admins'] is True
    assert github.EnableBranchProtection._plan({'owner': 'acme', 'repo': 'app', 'branch': 'main'})['json']['required_status_checks'] is None
    previous = github.normalize_protection(_fixture('github_protection.json'))
    assert previous == {'required_status_checks': {'strict': False, 'contexts': ['ci/build']}, 'enforce_admins': False,
                        'required_pull_request_reviews': {'dismiss_stale_reviews': False, 'require_code_owner_reviews': True, 'required_approving_review_count': 2},
                        'restrictions': None, 'allow_force_pushes': False, 'allow_deletions': False}


@pytest.mark.asyncio
async def test_github_branch_protection_lifecycle(settings, env):
    action = catalog.get('github.branch_protection.enable')
    params = action.normalize({'owner': 'acme', 'repo': 'app', 'branch': 'main'})
    with respx.mock(base_url='https://api.github.com', assert_all_called=False) as mock:
        mock.get('/repos/acme/app/branches/main').mock(return_value=httpx.Response(200, json={'name': 'main'}))
        mock.get('/repos/acme/app/branches/main/protection').mock(return_value=httpx.Response(404, json={'message': 'Branch not protected'}))
        put = mock.put('/repos/acme/app/branches/main/protection').mock(return_value=httpx.Response(200, json={}))
        delete = mock.delete('/repos/acme/app/branches/main/protection').mock(return_value=httpx.Response(204))
        dry = await action.dry_run(params, ctx(settings, 'github'))
        assert dry.ok and dry.details['previous'] is None
        result = await action.execute(params, ctx(settings, 'github'))
        assert put.calls.last.request.headers['Authorization'] == 'Bearer ghp_testtoken'
        assert json.loads(put.calls.last.request.content)['required_pull_request_reviews']['required_approving_review_count'] == 1
        await action.rollback(result.rollback_payload, ctx(settings, 'github'))
        assert delete.called
        mock.get('/repos/acme/app/branches/main/protection').mock(return_value=httpx.Response(200, json=_fixture('github_protection.json')))
        result = await action.execute(params, ctx(settings, 'github'))
        await action.rollback(result.rollback_payload, ctx(settings, 'github'))
        assert json.loads(put.calls.last.request.content)['required_pull_request_reviews']['required_approving_review_count'] == 2
        mock.get('/repos/acme/app/branches/main').mock(return_value=httpx.Response(404, json={}))
        assert (await action.dry_run(params, ctx(settings, 'github'))).ok is False


@pytest.mark.asyncio
async def test_github_secret_scanning(settings, env):
    plan = github.EnableSecretScanning._plan({'owner': 'acme', 'repo': 'app', 'push_protection': True})
    assert plan['json'] == {'security_and_analysis': {'secret_scanning': {'status': 'enabled'}, 'secret_scanning_push_protection': {'status': 'enabled'}}}
    assert 'secret_scanning_push_protection' not in github.EnableSecretScanning._plan({'owner': 'acme', 'repo': 'app', 'push_protection': False})['json']['security_and_analysis']
    action = catalog.get('github.secret_scanning.enable')
    assert action.risk == 'low'
    params = action.normalize({'owner': 'acme', 'repo': 'app'})
    with respx.mock(base_url='https://api.github.com', assert_all_called=False) as mock:
        mock.get('/repos/acme/app').mock(return_value=httpx.Response(200, json={'visibility': 'private', 'security_and_analysis': {
            'secret_scanning': {'status': 'disabled'}, 'secret_scanning_push_protection': {'status': 'disabled'}}}))
        patch = mock.patch('/repos/acme/app').mock(return_value=httpx.Response(200, json={}))
        assert (await action.dry_run(params, ctx(settings, 'github'))).ok
        result = await action.execute(params, ctx(settings, 'github'))
        assert result.rollback_payload['previous'] == {'secret_scanning': 'disabled', 'secret_scanning_push_protection': 'disabled'}
        await action.rollback(result.rollback_payload, ctx(settings, 'github'))
        assert json.loads(patch.calls.last.request.content)['security_and_analysis']['secret_scanning'] == {'status': 'disabled'}


def test_github_open_fix_pr_plan():
    params = {'owner': 'acme', 'repo': 'app', 'head_branch': 'argus/fix-1', 'title': 'Pin base image',
              'files': [{'path': 'Dockerfile', 'content': 'FROM python:3.12-slim\nRUN pip install x\n'},
                        {'path': 'NEW.md', 'content': 'hello\n'},
                        {'path': 'old.txt', 'delete': True}]}
    existing = {'Dockerfile': 'FROM python:latest\nRUN pip install x\n', 'NEW.md': None, 'old.txt': 'a\nb\n'}
    plan = github.OpenFixPr._plan(params, existing)
    assert plan['files'] == [{'path': 'Dockerfile', 'action': 'modify', 'added': 1, 'removed': 1},
                             {'path': 'NEW.md', 'action': 'add', 'added': 1, 'removed': 0},
                             {'path': 'old.txt', 'action': 'delete', 'added': 0, 'removed': 2}]
    assert plan['added'] == 2 and plan['removed'] == 3 and plan['commit_message'] == 'Pin base image'
    with pytest.raises(ActionError):
        github.OpenFixPr._plan({**params, 'files': [{'path': 'ghost', 'delete': True}]}, {'ghost': None})
    with pytest.raises(ActionError):
        github.OpenFixPr._plan({**params, 'files': [{'path': 'b', 'content': '!!!', 'encoding': 'base64'}]}, {'b': None})
    action = catalog.get('github.open_fix_pr')
    assert action.validate({**params, 'files': [{'path': '../etc/passwd', 'content': 'x'}]})
    assert action.validate({**params, 'head_branch': 'a..b'})
    assert not action.validate(params)


@pytest.mark.asyncio
async def test_github_open_fix_pr_lifecycle(settings, env):
    action = catalog.get('github.open_fix_pr')
    params = action.normalize({'owner': 'acme', 'repo': 'app', 'head_branch': 'argus/fix-1', 'title': 'Pin base image', 'body': 'why',
                               'files': [{'path': 'Dockerfile', 'content': 'FROM python:3.12-slim\n'}, {'path': 'docs/NEW.md', 'content': 'hello\n'}]})
    import base64

    with respx.mock(base_url='https://api.github.com', assert_all_called=False) as mock:
        mock.get('/repos/acme/app').mock(return_value=httpx.Response(200, json={'default_branch': 'main'}))
        mock.get('/repos/acme/app/branches/main').mock(return_value=httpx.Response(200, json={'commit': {'sha': 'base-sha'}}))
        mock.get('/repos/acme/app/git/ref/heads/argus/fix-1').mock(return_value=httpx.Response(404, json={}))
        mock.get('/repos/acme/app/contents/Dockerfile').mock(return_value=httpx.Response(200, json={'sha': 'old-sha', 'encoding': 'base64',
                                                                                                      'content': base64.b64encode(b'FROM python:latest\n').decode()}))
        mock.get('/repos/acme/app/contents/docs/NEW.md').mock(return_value=httpx.Response(404, json={}))
        ref = mock.post('/repos/acme/app/git/refs').mock(return_value=httpx.Response(201, json={'ref': 'refs/heads/argus/fix-1'}))
        put_docker = mock.put('/repos/acme/app/contents/Dockerfile').mock(return_value=httpx.Response(200, json={}))
        put_new = mock.put('/repos/acme/app/contents/docs/NEW.md').mock(return_value=httpx.Response(201, json={}))
        pulls = mock.post('/repos/acme/app/pulls').mock(return_value=httpx.Response(201, json={'number': 42, 'html_url': 'https://github.com/acme/app/pull/42'}))
        close = mock.patch('/repos/acme/app/pulls/42').mock(return_value=httpx.Response(200, json={}))
        del_ref = mock.delete('/repos/acme/app/git/refs/heads/argus/fix-1').mock(return_value=httpx.Response(204))
        dry = await action.dry_run(params, ctx(settings, 'github'))
        assert dry.ok and 'modify Dockerfile (+1/-1)' in dry.summary and 'add docs/NEW.md (+1/-0)' in dry.summary and dry.blast_radius['files'] == 2
        result = await action.execute(params, ctx(settings, 'github'))
        assert json.loads(ref.calls.last.request.content) == {'ref': 'refs/heads/argus/fix-1', 'sha': 'base-sha'}
        docker_body = json.loads(put_docker.calls.last.request.content)
        assert docker_body['sha'] == 'old-sha' and docker_body['branch'] == 'argus/fix-1' and base64.b64decode(docker_body['content']) == b'FROM python:3.12-slim\n'
        assert 'sha' not in json.loads(put_new.calls.last.request.content)
        assert json.loads(pulls.calls.last.request.content) == {'title': 'Pin base image', 'body': 'why', 'head': 'argus/fix-1', 'base': 'main'}
        assert result.rollback_payload['pr_number'] == 42 and '#42' in result.summary
        await action.rollback(result.rollback_payload, ctx(settings, 'github'))
        assert json.loads(close.calls.last.request.content) == {'state': 'closed'} and del_ref.called
        # head branch already exists -> dry run fails
        mock.get('/repos/acme/app/git/ref/heads/argus/fix-1').mock(return_value=httpx.Response(200, json={'ref': 'x'}))
        assert (await action.dry_run(params, ctx(settings, 'github'))).ok is False
        # a failure after the branch was created cleans the branch up
        mock.get('/repos/acme/app/git/ref/heads/argus/fix-1').mock(return_value=httpx.Response(404, json={}))
        mock.post('/repos/acme/app/pulls').mock(return_value=httpx.Response(422, json={'message': 'Validation Failed'}))
        before = del_ref.call_count
        with pytest.raises(ActionError):
            await action.execute(params, ctx(settings, 'github'))
        assert del_ref.call_count == before + 1


# ======================================================================== Okta


@pytest.mark.asyncio
async def test_okta_suspend_and_clear_sessions(settings, env):
    user = {'id': '00u1', 'status': 'ACTIVE', 'profile': {'login': 'mallory@acme.com'}}
    assert okta.SuspendUser._plan(user)['path'] == '/api/v1/users/00u1/lifecycle/suspend'
    assert okta.ClearUserSessions._plan(user, True) == {'method': 'DELETE', 'path': '/api/v1/users/00u1/sessions', 'params': {'oauthTokens': 'true'},
                                                         'blast_radius': {'entities': 1, 'kind': 'user', 'ids': ['mallory@acme.com']}}
    suspend, clear = catalog.get('okta.user.suspend'), catalog.get('okta.user.clear_sessions')
    assert clear.reversible is False
    with respx.mock(base_url='https://acme.okta.com', assert_all_called=False) as mock:
        mock.get('/api/v1/users/mallory@acme.com').mock(return_value=httpx.Response(200, json=user))
        sus = mock.post('/api/v1/users/00u1/lifecycle/suspend').mock(return_value=httpx.Response(200, json={}))
        unsus = mock.post('/api/v1/users/00u1/lifecycle/unsuspend').mock(return_value=httpx.Response(200, json={}))
        sessions = mock.delete('/api/v1/users/00u1/sessions').mock(return_value=httpx.Response(204))
        assert (await suspend.dry_run({'user': 'mallory@acme.com'}, ctx(settings, 'okta'))).ok
        result = await suspend.execute({'user': 'mallory@acme.com'}, ctx(settings, 'okta'))
        assert sus.calls.last.request.headers['Authorization'] == 'SSWS okta-token' and result.rollback_payload == {'id': '00u1', 'login': 'mallory@acme.com'}
        await suspend.rollback(result.rollback_payload, ctx(settings, 'okta'))
        assert unsus.called
        result = await clear.execute(clear.normalize({'user': 'mallory@acme.com', 'oauth_tokens': True}), ctx(settings, 'okta'))
        assert result.ok and sessions.calls.last.request.url.params['oauthTokens'] == 'true'
        mock.get('/api/v1/users/mallory@acme.com').mock(return_value=httpx.Response(200, json=dict(user, status='SUSPENDED')))
        assert (await suspend.dry_run({'user': 'mallory@acme.com'}, ctx(settings, 'okta'))).ok is False
        mock.get('/api/v1/users/ghost').mock(return_value=httpx.Response(404, json={'errorCode': 'E0000007'}))
        assert (await clear.dry_run({'user': 'ghost'}, ctx(settings, 'okta'))).ok is False


# ======================================================================== Cloudflare


def test_cloudflare_block_ip_plan():
    zone = '0' * 32
    plan = cloudflare.BlockIp._plan({'zone_id': zone, 'ip': '203.0.113.7', 'note': 'n'})
    assert plan['path'] == f'/zones/{zone}/firewall/access_rules/rules' and plan['json'] == {'mode': 'block', 'configuration': {'target': 'ip', 'value': '203.0.113.7'}, 'notes': 'n'}
    cidr = cloudflare.BlockIp._plan({'account_id': zone, 'ip': '203.0.113.0/24'})
    assert cidr['json']['configuration'] == {'target': 'ip_range', 'value': '203.0.113.0/24'} and cidr['scope_path'] == f'/accounts/{zone}'
    assert cloudflare.BlockIp._plan({'zone_id': zone, 'ip': '2001:db8::/32'})['json']['configuration']['target'] == 'ip_range'
    for bad in ({'zone_id': zone, 'account_id': zone, 'ip': '1.1.1.1'}, {'ip': '1.1.1.1'}, {'zone_id': zone, 'ip': 'not-an-ip'}, {'zone_id': zone, 'ip': '10.0.0.0/8'}):
        with pytest.raises(ActionError):
            cloudflare.BlockIp._plan(bad)


@pytest.mark.asyncio
async def test_cloudflare_block_ip_lifecycle(settings, env):
    zone = 'a' * 32
    action = catalog.get('cloudflare.waf.block_ip')
    params = action.normalize({'zone_id': zone, 'ip': '203.0.113.7'})
    with respx.mock(base_url='https://api.cloudflare.com/client/v4', assert_all_called=False) as mock:
        mock.get(f'/zones/{zone}').mock(return_value=httpx.Response(200, json={'success': True, 'result': {'id': zone}}))
        mock.get(f'/zones/{zone}/firewall/access_rules/rules').mock(return_value=httpx.Response(200, json={'success': True, 'result': []}))
        post = mock.post(f'/zones/{zone}/firewall/access_rules/rules').mock(return_value=httpx.Response(200, json={'success': True, 'result': {'id': 'rule-1'}}))
        delete = mock.delete(f'/zones/{zone}/firewall/access_rules/rules/rule-1').mock(return_value=httpx.Response(200, json={'success': True, 'result': {'id': 'rule-1'}}))
        dry = await action.dry_run(params, ctx(settings, 'cloudflare'))
        assert dry.ok and not dry.warnings
        result = await action.execute(params, ctx(settings, 'cloudflare'))
        assert json.loads(post.calls.last.request.content)['configuration'] == {'target': 'ip', 'value': '203.0.113.7'}
        assert post.calls.last.request.headers['Authorization'] == 'Bearer cf-token' and result.rollback_payload['rule_id'] == 'rule-1'
        await action.rollback(result.rollback_payload, ctx(settings, 'cloudflare'))
        assert delete.called
        mock.post(f'/zones/{zone}/firewall/access_rules/rules').mock(return_value=httpx.Response(200, json={'success': False, 'errors': [{'message': 'nope'}]}))
        with pytest.raises(ActionError):
            await action.execute(params, ctx(settings, 'cloudflare'))
        mock.get(f'/zones/{zone}').mock(return_value=httpx.Response(403, json={'success': False}))
        assert (await action.dry_run(params, ctx(settings, 'cloudflare'))).ok is False


# ======================================================================== Argus internal


@pytest.mark.asyncio
async def test_argus_internal_actions(app, client, settings, default_tenant_id):
    with app.state.db_factory() as db:
        finding = Finding(tenant_id=default_tenant_id, fingerprint='fp1', title='t', description='d', severity='high', source='test', status='open')
        asset = Asset(tenant_id=default_tenant_id, name='a', kind='web', target='https://a.test', approved=True)
        db.add_all([finding, asset])
        db.flush()
        db.add(AssetAuthorization(tenant_id=default_tenant_id, asset_id=asset.id, authorized_by='u', attestation='ok', allow_active=True))
        db.commit()
        fid, aid = finding.id, asset.id
    update, revoke = catalog.get('argus.finding.update_status'), catalog.get('argus.asset.revoke_authorization')
    with app.state.db_factory() as db:
        c = ctx(settings, 'argus', db=db)
        c.tenant_id = default_tenant_id
        dry = await update.dry_run({'finding_id': fid, 'status': 'resolved'}, c)
        assert dry.ok and dry.blast_radius == {'entities': 1, 'kind': 'finding', 'ids': [fid]}
        result = await update.execute({'finding_id': fid, 'status': 'resolved'}, c)
        assert db.get(Finding, fid).status == 'resolved' and result.rollback_payload == {'finding_id': fid, 'previous_status': 'open'}
        await update.rollback(result.rollback_payload, c)
        assert db.get(Finding, fid).status == 'open'
        assert (await update.dry_run({'finding_id': 'nope', 'status': 'open'}, c)).ok is False
        # other tenant's finding is invisible
        other = ctx(settings, 'argus', db=db)
        assert other.tenant_id != default_tenant_id
        assert (await update.dry_run({'finding_id': fid, 'status': 'open'}, other)).ok is False
        assert argus.UpdateFindingStatus._plan({'finding_id': fid, 'status': 'open'}, 'open')['warnings']
        assert argus.RevokeAssetAuthorization._plan({'asset_id': aid}, ['x', 'y'])['blast_radius']['entities'] == 2
        dry = await revoke.dry_run({'asset_id': aid}, c)
        assert dry.ok and dry.blast_radius['entities'] == 1
        result = await revoke.execute({'asset_id': aid}, c)
        assert db.get(Asset, aid).approved is False and len(result.rollback_payload['authorization_ids']) == 1
        assert (await revoke.dry_run({'asset_id': aid}, c)).ok is False
        await revoke.rollback(result.rollback_payload, c)
        assert db.get(Asset, aid).approved is True
        db.commit()


# ======================================================================== catalog-wide contract


def test_every_real_action_is_registered_with_a_plan():
    names = catalog.names()
    assert len([n for n in names if not n.startswith('test.')]) == 25
    for action in catalog.all():
        if action.name.startswith('test.'):
            continue
        assert callable(getattr(type(action), '_plan', None)), f'{action.name} has no _plan()'
        assert action.description and action.platforms and action.category in {'remediation', 'containment', 'internal'}


def test_argus_actions_available_without_credentials(settings):
    assert catalog.get('argus.finding.update_status').available(settings) is True
    assert catalog.get('github.open_fix_pr').available(settings) is False
    assert catalog.get('aws.iam.disable_access_key').available(settings) is False  # boto3 not installed here


@pytest.mark.asyncio
async def test_missing_credentials_surface_as_action_error(settings, monkeypatch):
    monkeypatch.delenv('ACTIONS_GITHUB_TOKEN', raising=False)
    with pytest.raises(ActionError) as excinfo:
        await catalog.get('github.secret_scanning.enable').dry_run({'owner': 'a', 'repo': 'b', 'push_protection': True}, ctx(settings, 'github'))
    assert 'ACTIONS_GITHUB_TOKEN' in str(excinfo.value)
    argus_action = argus.UpdateFindingStatus()
    with pytest.raises(ActionError):  # no database session on the context
        await argus_action.dry_run({'finding_id': 'x', 'status': 'open'}, ctx(settings, 'argus'))
