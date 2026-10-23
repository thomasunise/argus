"""collect() tests: SDK clients replaced by fakes built from the fixtures (boto3, azure, google and
kubernetes are not required to be installed), HTTP collectors mocked with respx. No network."""
from __future__ import annotations

import json
import shutil
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import respx

from app.collectors import CollectorContext, load_builtin, registry
from app.collectors import aws as aws_mod
from app.collectors import azure as azure_mod
from app.collectors import base as base_mod
from app.collectors import gcp as gcp_mod
from app.collectors import kubernetes as k8s_mod

FIXTURES = Path(__file__).parent / 'fixtures' / 'collectors'


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name / 'raw.json').read_text(encoding='utf-8'))


def make_ctx(settings, config: dict, since: datetime | None = None) -> CollectorContext:
    beats = {'n': 0}

    async def heartbeat():
        beats['n'] += 1

    ctx = CollectorContext(tenant_id='tenant-test', config=config, settings=settings, heartbeat=heartbeat, since=since)
    ctx.beats = beats  # type: ignore[attr-defined]
    return ctx


@pytest.fixture(autouse=True)
def _load():
    load_builtin()


def test_available_reports_missing_sdk(monkeypatch):
    monkeypatch.setattr(base_mod, 'modules_available', lambda *names: not names)  # every SDK missing
    aws = registry.get('aws')
    assert aws.available() is False and aws.install_hint() == 'install boto3'
    assert registry.get('netflow').available() is True  # no SDK needed
    monkeypatch.setattr(base_mod, 'modules_available', lambda *names: True)
    assert aws.available() is True and aws.install_hint() == ''


# ---------------------------------------------------------------- AWS (fake boto3 module)


class _AwsError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.response = {'Error': {'Code': code}}


def _raise(code: str):
    raise _AwsError(code)


class FakeClient:
    def __init__(self, ops: dict | None = None, pages: dict | None = None):
        self.ops, self.pages, self.calls = ops or {}, pages or {}, []

    def get_paginator(self, op):
        fn, calls = self.pages[op], self.calls

        class Paginator:
            def paginate(self, **kw):
                calls.append((op, kw))
                return iter(fn(**kw))

        return Paginator()

    def __getattr__(self, name):
        if name in {'ops', 'pages', 'calls'} or name not in self.ops:
            raise AttributeError(name)
        fn = self.ops[name]

        def call(**kw):
            self.calls.append((name, kw))
            return fn(**kw)

        return call


def build_fake_boto3(raw: dict) -> tuple[types.ModuleType, dict]:
    iam_raw = raw['iam']
    users = {u['UserName']: u for u in iam_raw['users']}
    roles = {r['RoleName']: r for r in iam_raw['roles']}
    policies = {p['Arn']: p for p in iam_raw['policies']}
    public = lambda d: {k: v for k, v in d.items() if k[:1].isupper() and k not in {'Document'}}  # noqa: E731
    one = lambda key, items: [{key: items}]  # noqa: E731
    sts = FakeClient(ops={
        'get_caller_identity': lambda: {'Account': raw['account_id'], 'Arn': 'arn:aws:sts::123456789012:assumed-role/x/y'},
        'assume_role': lambda **kw: {'Credentials': {'AccessKeyId': 'ASIAFAKE', 'SecretAccessKey': 'fake-secret', 'SessionToken': 'fake-token'}},
    })
    iam = FakeClient(ops={
        'get_account_summary': lambda: {'SummaryMap': {'AccountMFAEnabled': 1 if iam_raw['account_mfa_enabled'] else 0}},
        'list_mfa_devices': lambda UserName: {'MFADevices': users[UserName]['mfa_devices']},
        'list_access_keys': lambda UserName: {'AccessKeyMetadata': users[UserName]['access_keys']},
        'get_login_profile': lambda UserName: {'LoginProfile': {'UserName': UserName}} if users[UserName]['console_access'] else _raise('NoSuchEntity'),
        'get_user_policy': lambda UserName, PolicyName: next(p for p in users[UserName]['inline_policies'] if p['PolicyName'] == PolicyName),
        'get_role_policy': lambda RoleName, PolicyName: next(p for p in roles[RoleName]['inline_policies'] if p['PolicyName'] == PolicyName),
        'get_policy_version': lambda PolicyArn, VersionId: {'PolicyVersion': {'Document': policies[PolicyArn]['Document'], 'VersionId': VersionId}},
    }, pages={
        'list_users': lambda **kw: one('Users', [public(u) for u in users.values()]),
        'list_roles': lambda **kw: one('Roles', [public(r) for r in roles.values()] + [{'RoleName': 'AWSServiceRoleForSupport', 'Arn': 'arn:aws:iam::123456789012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport', 'Path': '/aws-service-role/support.amazonaws.com/'}]),
        'list_policies': lambda **kw: one('Policies', [public(p) for p in policies.values()]),
        'list_attached_user_policies': lambda UserName: one('AttachedPolicies', users[UserName]['attached_policies']),
        'list_user_policies': lambda UserName: one('PolicyNames', [p['PolicyName'] for p in users[UserName]['inline_policies']]),
        'list_groups_for_user': lambda UserName: one('Groups', users[UserName]['groups']),
        'list_attached_role_policies': lambda RoleName: one('AttachedPolicies', roles[RoleName]['attached_policies']),
        'list_role_policies': lambda RoleName: one('PolicyNames', [p['PolicyName'] for p in roles[RoleName]['inline_policies']]),
        'list_instance_profiles': lambda **kw: one('InstanceProfiles', [{'InstanceProfileName': n, 'Roles': [{'RoleName': r} for r in rs]} for n, rs in iam_raw['instance_profiles'].items()]),
    })
    region = raw['ec2']['us-east-1']
    ec2 = FakeClient(pages={'describe_instances': lambda **kw: [{'Reservations': region['reservations'][:1]}, {'Reservations': region['reservations'][1:]}],
                            'describe_security_groups': lambda **kw: one('SecurityGroups', region['security_groups'])})
    rds = FakeClient(pages={'describe_db_instances': lambda **kw: one('DBInstances', raw['rds']['us-east-1'])})
    lam = FakeClient(pages={'list_functions': lambda **kw: one('Functions', raw['lambda']['us-east-1'])})
    eks = FakeClient(ops={'describe_cluster': lambda name: {'cluster': next(c for c in raw['eks']['us-east-1'] if c['name'] == name)}},
                     pages={'list_clusters': lambda **kw: one('clusters', [c['name'] for c in raw['eks']['us-east-1']])})
    buckets = {b['Name']: b for b in raw['s3']['buckets']}
    s3 = FakeClient(ops={
        'list_buckets': lambda: {'Buckets': [{'Name': b['Name'], 'CreationDate': datetime(2022, 1, 1, tzinfo=timezone.utc)} for b in buckets.values()]},
        'get_bucket_location': lambda Bucket: {'LocationConstraint': None},
        'get_public_access_block': lambda Bucket: {'PublicAccessBlockConfiguration': buckets[Bucket]['public_access_block']} if buckets[Bucket]['public_access_block'] else _raise('NoSuchPublicAccessBlockConfiguration'),
        'get_bucket_policy_status': lambda Bucket: {'PolicyStatus': {'IsPublic': True}} if buckets[Bucket]['policy_public'] else _raise('NoSuchBucketPolicy'),
    })
    clients = {'sts': sts, 'iam': iam, 'ec2': ec2, 'rds': rds, 'lambda': lam, 'eks': eks, 's3': s3}
    sessions: list[dict] = []

    class Session:
        def __init__(self, **kwargs):
            sessions.append(kwargs)

        def client(self, name, region_name=None):
            return clients[name]

    module = types.ModuleType('boto3')
    module.Session = Session
    return module, {'clients': clients, 'sessions': sessions}


@pytest.mark.asyncio
async def test_aws_collect_with_fake_boto3(settings, monkeypatch):
    raw = fixture('aws')
    module, state = build_fake_boto3(raw)
    monkeypatch.setitem(sys.modules, 'boto3', module)
    ctx = make_ctx(settings, {'regions': ['us-east-1'], 'role_arn': 'arn:aws:iam::123456789012:role/SentinelAudit', 'external_id': 'ext-1',
                              'access_key_id': 'AKIAFAKEKEY', 'secret_access_key': 'fake'})
    result = await registry.get('aws').collect(ctx)
    expected = registry.get('aws')._normalize(raw)
    assert result.stats['iam_users'] == 3 and result.stats['instances'] == 2 and result.stats['buckets'] == 2 and result.stats['eks'] == 1
    assert sorted(e.action for e in result.events) == sorted(e.action for e in expected.events)
    assert {n.key for n in result.nodes if n.kind != 'permission'} >= {n.key for n in expected.nodes if n.kind != 'permission'}
    assert not any('AWSServiceRoleForSupport' in n.key for n in result.nodes)
    # assume-role path: first session uses the static key, the second the STS credentials
    assert state['sessions'][0]['aws_access_key_id'] == 'AKIAFAKEKEY' and state['sessions'][1]['aws_session_token'] == 'fake-token'
    assume = next(kw for op, kw in state['clients']['sts'].calls if op == 'assume_role')
    assert assume['RoleArn'].endswith('SentinelAudit') and assume['ExternalId'] == 'ext-1'
    ops = {op for client in state['clients'].values() for op, _ in client.calls}
    assert {'list_users', 'list_roles', 'list_policies', 'describe_instances', 'describe_security_groups', 'describe_db_instances', 'list_functions',
            'list_clusters', 'describe_cluster', 'list_buckets', 'get_public_access_block', 'get_bucket_policy_status', 'get_login_profile'} <= ops
    assert result.warnings == []


@pytest.mark.asyncio
async def test_aws_collect_tolerates_denied_apis(settings, monkeypatch):
    raw = fixture('aws')
    module, state = build_fake_boto3(raw)
    state['clients']['s3'].ops['list_buckets'] = lambda: _raise('AccessDenied')
    state['clients']['rds'].pages['describe_db_instances'] = lambda **kw: _raise('UnauthorizedOperation')
    monkeypatch.setitem(sys.modules, 'boto3', module)
    result = await registry.get('aws').collect(make_ctx(settings, {'regions': ['us-east-1']}))
    assert result.stats['buckets'] == 0 and result.stats['rds'] == 0 and result.stats['instances'] == 2
    assert 's3.list_buckets: AccessDenied' in result.warnings and 'rds.describe_db_instances[us-east-1]: UnauthorizedOperation' in result.warnings


# ---------------------------------------------------------------- Azure (fake mgmt clients)


class Obj:
    def __init__(self, data: dict):
        self._data = data

    def as_dict(self):
        return self._data


@pytest.mark.asyncio
async def test_azure_collect_with_fake_clients(settings, monkeypatch):
    raw = fixture('azure')
    sub = raw['subscriptions'][0]
    nics = []
    vms = []
    for vm in json.loads(json.dumps(sub['vms'])):
        for ref in vm['network_profile']['network_interfaces']:
            nics.append(Obj({'id': ref['id'], **ref.pop('detail')}))
        vms.append(Obj(vm))
    role_defs = {ra['role_definition_id']: ra['role_name'] for ra in sub['role_assignments']}
    assignments = [Obj({k: v for k, v in ra.items() if k != 'role_name'}) for ra in sub['role_assignments']]
    ns = types.SimpleNamespace
    clients = {
        'resource': ns(resource_groups=ns(list=lambda: [Obj(x) for x in sub['resource_groups']])),
        'compute': ns(virtual_machines=ns(list_all=lambda: vms)),
        'network': ns(network_security_groups=ns(list_all=lambda: [Obj(x) for x in sub['nsgs']]), network_interfaces=ns(list_all=lambda: nics),
                      public_ip_addresses=ns(list_all=lambda: [Obj(x) for x in sub['public_ips']])),
        'storage': ns(storage_accounts=ns(list=lambda: [Obj(x) for x in sub['storage_accounts']])),
        'authorization': ns(role_assignments=ns(list_for_subscription=lambda: assignments),
                            role_definitions=ns(get_by_id=lambda rd_id: Obj({'id': rd_id, 'role_name': role_defs[rd_id]}))),
        'containerservice': ns(managed_clusters=ns(list=lambda: [Obj(x) for x in sub['aks']])),
    }
    seen = {}
    monkeypatch.setattr(azure_mod, '_credential', lambda config: seen.setdefault('credential', config.get('auth', 'client_secret')))
    monkeypatch.setattr(azure_mod, '_subscription_client', lambda cred: ns(subscriptions=ns(list=lambda: [
        Obj({'subscription_id': 'sub-0001', 'display_name': 'Production', 'state': 'Enabled'}), Obj({'subscription_id': 'sub-9999', 'display_name': 'Sandbox', 'state': 'Enabled'})])))
    monkeypatch.setattr(azure_mod, '_clients', lambda cred, sub_id: seen.setdefault('subs', []).append(sub_id) or clients)
    ctx = make_ctx(settings, {'tenant_id': raw['tenant_id'], 'client_id': 'cid', 'client_secret': 'shh', 'subscriptions': ['sub-0001']})
    result = await registry.get('azure').collect(ctx)
    expected = registry.get('azure')._normalize(raw)
    assert seen['subs'] == ['sub-0001'] and seen['credential'] == 'client_secret'
    assert result.stats == {**result.stats, 'subscriptions': 1, 'vms': 1, 'nsgs': 1, 'storage_accounts': 2, 'role_assignments': 3, 'aks': 1}
    assert sorted(e.external_id for e in result.events) == sorted(e.external_id for e in expected.events)
    assert {n.key for n in result.nodes} == {n.key for n in expected.nodes}
    vm = next(n for n in result.nodes if n.key.endswith('/web-vm'))
    assert vm.props['public_ip'] == '20.1.2.3'


# ---------------------------------------------------------------- GCP (fake asset + projects clients)


@pytest.mark.asyncio
async def test_gcp_collect_with_fake_asset_inventory(settings, monkeypatch):
    raw = fixture('gcp')
    project = raw['projects'][0]
    resources = []
    for key, atype in (('instances', 'compute.googleapis.com/Instance'), ('firewalls', 'compute.googleapis.com/Firewall'), ('buckets', 'storage.googleapis.com/Bucket'),
                       ('gke_clusters', 'container.googleapis.com/Cluster')):
        for item in project[key]:
            resources.append({'name': item.get('name', f"//x/{item['data']['name']}"), 'asset_type': atype, 'resource': {'data': item['data']}})
    policies = [{'name': '//cloudresourcemanager.googleapis.com/projects/acme-prod', 'asset_type': 'cloudresourcemanager.googleapis.com/Project', 'iam_policy': {'bindings': project['iam_bindings']}}]
    for bucket, bindings in project['bucket_iam'].items():
        policies.append({'name': f'//storage.googleapis.com/{bucket}', 'asset_type': 'storage.googleapis.com/Bucket', 'iam_policy': {'bindings': bindings}})
    requests = []

    def list_assets(request):
        requests.append(request)
        return iter(resources if request['content_type'] == 'RESOURCE' else policies)

    monkeypatch.setattr(gcp_mod, '_credentials', lambda config: 'creds' if config.get('service_account_json') else None)
    monkeypatch.setattr(gcp_mod, '_asset_client', lambda creds: types.SimpleNamespace(list_assets=list_assets))
    monkeypatch.setattr(gcp_mod, '_projects_client', lambda creds: types.SimpleNamespace(search_projects=lambda query: [
        {'project_id': 'acme-prod', 'display_name': 'Acme Prod', 'state': 'ACTIVE', 'name': 'projects/123456789'}]))
    ctx = make_ctx(settings, {'service_account_json': json.dumps({'type': 'service_account', 'client_email': 'x@y', 'private_key': 'k'})})
    result = await registry.get('gcp').collect(ctx)
    expected = registry.get('gcp')._normalize(raw)
    assert [r_['parent'] for r_ in requests] == ['projects/acme-prod', 'projects/acme-prod'] and requests[1]['content_type'] == 'IAM_POLICY'
    assert result.stats == {**result.stats, 'projects': 1, 'instances': 2, 'firewalls': 2, 'buckets': 2, 'gke_clusters': 1}
    assert sorted(e.external_id for e in result.events) == sorted(e.external_id for e in expected.events)
    assert {n.key for n in result.nodes} == {n.key for n in expected.nodes}


# ---------------------------------------------------------------- Kubernetes (fake API clients)


@pytest.mark.asyncio
async def test_kubernetes_collect_strips_secret_data(settings, monkeypatch):
    raw = fixture('kubernetes')
    ns = types.SimpleNamespace
    secrets = [{'metadata': s['metadata'], 'type': s['type'], 'data': {k: 'c3VwZXJzZWNyZXQ=' for k in s['keys']}} for s in raw['secrets']]
    deployments = json.loads(json.dumps(raw['deployments']))
    for d in deployments:
        d['spec']['template']['spec'].pop('_labels', None)
    core = ns(list_namespace=lambda: {'items': raw['namespaces']}, list_pod_for_all_namespaces=lambda: {'items': raw['pods']},
              list_service_account_for_all_namespaces=lambda: {'items': raw['service_accounts']}, list_service_for_all_namespaces=lambda: {'items': raw['services']},
              list_secret_for_all_namespaces=lambda: {'items': secrets})
    apps = ns(list_deployment_for_all_namespaces=lambda: {'items': deployments}, list_daemon_set_for_all_namespaces=lambda: {'items': raw['daemonsets']},
              list_stateful_set_for_all_namespaces=lambda: {'items': raw['statefulsets']}, list_replica_set_for_all_namespaces=lambda: {'items': raw['replicasets']})
    rbac = ns(list_cluster_role_binding=lambda: {'items': raw['cluster_role_bindings']})
    version = ns(get_code=lambda: {'gitVersion': raw['version']})
    monkeypatch.setattr(k8s_mod, '_api_clients', lambda config: {'core': core, 'apps': apps, 'rbac': rbac, 'version': version, 'cluster': config.get('cluster_name') or 'ctx'})
    result = await registry.get('kubernetes').collect(make_ctx(settings, {'mode': 'kubeconfig', 'cluster_name': 'prod-eks'}))
    expected = registry.get('kubernetes')._normalize(raw)
    assert result.stats == {**result.stats, 'namespaces': 3, 'workloads': 3, 'pods': 3, 'secrets': 2, 'privileged_workloads': 2, 'cluster': 'prod-eks'}
    assert sorted(e.external_id for e in result.events) == sorted(e.external_id for e in expected.events)
    assert {n.key for n in result.nodes} == {n.key for n in expected.nodes}
    blob = json.dumps([n.props for n in result.nodes] + [e.metadata for e in result.events], default=str)
    assert 'c3VwZXJzZWNyZXQ=' not in blob
    assert next(n for n in result.nodes if n.key.endswith('/db-creds')).props['keys'] == ['password', 'username']
    assert any(e.src == ('asset', 'k8s:deployment:prod-eks/prod/api') and e.rel == 'exposes' for e in result.edges)  # labels carried for service matching
    scoped = await registry.get('kubernetes').collect(make_ctx(settings, {'cluster_name': 'prod-eks', 'namespaces': ['prod']}))
    assert scoped.stats['namespaces'] == 1 and all('kube-system' not in n.key and 'default' not in n.key.split('/')[1:2] for n in scoped.nodes if n.kind == 'asset')


# ---------------------------------------------------------------- GitHub (respx)


@pytest.mark.asyncio
async def test_github_collect_paginates_and_drops_secret_values(settings):
    raw = fixture('github')
    web, api = raw['repos']
    base = 'https://api.github.com'
    repo_fields = ('name', 'full_name', 'private', 'visibility', 'default_branch', 'archived', 'language', 'pushed_at', 'security_and_analysis')
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f'{base}/orgs/acme').respond(200, json=raw['org'])
        mock.get(f'{base}/orgs/acme/repos', params={'page': '2'}).respond(200, json=[{k: api[k] for k in repo_fields}, {'name': 'old', 'full_name': 'acme/old', 'archived': True, 'private': True}])
        mock.get(f'{base}/orgs/acme/repos').respond(200, json=[{k: web[k] for k in repo_fields}],
                                                     headers={'Link': f'<{base}/orgs/acme/repos?type=all&per_page=100&page=2>; rel="next"'})
        mock.get(f'{base}/repos/acme/web/branches/main/protection').respond(404, json={'message': 'Branch not protected'})
        mock.get(f'{base}/repos/acme/api/branches/main/protection').respond(200, json=api['branch_protection'])
        mock.get(f'{base}/repos/acme/web/dependabot/alerts').respond(200, json=[])
        mock.get(f'{base}/repos/acme/web/secret-scanning/alerts').respond(404, json={'message': 'Secret scanning is disabled on this repository.'})
        mock.get(f'{base}/repos/acme/web/code-scanning/alerts').respond(403, json={'message': 'Advanced Security must be enabled'})
        mock.get(f'{base}/repos/acme/web/collaborators').respond(200, json=web['collaborators'])
        mock.get(f'{base}/repos/acme/api/dependabot/alerts').respond(200, json=api['dependabot_alerts'])
        mock.get(f'{base}/repos/acme/api/secret-scanning/alerts').respond(200, json=api['secret_scanning_alerts'])
        mock.get(f'{base}/repos/acme/api/code-scanning/alerts').respond(200, json=api['code_scanning_alerts'])
        mock.get(f'{base}/repos/acme/api/collaborators').respond(200, json=api['collaborators'])
        ctx = make_ctx(settings, {'org': 'acme', 'token': 'ghp_testtoken_000000000000000000000000000000'})
        result = await registry.get('github').collect(ctx)
        first = mock.calls[0].request
        assert first.headers['Authorization'].startswith('Bearer ') and first.headers['X-GitHub-Api-Version'] == '2022-11-28'
    assert result.stats == {**result.stats, 'repos': 2, 'public_repos': 1, 'dependabot_alerts': 1, 'secret_scanning_alerts': 1, 'code_scanning_alerts': 1}
    assert sorted(e.action for e in result.events) == ['branch_unprotected', 'code_scanning_alert', 'dependency_vulnerable', 'org_2fa_not_required', 'secret_detected']
    assert 'web secret-scanning: HTTP 404' in result.warnings and 'web code-scanning: HTTP 403' in result.warnings
    assert api['secret_scanning_alerts'][0]['secret'] not in json.dumps([e.metadata for e in result.events] + [n.props for n in result.nodes], default=str)
    assert not any(n.key == 'github:repo:acme/old' for n in result.nodes)  # archived skipped by default
    assert ctx.beats['n'] >= 2


# ---------------------------------------------------------------- Okta (respx)


@pytest.mark.asyncio
async def test_okta_collect(settings):
    raw = fixture('okta')
    base = 'https://acme.okta.com'
    users = [{k: v for k, v in u.items() if k != 'factors'} for u in raw['users']]
    since = datetime(2026, 10, 23, 5, tzinfo=timezone.utc)
    with respx.mock(assert_all_called=True) as mock:
        mock.get(f'{base}/api/v1/users', params={'after': 'cursor2'}).respond(200, json=users[2:])
        mock.get(f'{base}/api/v1/users').respond(200, json=users[:2], headers={'link': f'<{base}/api/v1/users?after=cursor2&limit=200>; rel="next"'})
        for user in raw['users']:
            mock.get(f"{base}/api/v1/users/{user['id']}/factors").respond(200, json=user['factors'])
        mock.get(f'{base}/api/v1/groups').respond(200, json=raw['groups'])
        mock.get(f'{base}/api/v1/apps').respond(200, json=raw['apps'])
        mock.get(f'{base}/api/v1/iam/assignees/users').respond(200, json=[{'id': uid} for uid in raw['admin_roles']])
        for uid, roles in raw['admin_roles'].items():
            mock.get(f'{base}/api/v1/users/{uid}/roles').respond(200, json=roles)
        logs = mock.get(f'{base}/api/v1/logs').respond(200, json=raw['logs'])
        ctx = make_ctx(settings, {'domain': 'acme.okta.com', 'api_token': '00abcDEFtoken'}, since=since)
        result = await registry.get('okta').collect(ctx)
        log_request = logs.calls[0].request
        assert log_request.url.params['since'] == '2026-10-23T05:00:00Z' and 'user.mfa.factor.reset_all' in log_request.url.params['filter']
        assert log_request.headers['Authorization'] == 'SSWS 00abcDEFtoken'
    expected = registry.get('okta')._normalize(raw)
    assert result.stats == {**result.stats, 'users': 4, 'users_without_mfa': 1, 'admins': 2, 'log_events': 3}
    assert sorted(e.external_id for e in result.events) == sorted(e.external_id for e in expected.events)
    assert result.warnings == []


# ---------------------------------------------------------------- Entra (respx)


@pytest.mark.asyncio
async def test_entra_collect(settings):
    raw = fixture('entra')
    graph = 'https://graph.microsoft.com/v1.0'
    with respx.mock(assert_all_called=False) as mock:
        token = mock.post(f"https://login.microsoftonline.com/{raw['tenant_id']}/oauth2/v2.0/token").respond(200, json={'access_token': 'tok', 'expires_in': 3599})
        mock.get(f'{graph}/users', params={'$skiptoken': 'p2'}).respond(200, json={'value': raw['users'][2:]})
        mock.get(f'{graph}/users').respond(200, json={'value': raw['users'][:2], '@odata.nextLink': f'{graph}/users?$skiptoken=p2'})
        mock.get(f'{graph}/groups').respond(200, json={'value': raw['groups']})
        mock.get(f'{graph}/directoryRoles').respond(200, json={'value': [{k: v for k, v in r.items() if k != 'members'} for r in raw['directory_roles']]})
        for role in raw['directory_roles']:
            mock.get(f"{graph}/directoryRoles/{role['id']}/members").respond(200, json={'value': role['members']})
        mock.get(f'{graph}/servicePrincipals').respond(200, json={'value': raw['service_principals']})
        mock.get(f'{graph}/identity/conditionalAccess/policies').respond(403, json={'error': {'code': 'Authorization_RequestDenied'}})
        signins = mock.get(f'{graph}/auditLogs/signIns').respond(200, json={'value': raw['risky_sign_ins']})
        mock.get(f'{graph}/auditLogs/directoryAudits').respond(200, json={'value': raw['audit_logs']})
        ctx = make_ctx(settings, {'tenant_id': raw['tenant_id'], 'client_id': 'app-id', 'client_secret': 'cs'}, since=datetime(2026, 10, 23, tzinfo=timezone.utc))
        result = await registry.get('entra').collect(ctx)
        body = token.calls[0].request.content.decode()
        assert 'grant_type=client_credentials' in body and 'scope=https%3A%2F%2Fgraph.microsoft.com%2F.default' in body
        assert signins.calls[0].request.headers['Authorization'] == 'Bearer tok'
        assert 'createdDateTime ge 2026-10-23T00:00:00Z' in signins.calls[0].request.url.params['$filter']
    assert result.stats == {**result.stats, 'users': 3, 'guests': 1, 'global_admins': 2, 'risky_sign_ins': 1, 'audit_events': 1}
    assert 'conditionalAccess policies: HTTP 403' in result.warnings
    # policies unknown (denied) => no "missing conditional access" event, other events as in the fixture
    assert sorted(e.action for e in result.events) == ['admin_privilege_granted', 'global_admin_risky_member', 'risky_sign_in', 'sp_long_lived_secret']


# ---------------------------------------------------------------- osquery (FleetDM respx + directory under SCAN_ROOT)


@pytest.mark.asyncio
async def test_osquery_collect_fleet(settings):
    raw = fixture('osquery')
    fleet = 'https://fleet.acme.internal'
    hosts = [{'id': i + 1, 'uuid': h['identifier'], 'hostname': h['hostname'], 'platform': h['platform'], 'os_version': h['os_version'], 'primary_ip': h['primary_ip'],
              'osquery_version': h.get('osquery_version'), 'seen_time': h.get('last_seen')} for i, h in enumerate(raw['hosts'])]
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f'{fleet}/api/v1/fleet/hosts', params={'page': '0'}).respond(200, json={'hosts': hosts})
        mock.get(f'{fleet}/api/v1/fleet/hosts', params={'page': '1'}).respond(200, json={'hosts': []})
        for i, h in enumerate(raw['hosts']):
            mock.get(f'{fleet}/api/v1/fleet/hosts/{i + 1}').respond(200, json={'host': {
                'software': [{'name': p['name'], 'version': p['version'], 'source': p['source']} for p in h['packages']],
                'users': [{'username': u['username'], 'uid': u['uid'], 'shell': u['shell'], 'groupname': (u['groups'] or [''])[-1]} for u in h['users']]}})
        mock.get(f'{fleet}/api/v1/fleet/queries/11/report').respond(200, json={'results': [
            {'host_id': i + 1, 'host_name': h['hostname'], 'columns': p} for i, h in enumerate(raw['hosts']) for p in h['listening_ports']]})
        mock.get(f'{fleet}/api/v1/fleet/queries/12/report').respond(200, json={'results': [
            {'host_id': 1, 'host_name': raw['hosts'][0]['hostname'], 'columns': s} for s in raw['hosts'][0]['sudoers']]})
        mock.get(f'{fleet}/api/v1/fleet/queries/13/report').respond(200, json={'results': [
            {'host_id': i + 1, 'host_name': h['hostname'], 'columns': p} for i, h in enumerate(raw['hosts']) for p in h['processes']]})
        ctx = make_ctx(settings, {'mode': 'fleet', 'fleet_url': fleet, 'fleet_token': 'fleet-token', 'query_reports': {'listening_ports': 11, 'sudoers': 12, 'processes': 13}})
        result = await registry.get('osquery').collect(ctx)
        assert mock.calls[0].request.headers['Authorization'] == 'Bearer fleet-token'
    assert result.stats == {**result.stats, 'hosts': 2, 'listening_ports': 5, 'packages': 3, 'suspicious_processes': 2}
    assert result.stats['sudo_users'] >= 3 and sorted(e.action for e in result.events) == ['suspicious_child_process', 'suspicious_child_process']


@pytest.mark.asyncio
async def test_osquery_and_netflow_collect_from_scan_root(settings):
    root = Path(settings.scan_root)
    shutil.copytree(FIXTURES / 'osquery' / 'results', root / 'osquery', dirs_exist_ok=True)
    shutil.copytree(FIXTURES / 'netflow' / 'flows', root / 'flows', dirs_exist_ok=True)
    osq = await registry.get('osquery').collect(make_ctx(settings, {'mode': 'directory', 'path': 'osquery'}))
    assert osq.stats['hosts'] == 1 and osq.stats['listening_ports'] == 3 and [e.action for e in osq.events] == ['suspicious_child_process']
    flows = await registry.get('netflow').collect(make_ctx(settings, {'path': 'flows', 'site': 'hq', 'egress_threshold_mb': 100, 'beacon_min_connections': 10}))
    assert flows.stats['flows'] == 21 and flows.stats['beacons'] == 1 and sorted(e.action for e in flows.events) == ['beaconing', 'inbound_sensitive_service', 'large_egress']
    assert all(e.external_id.startswith('netflow:hq:') for e in flows.events)
    strict = await registry.get('netflow').collect(make_ctx(settings, {'path': 'flows', 'beacon_min_connections': 20}))
    assert strict.stats['beacons'] == 0
    owned = await registry.get('netflow').collect(make_ctx(settings, {'path': 'flows', 'internal_cidrs': ['203.0.113.0/24']}))
    assert owned.stats['beacons'] == 0 and 'beaconing' not in [e.action for e in owned.events]  # 203.0.113.50 is now internal
    for collector, cfg in (('osquery', {'mode': 'directory', 'path': '../../etc'}), ('netflow', {'path': '../..'})):
        with pytest.raises(ValueError):
            await registry.get(collector).collect(make_ctx(settings, cfg))
    missing = await registry.get('netflow').collect(make_ctx(settings, {'path': 'nope'}))
    assert missing.stats['flows'] == 0 and missing.warnings == ['directory not found: nope']
