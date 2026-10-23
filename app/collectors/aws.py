"""AWS collector (boto3, read-only). Inventories IAM, EC2, S3, RDS, Lambda and EKS into the
evidence graph and emits posture events (no MFA, stale access keys, public buckets).

API calls made (all read-only, paginated where AWS provides a paginator):
  sts:   GetCallerIdentity, AssumeRole (only when role_arn is configured)
  iam:   GetAccountSummary, ListUsers, ListMFADevices, ListAccessKeys, GetLoginProfile,
         ListGroupsForUser, ListAttachedUserPolicies, ListUserPolicies, GetUserPolicy, ListRoles,
         ListAttachedRolePolicies, ListRolePolicies, GetRolePolicy, ListPolicies(Scope=Local),
         GetPolicyVersion, ListInstanceProfiles
  ec2:   DescribeInstances, DescribeSecurityGroups            (per region)
  rds:   DescribeDBInstances                                  (per region)
  lambda:ListFunctions                                        (per region)
  eks:   ListClusters, DescribeCluster                        (per region)
  s3:    ListBuckets, GetBucketLocation, GetPublicAccessBlock, GetBucketPolicyStatus
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from .base import Collector, CollectorContext, CollectorResult, age_days, jsonable, parse_time, registry

log = logging.getLogger('sentinel.collectors.aws')

ACCESS_KEY_MAX_AGE_DAYS = 90
ADMIN_MANAGED_POLICIES = {'AdministratorAccess', 'IAMFullAccess'}
WORLD = ('0.0.0.0/0', '::/0')


# ---------------------------------------------------------------- policy summarization


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def summarize_policy(document: dict[str, Any] | None) -> dict[str, Any]:
    """Reduce an IAM policy document to the facts attack-path reasoning needs."""
    summary: dict[str, Any] = {'admin': False, 'wildcard': False, 'actions': [], 'services': [], 'statements': 0, 'not_action': False}
    if not isinstance(document, dict):
        return summary
    actions: set[str] = set()
    services: set[str] = set()
    for statement in _as_list(document.get('Statement')):
        if not isinstance(statement, dict) or statement.get('Effect', 'Allow') != 'Allow':
            continue
        summary['statements'] += 1
        stmt_actions = [str(a) for a in _as_list(statement.get('Action'))]
        resources = [str(r) for r in _as_list(statement.get('Resource'))]
        if 'NotAction' in statement:
            summary['not_action'] = True
            summary['wildcard'] = True
            if any(r == '*' for r in resources):
                summary['admin'] = True
        for action in stmt_actions:
            actions.add(action)
            service = action.split(':', 1)[0] if ':' in action else '*'
            services.add(service)
            if action == '*' and any(r == '*' for r in resources):
                summary['admin'] = True
            if action.endswith('*') or any(r == '*' for r in resources):
                summary['wildcard'] = True
            if action.lower() in {'iam:*', 'iam:passrole', 'iam:createpolicyversion', 'iam:attachuserpolicy', 'iam:attachrolepolicy',
                                  'iam:putuserpolicy', 'iam:putrolepolicy', 'sts:assumerole'} and any(r == '*' for r in resources):
                summary['privilege_escalation'] = True
    summary['actions'] = sorted(actions)[:50]
    summary['services'] = sorted(services)[:50]
    return summary


def _managed_policy_summary(name: str) -> dict[str, Any]:
    admin = name in ADMIN_MANAGED_POLICIES
    return {'admin': admin, 'wildcard': admin or name.endswith('FullAccess') or name == 'PowerUserAccess', 'managed': True, 'name': name}


# ---------------------------------------------------------------- normalizer


class AwsCollector(Collector):
    name = 'aws'
    kind = 'cloud'
    description = 'AWS account inventory: IAM identities and permissions, EC2 and security groups, S3, RDS, Lambda and EKS.'
    sdk_modules = ('boto3',)
    secret_fields = ['access_key_id', 'secret_access_key', 'session_token']
    config_schema = {
        'type': 'object', 'additionalProperties': False,
        'properties': {
            'regions': {'type': 'array', 'items': {'type': 'string', 'pattern': r'^[a-z]{2}(-gov)?-[a-z]+-\d$'}, 'description': 'Regions to inventory; default us-east-1'},
            'role_arn': {'type': 'string', 'pattern': r'^arn:aws[a-z-]*:iam::\d{12}:role/.+', 'description': 'Read-only role to assume (recommended: SecurityAudit)'},
            'external_id': {'type': 'string', 'maxLength': 1224},
            'include_global': {'type': 'boolean', 'description': 'Collect IAM and S3 (global services); default true'},
        },
    }

    async def collect(self, ctx: CollectorContext) -> CollectorResult:
        regions = [r for r in ctx.config.get('regions') or ['us-east-1'] if isinstance(r, str)]
        raw = await asyncio.to_thread(_fetch, ctx.config, regions, ctx.logger)
        return self._normalize(raw)

    def _normalize(self, raw: dict[str, Any]) -> CollectorResult:
        r = CollectorResult()
        now = parse_time(raw.get('collected_at')) or datetime.now(timezone.utc)
        source = self.source
        account_id = str(raw.get('account_id') or 'unknown')
        account = r.node('asset', f'aws:account:{account_id}', {'provider': 'aws', 'type': 'account', 'account_id': account_id,
                                                                'regions': raw.get('regions', [])}, label=f'AWS account {account_id}', criticality='high')
        for warning in raw.get('warnings', []) or []:
            r.warn(str(warning))

        iam = raw.get('iam') or {}
        counts = {'iam_users': 0, 'iam_roles': 0, 'policies': 0, 'instances': 0, 'security_groups': 0, 'buckets': 0, 'rds': 0, 'lambda': 0, 'eks': 0}

        if iam.get('account_mfa_enabled') is False:
            r.event(source, f'aws:{account_id}:root-no-mfa', f'AWS root account {account_id} has no MFA device', 'critical', 'cloud_api',
                    actor=f'arn:aws:iam::{account_id}:root', entity=account.key, action='root_mfa_missing', metadata={'account_id': account_id})

        # -- customer managed policies
        policy_nodes: dict[str, Any] = {}
        for policy in iam.get('policies', []) or []:
            arn = policy.get('Arn') or f"aws:policy:{policy.get('PolicyName')}"
            summary = summarize_policy(policy.get('Document'))
            node = r.node('permission', f'aws:policy:{arn}', {**summary, 'name': policy.get('PolicyName'), 'managed': False,
                                                            'attachment_count': policy.get('AttachmentCount', 0)},
                          label=policy.get('PolicyName') or arn, criticality='critical' if summary['admin'] else 'high' if summary['wildcard'] else 'medium')
            policy_nodes[arn] = node
            counts['policies'] += 1

        def permission_for(attached: dict[str, Any]) -> Any:
            arn = attached.get('PolicyArn') or ''
            if arn in policy_nodes:
                return policy_nodes[arn]
            name = attached.get('PolicyName') or arn.rsplit('/', 1)[-1]
            summary = _managed_policy_summary(name)
            node = r.node('permission', f'aws:policy:{arn or name}', summary, label=name, criticality='critical' if summary['admin'] else 'medium')
            policy_nodes[arn or name] = node
            return node

        def inline_permission(owner_arn: str, inline: dict[str, Any]) -> Any:
            summary = summarize_policy(inline.get('PolicyDocument'))
            name = inline.get('PolicyName', 'inline')
            return r.node('permission', f'aws:inline:{owner_arn}/{name}', {**summary, 'name': name, 'inline': True}, label=f'{name} (inline)',
                          criticality='critical' if summary['admin'] else 'high' if summary['wildcard'] else 'low')

        # -- users
        for user in iam.get('users', []) or []:
            arn = user.get('Arn') or f"arn:aws:iam::{account_id}:user/{user.get('UserName')}"
            name = user.get('UserName', arn)
            mfa = bool(user.get('mfa_devices'))
            console = user.get('console_access')
            keys = user.get('access_keys', []) or []
            active_keys = [k for k in keys if k.get('Status', 'Active') == 'Active']
            node = r.node('identity', f'aws:iam:user:{arn}', {'provider': 'aws', 'type': 'iam_user', 'name': name, 'arn': arn, 'mfa': mfa,
                                                              'console_access': console, 'created_at': user.get('CreateDate'),
                                                              'password_last_used': user.get('PasswordLastUsed'), 'access_keys': len(active_keys)},
                          label=f'IAM user {name}', criticality='medium')
            r.edge(account, node, 'owns')
            counts['iam_users'] += 1
            is_admin = False
            for attached in user.get('attached_policies', []) or []:
                perm = permission_for(attached)
                r.edge(node, perm, 'has_permission', {'via': 'attached'})
                is_admin = is_admin or bool(perm.props.get('admin'))
            for inline in user.get('inline_policies', []) or []:
                perm = inline_permission(arn, inline)
                r.edge(node, perm, 'has_permission', {'via': 'inline'})
                is_admin = is_admin or bool(perm.props.get('admin'))
            for group in user.get('groups', []) or []:
                gnode = r.node('role', f"aws:iam:group:{group.get('Arn') or group.get('GroupName')}", {'provider': 'aws', 'type': 'iam_group',
                                                                                                       'name': group.get('GroupName')},
                               label=f"IAM group {group.get('GroupName')}")
                r.edge(node, gnode, 'can_assume', {'via': 'group_membership'})
            if is_admin:
                node.props['admin'] = True
                node.criticality = 'critical'
            if not mfa and console is not False:
                r.event(source, f'aws:{account_id}:user-no-mfa:{name}', f'IAM user {name} has console access without MFA',
                        'high' if is_admin else 'medium', 'cloud_api', actor=arn, entity=node.key, action='mfa_missing',
                        metadata={'account_id': account_id, 'admin': is_admin, 'console_access': console})
            for key in active_keys:
                age = age_days(key.get('CreateDate'), now)
                if age is not None and age > ACCESS_KEY_MAX_AGE_DAYS:
                    key_id = str(key.get('AccessKeyId', ''))
                    r.event(source, f'aws:{account_id}:stale-key:{key_id}', f'Access key for {name} is {int(age)} days old',
                                'high' if is_admin else 'medium', 'cloud_api', actor=arn, entity=node.key, action='access_key_stale',
                                metadata={'account_id': account_id, 'key_suffix': key_id[-4:], 'age_days': int(age), 'last_used': key.get('LastUsedDate')})

        # -- roles
        role_by_name: dict[str, Any] = {}
        for role in iam.get('roles', []) or []:
            arn = role.get('Arn') or f"arn:aws:iam::{account_id}:role/{role.get('RoleName')}"
            name = role.get('RoleName', arn)
            trust = role.get('AssumeRolePolicyDocument') or {}
            trusted = _trusted_principals(trust)
            node = r.node('role', f'aws:iam:role:{arn}', {'provider': 'aws', 'type': 'iam_role', 'name': name, 'arn': arn,
                                                          'service_role': bool(trusted['services']) and not trusted['aws'],
                                                          'trusted_services': trusted['services'], 'trusted_accounts': trusted['accounts'],
                                                          'trusts_anyone': trusted['anyone'], 'created_at': role.get('CreateDate'),
                                                          'last_used': (role.get('RoleLastUsed') or {}).get('LastUsedDate')},
                          label=f'IAM role {name}')
            role_by_name[name] = node
            r.edge(account, node, 'owns')
            counts['iam_roles'] += 1
            is_admin = False
            for attached in role.get('attached_policies', []) or []:
                perm = permission_for(attached)
                r.edge(node, perm, 'has_permission', {'via': 'attached'})
                is_admin = is_admin or bool(perm.props.get('admin'))
            for inline in role.get('inline_policies', []) or []:
                perm = inline_permission(arn, inline)
                r.edge(node, perm, 'has_permission', {'via': 'inline'})
                is_admin = is_admin or bool(perm.props.get('admin'))
            if is_admin:
                node.props['admin'] = True
                node.criticality = 'critical'
            for principal_arn in trusted['aws']:
                if principal_arn.endswith(':root'):
                    ext_account = principal_arn.split(':')[4]
                    if ext_account != account_id:
                        ext = r.node('identity', f'aws:account:{ext_account}:root', {'provider': 'aws', 'type': 'external_account', 'account_id': ext_account},
                                     label=f'External account {ext_account}', criticality='high')
                        r.edge(ext, node, 'can_assume', {'trust': 'cross_account', 'external_id_required': trusted['external_id']})
                    continue
                kind = 'identity' if ':user/' in principal_arn else 'role'
                prefix = 'aws:iam:user:' if kind == 'identity' else 'aws:iam:role:'
                src = r.node(kind, f'{prefix}{principal_arn}', {'provider': 'aws', 'arn': principal_arn}, label=principal_arn.rsplit('/', 1)[-1])
                r.edge(src, node, 'can_assume', {'trust': 'same_account'})
            if trusted['anyone']:
                exposure = r.node('exposure', f'aws:exposure:role-trust:{arn}', {'type': 'role_trusts_anyone', 'arn': arn}, label=f'{name} assumable by anyone',
                                  criticality='critical')
                r.edge(node, exposure, 'exposes')
                r.event(source, f'aws:{account_id}:role-trusts-anyone:{name}', f'IAM role {name} can be assumed by any AWS principal', 'critical',
                        'cloud_api', actor='*', entity=node.key, action='role_trust_open', metadata={'account_id': account_id})

        instance_profiles: dict[str, list[str]] = {k: list(v) for k, v in (iam.get('instance_profiles') or {}).items()}

        # -- EC2
        for region, data in (raw.get('ec2') or {}).items():
            sg_nodes: dict[str, Any] = {}
            open_rules: dict[str, list[dict[str, Any]]] = {}
            for sg in data.get('security_groups', []) or []:
                gid = sg.get('GroupId', '')
                rules = _open_ingress(sg)
                open_rules[gid] = rules
                node = r.node('network', f'aws:sg:{gid}', {'provider': 'aws', 'type': 'security_group', 'name': sg.get('GroupName'), 'vpc_id': sg.get('VpcId'),
                                                            'region': region, 'open_ingress': rules}, label=f"SG {sg.get('GroupName') or gid}",
                              criticality='high' if rules else 'low')
                sg_nodes[gid] = node
                r.edge(account, node, 'owns')
                counts['security_groups'] += 1
                for rule in rules:
                    exposure = r.node('exposure', f"aws:exposure:sg:{gid}:{rule['protocol']}:{rule['ports']}",
                                      {'type': 'open_security_group', 'protocol': rule['protocol'], 'ports': rule['ports'], 'cidr': rule['cidr'], 'region': region},
                                      label=f"{sg.get('GroupName') or gid} {rule['protocol']}/{rule['ports']} from {rule['cidr']}",
                                      criticality='critical' if rule['sensitive'] else 'high')
                    r.edge(node, exposure, 'exposes')
            for reservation in data.get('reservations', []) or []:
                for instance in reservation.get('Instances', []) or []:
                    iid = instance.get('InstanceId', '')
                    tags = {t.get('Key'): t.get('Value') for t in instance.get('Tags', []) or [] if isinstance(t, dict)}
                    public_ip = instance.get('PublicIpAddress')
                    node = r.node('asset', f'aws:ec2:{iid}', {'provider': 'aws', 'type': 'ec2_instance', 'name': tags.get('Name', iid), 'region': region,
                                                              'state': (instance.get('State') or {}).get('Name'), 'instance_type': instance.get('InstanceType'),
                                                              'public_ip': public_ip, 'private_ip': instance.get('PrivateIpAddress'), 'vpc_id': instance.get('VpcId'),
                                                              'subnet_id': instance.get('SubnetId'), 'image_id': instance.get('ImageId'),
                                                              'imdsv2_required': (instance.get('MetadataOptions') or {}).get('HttpTokens') == 'required',
                                                              'tags': tags}, label=tags.get('Name', iid), criticality='high' if public_ip else 'medium')
                    r.edge(account, node, 'owns')
                    counts['instances'] += 1
                    for group in instance.get('SecurityGroups', []) or []:
                        gid = group.get('GroupId', '')
                        sg_node = sg_nodes.get(gid) or r.node('network', f'aws:sg:{gid}', {'provider': 'aws', 'type': 'security_group', 'region': region},
                                                              label=f'SG {gid}')
                        r.edge(node, sg_node, 'connects_to', {'via': 'security_group'})
                        for rule in open_rules.get(gid, []):
                            r.edge(node, ('exposure', f"aws:exposure:sg:{gid}:{rule['protocol']}:{rule['ports']}"), 'exposes',
                                   {'public_ip': public_ip, 'reachable': bool(public_ip)})
                    profile_arn = (instance.get('IamInstanceProfile') or {}).get('Arn')
                    if profile_arn:
                        profile_name = profile_arn.rsplit('/', 1)[-1]
                        for role_name in instance_profiles.get(profile_name) or instance_profiles.get(profile_arn) or [profile_name]:
                            target = role_by_name.get(role_name) or r.node('role', f'aws:iam:role:arn:aws:iam::{account_id}:role/{role_name}',
                                                                           {'provider': 'aws', 'type': 'iam_role', 'name': role_name}, label=f'IAM role {role_name}')
                            r.edge(node, target, 'can_assume', {'via': 'instance_profile'})

        # -- S3
        for bucket in (raw.get('s3') or {}).get('buckets', []) or []:
            name = bucket.get('Name', '')
            pab = bucket.get('public_access_block') or {}
            pab_complete = all(pab.get(k) for k in ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')) if pab else False
            policy_public = bool(bucket.get('policy_public'))
            public = policy_public and not pab_complete
            node = r.node('data_store', f'aws:s3:{name}', {'provider': 'aws', 'type': 's3_bucket', 'name': name, 'region': bucket.get('Region'),
                                                           'public_access_block': pab_complete, 'policy_public': policy_public, 'public': public,
                                                           'created_at': bucket.get('CreationDate')}, label=f's3://{name}',
                          criticality='critical' if public else 'high')
            r.edge(account, node, 'owns')
            counts['buckets'] += 1
            if public:
                exposure = r.node('exposure', f'aws:exposure:s3:{name}', {'type': 'public_bucket', 'bucket': name}, label=f'Public bucket {name}', criticality='critical')
                r.edge(node, exposure, 'exposes')
                r.event(source, f'aws:{account_id}:public-bucket:{name}', f'S3 bucket {name} is publicly accessible by policy', 'high', 'cloud_api',
                        entity=node.key, action='bucket_public', metadata={'account_id': account_id, 'public_access_block': pab_complete})
            elif not pab_complete:
                r.warn(f'bucket {name} has an incomplete public access block')

        # -- RDS
        for region, instances in (raw.get('rds') or {}).items():
            for dbi in instances or []:
                ident = dbi.get('DBInstanceIdentifier', '')
                public = bool(dbi.get('PubliclyAccessible'))
                node = r.node('data_store', f'aws:rds:{region}:{ident}', {'provider': 'aws', 'type': 'rds_instance', 'name': ident, 'region': region,
                                                                         'engine': dbi.get('Engine'), 'engine_version': dbi.get('EngineVersion'),
                                                                         'publicly_accessible': public, 'encrypted': bool(dbi.get('StorageEncrypted')),
                                                                         'multi_az': bool(dbi.get('MultiAZ')), 'endpoint': (dbi.get('Endpoint') or {}).get('Address')},
                              label=f'RDS {ident}', criticality='critical' if public else 'high')
                r.edge(account, node, 'owns')
                counts['rds'] += 1
                for group in dbi.get('VpcSecurityGroups', []) or []:
                    gid = group.get('VpcSecurityGroupId', '')
                    if gid:
                        r.edge(node, ('network', f'aws:sg:{gid}'), 'connects_to', {'via': 'security_group'})
                if public:
                    exposure = r.node('exposure', f'aws:exposure:rds:{ident}', {'type': 'public_database', 'engine': dbi.get('Engine'), 'region': region},
                                      label=f'Public RDS {ident}', criticality='critical')
                    r.edge(node, exposure, 'exposes')
                    r.event(source, f'aws:{account_id}:public-rds:{ident}', f'RDS instance {ident} is publicly accessible', 'high', 'cloud_api',
                            entity=node.key, action='database_public', metadata={'account_id': account_id, 'engine': dbi.get('Engine'), 'region': region})

        # -- Lambda
        for region, functions in (raw.get('lambda') or {}).items():
            for fn in functions or []:
                arn = fn.get('FunctionArn', '')
                node = r.node('asset', f'aws:lambda:{arn}', {'provider': 'aws', 'type': 'lambda_function', 'name': fn.get('FunctionName'), 'region': region,
                                                            'runtime': fn.get('Runtime'), 'role': fn.get('Role'), 'last_modified': fn.get('LastModified'),
                                                            'in_vpc': bool((fn.get('VpcConfig') or {}).get('VpcId'))}, label=fn.get('FunctionName') or arn)
                r.edge(account, node, 'owns')
                counts['lambda'] += 1
                if fn.get('Role'):
                    r.edge(node, ('role', f"aws:iam:role:{fn['Role']}"), 'can_assume', {'via': 'execution_role'})

        # -- EKS
        for region, clusters in (raw.get('eks') or {}).items():
            for cluster in clusters or []:
                arn = cluster.get('arn') or cluster.get('name', '')
                vpc = cluster.get('resourcesVpcConfig') or {}
                public_cidrs = vpc.get('publicAccessCidrs') or []
                open_public = bool(vpc.get('endpointPublicAccess')) and any(c in WORLD for c in public_cidrs)
                node = r.node('asset', f'aws:eks:{arn}', {'provider': 'aws', 'type': 'eks_cluster', 'name': cluster.get('name'), 'region': region,
                                                          'version': cluster.get('version'), 'endpoint_public_access': bool(vpc.get('endpointPublicAccess')),
                                                          'endpoint_private_access': bool(vpc.get('endpointPrivateAccess')), 'public_access_cidrs': public_cidrs,
                                                          'logging': [t.get('types') for t in (cluster.get('logging') or {}).get('clusterLogging', []) if t.get('enabled')]},
                              label=f"EKS {cluster.get('name')}", criticality='critical' if open_public else 'high')
                r.edge(account, node, 'owns')
                counts['eks'] += 1
                if cluster.get('roleArn'):
                    r.edge(node, ('role', f"aws:iam:role:{cluster['roleArn']}"), 'can_assume', {'via': 'cluster_role'})
                if open_public:
                    exposure = r.node('exposure', f'aws:exposure:eks:{arn}', {'type': 'public_k8s_api', 'region': region}, label=f"Public EKS API {cluster.get('name')}",
                                      criticality='high')
                    r.edge(node, exposure, 'exposes')
                    r.event(source, f"aws:{account_id}:eks-public:{cluster.get('name')}", f"EKS cluster {cluster.get('name')} API endpoint is open to the Internet",
                            'medium', 'cloud_api', entity=node.key, action='k8s_api_public', metadata={'account_id': account_id, 'region': region})

        r.stats.update(counts)
        r.stats['account_id'] = account_id
        return r.finalize()


def _trusted_principals(trust: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {'aws': [], 'services': [], 'accounts': [], 'anyone': False, 'external_id': False}
    for statement in _as_list(trust.get('Statement')):
        if not isinstance(statement, dict) or statement.get('Effect') != 'Allow':
            continue
        principal = statement.get('Principal')
        condition = statement.get('Condition') or {}
        if any('sts:ExternalId' in (v or {}) for v in condition.values() if isinstance(v, dict)):
            out['external_id'] = True
        if principal == '*':
            out['anyone'] = not condition
            continue
        if not isinstance(principal, dict):
            continue
        for p in _as_list(principal.get('AWS')):
            p = str(p)
            if p == '*':
                out['anyone'] = not condition
            elif p.isdigit():
                out['accounts'].append(p)
                out['aws'].append(f'arn:aws:iam::{p}:root')
            else:
                out['aws'].append(p)
                parts = p.split(':')
                if len(parts) > 4 and parts[4]:
                    out['accounts'].append(parts[4])
        for s in _as_list(principal.get('Service')):
            out['services'].append(str(s))
    out['accounts'] = sorted(set(out['accounts']))
    out['services'] = sorted(set(out['services']))
    return out


SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 2375, 2379, 5900, 445, 139, 23, 21, 6443, 10250, 11211, 5984, 9092}


def _open_ingress(sg: dict[str, Any]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for perm in sg.get('IpPermissions', []) or []:
        cidrs = [rng.get('CidrIp') for rng in perm.get('IpRanges', []) or []] + [rng.get('CidrIpv6') for rng in perm.get('Ipv6Ranges', []) or []]
        world = [c for c in cidrs if c in WORLD]
        if not world:
            continue
        protocol = perm.get('IpProtocol', '-1')
        from_port, to_port = perm.get('FromPort'), perm.get('ToPort')
        if protocol == '-1' or from_port is None:
            ports, sensitive = 'all', True
        elif from_port == to_port:
            ports, sensitive = str(from_port), from_port in SENSITIVE_PORTS
        else:
            ports = f'{from_port}-{to_port}'
            sensitive = any(from_port <= p <= to_port for p in SENSITIVE_PORTS)
        rules.append({'protocol': 'all' if protocol == '-1' else protocol, 'ports': ports, 'cidr': world[0], 'sensitive': sensitive})
    return rules


# ---------------------------------------------------------------- fetch (boto3, run in a thread)


def _boto_session(config: dict[str, Any], region: str) -> Any:
    """Build the boto3 session; tests monkeypatch this. Static keys come from resolved secrets,
    otherwise the default credential chain (env, profile, instance role) is used."""
    import boto3  # lazy

    kwargs: dict[str, Any] = {'region_name': region}
    if config.get('access_key_id') and config.get('secret_access_key'):
        kwargs.update(aws_access_key_id=config['access_key_id'], aws_secret_access_key=config['secret_access_key'])
        if config.get('session_token'):
            kwargs['aws_session_token'] = config['session_token']
    session = boto3.Session(**kwargs)
    if config.get('role_arn'):
        params = {'RoleArn': config['role_arn'], 'RoleSessionName': 'sentinel-collector', 'DurationSeconds': 3600}
        if config.get('external_id'):
            params['ExternalId'] = config['external_id']
        creds = session.client('sts').assume_role(**params)['Credentials']
        session = boto3.Session(aws_access_key_id=creds['AccessKeyId'], aws_secret_access_key=creds['SecretAccessKey'],
                                aws_session_token=creds['SessionToken'], region_name=region)
    return session


def _error_code(exc: Exception) -> str:
    response = getattr(exc, 'response', None)
    if isinstance(response, dict):
        return str((response.get('Error') or {}).get('Code', ''))
    return type(exc).__name__


def _paginate(client: Any, operation: str, key: str, **kwargs: Any) -> list[Any]:
    items: list[Any] = []
    for page in client.get_paginator(operation).paginate(**kwargs):
        items.extend(page.get(key, []) or [])
    return items


def _fetch(config: dict[str, Any], regions: list[str], logger: logging.Logger) -> dict[str, Any]:
    warnings: list[str] = []
    session = _boto_session(config, regions[0])
    sts = session.client('sts')
    account_id = sts.get_caller_identity().get('Account', '')
    raw: dict[str, Any] = {'account_id': account_id, 'regions': regions, 'collected_at': datetime.now(timezone.utc), 'warnings': warnings,
                           'iam': {}, 'ec2': {}, 's3': {}, 'rds': {}, 'lambda': {}, 'eks': {}}

    def note(label: str, exc: Exception) -> None:
        code = _error_code(exc)
        warnings.append(f'{label}: {code}')
        logger.warning('aws collector: %s failed with %s', label, code)

    def guarded(label: str, fn, default):
        try:
            return fn()
        except Exception as exc:  # one denied API must not sink the whole inventory
            note(label, exc)
            return default

    if config.get('include_global', True):
        iam = session.client('iam')
        raw['iam'] = _fetch_iam(iam, guarded)
        raw['s3'] = {'buckets': _fetch_s3(session.client('s3'), guarded, note)}

    for region in regions:
        ec2 = session.client('ec2', region_name=region)
        raw['ec2'][region] = {
            'reservations': guarded(f'ec2.describe_instances[{region}]', lambda: _paginate(ec2, 'describe_instances', 'Reservations'), []),
            'security_groups': guarded(f'ec2.describe_security_groups[{region}]', lambda: _paginate(ec2, 'describe_security_groups', 'SecurityGroups'), []),
        }
        rds = session.client('rds', region_name=region)
        raw['rds'][region] = guarded(f'rds.describe_db_instances[{region}]', lambda: _paginate(rds, 'describe_db_instances', 'DBInstances'), [])
        lam = session.client('lambda', region_name=region)
        raw['lambda'][region] = guarded(f'lambda.list_functions[{region}]', lambda: _paginate(lam, 'list_functions', 'Functions'), [])
        eks = session.client('eks', region_name=region)
        names = guarded(f'eks.list_clusters[{region}]', lambda: _paginate(eks, 'list_clusters', 'clusters'), [])
        raw['eks'][region] = [c for c in (guarded(f'eks.describe_cluster[{n}]', lambda n=n: eks.describe_cluster(name=n).get('cluster'), None) for n in names) if c]
    return jsonable(raw)


def _fetch_iam(iam: Any, guarded) -> dict[str, Any]:
    out: dict[str, Any] = {'users': [], 'roles': [], 'policies': [], 'instance_profiles': {}, 'account_mfa_enabled': None}
    summary = guarded('iam.get_account_summary', lambda: iam.get_account_summary().get('SummaryMap', {}), {})
    if 'AccountMFAEnabled' in summary:
        out['account_mfa_enabled'] = bool(summary['AccountMFAEnabled'])
    for user in guarded('iam.list_users', lambda: _paginate(iam, 'list_users', 'Users'), []):
        name = user['UserName']
        user['mfa_devices'] = guarded(f'iam.list_mfa_devices[{name}]', lambda: iam.list_mfa_devices(UserName=name).get('MFADevices', []), [])
        user['access_keys'] = guarded(f'iam.list_access_keys[{name}]', lambda: iam.list_access_keys(UserName=name).get('AccessKeyMetadata', []), [])
        user['attached_policies'] = guarded(f'iam.list_attached_user_policies[{name}]', lambda: _paginate(iam, 'list_attached_user_policies', 'AttachedPolicies', UserName=name), [])
        user['groups'] = guarded(f'iam.list_groups_for_user[{name}]', lambda: _paginate(iam, 'list_groups_for_user', 'Groups', UserName=name), [])
        inline_names = guarded(f'iam.list_user_policies[{name}]', lambda: _paginate(iam, 'list_user_policies', 'PolicyNames', UserName=name), [])
        user['inline_policies'] = [p for p in (guarded(f'iam.get_user_policy[{name}/{pn}]', lambda pn=pn: iam.get_user_policy(UserName=name, PolicyName=pn), None)
                                               for pn in inline_names) if p]
        try:
            iam.get_login_profile(UserName=name)
            user['console_access'] = True
        except Exception as exc:
            user['console_access'] = False if _error_code(exc) == 'NoSuchEntity' else None
        out['users'].append(user)
    for role in guarded('iam.list_roles', lambda: _paginate(iam, 'list_roles', 'Roles'), []):
        name = role['RoleName']
        if '/aws-service-role/' in role.get('Path', ''):
            continue  # AWS-managed service-linked roles are not actionable
        role['attached_policies'] = guarded(f'iam.list_attached_role_policies[{name}]', lambda: _paginate(iam, 'list_attached_role_policies', 'AttachedPolicies', RoleName=name), [])
        inline_names = guarded(f'iam.list_role_policies[{name}]', lambda: _paginate(iam, 'list_role_policies', 'PolicyNames', RoleName=name), [])
        role['inline_policies'] = [p for p in (guarded(f'iam.get_role_policy[{name}/{pn}]', lambda pn=pn: iam.get_role_policy(RoleName=name, PolicyName=pn), None)
                                               for pn in inline_names) if p]
        out['roles'].append(role)
    for policy in guarded('iam.list_policies', lambda: _paginate(iam, 'list_policies', 'Policies', Scope='Local', OnlyAttached=False), []):
        version = guarded(f"iam.get_policy_version[{policy['PolicyName']}]",
                          lambda: iam.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId']).get('PolicyVersion', {}), {})
        policy['Document'] = version.get('Document')
        out['policies'].append(policy)
    for profile in guarded('iam.list_instance_profiles', lambda: _paginate(iam, 'list_instance_profiles', 'InstanceProfiles'), []):
        out['instance_profiles'][profile['InstanceProfileName']] = [r.get('RoleName') for r in profile.get('Roles', [])]
    return out


def _fetch_s3(s3: Any, guarded, note) -> list[dict[str, Any]]:
    buckets: list[dict[str, Any]] = []
    for bucket in guarded('s3.list_buckets', lambda: s3.list_buckets().get('Buckets', []), []):
        name = bucket['Name']
        bucket['Region'] = guarded(f's3.get_bucket_location[{name}]', lambda: s3.get_bucket_location(Bucket=name).get('LocationConstraint') or 'us-east-1', None)
        try:
            bucket['public_access_block'] = s3.get_public_access_block(Bucket=name).get('PublicAccessBlockConfiguration', {})
        except Exception as exc:
            bucket['public_access_block'] = None  # no block configured at all, or unreadable: treat as absent
            if _error_code(exc) != 'NoSuchPublicAccessBlockConfiguration':
                note(f's3.get_public_access_block[{name}]', exc)
        try:
            bucket['policy_public'] = bool(s3.get_bucket_policy_status(Bucket=name).get('PolicyStatus', {}).get('IsPublic'))
        except Exception as exc:
            bucket['policy_public'] = False
            if _error_code(exc) != 'NoSuchBucketPolicy':
                note(f's3.get_bucket_policy_status[{name}]', exc)
        buckets.append(bucket)
    return buckets


registry.register(AwsCollector())
