"""AWS executors (boto3, imported lazily). Credentials: ACTIONS_AWS_ROLE_ARN (assumed via STS,
optionally with ACTIONS_AWS_EXTERNAL_ID) or static ACTIONS_AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY.
Every call is blocking boto3 run off the loop; tests monkeypatch `_client`."""
from __future__ import annotations

from typing import Any

from ..catalog import ActionError, ActionType, DryRunResult, ExecContext, ExecResult, entities, register
from ._common import is_not_found, run_blocking

_NAME = {'type': 'string', 'minLength': 1, 'maxLength': 128, 'pattern': r'^[\w+=,.@-]+$'}
_ARN = {'type': 'string', 'minLength': 20, 'maxLength': 2048, 'pattern': r'^arn:aws[a-zA-Z-]*:iam::(aws|\d{12}):policy/.+$'}
_SG = {'type': 'string', 'pattern': r'^sg-[0-9a-f]{8,17}$'}
_CIDR4 = {'type': 'string', 'pattern': r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'}
_CIDR6 = {'type': 'string', 'pattern': r'^[0-9a-fA-F:]+/\d{1,3}$'}


def _session(ctx: ExecContext):
    import boto3  # lazy

    region = ctx.credential('region') or None
    role_arn = ctx.credential('role_arn')
    if role_arn:
        base = boto3.session.Session(region_name=region)
        kwargs: dict[str, Any] = {'RoleArn': role_arn, 'RoleSessionName': f'sentinel-actions-{(ctx.request_id or "adhoc")[:24]}', 'DurationSeconds': 900}
        external_id = ctx.credential('external_id')
        if external_id:
            kwargs['ExternalId'] = external_id
        creds = base.client('sts').assume_role(**kwargs)['Credentials']
        return boto3.session.Session(aws_access_key_id=creds['AccessKeyId'], aws_secret_access_key=creds['SecretAccessKey'],
                                     aws_session_token=creds['SessionToken'], region_name=region)
    access_key = ctx.require_credential('access_key_id')
    return boto3.session.Session(aws_access_key_id=access_key, aws_secret_access_key=ctx.require_credential('secret_access_key'),
                                 aws_session_token=ctx.credential('session_token') or None, region_name=region)


def _client(ctx: ExecContext, service: str):
    """Build a boto3 client. Monkeypatched in tests."""
    return _session(ctx).client(service)


async def _call(fn, **kwargs):
    return await run_blocking(fn, **kwargs)


async def _maybe(fn, **kwargs):
    """Like _call but returns None when the resource does not exist."""
    try:
        return await run_blocking(fn, **kwargs)
    except ActionError as exc:
        if exc.__cause__ is not None and is_not_found(exc.__cause__):
            return None
        raise


# ---------------------------------------------------------------- IAM access keys


@register
class DisableAccessKey(ActionType):
    name = 'aws.iam.disable_access_key'
    description = 'Set an IAM user access key to Inactive (iam:UpdateAccessKey). Rollback re-activates it.'
    params_schema = {'properties': {'user_name': _NAME, 'access_key_id': {'type': 'string', 'pattern': r'^[A-Z0-9]{16,128}$'}},
                     'required': ['user_name', 'access_key_id']}
    risk = 'medium'
    reversible = True
    platforms = ['aws']
    sdk = 'boto3'
    category = 'containment'

    @staticmethod
    def _plan(params: dict) -> dict:
        return {'service': 'iam', 'call': 'UpdateAccessKey',
                'kwargs': {'UserName': params['user_name'], 'AccessKeyId': params['access_key_id'], 'Status': 'Inactive'},
                'rollback_call': 'UpdateAccessKey', 'blast_radius': entities(1, 'iam_access_key', [params['access_key_id']], user=params['user_name'])}

    async def _current(self, ctx: ExecContext, params: dict) -> dict | None:
        iam = _client(ctx, 'iam')
        listing = await _maybe(iam.list_access_keys, UserName=params['user_name'])
        if listing is None:
            return None
        return next((k for k in listing.get('AccessKeyMetadata', []) if k.get('AccessKeyId') == params['access_key_id']), None)

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        plan = self._plan(params)
        key = await self._current(ctx, params)
        if key is None:
            return DryRunResult(ok=False, summary='access key not found on that user', blast_radius=plan['blast_radius'])
        warnings = ['key is already Inactive'] if key.get('Status') == 'Inactive' else []
        return DryRunResult(ok=True, summary=f'deactivate access key {params["access_key_id"]} of user {params["user_name"]}',
                            blast_radius=plan['blast_radius'], warnings=warnings, details={'current_status': key.get('Status')})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(params)
        key = await self._current(ctx, params)
        if key is None:
            raise ActionError('access key not found on that user')
        await _call(_client(ctx, 'iam').update_access_key, **plan['kwargs'])
        return ExecResult(ok=True, summary=f'access key {params["access_key_id"]} set to Inactive',
                          rollback_payload={'user_name': params['user_name'], 'access_key_id': params['access_key_id'],
                                            'previous_status': key.get('Status', 'Active')})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        status = 'Active' if payload.get('previous_status', 'Active') == 'Active' else 'Inactive'
        await _call(_client(ctx, 'iam').update_access_key, UserName=payload['user_name'], AccessKeyId=payload['access_key_id'], Status=status)
        return ExecResult(ok=True, summary=f'access key {payload["access_key_id"]} restored to {status}')


# ---------------------------------------------------------------- IAM policies

_PRINCIPAL_KEYS = {'user': 'UserName', 'role': 'RoleName', 'group': 'GroupName'}


@register
class DetachPolicy(ActionType):
    name = 'aws.iam.detach_policy'
    description = 'Detach a managed policy from an IAM user, role or group (iam:Detach*Policy). Rollback re-attaches it.'
    params_schema = {'properties': {'principal_type': {'type': 'string', 'enum': ['user', 'role', 'group']}, 'principal_name': _NAME,
                                    'policy_arn': _ARN},
                     'required': ['principal_type', 'principal_name', 'policy_arn']}
    risk = 'medium'
    reversible = True
    platforms = ['aws']
    sdk = 'boto3'
    category = 'remediation'

    @staticmethod
    def _plan(params: dict) -> dict:
        kind = params['principal_type']
        key = _PRINCIPAL_KEYS[kind]
        return {'service': 'iam', 'call': f'Detach{kind.capitalize()}Policy', 'rollback_call': f'Attach{kind.capitalize()}Policy',
                'list_call': f'list_attached_{kind}_policies', 'detach': f'detach_{kind}_policy', 'attach': f'attach_{kind}_policy',
                'kwargs': {key: params['principal_name'], 'PolicyArn': params['policy_arn']},
                'blast_radius': entities(1, f'iam_{kind}', [params['principal_name']], policy_arn=params['policy_arn'])}

    async def _attached(self, ctx: ExecContext, plan: dict, params: dict) -> bool | None:
        iam = _client(ctx, 'iam')
        key = _PRINCIPAL_KEYS[params['principal_type']]
        listing = await _maybe(getattr(iam, plan['list_call']), **{key: params['principal_name']})
        if listing is None:
            return None
        return any(p.get('PolicyArn') == params['policy_arn'] for p in listing.get('AttachedPolicies', []))

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        plan = self._plan(params)
        attached = await self._attached(ctx, plan, params)
        if attached is None:
            return DryRunResult(ok=False, summary=f'{params["principal_type"]} {params["principal_name"]} not found', blast_radius=plan['blast_radius'])
        if not attached:
            return DryRunResult(ok=False, summary='policy is not attached to that principal', blast_radius=plan['blast_radius'])
        warnings = ['AWS managed AdministratorAccess-style policies may be the only access path; confirm a break-glass route exists'] \
            if params['policy_arn'].endswith(('/AdministratorAccess', '/PowerUserAccess')) else []
        return DryRunResult(ok=True, summary=f'detach {params["policy_arn"]} from {params["principal_type"]} {params["principal_name"]}',
                            blast_radius=plan['blast_radius'], warnings=warnings)

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(params)
        await _call(getattr(_client(ctx, 'iam'), plan['detach']), **plan['kwargs'])
        return ExecResult(ok=True, summary=f'detached {params["policy_arn"]} from {params["principal_name"]}',
                          rollback_payload={'principal_type': params['principal_type'], 'principal_name': params['principal_name'], 'policy_arn': params['policy_arn']})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(payload)
        await _call(getattr(_client(ctx, 'iam'), plan['attach']), **plan['kwargs'])
        return ExecResult(ok=True, summary=f're-attached {payload["policy_arn"]} to {payload["principal_name"]}')


# ---------------------------------------------------------------- S3 public access block


@register
class BlockPublicAccess(ActionType):
    name = 'aws.s3.block_public_access'
    description = 'Enable the S3 Block Public Access settings on a bucket (s3:PutPublicAccessBlock). Rollback restores the previous configuration.'
    params_schema = {'properties': {'bucket': {'type': 'string', 'minLength': 3, 'maxLength': 63, 'pattern': r'^[a-z0-9][a-z0-9.-]+[a-z0-9]$'},
                                    'block_public_acls': {'type': 'boolean', 'default': True}, 'ignore_public_acls': {'type': 'boolean', 'default': True},
                                    'block_public_policy': {'type': 'boolean', 'default': True}, 'restrict_public_buckets': {'type': 'boolean', 'default': True}},
                     'required': ['bucket']}
    risk = 'medium'
    reversible = True
    platforms = ['aws']
    sdk = 'boto3'
    category = 'remediation'

    @staticmethod
    def _plan(params: dict) -> dict:
        config = {'BlockPublicAcls': bool(params.get('block_public_acls', True)), 'IgnorePublicAcls': bool(params.get('ignore_public_acls', True)),
                  'BlockPublicPolicy': bool(params.get('block_public_policy', True)), 'RestrictPublicBuckets': bool(params.get('restrict_public_buckets', True))}
        return {'service': 's3', 'call': 'PutPublicAccessBlock', 'kwargs': {'Bucket': params['bucket'], 'PublicAccessBlockConfiguration': config},
                'blast_radius': entities(1, 's3_bucket', [params['bucket']])}

    async def _previous(self, ctx: ExecContext, bucket: str) -> tuple[bool, dict | None]:
        s3 = _client(ctx, 's3')
        if await _maybe(s3.head_bucket, Bucket=bucket) is None:
            return False, None
        current = await _maybe(s3.get_public_access_block, Bucket=bucket)
        return True, (current or {}).get('PublicAccessBlockConfiguration') if current else None

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        plan = self._plan(params)
        exists, previous = await self._previous(ctx, params['bucket'])
        if not exists:
            return DryRunResult(ok=False, summary='bucket not found or not accessible', blast_radius=plan['blast_radius'])
        warnings = []
        if previous == plan['kwargs']['PublicAccessBlockConfiguration']:
            warnings.append('bucket already has this configuration')
        warnings.append('public website hosting or anonymous object reads from this bucket will stop working')
        return DryRunResult(ok=True, summary=f'block public access on bucket {params["bucket"]}', blast_radius=plan['blast_radius'],
                            warnings=warnings, details={'previous': previous})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(params)
        exists, previous = await self._previous(ctx, params['bucket'])
        if not exists:
            raise ActionError('bucket not found or not accessible')
        await _call(_client(ctx, 's3').put_public_access_block, **plan['kwargs'])
        return ExecResult(ok=True, summary=f'public access blocked on {params["bucket"]}', rollback_payload={'bucket': params['bucket'], 'previous': previous})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        s3 = _client(ctx, 's3')
        if payload.get('previous'):
            await _call(s3.put_public_access_block, Bucket=payload['bucket'], PublicAccessBlockConfiguration=payload['previous'])
            return ExecResult(ok=True, summary=f'previous public access block restored on {payload["bucket"]}')
        await _call(s3.delete_public_access_block, Bucket=payload['bucket'])
        return ExecResult(ok=True, summary=f'public access block removed from {payload["bucket"]} (none existed before)')


# ---------------------------------------------------------------- EC2 security group ingress


@register
class RevokeSgIngress(ActionType):
    name = 'aws.ec2.revoke_sg_ingress'
    description = 'Remove one ingress rule from a security group (ec2:RevokeSecurityGroupIngress). Rollback re-authorizes the exact rule.'
    params_schema = {'properties': {'group_id': _SG, 'ip_protocol': {'type': 'string', 'enum': ['tcp', 'udp', 'icmp', 'icmpv6', '-1']},
                                    'from_port': {'type': 'integer', 'minimum': -1, 'maximum': 65535}, 'to_port': {'type': 'integer', 'minimum': -1, 'maximum': 65535},
                                    'cidr_ipv4': _CIDR4, 'cidr_ipv6': _CIDR6, 'source_group_id': _SG},
                     'required': ['group_id', 'ip_protocol']}
    risk = 'medium'
    reversible = True
    platforms = ['aws']
    sdk = 'boto3'
    category = 'containment'

    @staticmethod
    def _plan(params: dict) -> dict:
        present = [k for k in ('cidr_ipv4', 'cidr_ipv6', 'source_group_id') if params.get(k)]
        if len(present) != 1:
            raise ActionError('exactly one of cidr_ipv4, cidr_ipv6, source_group_id is required')
        perm: dict[str, Any] = {'IpProtocol': params['ip_protocol']}
        if params['ip_protocol'] != '-1':
            if params.get('from_port') is None or params.get('to_port') is None:
                raise ActionError('from_port and to_port are required unless ip_protocol is -1')
            perm['FromPort'], perm['ToPort'] = int(params['from_port']), int(params['to_port'])
        source = present[0]
        if source == 'cidr_ipv4':
            perm['IpRanges'] = [{'CidrIp': params['cidr_ipv4']}]
        elif source == 'cidr_ipv6':
            perm['Ipv6Ranges'] = [{'CidrIpv6': params['cidr_ipv6']}]
        else:
            perm['UserIdGroupPairs'] = [{'GroupId': params['source_group_id']}]
        return {'service': 'ec2', 'call': 'RevokeSecurityGroupIngress', 'rollback_call': 'AuthorizeSecurityGroupIngress',
                'kwargs': {'GroupId': params['group_id'], 'IpPermissions': [perm]}, 'source': params[source],
                'blast_radius': entities(1, 'security_group', [params['group_id']], rule=f'{params["ip_protocol"]} {perm.get("FromPort", "*")}-{perm.get("ToPort", "*")} from {params[source]}')}

    @staticmethod
    def _matches(existing: dict, wanted: dict) -> bool:
        if existing.get('IpProtocol') != wanted['IpProtocol']:
            return False
        if wanted['IpProtocol'] != '-1' and (existing.get('FromPort') != wanted.get('FromPort') or existing.get('ToPort') != wanted.get('ToPort')):
            return False
        if 'IpRanges' in wanted:
            return any(r.get('CidrIp') == wanted['IpRanges'][0]['CidrIp'] for r in existing.get('IpRanges', []))
        if 'Ipv6Ranges' in wanted:
            return any(r.get('CidrIpv6') == wanted['Ipv6Ranges'][0]['CidrIpv6'] for r in existing.get('Ipv6Ranges', []))
        return any(p.get('GroupId') == wanted['UserIdGroupPairs'][0]['GroupId'] for p in existing.get('UserIdGroupPairs', []))

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        plan = self._plan(params)
        ec2 = _client(ctx, 'ec2')
        described = await _maybe(ec2.describe_security_groups, GroupIds=[params['group_id']])
        groups = (described or {}).get('SecurityGroups', [])
        if not groups:
            return DryRunResult(ok=False, summary='security group not found', blast_radius=plan['blast_radius'])
        wanted = plan['kwargs']['IpPermissions'][0]
        if not any(self._matches(p, wanted) for p in groups[0].get('IpPermissions', [])):
            return DryRunResult(ok=False, summary='that ingress rule is not present on the group', blast_radius=plan['blast_radius'])
        enis = await _maybe(ec2.describe_network_interfaces, Filters=[{'Name': 'group-id', 'Values': [params['group_id']]}]) or {}
        radius = dict(plan['blast_radius'], attached_interfaces=len(enis.get('NetworkInterfaces', [])))
        return DryRunResult(ok=True, summary=f'revoke ingress {radius["rule"]} on {params["group_id"]}', blast_radius=radius,
                            warnings=[f'{radius["attached_interfaces"]} network interface(s) use this group'] if radius['attached_interfaces'] > 1 else [])

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(params)
        await _call(_client(ctx, 'ec2').revoke_security_group_ingress, **plan['kwargs'])
        return ExecResult(ok=True, summary=f'revoked ingress {plan["blast_radius"]["rule"]} on {params["group_id"]}',
                          rollback_payload={'group_id': params['group_id'], 'permission': plan['kwargs']['IpPermissions'][0]})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        await _call(_client(ctx, 'ec2').authorize_security_group_ingress, GroupId=payload['group_id'], IpPermissions=[payload['permission']])
        return ExecResult(ok=True, summary=f're-authorized ingress rule on {payload["group_id"]}')


# ---------------------------------------------------------------- EC2 instance isolation


@register
class IsolateInstance(ActionType):
    name = 'aws.ec2.isolate_instance'
    description = 'Swap every network interface of an instance to a quarantine security group (ec2:ModifyNetworkInterfaceAttribute). Rollback restores the original groups.'
    params_schema = {'properties': {'instance_id': {'type': 'string', 'pattern': r'^i-[0-9a-f]{8,17}$'}, 'quarantine_sg_id': _SG},
                     'required': ['instance_id', 'quarantine_sg_id']}
    risk = 'high'
    reversible = True
    platforms = ['aws']
    sdk = 'boto3'
    category = 'containment'

    @staticmethod
    def _plan(instance: dict, quarantine: dict) -> dict:
        interfaces = [{'id': eni['NetworkInterfaceId'], 'groups': [g['GroupId'] for g in eni.get('Groups', [])]} for eni in instance.get('NetworkInterfaces', [])]
        warnings = []
        if instance.get('VpcId') and quarantine.get('VpcId') and instance['VpcId'] != quarantine['VpcId']:
            raise ActionError('quarantine security group is in a different VPC than the instance')
        if quarantine.get('IpPermissions'):
            warnings.append('quarantine group allows ingress; isolation will be partial')
        egress = quarantine.get('IpPermissionsEgress', [])
        if any(r.get('CidrIp') == '0.0.0.0/0' for p in egress for r in p.get('IpRanges', [])):
            warnings.append('quarantine group allows egress to 0.0.0.0/0; outbound traffic will not be contained')
        if not interfaces:
            raise ActionError('instance has no network interfaces')
        calls = [{'call': 'ModifyNetworkInterfaceAttribute', 'kwargs': {'NetworkInterfaceId': i['id'], 'Groups': [quarantine['GroupId']]}} for i in interfaces]
        return {'service': 'ec2', 'calls': calls, 'interfaces': interfaces, 'warnings': warnings,
                'blast_radius': entities(1, 'ec2_instance', [instance.get('InstanceId', '')], interfaces=len(interfaces),
                                         state=(instance.get('State') or {}).get('Name', ''))}

    async def _load(self, ctx: ExecContext, params: dict) -> tuple[dict | None, dict | None]:
        ec2 = _client(ctx, 'ec2')
        described = await _maybe(ec2.describe_instances, InstanceIds=[params['instance_id']])
        instance = next((i for r in (described or {}).get('Reservations', []) for i in r.get('Instances', [])), None)
        groups = await _maybe(ec2.describe_security_groups, GroupIds=[params['quarantine_sg_id']])
        quarantine = next(iter((groups or {}).get('SecurityGroups', [])), None)
        return instance, quarantine

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        instance, quarantine = await self._load(ctx, params)
        if instance is None:
            return DryRunResult(ok=False, summary='instance not found', blast_radius=entities(0, 'ec2_instance'))
        if quarantine is None:
            return DryRunResult(ok=False, summary='quarantine security group not found', blast_radius=entities(0, 'ec2_instance'))
        plan = self._plan(instance, quarantine)
        return DryRunResult(ok=True, summary=f'move {len(plan["interfaces"])} interface(s) of {params["instance_id"]} to {params["quarantine_sg_id"]}',
                            blast_radius=plan['blast_radius'], warnings=plan['warnings'], details={'interfaces': plan['interfaces']})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        instance, quarantine = await self._load(ctx, params)
        if instance is None or quarantine is None:
            raise ActionError('instance or quarantine security group not found')
        plan = self._plan(instance, quarantine)
        ec2 = _client(ctx, 'ec2')
        for call in plan['calls']:
            await _call(ec2.modify_network_interface_attribute, **call['kwargs'])
            await ctx.heartbeat()
        return ExecResult(ok=True, summary=f'instance {params["instance_id"]} isolated behind {params["quarantine_sg_id"]}',
                          rollback_payload={'instance_id': params['instance_id'], 'interfaces': plan['interfaces']})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        ec2 = _client(ctx, 'ec2')
        for eni in payload.get('interfaces', []):
            if eni.get('groups'):
                await _call(ec2.modify_network_interface_attribute, NetworkInterfaceId=eni['id'], Groups=eni['groups'])
        return ExecResult(ok=True, summary=f'security groups restored on {payload["instance_id"]}')


# ---------------------------------------------------------------- IAM permissions boundary


@register
class AttachDenyAllBoundary(ActionType):
    name = 'aws.iam.attach_deny_all_boundary'
    description = 'Attach a deny-all permissions boundary to an IAM user or role (iam:Put*PermissionsBoundary), neutralizing every permission it has. Rollback restores the previous boundary.'
    params_schema = {'properties': {'principal_type': {'type': 'string', 'enum': ['user', 'role']}, 'principal_name': _NAME, 'boundary_policy_arn': _ARN},
                     'required': ['principal_type', 'principal_name', 'boundary_policy_arn']}
    risk = 'critical'
    reversible = True
    platforms = ['aws']
    sdk = 'boto3'
    category = 'containment'

    @staticmethod
    def _plan(params: dict) -> dict:
        kind = params['principal_type']
        key = _PRINCIPAL_KEYS[kind]
        return {'service': 'iam', 'call': f'Put{kind.capitalize()}PermissionsBoundary', 'get': f'get_{kind}', 'put': f'put_{kind}_permissions_boundary',
                'delete': f'delete_{kind}_permissions_boundary', 'kwargs': {key: params['principal_name'], 'PermissionsBoundary': params['boundary_policy_arn']},
                'key': key, 'blast_radius': entities(1, f'iam_{kind}', [params['principal_name']])}

    async def _current(self, ctx: ExecContext, plan: dict, params: dict) -> tuple[bool, str | None, bool]:
        iam = _client(ctx, 'iam')
        policy = await _maybe(iam.get_policy, PolicyArn=params['boundary_policy_arn'])
        got = await _maybe(getattr(iam, plan['get']), **{plan['key']: params['principal_name']})
        if got is None:
            return False, None, policy is not None
        record = got.get('User') or got.get('Role') or {}
        boundary = (record.get('PermissionsBoundary') or {}).get('PermissionsBoundaryArn')
        return True, boundary, policy is not None

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        plan = self._plan(params)
        exists, boundary, policy_ok = await self._current(ctx, plan, params)
        if not exists:
            return DryRunResult(ok=False, summary=f'{params["principal_type"]} {params["principal_name"]} not found', blast_radius=plan['blast_radius'])
        if not policy_ok:
            return DryRunResult(ok=False, summary='boundary policy not found', blast_radius=plan['blast_radius'])
        warnings = ['this neutralizes every permission of the principal, including any used by running workloads']
        if boundary:
            warnings.append(f'existing boundary {boundary} will be replaced')
        return DryRunResult(ok=True, summary=f'attach boundary {params["boundary_policy_arn"]} to {params["principal_type"]} {params["principal_name"]}',
                            blast_radius=plan['blast_radius'], warnings=warnings, details={'previous_boundary': boundary})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(params)
        exists, boundary, policy_ok = await self._current(ctx, plan, params)
        if not exists or not policy_ok:
            raise ActionError('principal or boundary policy not found')
        await _call(getattr(_client(ctx, 'iam'), plan['put']), **plan['kwargs'])
        return ExecResult(ok=True, summary=f'boundary attached to {params["principal_name"]}',
                          rollback_payload={'principal_type': params['principal_type'], 'principal_name': params['principal_name'], 'previous_boundary': boundary})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        kind = payload['principal_type']
        key = _PRINCIPAL_KEYS[kind]
        iam = _client(ctx, 'iam')
        if payload.get('previous_boundary'):
            await _call(getattr(iam, f'put_{kind}_permissions_boundary'), **{key: payload['principal_name'], 'PermissionsBoundary': payload['previous_boundary']})
            return ExecResult(ok=True, summary=f'previous boundary restored on {payload["principal_name"]}')
        await _call(getattr(iam, f'delete_{kind}_permissions_boundary'), **{key: payload['principal_name']})
        return ExecResult(ok=True, summary=f'boundary removed from {payload["principal_name"]}')
