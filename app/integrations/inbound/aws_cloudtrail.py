"""AWS CloudTrail: `{"Records": [...]}` files, single records, or EventBridge "AWS API Call via
CloudTrail" envelopes. eventSource/eventName map to dotted actions (`s3.put_bucket_policy`) and
public-exposure markers in requestParameters are surfaced for the cloud detection rules."""
from __future__ import annotations

from typing import Any

from ...core.findings import EventDraft
from . import registry
from ._common import ParseContext, Parser, dig, event, first, hash_item, scan_markers, snake

# eventNames whose dotted form the identity rules treat as data access.
_DATA_ACCESS = {'s3.get_object', 's3.list_bucket', 's3.list_objects', 's3.list_objects_v2', 'dynamodb.scan', 'dynamodb.query', 'dynamodb.get_item',
                'dynamodb.batch_get_item', 'secretsmanager.get_secret_value', 'ssm.get_parameter', 'ssm.get_parameters', 'ssm.get_parameters_by_path',
                'kms.decrypt', 'rds.describe_db_snapshots', 'rds.download_db_log_file_portion', 'athena.get_query_results', 'lambda.get_function'}
_GRANT_PREFIXES = ('iam.attach_', 'iam.put_', 'iam.add_user_to_group', 'iam.create_access_key', 'iam.create_policy_version', 'iam.create_login_profile',
                   'iam.update_assume_role_policy', 'organizations.attach_policy', 'sso.put_permissions_boundary')
_EXPOSURE = {'s3.put_bucket_policy', 's3.put_bucket_acl', 's3.put_object_acl', 's3.delete_public_access_block', 's3.put_public_access_block',
             'ec2.authorize_security_group_ingress', 'ec2.modify_security_group_rules', 'ec2.create_security_group', 'rds.modify_db_instance',
             'lambda.add_permission', 'sns.add_permission', 'sqs.add_permission', 'kms.put_key_policy', 'ecr.set_repository_policy',
             'elasticfilesystem.put_file_system_policy', 'es.update_elasticsearch_domain_config', 'glacier.set_vault_access_policy'}
_READ_PREFIXES = ('describe', 'list', 'get', 'head', 'lookup', 'search', 'query', 'batch_get', 'select')
_SENSITIVE_WRITE = ('delete', 'stop', 'disable', 'deactivate', 'update_trail', 'put_event_selectors')

_ENTITY_KEYS = ('bucketName', 'roleArn', 'roleName', 'userName', 'groupId', 'groupName', 'policyArn', 'instanceId', 'functionName', 'tableName',
                'secretId', 'keyId', 'name', 'dBInstanceIdentifier', 'repositoryName', 'topicArn', 'queueUrl', 'domainName', 'trailName', 'clusterName')


def _actor(identity: dict) -> str:
    arn = identity.get('arn') or ''
    if arn:
        return str(arn)
    issuer = dig(identity, 'sessionContext', 'sessionIssuer', 'arn')
    if issuer:
        return str(issuer)
    if identity.get('type') == 'Root':
        return f'root:{identity.get("accountId", "")}'
    if identity.get('type') == 'AWSService':
        return str(identity.get('invokedBy') or 'aws-service')
    return str(identity.get('userName') or identity.get('principalId') or identity.get('accountId') or '')


def _entity(params: dict, resources: list, request: dict) -> str:
    value = first(params, *_ENTITY_KEYS)
    if isinstance(value, (str, int)):
        return str(value)
    if isinstance(value, dict):
        inner = first(value, 'name', 'arn')
        if inner:
            return str(inner)
    for res in resources:
        if isinstance(res, dict) and res.get('ARN'):
            return str(res['ARN'])
    sg_items = dig(params, 'groupId') or dig(params, 'securityGroupRuleIds')
    if sg_items:
        return str(sg_items)
    return ''


class CloudTrailParser(Parser):
    name = 'aws_cloudtrail'
    aliases = ('cloudtrail',)
    source = 'aws_cloudtrail'
    description = 'AWS CloudTrail records (log file Records[], single records, or EventBridge "AWS API Call via CloudTrail" events).'
    kind = 'events'
    example = 'tests/fixtures/integrations/aws_cloudtrail/records.json'

    def items(self, payload: Any) -> list[Any]:
        if isinstance(payload, dict):
            if isinstance(payload.get('Records'), list):
                return payload['Records']
            if isinstance(payload.get('detail'), dict) and 'eventName' in payload['detail']:
                return [payload['detail']]
            return [payload]
        out: list[Any] = []
        for item in payload:
            if isinstance(item, dict) and isinstance(item.get('detail'), dict) and 'eventName' in item['detail']:
                out.append(item['detail'])
            elif isinstance(item, dict) and isinstance(item.get('Records'), list):
                out.extend(item['Records'])
            else:
                out.append(item)
        return out

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        service = str(item.get('eventSource') or 'aws').split('.')[0].lower()
        name = str(item.get('eventName') or 'unknown')
        action = f'{service}.{snake(name)}'
        identity = item.get('userIdentity') if isinstance(item.get('userIdentity'), dict) else {}
        params = item.get('requestParameters') if isinstance(item.get('requestParameters'), dict) else {}
        resources = item.get('resources') if isinstance(item.get('resources'), list) else []
        actor = _actor(identity)
        entity = _entity(params, resources, item)
        markers = scan_markers(params) if action in _EXPOSURE or service in {'s3', 'ec2', 'iam', 'kms', 'lambda', 'sns', 'sqs'} else []
        read_only = item.get('readOnly')
        if read_only is None:
            read_only = snake(name).startswith(_READ_PREFIXES)
        if action in _DATA_ACCESS:
            category, severity = 'data_access', 'low'
        elif service in {'sts', 'signin'} or (service == 'iam' and action.startswith(_GRANT_PREFIXES)):
            category, severity = 'identity', 'medium' if not read_only else 'low'
        else:
            category = 'cloud_api'
            severity = 'informational' if read_only else 'medium' if snake(name).startswith(_SENSITIVE_WRITE) else 'low'
        if action in _EXPOSURE and markers:
            severity = 'high'
        if item.get('errorCode'):
            severity = 'low' if severity == 'informational' else severity
        if action in {'sts.assume_role', 'sts.assume_role_with_web_identity', 'sts.assume_role_with_saml'}:
            entity = str(params.get('roleArn') or entity)
        session_ctx = identity.get('sessionContext') if isinstance(identity.get('sessionContext'), dict) else {}
        meta: dict[str, Any] = {
            'ip': item.get('sourceIPAddress') or '', 'user_agent': item.get('userAgent') or '', 'region': item.get('awsRegion') or '',
            'account': item.get('recipientAccountId') or identity.get('accountId') or '', 'service': service, 'event_source': item.get('eventSource') or '',
            'event_name': name, 'event_id': item.get('eventID') or '', 'event_type': item.get('eventType') or '', 'read_only': bool(read_only),
            'identity_type': identity.get('type') or '', 'principal_id': identity.get('principalId') or '', 'user_name': identity.get('userName') or '',
            'role': dig(session_ctx, 'sessionIssuer', 'arn') or '', 'mfa': dig(session_ctx, 'attributes', 'mfaAuthenticated') or '',
            'error_code': item.get('errorCode') or '', 'error_message': item.get('errorMessage') or '', 'request_parameters': params,
            'resources': [str(r.get('ARN')) for r in resources if isinstance(r, dict) and r.get('ARN')][:10], 'markers': markers,
            'tls': dig(item, 'tlsDetails', 'tlsVersion') or '', 'management_event': item.get('managementEvent'),
        }
        if markers:
            meta['public'] = True
        title = f'{name} on {entity}' if entity else f'{name} ({service})'
        external_id = item.get('eventID') or hash_item(item)
        return [event(self.source, external_id, title, severity=severity, category=category, actor=actor, entity=entity, action=action,
                      occurred_at=item.get('eventTime'), metadata=meta)]


registry.register(CloudTrailParser())
