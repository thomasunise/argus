"""Amazon GuardDuty findings: raw finding JSON (GetFindings shape) or the EventBridge envelope
`{"detail-type": "GuardDuty Finding", "detail": {...}}`."""
from __future__ import annotations

from typing import Any

from ...core.findings import EventDraft
from . import registry
from ._common import ParseContext, Parser, as_float, dig, event, first, geo, hash_item, snake


def _lower_first(node: Any, depth: int = 0) -> Any:
    """Recursively lower-case the first character of every key (PascalCase -> camelCase). Bounded depth."""
    if depth > 8:
        return node
    if isinstance(node, dict):
        return {(k[0].lower() + k[1:]) if isinstance(k, str) and k else k: _lower_first(v, depth + 1) for k, v in node.items()}
    if isinstance(node, list):
        return [_lower_first(v, depth + 1) for v in node[:100]]
    return node


def _severity(value: Any) -> str:
    score = as_float(value)
    if score is None:
        return 'medium'
    if score >= 9.0:
        return 'critical'
    if score >= 7.0:
        return 'high'
    if score >= 4.0:
        return 'medium'
    return 'low'


def _resource_entity(resource: dict) -> tuple[str, str]:
    kind = str(resource.get('resourceType') or '')
    if kind == 'AccessKey':
        key = resource.get('accessKeyDetails') if isinstance(resource.get('accessKeyDetails'), dict) else {}
        return str(key.get('userName') or key.get('principalId') or ''), 'identity'
    if kind == 'Instance':
        inst = resource.get('instanceDetails') if isinstance(resource.get('instanceDetails'), dict) else {}
        return str(inst.get('instanceId') or ''), 'host'
    if kind == 'S3Bucket':
        buckets = resource.get('s3BucketDetails') if isinstance(resource.get('s3BucketDetails'), list) else []
        return str(buckets[0].get('name') if buckets and isinstance(buckets[0], dict) else ''), 'data_store'
    if kind == 'EKSCluster':
        return str(dig(resource, 'eksClusterDetails', 'name') or ''), 'k8s_cluster'
    if kind == 'Lambda':
        return str(dig(resource, 'lambdaDetails', 'functionName') or ''), 'function'
    if kind == 'RDSDBInstance':
        return str(dig(resource, 'rdsDbInstanceDetails', 'dbInstanceIdentifier') or ''), 'database'
    return '', kind.lower() or 'resource'


class GuardDutyParser(Parser):
    name = 'aws_guardduty'
    aliases = ('guardduty',)
    source = 'aws_guardduty'
    description = 'Amazon GuardDuty findings (GetFindings JSON or EventBridge envelope).'
    kind = 'events'
    example = 'tests/fixtures/integrations/aws_guardduty/findings.json'
    correlate_alerts = True

    def items(self, payload: Any) -> list[Any]:
        if isinstance(payload, dict):
            if isinstance(payload.get('Findings'), list):
                return payload['Findings']
            if isinstance(payload.get('detail'), dict):
                return [payload['detail']]
            return [payload]
        return [p.get('detail') if isinstance(p, dict) and isinstance(p.get('detail'), dict) else p for p in payload]

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        item = _lower_first(item)  # GetFindings returns PascalCase, EventBridge camelCase; normalise to camelCase
        ftype = str(item.get('Type') or item.get('type') or 'Unknown')
        purpose = ftype.split(':')[0]
        resource = item.get('Resource') or item.get('resource') or {}
        resource = resource if isinstance(resource, dict) else {}
        service = item.get('Service') or item.get('service') or {}
        service = service if isinstance(service, dict) else {}
        entity, entity_kind = _resource_entity(resource)
        action_info = service.get('Action') or service.get('action') or {}
        action_info = action_info if isinstance(action_info, dict) else {}
        aws_api = action_info.get('AwsApiCallAction') or action_info.get('awsApiCallAction') or {}
        remote = dig(aws_api, 'RemoteIpDetails') or dig(aws_api, 'remoteIpDetails') or dig(action_info, 'NetworkConnectionAction', 'RemoteIpDetails') or \
            dig(action_info, 'networkConnectionAction', 'remoteIpDetails') or {}
        remote = remote if isinstance(remote, dict) else {}
        geo_src = remote.get('GeoLocation') or remote.get('geoLocation') or {}
        country = dig(remote, 'country', 'countryCode') or dig(remote, 'Country', 'CountryCode') or dig(remote, 'country', 'countryName') or \
            dig(remote, 'Country', 'CountryName') or ''
        key_details = resource.get('accessKeyDetails') if isinstance(resource.get('accessKeyDetails'), dict) else {}
        actor = str(key_details.get('userName') or '')
        severity = _severity(item.get('Severity', item.get('severity')))
        api_name = aws_api.get('Api') or aws_api.get('api') or ''
        api_service = str(aws_api.get('ServiceName') or aws_api.get('serviceName') or '').split('.')[0]
        meta: dict[str, Any] = {
            'finding_type': ftype, 'finding_id': item.get('Id') or item.get('id') or '', 'account': item.get('AccountId') or item.get('accountId') or '',
            'region': item.get('Region') or item.get('region') or '', 'severity_score': as_float(item.get('Severity', item.get('severity'))),
            'resource_type': resource.get('resourceType') or '', 'entity_kind': entity_kind, 'service': 'guardduty',
            'ip': remote.get('IpAddressV4') or remote.get('ipAddressV4') or '', 'org': dig(remote, 'Organization', 'Org') or dig(remote, 'organization', 'org') or '',
            'geo': geo(geo_src.get('Lat', geo_src.get('lat')), geo_src.get('Lon', geo_src.get('lon')), country, dig(remote, 'City', 'CityName') or dig(remote, 'city', 'cityName')),
            'api': f'{api_service}.{snake(api_name)}' if api_name else '', 'count': service.get('Count') or service.get('count'),
            'archived': service.get('Archived') or service.get('archived'), 'threat_names': dig(service, 'Evidence', 'ThreatIntelligenceDetails') or [],
            'user_agent': dig(aws_api, 'UserAgent') or dig(aws_api, 'userAgent') or '',
        }
        title = str(item.get('Title') or item.get('title') or ftype)
        external_id = item.get('Id') or item.get('id') or hash_item(item)
        occurred = first(service, 'EventLastSeen', 'eventLastSeen') or first(item, 'UpdatedAt', 'updatedAt', 'CreatedAt', 'createdAt')
        return [event(self.source, external_id, title, severity=severity, category='cloud', actor=actor, entity=entity,
                      action=f'guardduty.{snake(purpose)}', occurred_at=occurred, metadata=meta)]


registry.register(GuardDutyParser())
