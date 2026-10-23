"""Microsoft Defender for Cloud security alerts (Microsoft.Security/Locations/alerts schema, as
exported by continuous export / Event Hub) and Azure Activity Log entries for NSG, storage,
role-assignment and Key Vault writes."""
from __future__ import annotations

from typing import Any

from ...core.findings import EventDraft
from . import registry
from ._common import ParseContext, Parser, dig, event, first, hash_item, scan_markers, snake

# operationName (lower-case) -> dotted action the cloud/identity rules recognise.
_OPERATIONS = {
    'microsoft.network/networksecuritygroups/securityrules/write': 'az.network.nsg.rule.write',
    'microsoft.network/networksecuritygroups/write': 'az.network.nsg.write',
    'microsoft.storage/storageaccounts/write': 'az.storage.account.write',
    'microsoft.storage/storageaccounts/blobservices/containers/write': 'az.storage.container.write',
    'microsoft.storage/storageaccounts/listkeys/action': 'az.storage.list_keys',
    'microsoft.authorization/roleassignments/write': 'az.role_assignment.write',
    'microsoft.authorization/roleassignments/delete': 'az.role_assignment.delete',
    'microsoft.authorization/roleassignmentschedulerequests/write': 'az.role.activate',
    'microsoft.authorization/roleeligibilityschedulerequests/write': 'az.role.activate',
    'microsoft.keyvault/vaults/secrets/read': 'az.keyvault.secret.get',
    'microsoft.keyvault/vaults/secrets/write': 'az.keyvault.secret.write',
    'microsoft.keyvault/vaults/accesspolicies/write': 'az.keyvault.access_policy.write',
    'microsoft.storage/storageaccounts/blobservices/containers/blobs/read': 'az.storage.blob.read',
    'microsoft.compute/virtualmachines/runcommand/action': 'az.compute.vm.run_command',
    'microsoft.compute/virtualmachines/extensions/write': 'az.compute.vm.extension.write',
}
_DATA_ACCESS = {'az.keyvault.secret.get', 'az.storage.blob.read', 'az.storage.list_keys'}
_IDENTITY = {'az.role_assignment.write', 'az.role_assignment.delete', 'az.role.activate', 'az.keyvault.access_policy.write'}


def _activity_action(operation: str) -> str:
    key = operation.lower()
    if key in _OPERATIONS:
        return _OPERATIONS[key]
    parts = [p for p in key.replace('microsoft.', '', 1).split('/') if p]
    return 'az.' + '.'.join(snake(p) for p in parts)[:100] if parts else 'az.unknown'


def _severity(value: Any) -> str:
    text = str(value or 'medium').lower()
    return {'high': 'high', 'medium': 'medium', 'low': 'low', 'informational': 'informational', 'critical': 'critical'}.get(text, 'medium')


class AzureDefenderParser(Parser):
    name = 'azure_defender'
    aliases = ('defender', 'azure_activity', 'azure')
    source = 'azure_defender'
    description = 'Defender for Cloud security alerts and Azure Activity Log administrative events.'
    kind = 'events'
    example = 'tests/fixtures/integrations/azure_defender/alerts.json'
    correlate_alerts = True

    def items(self, payload: Any) -> list[Any]:
        if isinstance(payload, dict):
            if isinstance(payload.get('records'), list):      # Event Hub / diagnostic settings batch
                return payload['records']
            if isinstance(payload.get('value'), list):        # ARM list response
                return payload['value']
            return [payload]
        return payload

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        props = item.get('properties') if isinstance(item.get('properties'), dict) else {}
        if 'alertDisplayName' in props or 'alertType' in props or str(item.get('type') or '').lower().endswith('/alerts'):
            return [self._alert(item, props)]
        if 'operationName' in item or 'operationName' in props:
            return [self._activity(item, props)]
        if 'AlertDisplayName' in item or 'AlertType' in item:  # Log Analytics SecurityAlert table row
            return [self._alert(item, {k[0].lower() + k[1:]: v for k, v in item.items()})]
        raise ValueError('not a Defender alert or Activity Log entry')

    def _alert(self, item: dict, props: dict) -> EventDraft:
        alert_type = str(props.get('alertType') or props.get('alertName') or 'SecurityAlert')
        entities = props.get('entities') if isinstance(props.get('entities'), list) else []
        accounts = [e for e in entities if isinstance(e, dict) and str(e.get('type', '')).lower() == 'account']
        hosts = [e for e in entities if isinstance(e, dict) and str(e.get('type', '')).lower() == 'host']
        ips = [e for e in entities if isinstance(e, dict) and str(e.get('type', '')).lower() == 'ip']
        actor = ''
        if accounts:
            a = accounts[0]
            actor = str(a.get('upnSuffix') and f'{a.get("name")}@{a.get("upnSuffix")}' or a.get('name') or a.get('aadUserId') or '')
        resource_ids = props.get('resourceIdentifiers') if isinstance(props.get('resourceIdentifiers'), list) else []
        azure_res = next((r for r in resource_ids if isinstance(r, dict) and r.get('azureResourceId')), {})
        entity = str(props.get('compromisedEntity') or (hosts[0].get('hostName') if hosts else '') or azure_res.get('azureResourceId') or '')
        ext = props.get('extendedProperties') if isinstance(props.get('extendedProperties'), dict) else {}
        meta: dict[str, Any] = {
            'alert_type': alert_type, 'alert_id': props.get('systemAlertId') or item.get('name') or '', 'status': props.get('status') or '',
            'intent': props.get('intent') or '', 'product': props.get('productName') or 'Microsoft Defender for Cloud',
            'subscription': next((r.get('azureResourceSubscriptionId') for r in resource_ids if isinstance(r, dict) and r.get('azureResourceSubscriptionId')), ''),
            'resource_id': azure_res.get('azureResourceId') or '', 'tenant': next((r.get('aadTenantId') for r in resource_ids if isinstance(r, dict) and r.get('aadTenantId')), ''),
            'ip': str(ips[0].get('address')) if ips else '', 'host': hosts[0].get('hostName') if hosts else '', 'service': 'defender',
            'techniques': [str(t) for t in (props.get('techniques') or [])][:8], 'remediation_steps': [str(s)[:300] for s in (props.get('remediationSteps') or [])][:5],
            'extended': {k: v for k, v in ext.items() if isinstance(v, (str, int, float, bool))},
            'alert_uri': props.get('alertUri') or '', 'region': item.get('location') or '',
        }
        title = str(props.get('alertDisplayName') or alert_type)
        external_id = props.get('systemAlertId') or item.get('id') or item.get('name') or hash_item(item)
        return event(self.source, external_id, title, severity=_severity(props.get('severity')), category='cloud', actor=actor, entity=entity,
                     action=f'defender.{snake(alert_type)[:100]}', occurred_at=first(props, 'timeGeneratedUtc', 'startTimeUtc', 'processingEndTimeUtc'),
                     metadata=meta)

    def _activity(self, item: dict, props: dict) -> EventDraft:
        op = item.get('operationName')
        operation = str(op.get('value') if isinstance(op, dict) else op or props.get('operationName') or '')
        action = _activity_action(operation)
        caller = str(item.get('caller') or dig(item, 'claims', 'name') or dig(item, 'identity', 'claims', 'name') or props.get('caller') or '')
        resource_id = str(item.get('resourceId') or props.get('resourceId') or dig(item, 'resourceId', 'value') or '')
        http = item.get('httpRequest') if isinstance(item.get('httpRequest'), dict) else {}
        ip = http.get('clientIpAddress') or item.get('callerIpAddress') or props.get('callerIpAddress') or ''
        status = item.get('status')
        status_text = str(status.get('value') if isinstance(status, dict) else status or props.get('status') or '')
        request_body = props.get('requestbody') if isinstance(props.get('requestbody'), str) else ''
        markers = scan_markers({'body': request_body, 'props': props}) if action.startswith(('az.network', 'az.storage')) else []
        if action in _DATA_ACCESS:
            category, severity = 'data_access', 'low'
        elif action in _IDENTITY:
            category, severity = 'identity', 'medium'
        else:
            category = 'cloud_api'
            severity = 'medium' if action.endswith(('.write', '.delete', '.action')) else 'low'
        if markers and action.startswith(('az.network', 'az.storage')):
            severity = 'high'
        parts = [p for p in resource_id.split('/') if p]
        subscription = parts[1] if len(parts) > 1 and parts[0].lower() == 'subscriptions' else item.get('subscriptionId') or ''
        resource_group = parts[3] if len(parts) > 3 and parts[2].lower() == 'resourcegroups' else item.get('resourceGroupName') or ''
        meta: dict[str, Any] = {
            'operation': operation, 'status': status_text, 'ip': ip, 'subscription': subscription, 'resource_group': resource_group,
            'resource_id': resource_id, 'region': item.get('resourceLocation') or props.get('resourceLocation') or '', 'service': 'azure',
            'correlation_id': item.get('correlationId') or props.get('correlationId') or '', 'category': dig(item, 'category', 'value') or item.get('category') or '',
            'request_body': request_body, 'markers': markers,
            'resource_provider': dig(item, 'resourceProviderName', 'value') or item.get('resourceProviderName') or '',
            'message': dig(props, 'message') or dig(props, 'statusMessage') or '',
        }
        if markers:
            meta['public'] = True
        entity = parts[-1] if parts else resource_id
        title = f'{operation} on {entity}' if entity else operation
        external_id = item.get('eventDataId') or item.get('correlationId') or item.get('id') or hash_item(item)
        return event(self.source, external_id, title, severity=severity, category=category, actor=caller, entity=resource_id or entity, action=action,
                     occurred_at=first(item, 'eventTimestamp', 'time', 'submissionTimestamp') or props.get('eventTimestamp'), metadata=meta)


registry.register(AzureDefenderParser())
