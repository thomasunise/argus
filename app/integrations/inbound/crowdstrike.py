"""CrowdStrike Falcon: detection summaries (detects API / Alerts API shape) and Event Streams
(SIEM connector) records `{metadata: {eventType}, event: {...}}`."""
from __future__ import annotations

from typing import Any

from ...core.findings import EventDraft
from . import registry
from ._common import ParseContext, Parser, as_float, event, first, hash_item, snake

_SEVERITY_NAMES = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low', 'informational': 'informational', 'info': 'informational'}


def _severity(value: Any, name: Any = None) -> str:
    if name and str(name).lower() in _SEVERITY_NAMES:
        return _SEVERITY_NAMES[str(name).lower()]
    score = as_float(value)
    if score is None:
        return 'medium'
    if score <= 5:  # event-stream scale 1..5
        return {5: 'critical', 4: 'high', 3: 'medium', 2: 'low', 1: 'informational', 0: 'informational'}.get(int(score), 'medium')
    if score >= 90:
        return 'critical'
    if score >= 70:
        return 'high'
    if score >= 50:
        return 'medium'
    if score >= 30:
        return 'low'
    return 'informational'


class CrowdStrikeParser(Parser):
    name = 'crowdstrike'
    aliases = ('falcon',)
    source = 'crowdstrike'
    description = 'CrowdStrike Falcon detections (detects/alerts API) and Event Streams records.'
    kind = 'events'
    example = 'tests/fixtures/integrations/crowdstrike/detections.json'
    correlate_alerts = True

    def items(self, payload: Any) -> list[Any]:
        if isinstance(payload, dict) and isinstance(payload.get('resources'), list):
            return payload['resources']
        return super().items(payload)

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        if isinstance(item.get('event'), dict) and isinstance(item.get('metadata'), dict):
            return [self._stream(item['metadata'], item['event'], item)]
        if 'behaviors' in item or 'detection_id' in item or 'composite_id' in item:
            return [self._detection(item)]
        raise ValueError('not a Falcon detection or event-stream record')

    def _detection(self, item: dict) -> EventDraft:
        device = item.get('device') if isinstance(item.get('device'), dict) else {}
        behaviors = [b for b in (item.get('behaviors') or []) if isinstance(b, dict)]
        lead = behaviors[0] if behaviors else item
        tactic = str(first(lead, 'tactic', 'tactic_id') or item.get('tactic') or 'detection')
        technique = str(first(lead, 'technique', 'technique_id') or item.get('technique') or '')
        hostname = str(device.get('hostname') or item.get('hostname') or '')
        user = str(first(lead, 'user_name') or item.get('user_name') or '')
        meta: dict[str, Any] = {
            'detection_id': item.get('detection_id') or item.get('composite_id') or '', 'status': item.get('status') or '', 'tactic': tactic,
            'technique': technique, 'tactics': [str(b.get('tactic')) for b in behaviors if b.get('tactic')][:8],
            'techniques': [str(b.get('technique')) for b in behaviors if b.get('technique')][:8],
            'severity_score': as_float(item.get('max_severity', lead.get('severity'))), 'confidence': as_float(item.get('max_confidence', lead.get('confidence'))),
            'host': hostname, 'device_id': device.get('device_id') or '', 'platform': device.get('platform_name') or '', 'os': device.get('os_version') or '',
            'ip': device.get('external_ip') or '', 'local_ip': device.get('local_ip') or '', 'mac': device.get('mac_address') or '',
            'filename': first(lead, 'filename') or '', 'filepath': first(lead, 'filepath') or '', 'cmdline': first(lead, 'cmdline') or '',
            'parent': first(lead, 'parent_details', default={}).get('filename') if isinstance(first(lead, 'parent_details'), dict) else '',
            'sha256': first(lead, 'sha256') or '', 'ioc_type': first(lead, 'ioc_type') or '', 'ioc_value': first(lead, 'ioc_value') or '',
            'scenario': first(lead, 'scenario') or '', 'objective': first(lead, 'objective') or '', 'service': 'crowdstrike',
            'behaviors': len(behaviors), 'url': item.get('falcon_host_link') or '',
        }
        title = str(first(lead, 'display_name', 'description') or f'Falcon detection: {tactic}')
        external_id = item.get('detection_id') or item.get('composite_id') or hash_item(item)
        return event(self.source, external_id, title, severity=_severity(item.get('max_severity', lead.get('severity')), item.get('max_severity_displayname')),
                     category='endpoint', actor=user, entity=hostname, action=f'crowdstrike.{snake(tactic)[:80]}',
                     occurred_at=first(item, 'created_timestamp', 'first_behavior', 'last_behavior') or first(lead, 'timestamp'), metadata=meta)

    def _stream(self, metadata: dict, ev: dict, raw: dict) -> EventDraft:
        kind = str(metadata.get('eventType') or 'Event')
        hostname = str(first(ev, 'ComputerName', 'Hostname') or '')
        user = str(first(ev, 'UserName', 'UserId') or '')
        occurred = first(ev, 'ProcessStartTime', 'UTCTimestamp', 'DetectTime') or metadata.get('eventCreationTime')
        base: dict[str, Any] = {'stream_event_type': kind, 'offset': metadata.get('offset'), 'customer_id': metadata.get('customerIDString') or '',
                                'host': hostname, 'service': 'crowdstrike', 'url': ev.get('FalconHostLink') or ''}
        if kind == 'DetectionSummaryEvent' or kind == 'EppDetectionSummaryEvent':
            tactic = str(ev.get('Tactic') or 'detection')
            base.update({'tactic': tactic, 'technique': ev.get('Technique') or '', 'severity_score': as_float(ev.get('Severity')), 'severity_name': ev.get('SeverityName') or '',
                         'detect_name': ev.get('DetectName') or '', 'cmdline': ev.get('CommandLine') or '', 'filename': ev.get('FileName') or '',
                         'filepath': ev.get('FilePath') or '', 'sha256': ev.get('SHA256String') or '', 'ip': ev.get('LocalIP') or '', 'mac': ev.get('MACAddress') or '',
                         'detection_id': ev.get('DetectId') or ev.get('CompositeId') or '', 'objective': ev.get('Objective') or '', 'pattern_id': ev.get('PatternId')})
            title = str(ev.get('DetectName') or ev.get('DetectDescription') or f'Falcon detection: {tactic}')[:300]
            external_id = ev.get('DetectId') or ev.get('CompositeId') or hash_item(raw)
            return event(self.source, external_id, title, severity=_severity(ev.get('Severity'), ev.get('SeverityName')), category='endpoint', actor=user,
                         entity=hostname, action=f'crowdstrike.{snake(tactic)[:80]}', occurred_at=occurred, metadata=base)
        if kind in {'AuthActivityAuditEvent', 'UserActivityAuditEvent'}:
            operation = str(ev.get('OperationName') or 'activity')
            base.update({'operation': operation, 'ip': ev.get('UserIp') or '', 'success': ev.get('Success'), 'service_name': ev.get('ServiceName') or '',
                         'audit_keys': [a.get('Key') for a in (ev.get('AuditKeyValues') or []) if isinstance(a, dict)][:10]})
            severity = 'medium' if ev.get('Success') is False or 'delete' in operation.lower() or 'create' in operation.lower() else 'low'
            external_id = hash_item({'o': metadata.get('offset'), 'c': metadata.get('customerIDString'), 'k': kind})
            return event(self.source, external_id, f'Falcon console: {operation}', severity=severity, category='auth' if kind.startswith('Auth') else 'saas',
                         actor=user, entity=ev.get('ServiceName') or 'falcon-console', action=f'crowdstrike.console.{snake(operation)[:60]}', occurred_at=occurred,
                         metadata=base)
        if kind == 'IncidentSummaryEvent':
            base.update({'incident_id': ev.get('IncidentID') or '', 'fine_score': ev.get('FineScore'), 'state': ev.get('State') or '', 'lateral_movement': ev.get('LateralMovement')})
            external_id = ev.get('IncidentID') or hash_item(raw)
            return event(self.source, external_id, f'Falcon incident {ev.get("IncidentID") or ""}'.strip(), severity=_severity(as_float(ev.get('FineScore')) or 50),
                         category='endpoint', actor=user, entity=hostname, action='crowdstrike.incident', occurred_at=occurred, metadata=base)
        base.update({k: v for k, v in ev.items() if isinstance(v, (str, int, float, bool)) and len(str(v)) <= 300})
        return event(self.source, hash_item(raw), f'Falcon {kind}', severity='low', category='endpoint', actor=user, entity=hostname,
                     action=f'crowdstrike.{snake(kind)[:80]}', occurred_at=occurred, metadata=base)


registry.register(CrowdStrikeParser())
