"""SentinelOne threats (GET /web/api/v2.1/threats `data[]` shape, single threat, or Singularity
notification envelope)."""
from __future__ import annotations

from typing import Any

from ...core.findings import EventDraft
from . import registry
from ._common import ParseContext, Parser, dig, event, first, hash_item, snake


def _severity(confidence: Any, mitigation: Any, verdict: Any) -> str:
    level = str(confidence or '').lower()
    status = str(mitigation or '').lower()
    if str(verdict or '').lower() in {'false_positive', 'suspicious_false_positive'}:
        return 'low'
    if level == 'malicious':
        return 'critical' if status in {'not_mitigated', 'active'} else 'high'
    if level == 'suspicious':
        return 'medium'
    return 'low'


class SentinelOneParser(Parser):
    name = 'sentinelone'
    aliases = ('s1',)
    source = 'sentinelone'
    description = 'SentinelOne threats (management API v2.1 data[] or a single threat object).'
    kind = 'events'
    example = 'tests/fixtures/integrations/sentinelone/threats.json'
    correlate_alerts = True

    def items(self, payload: Any) -> list[Any]:
        if isinstance(payload, dict):
            if isinstance(payload.get('data'), list):
                return payload['data']
            if isinstance(payload.get('data'), dict):
                return [payload['data']]
            if isinstance(payload.get('threats'), list):
                return payload['threats']
        return super().items(payload)

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        info = item.get('threatInfo') if isinstance(item.get('threatInfo'), dict) else item
        agent_rt = item.get('agentRealtimeInfo') if isinstance(item.get('agentRealtimeInfo'), dict) else {}
        agent_det = item.get('agentDetectionInfo') if isinstance(item.get('agentDetectionInfo'), dict) else {}
        indicators = [i for i in (item.get('indicators') or []) if isinstance(i, dict)]
        classification = str(info.get('classification') or 'Threat')
        hostname = str(agent_rt.get('agentComputerName') or agent_det.get('agentComputerName') or item.get('computerName') or '')
        user = str(agent_det.get('agentLastLoggedInUserName') or info.get('processUser') or '')
        mitigations = [m for m in (item.get('mitigationStatus') or []) if isinstance(m, dict)]
        meta: dict[str, Any] = {
            'threat_id': info.get('threatId') or item.get('id') or '', 'threat_name': info.get('threatName') or '', 'classification': classification,
            'classification_source': info.get('classificationSource') or '', 'confidence': info.get('confidenceLevel') or '',
            'mitigation_status': info.get('mitigationStatus') or '', 'incident_status': info.get('incidentStatus') or '', 'analyst_verdict': info.get('analystVerdict') or '',
            'sha1': info.get('sha1') or '', 'sha256': info.get('sha256') or '', 'filepath': info.get('filePath') or '', 'initiated_by': info.get('initiatedBy') or '',
            'detection_type': info.get('detectionType') or '', 'engines': [str(e) for e in (info.get('engines') or [])][:6], 'storyline': info.get('storyline') or '',
            'originator_process': info.get('originatorProcess') or '', 'host': hostname, 'agent_id': agent_rt.get('agentUuid') or agent_det.get('agentUuid') or '',
            'os': agent_rt.get('agentOsName') or agent_det.get('agentOsName') or '', 'site': agent_det.get('siteName') or agent_rt.get('siteName') or '',
            'account': agent_det.get('accountName') or '', 'group': agent_det.get('groupName') or '', 'ip': agent_det.get('externalIp') or '',
            'local_ip': agent_det.get('agentIpV4') or '', 'domain': agent_det.get('agentDomain') or '', 'service': 'sentinelone',
            'indicator_categories': sorted({str(i.get('category')) for i in indicators if i.get('category')})[:8],
            'tactics': sorted({str(t.get('name')) for i in indicators for t in (i.get('tactics') or []) if isinstance(t, dict) and t.get('name')})[:8],
            'mitigation_actions': [f'{m.get("action")}:{m.get("status")}' for m in mitigations][:6], 'reboot_required': info.get('rebootRequired'),
        }
        severity = _severity(info.get('confidenceLevel'), info.get('mitigationStatus'), info.get('analystVerdict'))
        title = f'{info.get("threatName") or classification} on {hostname}' if hostname else str(info.get('threatName') or classification)
        external_id = info.get('threatId') or item.get('id') or hash_item(item)
        return [event(self.source, external_id, title, severity=severity, category='endpoint', actor=user, entity=hostname,
                      action=f'sentinelone.threat.{snake(classification)[:60]}', occurred_at=first(info, 'identifiedAt', 'createdAt', 'updatedAt') or dig(item, 'createdAt'),
                      metadata=meta)]


registry.register(SentinelOneParser())
