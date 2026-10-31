"""Passive industrial-control monitoring, never probing or commanding devices."""
from __future__ import annotations

from ..engine import DetectionDraft, DetectionRule, RuleContext, registry
from ..util import event_time, iso, meta, window_bucket


class IndustrialWriteObserved(DetectionRule):
    id = 'industrial.modbus_write_observed'
    name = 'Industrial control write observed'
    category = 'industrial'
    severity = 'high'
    description = 'A passive network sensor reported a Modbus write request (coils or registers).'
    remediation = 'Confirm this write with the OT process owner and the approved operations schedule before taking action.'
    default_params = {'window_minutes': 60, 'max_drafts': 100}

    def evaluate(self, ctx: RuleContext) -> list[DetectionDraft]:
        window = max(1, int(ctx.param('window_minutes', 60)))
        limit = max(1, min(200, int(ctx.param('max_drafts', 100))))
        drafts = []
        for ev in ctx.events(action='network.modbus.write'):
            data = meta(ev)
            if data.get('industrial_protocol') != 'modbus':
                continue
            when = event_time(ev)
            drafts.append(DetectionDraft(
                rule_id=self.id, title='Modbus write request observed',
                description=f'Passive sensor {ev.source} reported a Modbus write directed to {ev.entity} at {iso(when)}.',
                severity=self.severity, confidence=0.85,
                entity=ev.entity or 'unknown destination', entity_kind='asset',
                asset_id=ev.asset_id, fingerprint_parts=[ev.entity or '', str(data.get('function_code') or '')],
                window_bucket=window_bucket(when, window),
                first_seen_at=when, last_seen_at=when,
                evidence={'event_ids': [ev.id], 'source': ev.source,
                          'function_code': data.get('function_code'),
                          'source_ip': data.get('src_ip'), 'destination_ip': data.get('dst_ip'),
                          'sensor_observation_only': True, 'device_command_success_unknown': True}))
            if len(drafts) >= limit:
                break
        return drafts


registry.register(IndustrialWriteObserved())
