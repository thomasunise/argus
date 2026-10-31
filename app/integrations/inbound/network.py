"""Bounded Suricata EVE and Zeek JSON event ingestion (telemetry only)."""
from __future__ import annotations

from typing import Any

from ...core.findings import EventDraft
from . import registry
from ._common import ParseContext, Parser, event, first, hash_item


class SuricataParser(Parser):
    name = 'suricata'
    aliases = ('eve', 'suricata_eve')
    source = 'suricata'
    description = 'Suricata EVE JSON alerts, flows, DNS and network metadata.'
    kind = 'events'
    example = 'tests/fixtures/integrations/suricata/events.json'

    def items(self, payload: Any) -> list[Any]:
        return payload.get('events', [payload]) if isinstance(payload, dict) else payload

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        kind = str(item.get('event_type') or 'event').lower()
        alert = item.get('alert') if isinstance(item.get('alert'), dict) else {}
        level = int(alert.get('severity') or 4) if str(alert.get('severity') or 4).isdigit() else 4
        severity = {1: 'critical', 2: 'high', 3: 'medium'}.get(level, 'low') if kind == 'alert' else 'informational'
        src = str(item.get('src_ip') or '')
        dst = str(item.get('dest_ip') or '')
        modbus = item.get('modbus') if isinstance(item.get('modbus'), dict) else {}
        try:
            fc = int(modbus.get('function_code')) if modbus.get('function_code') is not None else 0
        except (ValueError, TypeError):
            fc = 0
        is_write = str(item.get('app_proto') or '').lower() == 'modbus' and fc in {5, 6, 15, 16}
        metadata = {'industrial_protocol': 'modbus' if modbus or str(item.get('app_proto') or '').lower() == 'modbus' else '',
                    'function_code': fc or None, 'modbus_unit': modbus.get('unit'),
                    'src_ip': src, 'dst_ip': dst, 'dst_port': item.get('dest_port'),
                    'protocol': item.get('proto') or '', 'signature': alert.get('signature') or '',
                    'signature_id': alert.get('signature_id'), 'category': alert.get('category') or '',
                    'flow_id': item.get('flow_id'), 'service': 'suricata'}
        title = str(alert.get('signature') or f'Suricata {kind}')
        return [event(self.source, item.get('event_id') or hash_item(item), title,
                      severity=severity, category='network', actor=src, entity=dst,
                      action='network.modbus.write' if is_write else f'network.{kind}',
                      occurred_at=item.get('timestamp'), metadata=metadata)]


class ZeekParser(Parser):
    name = 'zeek'
    aliases = ('zeek_json',)
    source = 'zeek'
    description = 'Zeek JSON connection, DNS, HTTP and SSL log metadata.'
    kind = 'events'
    example = 'tests/fixtures/integrations/zeek/events.json'

    def items(self, payload: Any) -> list[Any]:
        return payload.get('events', [payload]) if isinstance(payload, dict) else payload

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        src = str(first(item, 'id.orig_h', 'orig_h', 'src_ip') or '')
        dst = str(first(item, 'id.resp_h', 'resp_h', 'dst_ip') or '')
        kind = str(first(item, '_path', 'log_type', 'type') or 'conn').lower()
        metadata = {'src_ip': src, 'dst_ip': dst, 'dst_port': first(item, 'id.resp_p', 'resp_p'),
                    'protocol': item.get('proto') or '', 'service': item.get('service') or 'zeek',
                    'dns_query': item.get('query') or '', 'uid': item.get('uid') or '',
                    'duration': item.get('duration')}
        return [event(self.source, hash_item(item), f'Zeek {kind}',
                      severity='informational', category='network', actor=src, entity=dst,
                      action=f'network.{kind}', occurred_at=item.get('ts'), metadata=metadata)]


registry.register(SuricataParser())
registry.register(ZeekParser())
