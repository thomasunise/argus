"""Generic events: OCSF-style objects (class_uid, activity_name, actor.user.name, src_endpoint.ip,
metadata.product) or flat JSON with actor/entity/action keys. Unknown small scalar keys are kept
in metadata; everything passes through the bounded cleaner."""
from __future__ import annotations

from typing import Any

from ...core.findings import EventDraft
from . import registry
from ._common import ParseContext, Parser, dig, event, first, geo, hash_item, snake

_OCSF_SEVERITY = {0: 'informational', 1: 'informational', 2: 'low', 3: 'medium', 4: 'high', 5: 'critical', 6: 'critical', 99: 'low'}
_OCSF_CATEGORY = {1: 'host', 2: 'finding', 3: 'identity', 4: 'network', 5: 'discovery', 6: 'application', 7: 'remediation'}
_RESERVED = {'id', 'uuid', 'event_id', 'external_id', 'title', 'message', 'summary', 'severity', 'severity_id', 'category', 'category_uid', 'category_name',
             'actor', 'entity', 'target', 'action', 'activity_name', 'activity_id', 'class_name', 'class_uid', 'type_name', 'occurred_at', 'timestamp', 'time',
             '@timestamp', 'metadata', 'src_endpoint', 'dst_endpoint', 'device', 'http_request', 'user', 'resource', 'resources', 'geo'}
_PASSTHROUGH_MAX = 24


class GenericParser(Parser):
    name = 'generic'
    aliases = ('ocsf', 'custom')
    source = 'generic'
    description = 'OCSF-style or flat JSON events with actor/entity/action keys.'
    kind = 'events'
    example = 'tests/fixtures/integrations/generic/events.json'

    def items(self, payload: Any) -> list[Any]:
        if isinstance(payload, dict) and isinstance(payload.get('events'), list):
            return payload['events']
        return super().items(payload)

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        meta_in = item.get('metadata') if isinstance(item.get('metadata'), dict) else {}
        product = dig(meta_in, 'product', 'name') or meta_in.get('product') or item.get('product') or item.get('vendor') or ''
        source_label = str(item.get('source') or product or '').strip()
        actor_in = item.get('actor')
        if isinstance(actor_in, dict):
            actor = first(actor_in, 'user', 'email', 'name', 'id', 'arn')
            actor = first(actor, 'email_addr', 'name', 'uid', 'email') if isinstance(actor, dict) else actor
        else:
            actor = actor_in or first(item, 'user', 'user_name', 'username', 'principal', 'email')
            actor = first(actor, 'email_addr', 'name', 'uid') if isinstance(actor, dict) else actor
        entity_in = first(item, 'entity', 'target', 'resource', 'resource_name', 'object', 'host', 'hostname')
        if isinstance(entity_in, dict):
            entity_in = first(entity_in, 'name', 'uid', 'id', 'hostname', 'arn')
        if not entity_in:
            entity_in = dig(item, 'device', 'hostname') or dig(item, 'dst_endpoint', 'hostname') or dig(item, 'dst_endpoint', 'ip') or ''
        explicit = str(first(item, 'action', 'event_type', 'eventName') or '')
        class_name = item.get('class_name') or item.get('class')
        if explicit:
            action = explicit if '.' in explicit else snake(explicit)
        elif class_name and item.get('activity_name'):
            action = f'{snake(class_name)}.{snake(item["activity_name"])}'
        else:
            fallback = str(first(item, 'activity_name', 'type_name') or '')
            action = (fallback if '.' in fallback else snake(fallback)) or 'generic.event'
        severity: Any = first(item, 'severity', 'level', 'priority')
        if severity is None and 'severity_id' in item:
            try:
                severity = _OCSF_SEVERITY.get(int(item['severity_id']), 'low')
            except (TypeError, ValueError):
                severity = 'low'
        category = str(first(item, 'category') or '')
        if not category and 'category_uid' in item:
            try:
                category = _OCSF_CATEGORY.get(int(item['category_uid']), 'generic')
            except (TypeError, ValueError):
                category = 'generic'
        if not category:
            category = snake(first(item, 'category_name') or '')[:40]
        src = item.get('src_endpoint') if isinstance(item.get('src_endpoint'), dict) else {}
        http = item.get('http_request') if isinstance(item.get('http_request'), dict) else {}
        location = src.get('location') if isinstance(src.get('location'), dict) else item.get('geo') if isinstance(item.get('geo'), dict) else {}
        meta: dict[str, Any] = {
            'ip': first(item, 'ip', 'src_ip', 'source_ip', 'client_ip', 'remote_addr') or src.get('ip') or '',
            'user_agent': first(item, 'user_agent', 'userAgent') or http.get('user_agent') or '',
            'geo': geo(first(location, 'lat', 'latitude'), first(location, 'lon', 'long', 'longitude'), first(location, 'country', 'country_code'), location.get('city')),
            'service': first(item, 'service') or product or source_label or '', 'product': product or '', 'region': first(item, 'region') or '',
            'account': first(item, 'account', 'account_id') or dig(item, 'cloud', 'account', 'uid') or '', 'namespace': first(item, 'namespace') or '',
            'repo': first(item, 'repo', 'repository') or '', 'host': dig(item, 'device', 'hostname') or first(item, 'host', 'hostname') or '',
            'class_uid': item.get('class_uid'), 'activity_id': item.get('activity_id'), 'status': first(item, 'status') or '',
            'ocsf_version': meta_in.get('version') or '', 'labels': [str(x) for x in (meta_in.get('labels') or [])][:10] if isinstance(meta_in.get('labels'), list) else [],
        }
        if isinstance(item.get('metadata'), dict):
            for key, value in list(item['metadata'].items())[:_PASSTHROUGH_MAX]:
                if key not in {'product', 'version', 'labels'} and key not in meta:
                    meta[str(key)] = value
        for key, value in list(item.items())[:_PASSTHROUGH_MAX * 2]:
            if key in _RESERVED or key in meta:
                continue
            if isinstance(value, (str, int, float, bool)) or (isinstance(value, (dict, list)) and len(str(value)) <= 1500):
                meta[str(key)] = value
        title = str(first(item, 'title', 'message', 'summary', 'description') or action)
        external_id = first(item, 'id', 'uuid', 'event_id', 'external_id') or meta_in.get('uid') or hash_item(item)
        return [event(self.source, external_id, title, severity=severity if severity is not None else 'low', category=category or 'generic', actor=actor or '',
                      entity=entity_in or '', action=action, occurred_at=first(item, 'occurred_at', 'timestamp', 'time', '@timestamp', 'event_time'), metadata=meta)]


registry.register(GenericParser())
