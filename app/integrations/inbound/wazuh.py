"""Wazuh alerts: raw alert JSON, an OpenSearch/Wazuh-indexer hit (`_source`), or a whole search
response (`hits.hits[]`)."""
from __future__ import annotations

from typing import Any

from ...core.findings import EventDraft
from . import registry
from ._common import ParseContext, Parser, dig, event, first, geo, hash_item, listify

_AUTH_FAIL = {'authentication_failed', 'authentication_failures', 'invalid_login', 'login_denied'}
_AUTH_OK = {'authentication_success', 'login_success'}
_PRIV = {'sudo', 'su', 'privilege_escalation'}
_FILE = {'syscheck'}
_ROOTKIT = {'rootcheck', 'rootkit'}
_WEB = {'web', 'attack', 'web_scan', 'sql_injection', 'xss'}
_MALWARE = {'malware', 'virustotal', 'yara'}


def level_severity(level: int) -> str:
    """Wazuh rule levels (0-16) use their own scale, not CVSS: 13+ critical, 10+ high, 6+ medium, 3+ low."""
    if level >= 13:
        return 'critical'
    if level >= 10:
        return 'high'
    if level >= 6:
        return 'medium'
    if level >= 3:
        return 'low'
    return 'informational'


def _action(groups: list[str], item: dict) -> tuple[str, str]:
    g = {str(x).lower() for x in groups}
    if g & _AUTH_FAIL:
        return 'auth.failure', 'auth'
    if g & _AUTH_OK:
        return 'auth.success', 'auth'
    if g & _FILE:
        change = str(dig(item, 'syscheck', 'event') or 'modified').lower()
        return f'file.{change}', 'file'
    if g & _PRIV:
        return 'privilege.sudo', 'process'
    if g & _ROOTKIT:
        return 'host.rootcheck', 'host'
    if g & _MALWARE:
        return 'malware.detected', 'endpoint'
    if g & _WEB:
        return 'web.attack', 'network'
    if 'pam' in g or 'sshd' in g:
        return 'auth.session', 'auth'
    if 'audit' in g or 'audit_command' in g:
        return 'process.audit', 'process'
    primary = next((x for x in groups if x), 'alert')
    return f'wazuh.{str(primary).lower()[:60]}', 'host'


class WazuhParser(Parser):
    name = 'wazuh'
    source = 'wazuh'
    description = 'Wazuh manager alerts (alerts.json shape) or Wazuh indexer search hits.'
    kind = 'events'
    example = 'tests/fixtures/integrations/wazuh/alerts.json'
    correlate_alerts = True
    pull = True
    secret_fields = ['username', 'password']
    config_schema = {
        'type': 'object', 'additionalProperties': False,
        'properties': {
            'indexer_url': {'type': 'string', 'description': 'https://indexer:9200', 'pattern': '^https://'},
            'index_pattern': {'type': 'string', 'default': 'wazuh-alerts-*'},
            'ca_bundle': {'type': 'string', 'description': 'Path to a CA bundle for the indexer TLS certificate'},
            'lookback_minutes': {'type': 'integer', 'minimum': 1, 'maximum': 1440, 'default': 30},
            'page_size': {'type': 'integer', 'minimum': 1, 'maximum': 1000, 'default': 200},
            'schedule_minutes': {'type': 'integer', 'minimum': 0, 'maximum': 1440, 'default': 0},
        },
    }

    def items(self, payload: Any) -> list[Any]:
        if isinstance(payload, dict):
            hits = dig(payload, 'hits', 'hits')
            if isinstance(hits, list):
                return [self._unwrap(h) for h in hits]
            return [self._unwrap(payload)]
        return [self._unwrap(x) for x in payload]

    @staticmethod
    def _unwrap(item: Any) -> Any:
        if isinstance(item, dict) and isinstance(item.get('_source'), dict):
            src = dict(item['_source'])
            src.setdefault('id', item.get('_id'))
            return src
        return item

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        rule = item.get('rule') if isinstance(item.get('rule'), dict) else {}
        agent = item.get('agent') if isinstance(item.get('agent'), dict) else {}
        data = item.get('data') if isinstance(item.get('data'), dict) else {}
        groups = [str(g) for g in listify(rule.get('groups'))][:12]
        level = rule.get('level')
        try:
            level = int(level) if level is not None else 0
        except (TypeError, ValueError):
            level = 0
        action, category = _action(groups, item)
        win = dig(data, 'win', 'eventdata') if isinstance(dig(data, 'win', 'eventdata'), dict) else {}
        actor = first(data, 'srcuser', 'dstuser', 'user') or first(win, 'targetUserName', 'subjectUserName') or ''
        host = agent.get('name') or dig(item, 'manager', 'name') or ''
        mitre = rule.get('mitre') if isinstance(rule.get('mitre'), dict) else {}
        full_log = item.get('full_log')
        meta: dict[str, Any] = {
            'rule_id': str(rule.get('id') or ''), 'rule_level': level, 'groups': groups, 'agent_id': str(agent.get('id') or ''),
            'agent_ip': agent.get('ip') or '', 'host': host or '', 'ip': first(data, 'srcip', 'src_ip') or '', 'dst_ip': data.get('dstip') or '',
            'location': item.get('location') or '', 'decoder': dig(item, 'decoder', 'name') or '', 'mitre_ids': listify(mitre.get('id'))[:6],
            'mitre_tactics': listify(mitre.get('tactic'))[:6], 'command': data.get('command') or dig(data, 'audit', 'command') or '',
            'file': dig(item, 'syscheck', 'path') or '', 'syscheck_event': dig(item, 'syscheck', 'event') or '',
            'full_log': full_log if isinstance(full_log, str) else '', 'service': 'wazuh',
        }
        if item.get('GeoLocation') and isinstance(item['GeoLocation'], dict):
            geo_src = item['GeoLocation']
            loc = geo_src.get('location') if isinstance(geo_src.get('location'), dict) else {}
            meta['geo'] = geo(loc.get('lat'), loc.get('lon'), geo_src.get('country_code2') or geo_src.get('country_name'), geo_src.get('city_name'))
        external_id = item.get('id') or hash_item(item)
        title = str(rule.get('description') or 'Wazuh alert')
        return [event(self.source, external_id, title, severity=level_severity(level), category=category, actor=actor, entity=host or '', action=action,
                      occurred_at=item.get('timestamp') or item.get('@timestamp'), metadata=meta)]


registry.register(WazuhParser())
