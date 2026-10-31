"""Tenant-configurable tool-call guard for Argus agents and MCP gateway clients.

This module evaluates proposed calls; it does not execute external MCP tools.
External tools MUST pass through an enforcing gateway for a blocked decision to
actually prevent execution. Argus's own AgentRuntime enforces decisions directly.
No raw arguments, secrets, or payloads are returned in decisions.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit
import fnmatch

from ..models import Tenant, loads

MODES = frozenset({'monitor', 'enforce'})
RISKS = frozenset({'read', 'propose', 'execute_testing', 'write', 'execute', 'unknown'})


@dataclass(frozen=True)
class Decision:
    allowed: bool
    would_block: bool
    mode: str
    reasons: tuple[str, ...]
    tool: str
    risk: str

    def as_dict(self) -> dict:
        return {'allowed': self.allowed, 'would_block': self.would_block,
                'mode': self.mode, 'reasons': list(self.reasons),
                'tool': self.tool, 'risk': self.risk}


def policy_for(db, tenant_id: str) -> dict:
    tenant = db.get(Tenant, tenant_id)
    data = loads(tenant.settings_json, {}) if tenant is not None else {}
    policy = data.get('tool_guard', {}) if isinstance(data, dict) else {}
    return policy if isinstance(policy, dict) else {}


def validate_policy(data: dict) -> dict:
    if set(data) - {'mode', 'allow_tools', 'deny_tools', 'deny_risks', 'allow_hosts', 'deny_hosts'}:
        raise ValueError('Unknown tool guard policy field')
    mode = data.get('mode', 'monitor')
    if mode not in MODES:
        raise ValueError('mode must be monitor or enforce')
    out = {'mode': mode}
    for key in ('allow_tools', 'deny_tools', 'deny_risks', 'allow_hosts', 'deny_hosts'):
        value = data.get(key, [])
        if not isinstance(value, list) or len(value) > 100 or any(not isinstance(s, str) or len(s) > 200 or not s.strip() for s in value):
            raise ValueError(f'{key} must be a list of at most 100 nonempty strings')
        if key == 'deny_risks' and any(r not in RISKS for r in value):
            raise ValueError('unknown tool risk')
        out[key] = sorted(set(s.lower().strip() for s in value))
    return out


def _hosts(value, depth: int = 0):
    """Inspect named URL/endpoint fields only. Never inspect/log payload text."""
    if depth > 4:
        return
    if isinstance(value, dict):
        for key, item in list(value.items())[:60]:
            if key.lower() in {'url', 'endpoint', 'webhook_url', 'base_url', 'destination_url', 'target_url'} and isinstance(item, str):
                try:
                    parsed = urlsplit(item)
                    if parsed.scheme in {'http', 'https'} and parsed.hostname:
                        yield parsed.hostname.lower().rstrip('.')
                except ValueError:
                    continue
            elif isinstance(item, (dict, list)):
                yield from _hosts(item, depth + 1)
    elif isinstance(value, list):
        for item in value[:40]:
            yield from _hosts(item, depth + 1)


def _host_matches(host: str, pattern: str) -> bool:
    pattern = pattern.lower().lstrip('.')
    if not pattern or '*' in pattern:
        return False
    return host == pattern or host.endswith('.' + pattern)


def evaluate(tool: str, risk: str, arguments: dict, policy: dict) -> Decision:
    p = validate_policy(policy)
    name = str(tool or '')[:200].lower()
    risk = str(risk or 'unknown').lower()
    risk = risk if risk in RISKS else 'unknown'
    reasons: list[str] = []
    if any(fnmatch.fnmatchcase(name, pattern) for pattern in p['deny_tools']):
        reasons.append('denied_tool')
    if p['allow_tools'] and not any(fnmatch.fnmatchcase(name, pattern) for pattern in p['allow_tools']):
        reasons.append('tool_not_allowlisted')
    if risk in p['deny_risks']:
        reasons.append('denied_risk')
    for host in set(_hosts(arguments if isinstance(arguments, dict) else {})):
        if any(_host_matches(host, domain) for domain in p['deny_hosts']):
            reasons.append('denied_destination')
        if p['allow_hosts'] and not any(_host_matches(host, domain) for domain in p['allow_hosts']):
            reasons.append('destination_not_allowlisted')
    would_block = bool(reasons)
    return Decision(allowed=(p['mode'] != 'enforce' or not would_block),
                    would_block=would_block, mode=p['mode'],
                    reasons=tuple(sorted(set(reasons))), tool=name, risk=risk)
