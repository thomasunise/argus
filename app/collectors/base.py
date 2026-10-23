"""Collector contract: drafts for the evidence graph, the run context, the result bag and the
registry. Collectors turn an external estate (cloud account, IdP, code host, fleet, flow
logs) into NodeDraft/EdgeDraft/EventDraft objects. They never write to the database
themselves; the run handler applies results to the graph and the event store.

Drafts use exactly the field names the graph service consumes:
  NodeDraft(kind, key, props, label, criticality)
  EdgeDraft(src=(kind, key), dst=(kind, key), rel, props)
EventDraft is the core one from app.core.findings so events go through upsert_event unchanged.
"""
from __future__ import annotations

import importlib.util
import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable

from ..core.config import Settings
from ..core.findings import EventDraft
from .registry import KINDS, Registry, registry  # noqa: F401

__all__ = ['Collector', 'CollectorContext', 'CollectorResult', 'EdgeDraft', 'EventDraft', 'NodeDraft', 'Registry', 'registry',
           'KINDS', 'NODE_KINDS', 'RELS', 'SECRET_REF_PREFIXES', 'age_days', 'is_private_ip', 'is_secret_ref', 'jsonable',
           'modules_available', 'parse_time', 'validate_config']

NODE_KINDS = ('asset', 'identity', 'role', 'permission', 'network', 'exposure', 'vuln', 'secret', 'data_store', 'finding', 'event', 'canary')
RELS = ('owns', 'can_assume', 'has_permission', 'exposes', 'runs', 'connects_to', 'affected_by', 'accessed', 'triggered')
SECRET_REF_PREFIXES = ('env:', 'file:', 'secrets:', 'literal:')
CRITICALITIES = ('low', 'medium', 'high', 'critical')


# ---------------------------------------------------------------- drafts


@dataclass
class NodeDraft:
    kind: str
    key: str
    props: dict[str, Any] = field(default_factory=dict)
    label: str = ''
    criticality: str = 'medium'

    @property
    def ref(self) -> tuple[str, str]:
        return (self.kind, self.key)


@dataclass
class EdgeDraft:
    src: tuple[str, str]
    dst: tuple[str, str]
    rel: str
    props: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectorResult:
    nodes: list[NodeDraft] = field(default_factory=list)
    edges: list[EdgeDraft] = field(default_factory=list)
    events: list[EventDraft] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._node_index: dict[tuple[str, str], NodeDraft] = {n.ref: n for n in self.nodes}
        self._edge_index: dict[tuple[tuple[str, str], tuple[str, str], str], EdgeDraft] = {(e.src, e.dst, e.rel): e for e in self.edges}
        self._event_ids: set[tuple[str, str]] = {(e.source, e.external_id) for e in self.events}

    # -- builders (deduplicating, so normalizers can be written naively)
    def node(self, kind: str, key: str, props: dict[str, Any] | None = None, label: str = '', criticality: str = 'medium') -> NodeDraft:
        if kind not in NODE_KINDS:
            raise ValueError(f'unknown node kind {kind!r}')
        if criticality not in CRITICALITIES:
            criticality = 'medium'
        key = str(key)[:512]
        existing = self._node_index.get((kind, key))
        if existing:
            existing.props.update(props or {})
            if label and existing.label == existing.key:
                existing.label = label
            if CRITICALITIES.index(criticality) > CRITICALITIES.index(existing.criticality):
                existing.criticality = criticality
            return existing
        draft = NodeDraft(kind=kind, key=key, props=dict(props or {}), label=(label or key)[:200], criticality=criticality)
        self.nodes.append(draft)
        self._node_index[draft.ref] = draft
        return draft

    def edge(self, src: tuple[str, str] | NodeDraft, dst: tuple[str, str] | NodeDraft, rel: str, props: dict[str, Any] | None = None) -> EdgeDraft:
        if rel not in RELS:
            raise ValueError(f'unknown relation {rel!r}')
        s = src.ref if isinstance(src, NodeDraft) else (src[0], str(src[1])[:512])
        d = dst.ref if isinstance(dst, NodeDraft) else (dst[0], str(dst[1])[:512])
        existing = self._edge_index.get((s, d, rel))
        if existing:
            existing.props.update(props or {})
            return existing
        draft = EdgeDraft(src=s, dst=d, rel=rel, props=dict(props or {}))
        self.edges.append(draft)
        self._edge_index[(s, d, rel)] = draft
        return draft

    def event(self, source: str, external_id: str, title: str, severity: Any = 'low', category: str = '', actor: str = '',
              entity: str = '', action: str = '', occurred_at: datetime | None = None, metadata: dict[str, Any] | None = None) -> EventDraft | None:
        key = (source, external_id[:128])
        if key in self._event_ids:
            return None
        draft = EventDraft(source=source, external_id=external_id[:128], title=title, severity=severity, category=category, actor=actor,
                           entity=entity, action=action, occurred_at=occurred_at, metadata=dict(metadata or {}))
        self.events.append(draft)
        self._event_ids.add(key)
        return draft

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message[:500])

    def has_node(self, kind: str, key: str) -> bool:
        return (kind, key) in self._node_index

    def finalize(self) -> 'CollectorResult':
        self.stats['nodes'] = len(self.nodes)
        self.stats['edges'] = len(self.edges)
        self.stats['events'] = len(self.events)
        self.stats['warnings'] = len(self.warnings)
        return self

    def summary(self) -> dict[str, Any]:
        return {**self.stats, 'nodes': len(self.nodes), 'edges': len(self.edges), 'events': len(self.events), 'warnings': len(self.warnings)}


# ---------------------------------------------------------------- context


async def _noop_heartbeat() -> None:
    return None


@dataclass
class CollectorContext:
    tenant_id: str
    config: dict[str, Any]
    settings: Settings
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger('sentinel.collectors'))
    heartbeat: Callable[[], Awaitable[None]] = _noop_heartbeat
    since: datetime | None = None
    config_id: str = ''
    run_id: str = ''

    def since_or(self, hours: int) -> datetime:
        if self.since is not None:
            return self.since if self.since.tzinfo else self.since.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - timedelta(hours=hours)


# ---------------------------------------------------------------- collector base


class Collector:
    """Subclasses set the class attributes, implement `_normalize(raw)` as a pure function of
    already-fetched JSON-able data, and a thin `collect()` that fetches and normalizes."""

    name: str = ''
    kind: str = 'cloud'
    description: str = ''
    config_schema: dict[str, Any] = {'type': 'object', 'properties': {}, 'additionalProperties': False}
    secret_fields: list[str] = []
    sdk_modules: tuple[str, ...] = ()  # python modules that must be importable for collect()
    default_schedule_minutes: int = 360

    def available(self) -> bool:
        return modules_available(*self.sdk_modules)

    def install_hint(self) -> str:
        missing = [m for m in self.sdk_modules if not modules_available(m)]
        return f'install {", ".join(missing)}' if missing else ''

    async def collect(self, ctx: CollectorContext) -> CollectorResult:  # pragma: no cover - interface
        raise NotImplementedError

    def _normalize(self, raw: dict[str, Any]) -> CollectorResult:  # pragma: no cover - interface
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        return {'name': self.name, 'kind': self.kind, 'description': self.description, 'config_schema': self.config_schema,
                'secret_fields': list(self.secret_fields), 'available': self.available(), 'install_hint': self.install_hint(),
                'default_schedule_minutes': self.default_schedule_minutes}

    @property
    def source(self) -> str:
        return f'collector:{self.name}'




# ---------------------------------------------------------------- helpers shared by collectors


def modules_available(*names: str) -> bool:
    for name in names:
        try:
            if importlib.util.find_spec(name) is None:
                return False
        except (ImportError, ValueError, AttributeError):
            return False
    return True


_TYPE_CHECKS: dict[str, tuple[type, ...]] = {
    'string': (str,), 'integer': (int,), 'number': (int, float), 'boolean': (bool,), 'array': (list,), 'object': (dict,),
}


def validate_config(schema: dict[str, Any], config: dict[str, Any], path: str = '') -> list[str]:
    """Small JSON-schema subset (type, properties, required, additionalProperties, enum, items,
    minimum, maximum, maxLength, pattern). Returns human-readable errors; empty means valid."""
    if not isinstance(config, dict):
        return [f'{path or "config"} must be an object']
    errors: list[str] = []
    properties: dict[str, Any] = schema.get('properties', {}) or {}
    if schema.get('additionalProperties') is False:
        for key in config:
            if key not in properties:
                errors.append(f'unknown config key {path}{key}')
    for key in schema.get('required', []) or []:
        if key not in config or config[key] in ('', None, []):
            errors.append(f'missing required config key {path}{key}')
    for key, rule in properties.items():
        if key not in config or config[key] is None:
            continue
        errors.extend(_validate_value(rule, config[key], f'{path}{key}'))
    return errors


def _validate_value(rule: dict[str, Any], value: Any, path: str) -> list[str]:
    errors: list[str] = []
    expected = rule.get('type')
    if expected:
        types = expected if isinstance(expected, list) else [expected]
        ok = False
        for t in types:
            allowed = _TYPE_CHECKS.get(t)
            if allowed and isinstance(value, allowed) and not (t in ('integer', 'number') and isinstance(value, bool)):
                ok = True
                break
        if not ok:
            return [f'{path} must be of type {expected}']
    if 'enum' in rule and value not in rule['enum']:
        errors.append(f'{path} must be one of {rule["enum"]}')
    if isinstance(value, str):
        if rule.get('maxLength') and len(value) > rule['maxLength']:
            errors.append(f'{path} is longer than {rule["maxLength"]} characters')
        if rule.get('pattern') and not re.search(rule['pattern'], value):
            errors.append(f'{path} does not match {rule["pattern"]}')
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if 'minimum' in rule and value < rule['minimum']:
            errors.append(f'{path} must be >= {rule["minimum"]}')
        if 'maximum' in rule and value > rule['maximum']:
            errors.append(f'{path} must be <= {rule["maximum"]}')
    if isinstance(value, list) and rule.get('items'):
        for i, item in enumerate(value):
            errors.extend(_validate_value(rule['items'], item, f'{path}[{i}]'))
    if isinstance(value, dict) and (rule.get('properties') or rule.get('additionalProperties') is False):
        errors.extend(validate_config(rule, value, f'{path}.'))
    return errors


def is_secret_ref(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(SECRET_REF_PREFIXES) and len(value) > value.index(':') + 1


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return '<bytes>'
    if isinstance(value, set):
        return sorted(value, key=str)
    if hasattr(value, 'as_dict'):
        return value.as_dict()
    if hasattr(value, 'to_dict'):
        return value.to_dict()
    return str(value)


def jsonable(value: Any) -> Any:
    """Round-trip through JSON so normalizers only see plain dict/list/str/number data,
    regardless of which SDK produced it (datetimes become ISO strings)."""
    return json.loads(json.dumps(value, default=_json_default))


def parse_time(value: Any) -> datetime | None:
    if value is None or value == '':
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value > 1e12:
            value = value / 1000.0
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if re.fullmatch(r'\d{9,13}(\.\d+)?', text):
        return parse_time(float(text))
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    text = re.sub(r'(\.\d{6})\d+', r'\1', text)  # trim sub-microsecond precision
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%a, %d %b %Y %H:%M:%S %Z'):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def age_days(value: Any, now: datetime | None = None) -> float | None:
    parsed = parse_time(value)
    if parsed is None:
        return None
    now = now or datetime.now(timezone.utc)
    return (now - parsed).total_seconds() / 86400.0


_INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10',
                                                        '0.0.0.0/8', '224.0.0.0/4', '255.255.255.255/32', '::1/128', '::/128', 'fc00::/7', 'fe80::/10', 'ff00::/8')]


def is_private_ip(address: str, extra_cidrs: list[str] | None = None) -> bool:
    """True for RFC 1918 / CGNAT / loopback / link-local / multicast / ULA addresses and any extra
    CIDRs. Documentation ranges (192.0.2.0/24 etc.) count as external, unlike ipaddress.is_private."""
    try:
        ip = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    for net in _INTERNAL_NETWORKS:
        if ip.version == net.version and ip in net:
            return True
    for cidr in extra_cidrs or []:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if ip.version == net.version and ip in net:
            return True
    return False
