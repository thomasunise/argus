"""Shared building blocks for inbound parsers: the parser base class, parse context, finding
drafts, time parsing, dotted action names, and the bounded, redacted metadata cleaner.

Every parser produces `EventDraft`s (from app.core.findings) whose `action` uses the dotted
vocabulary the detection rules match on, and whose `metadata` is small, whitelisted and secret free.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from ...core.findings import EventDraft
from ...core.findings import severity as normalize_severity
from ...core.security import redact
from ...models import dumps

log = logging.getLogger('argus.integrations.inbound')

MAX_STRING = 2048           # strings longer than this are raw log bodies: dropped, never stored
MAX_DEPTH = 4
MAX_LIST = 50
MAX_METADATA_BYTES = 6000   # upsert_event truncates at 8000; stay below so nothing is lost silently

# Keys whose values are credentials or raw matches. Removed recursively from every metadata dict.
SENSITIVE_KEYS = {'password', 'passwd', 'pwd', 'secret', 'secret_value', 'secretstring', 'token', 'access_token', 'refresh_token', 'id_token',
                  'authorization', 'auth', 'api_key', 'apikey', 'x-api-key', 'private_key', 'privatekey', 'client_secret', 'session_token',
                  'sessiontoken', 'secretaccesskey', 'secret_access_key', 'match', 'code', 'raw', 'cookie', 'set-cookie', 'credentials',
                  'credential', 'key_material', 'plaintext', 'ciphertext', 'full_log_raw'}

PUBLIC_MARKERS = ['0.0.0.0/0', '::/0', 'allUsers', 'allAuthenticatedUsers', 'public-read', 'public-read-write', 'authenticated-read',
                  '"publicAccess":"blob"', '"publicAccess":"container"', '"allowBlobPublicAccess":true', 'Internet', '"Any"']
_WILDCARD_PRINCIPAL = re.compile(r'"(Principal|AWS|principal|members?)":\s*(\[\s*)?"\*"')


# ---------------------------------------------------------------- drafts and context


@dataclass
class FindingDraft:
    """A vulnerability-report item destined for `upsert_finding`. Evidence is whitelisted by the parser."""

    source: str
    rule: str
    title: str
    description: str
    severity: Any = 'medium'
    remediation: str = ''
    evidence: dict = field(default_factory=dict)
    cve_ids: list[str] = field(default_factory=list)
    cvss: float | None = None
    asset_id: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass
class ParseContext:
    tenant_id: str
    source: str
    asset_id: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    errors: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def header(self, name: str, default: str = '') -> str:
        wanted = name.lower()
        for key, value in self.headers.items():
            if key.lower() == wanted:
                return value
        return default


# ---------------------------------------------------------------- parser base


class Parser:
    """Base inbound parser. Subclasses set `name`, `source`, implement `parse_item` and optionally
    `findings_for_item`, `items` (to unwrap envelopes) and `verify` (webhook signatures)."""

    name: str = ''                      # registry key and ingest path segment
    aliases: tuple[str, ...] = ()
    source: str = ''                    # SecurityEvent.source label (<= 30 chars)
    description: str = ''
    kind: str = 'events'                # events | findings | both
    example: str = ''                   # repository-relative path of a realistic payload
    correlate_alerts: bool = False      # create a finding for high/critical events (alert sources)
    supports_verify: bool = False       # webhook signature verification
    secret_fields: list[str] = []       # secret refs an inbound IntegrationConfig of this kind may carry
    config_schema: dict[str, Any] = {'type': 'object', 'properties': {}, 'additionalProperties': False}
    pull: bool = False                  # has a queue job that pulls from the source

    def items(self, payload: Any) -> list[Any]:
        if isinstance(payload, list):
            return payload
        return [payload]

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:  # pragma: no cover - interface
        raise NotImplementedError

    def findings_for_item(self, item: dict, ctx: ParseContext) -> list[FindingDraft]:
        return []

    def parse(self, payload: dict | list, ctx: ParseContext) -> list[EventDraft]:
        drafts: list[EventDraft] = []
        for index, item in enumerate(self.items(payload)):
            if not isinstance(item, dict):
                ctx.errors.append(f'item {index}: not a JSON object')
                continue
            try:
                for draft in self.parse_item(item, ctx):
                    drafts.append(self.finalize(draft, ctx))
            except Exception as exc:  # one bad record must not reject the batch
                log.debug('parser %s failed on item %s', self.name, index, exc_info=True)
                ctx.errors.append(f'item {index}: {type(exc).__name__}: {str(exc)[:160]}')
        return drafts

    def findings(self, payload: dict | list, ctx: ParseContext) -> list[FindingDraft]:
        drafts: list[FindingDraft] = []
        for index, item in enumerate(self.items(payload)):
            if not isinstance(item, dict):
                continue
            try:
                for draft in self.findings_for_item(item, ctx):
                    draft.source = draft.source or self.source
                    draft.asset_id = draft.asset_id or ctx.asset_id
                    draft.severity = normalize_severity(draft.severity)
                    draft.evidence = clean_metadata(draft.evidence)
                    drafts.append(draft)
            except Exception as exc:
                log.debug('parser %s findings failed on item %s', self.name, index, exc_info=True)
                ctx.errors.append(f'item {index}: {type(exc).__name__}: {str(exc)[:160]}')
        return drafts

    def finalize(self, draft: EventDraft, ctx: ParseContext) -> EventDraft:
        draft.source = (draft.source or self.source)[:30]
        draft.external_id = str(draft.external_id or '')[:128] or stable_id(draft.title, draft.actor, draft.entity, draft.action)
        draft.asset_id = draft.asset_id or ctx.asset_id
        draft.action = (draft.action or 'unknown')[:120]
        draft.category = (draft.category or 'generic')[:40]
        draft.severity = normalize_severity(draft.severity)
        draft.metadata = clean_metadata(draft.metadata)
        return draft

    def verify(self, ctx: ParseContext, body: bytes, secret: str) -> bool:
        return False

    def describe(self) -> dict[str, Any]:
        return {'name': self.name, 'aliases': list(self.aliases), 'source': self.source, 'description': self.description, 'kind': self.kind,
                'example': self.example, 'supports_verify': self.supports_verify, 'pull': self.pull, 'secret_fields': list(self.secret_fields),
                'config_schema': self.config_schema, 'correlate_alerts': self.correlate_alerts}


# ---------------------------------------------------------------- helpers


def stable_id(*parts: Any) -> str:
    material = '|'.join('' if p is None else str(p) for p in parts)
    return hashlib.sha256(material.encode('utf-8', 'replace')).hexdigest()


def hash_item(item: Any) -> str:
    return hashlib.sha256(json.dumps(item, sort_keys=True, default=str).encode('utf-8', 'replace')).hexdigest()


def parse_time(value: Any) -> datetime | None:
    """ISO-8601 (with Z, offsets, nanoseconds), epoch seconds or milliseconds. None when unparseable."""
    if value in (None, ''):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1e12:
            ts /= 1000.0
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if text.isdigit():
        return parse_time(int(text))
    text = text.replace('Z', '+00:00')
    # Trim sub-microsecond precision (Falco/k8s emit nanoseconds) and compact offsets like +0000.
    match = re.match(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$', text)
    if match:
        frac = (match.group(2) or '')[:7]
        tail = match.group(3) or ''
        if re.fullmatch(r'[+-]\d{4}', tail):
            tail = tail[:3] + ':' + tail[3:]
        text = match.group(1) + frac + tail
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


_CAMEL_1 = re.compile(r'(.)([A-Z][a-z]+)')
_CAMEL_2 = re.compile(r'([a-z0-9])([A-Z])')


def snake(value: Any) -> str:
    text = str(value or '').strip()
    text = _CAMEL_1.sub(r'\1_\2', text)
    text = _CAMEL_2.sub(r'\1_\2', text)
    text = re.sub(r'[^A-Za-z0-9]+', '_', text)
    return text.strip('_').lower()


def dotted(*parts: Any) -> str:
    return '.'.join(p for p in (snake(x) for x in parts) if p)


def first(data: dict | None, *keys: str, default: Any = None) -> Any:
    if not isinstance(data, dict):
        return default
    for key in keys:
        if key in data and data[key] not in (None, '', [], {}):
            return data[key]
    return default


def dig(data: Any, *path: str, default: Any = None) -> Any:
    node = data
    for key in path:
        if isinstance(node, dict) and key in node:
            node = node[key]
        else:
            return default
    return default if node in (None, '') else node


def as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def scan_markers(data: Any) -> list[str]:
    """Public-exposure markers present anywhere in a (bounded) structure."""
    text = dumps(data, limit=20000)
    found = [m for m in PUBLIC_MARKERS if m in text]
    if _WILDCARD_PRINCIPAL.search(text):
        found.append('Principal:*')
    return sorted(set(found))


def geo(lat: Any = None, lon: Any = None, country: Any = None, city: Any = None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    lat_f, lon_f = as_float(lat), as_float(lon)
    if lat_f is not None and lon_f is not None:
        out['lat'], out['lon'] = round(lat_f, 4), round(lon_f, 4)
    if country:
        text = str(country).strip()
        out['country'] = text.upper() if len(text) <= 3 else text[:56]  # ISO codes upper-cased, names kept readable
    if city:
        out['city'] = str(city)[:80]
    return out


def _clean(node: Any, depth: int) -> Any:
    if depth > MAX_DEPTH:
        return None
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in list(node.items())[:MAX_LIST]:
            key_text = str(key)
            if key_text.lower() in SENSITIVE_KEYS:
                continue
            cleaned = _clean(value, depth + 1)
            if cleaned is None or cleaned == '' or cleaned == {} or cleaned == []:
                continue
            out[key_text[:80]] = cleaned
        return out
    if isinstance(node, (list, tuple, set)):
        items = [_clean(v, depth + 1) for v in list(node)[:MAX_LIST]]
        return [v for v in items if v is not None and v != '' and v != {} and v != []]
    if isinstance(node, bool) or node is None:
        return node
    if isinstance(node, (int, float)):
        return node
    if isinstance(node, datetime):
        return node.isoformat()
    text = str(node)
    if len(text) > MAX_STRING:
        return None  # raw log body: never persisted
    return redact(text)


def clean_metadata(data: dict | None) -> dict[str, Any]:
    """Whitelist-friendly cleaner: strips secret-bearing keys, drops strings over 2 KB, bounds depth,
    list sizes and total encoded size, and redacts credential patterns in what remains."""
    cleaned = _clean(data or {}, 0)
    if not isinstance(cleaned, dict):
        return {}
    encoded = dumps(cleaned)
    if len(encoded) <= MAX_METADATA_BYTES:
        return cleaned
    # Too large: drop the biggest values until it fits.
    sized = sorted(cleaned.items(), key=lambda kv: len(dumps(kv[1])), reverse=True)
    for key, _ in sized:
        cleaned.pop(key, None)
        cleaned.setdefault('truncated_keys', []).append(key)
        if len(dumps(cleaned)) <= MAX_METADATA_BYTES:
            break
    return cleaned


def event(source: str, external_id: Any, title: str, *, severity: Any = 'low', category: str = '', actor: Any = '', entity: Any = '',
          action: str = '', occurred_at: Any = None, metadata: dict | None = None, asset_id: str | None = None) -> EventDraft:
    """Convenience constructor that coerces actor/entity to strings and parses timestamps."""
    return EventDraft(source=source, external_id=str(external_id or ''), title=str(title or '')[:300], severity=severity, category=category,
                      actor=str(actor or '')[:200], entity=str(entity or '')[:200], action=action, asset_id=asset_id,
                      occurred_at=parse_time(occurred_at), metadata=metadata or {})


def listify(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def sample(values: Iterable[Any], cap: int = 10) -> list[str]:
    out: list[str] = []
    for value in values:
        text = str(value)[:200] if value not in (None, '') else ''
        if text and text not in out:
            out.append(text)
            if len(out) >= cap:
                break
    return out
