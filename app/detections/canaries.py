"""Canary tokens: creation of lure material per kind, hit recording, revocation and artifact
generation. A canary's `token` is the identifier an attacker would present (the URL path
segment, the fake AWS key id, the fake username, the DNS label) so hits can be reported by it.

Credential-style canaries are deliberately shaped like real secrets but are never valid
anywhere; they exist only to be noticed when used.
"""
from __future__ import annotations

import json
import logging
import re
import secrets
import string
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.findings import EventDraft, upsert_event
from ..core.security import redact
from ..models import dumps, loads, utcnow
from ..models.detections import CANARY_KINDS, Canary, CanaryHit
from .util import aware

log = logging.getLogger('argus.detections.canaries')

_ALNUM = string.ascii_letters + string.digits
_UPPER = string.ascii_uppercase + string.digits
_LOWER = string.ascii_lowercase + string.digits
_TOKEN_RE = re.compile(r'^[A-Za-z0-9_\-]{8,64}$')
_DROP_HEADERS = {'cookie', 'authorization', 'proxy-authorization', 'x-api-key', 'x-csrf-token', 'set-cookie'}
MAX_HEADERS = 20
MAX_PAYLOAD_CHARS = 2000
DEFAULT_DNS_DOMAIN = 'canary.invalid'

# 1x1 transparent GIF served for GET hits so URL canaries work as tracking pixels in documents.
PIXEL_GIF = (b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')


def _rand(n: int, alphabet: str = _ALNUM) -> str:
    return ''.join(secrets.choice(alphabet) for _ in range(n))


def _slug(text: str) -> str:
    slug = re.sub(r'[^a-z0-9]+', '-', (text or 'canary').lower()).strip('-')
    return (slug or 'canary')[:32]


def canary_url(token: str, settings: Any) -> str:
    base = str(getattr(settings, 'base_url', '') or 'http://127.0.0.1:8080').rstrip('/')
    return f'{base}/api/v1/canaries/{token}/hit'


def valid_token(token: str) -> bool:
    return bool(token) and bool(_TOKEN_RE.match(token))


def _material(kind: str, label: str, settings: Any) -> tuple[str, dict]:
    """(token, metadata) for a new canary of `kind`."""
    if kind == 'token':
        token = _rand(32)
        return token, {'value': token}
    if kind == 'url':
        token = _rand(32)
        return token, {'url': canary_url(token, settings)}
    if kind == 'credential':
        token = f'svc_{_rand(20)}'
        return token, {'username': token, 'password': _rand(24), 'hint': f'{_slug(label)} service account', 'valid': False}
    if kind == 'aws_key':
        token = 'AKIA' + _rand(16, _UPPER)
        return token, {'aws_access_key_id': token, 'aws_secret_access_key': _rand(40, _ALNUM + '+/'), 'valid': False}
    if kind == 'api_key':
        token = 'cnry_' + _rand(27)
        return token, {'api_key': token, 'valid': False}
    if kind == 'dns':
        token = _rand(24, _LOWER)
        domain = str(getattr(settings, 'canary_dns_domain', '') or DEFAULT_DNS_DOMAIN).strip('.')
        return token, {'hostname': f'{token}.{domain}', 'domain': domain}
    if kind in {'file', 'document'}:
        token = _rand(32)
        ext = 'pdf' if kind == 'file' else 'html'
        return token, {'url': canary_url(token, settings), 'filename': f'{_slug(label)}.{ext}', 'content_type': 'application/pdf' if kind == 'file' else 'text/html'}
    raise ValueError(f'unknown canary kind {kind!r}')


def create_canary(db: Session, tenant_id: str, *, kind: str, label: str, placement: str = '', metadata: dict | None = None,
                  created_by: str = '', expires_at: datetime | None = None, settings: Any = None) -> Canary:
    if kind not in CANARY_KINDS:
        raise ValueError(f'kind must be one of {", ".join(CANARY_KINDS)}')
    for _ in range(5):
        token, material = _material(kind, label, settings)
        if find_canary(db, token) is None:
            break
    else:  # pragma: no cover - 5 collisions on 32 random chars does not happen
        raise RuntimeError('could not allocate a unique canary token')
    user_meta = {str(k)[:60]: (redact(v)[:300] if isinstance(v, str) else v) for k, v in list((metadata or {}).items())[:30]}
    canary = Canary(tenant_id=tenant_id, kind=kind, token=token, label=redact(label)[:120], placement=redact(placement)[:2000],
                    metadata_json=dumps({**user_meta, **material}, limit=8000), created_by=created_by[:200], expires_at=aware(expires_at))
    db.add(canary)
    db.flush()
    return canary


def find_canary(db: Session, token: str) -> Canary | None:
    if not token:
        return None
    canary = db.execute(select(Canary).where(Canary.token == token)).scalar_one_or_none()
    if canary is None and token != token.lower():
        canary = db.execute(select(Canary).where(func.lower(Canary.token) == token.lower())).scalar_one_or_none()
    return canary


def _bounded_headers(headers: Any) -> dict:
    out: dict[str, str] = {}
    try:
        items = list(headers.items()) if hasattr(headers, 'items') else list(headers or [])
    except Exception:
        return out
    for key, value in items:
        name = str(key).lower()[:60]
        if name in _DROP_HEADERS:
            continue
        out[name] = redact(str(value))[:200]
        if len(out) >= MAX_HEADERS:
            break
    return out


def _bounded_payload(payload: Any) -> dict:
    if payload is None or payload == b'' or payload == '':
        return {}
    if isinstance(payload, (bytes, bytearray)):
        try:
            payload = payload.decode('utf-8', errors='replace')
        except Exception:
            return {'bytes': len(payload)}
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
            if isinstance(parsed, (dict, list)):
                payload = parsed
        except ValueError:
            return {'raw': redact(payload[:MAX_PAYLOAD_CHARS])}
    # Redact on the serialized form so nested strings are covered too, then re-parse.
    text = redact(json.dumps(payload, default=str, sort_keys=True))
    if len(text) > MAX_PAYLOAD_CHARS:
        return {'truncated': True, 'preview': text[:MAX_PAYLOAD_CHARS]}
    try:
        cleaned = json.loads(text)
    except ValueError:
        return {'raw': text[:MAX_PAYLOAD_CHARS]}
    if isinstance(cleaned, dict):
        return {str(k)[:60]: v for k, v in list(cleaned.items())[:40]}
    return {'items': cleaned[:40]}


def record_hit(db: Session, canary: Canary, *, source_ip: str = '', user_agent: str = '', headers: Any = None, payload: Any = None,
               received_at: datetime | None = None) -> CanaryHit | None:
    """Persist a hit, bump counters and emit a `canary` SecurityEvent. Revoked canaries record nothing."""
    if canary.revoked_at is not None:
        return None
    now = aware(received_at) or utcnow()
    hit = CanaryHit(tenant_id=canary.tenant_id, canary_id=canary.id, source_ip=str(source_ip or '')[:64], user_agent=redact(str(user_agent or ''))[:300],
                    headers_json=dumps(_bounded_headers(headers), limit=4000), payload_json=dumps(_bounded_payload(payload), limit=4000), received_at=now)
    db.add(hit)
    canary.hit_count = (canary.hit_count or 0) + 1
    canary.last_hit_at = now
    db.flush()
    upsert_event(db, canary.tenant_id, EventDraft(
        source='canary', external_id=hit.id, title=f'Canary "{canary.label}" ({canary.kind}) hit', severity='critical', category='canary',
        actor=hit.source_ip, entity=canary.label, action='canary.hit', occurred_at=now,
        metadata={'canary_id': canary.id, 'kind': canary.kind, 'placement': canary.placement[:300], 'src_ip': hit.source_ip,
                  'user_agent': hit.user_agent, 'hit_id': hit.id}))
    log.warning('canary hit tenant=%s canary=%s kind=%s ip=%s', canary.tenant_id, canary.id, canary.kind, hit.source_ip)
    return hit


def revoke_canary(db: Session, canary: Canary) -> Canary:
    if canary.revoked_at is None:
        canary.revoked_at = utcnow()
        db.flush()
    return canary


# ---------------------------------------------------------------- artifacts


def _pdf_escape(text: str) -> str:
    return text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')


def _minimal_pdf(title: str, body: str, url: str) -> bytes:
    """A valid single-page PDF whose page carries a clickable link and an OpenAction to the canary URL."""
    content = f'BT /F1 16 Tf 72 720 Td ({_pdf_escape(title)}) Tj 0 -28 Td /F1 11 Tf ({_pdf_escape(body)}) Tj ET'.encode('latin-1', 'replace')
    objects = [
        f'<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /URI /URI ({_pdf_escape(url)}) >> >>'.encode(),
        b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> /Annots [6 0 R] >>',
        b'<< /Length ' + str(len(content)).encode() + b' >>\nstream\n' + content + b'\nendstream',
        b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
        f'<< /Type /Annot /Subtype /Link /Rect [72 690 540 740] /Border [0 0 0] /A << /S /URI /URI ({_pdf_escape(url)}) >> >>'.encode(),
    ]
    out = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
    offsets = []
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f'{index} 0 obj\n'.encode() + obj + b'\nendobj\n'
    xref = len(out)
    out += f'xref\n0 {len(objects) + 1}\n0000000000 65535 f \n'.encode()
    for offset in offsets:
        out += f'{offset:010d} 00000 n \n'.encode()
    out += f'trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode()
    return bytes(out)


def artifact(canary: Canary, settings: Any) -> tuple[bytes, str, str]:
    """(bytes, media_type, filename) for download. Every kind produces something plantable."""
    data = loads(canary.metadata_json)
    slug = _slug(canary.label)
    if canary.kind == 'file':
        url = data.get('url') or canary_url(canary.token, settings)
        title = canary.label or 'Confidential'
        pdf = _minimal_pdf(title, f'Internal document. Latest version: {url}', url)
        return pdf, 'application/pdf', data.get('filename') or f'{slug}.pdf'
    if canary.kind == 'document':
        url = data.get('url') or canary_url(canary.token, settings)
        html = (f'<!doctype html><html><head><meta charset="utf-8"><title>{_html(canary.label)}</title></head><body>'
                f'<h1>{_html(canary.label)}</h1><p>Internal document. The current version is kept at <a href="{_html(url)}">{_html(url)}</a>.</p>'
                f'<img src="{_html(url)}" width="1" height="1" alt=""></body></html>').encode()
        return html, 'text/html; charset=utf-8', data.get('filename') or f'{slug}.html'
    if canary.kind == 'aws_key':
        text = f"[default]\naws_access_key_id = {data.get('aws_access_key_id', canary.token)}\naws_secret_access_key = {data.get('aws_secret_access_key', '')}\nregion = us-east-1\n"
        return text.encode(), 'text/plain; charset=utf-8', 'credentials'
    if canary.kind == 'credential':
        text = f"# {canary.label}\nusername={data.get('username', canary.token)}\npassword={data.get('password', '')}\n"
        return text.encode(), 'text/plain; charset=utf-8', f'{slug}.env'
    if canary.kind == 'api_key':
        return f"API_KEY={data.get('api_key', canary.token)}\n".encode(), 'text/plain; charset=utf-8', f'{slug}.env'
    if canary.kind == 'url':
        return f"{data.get('url', canary_url(canary.token, settings))}\n".encode(), 'text/plain; charset=utf-8', f'{slug}.url.txt'
    if canary.kind == 'dns':
        return f"{data.get('hostname', canary.token)}\n".encode(), 'text/plain; charset=utf-8', f'{slug}.host.txt'
    return f"{data.get('value', canary.token)}\n".encode(), 'text/plain; charset=utf-8', f'{slug}.token.txt'


def _html(text: str) -> str:
    return (text or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


# ---------------------------------------------------------------- serialization


def canary_to_dict(c: Canary) -> dict:
    return {'id': c.id, 'kind': c.kind, 'token': c.token, 'label': c.label, 'placement': c.placement, 'metadata': loads(c.metadata_json),
            'created_by': c.created_by, 'created_at': c.created_at, 'expires_at': c.expires_at, 'revoked_at': c.revoked_at,
            'hit_count': c.hit_count, 'last_hit_at': c.last_hit_at, 'active': c.revoked_at is None}


def hit_to_dict(h: CanaryHit) -> dict:
    return {'id': h.id, 'canary_id': h.canary_id, 'source_ip': h.source_ip, 'user_agent': h.user_agent, 'headers': loads(h.headers_json),
            'payload': loads(h.payload_json), 'received_at': h.received_at}


__all__ = ['create_canary', 'find_canary', 'record_hit', 'revoke_canary', 'artifact', 'canary_url', 'valid_token', 'canary_to_dict', 'hit_to_dict',
           'PIXEL_GIF']
