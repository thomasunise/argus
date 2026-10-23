"""Hash-chained audit log with optional external append-only sinks.

The chain is per tenant. Each entry hashes (tenant, previous_hash, actor, action, subject,
detail, created_at). AUDIT_SIGNING_KEY adds an HMAC so a database admin cannot silently
rewrite history without the key. Sinks mirror every entry out of the database.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AuditEntry, dumps, utcnow
from .config import Settings
from .rbac import Principal
from .security import redact

log = logging.getLogger('sentinel.audit')
_lock = threading.Lock()


class AuditSink:
    name = 'base'

    def write(self, record: dict) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class JsonlSink(AuditSink):
    name = 'jsonl'

    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: dict) -> None:
        with _lock, self.path.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(record, sort_keys=True, default=str) + '\n')


class S3ObjectLockSink(AuditSink):
    """Writes one object per entry into a bucket with Object Lock (compliance mode) enabled."""

    name = 's3'

    def __init__(self, bucket: str, prefix: str):
        self.bucket, self.prefix = bucket, prefix

    def write(self, record: dict) -> None:
        import boto3  # lazy

        key = f"{self.prefix}{record['tenant_id']}/{record['id']:012d}.json"
        boto3.client('s3').put_object(Bucket=self.bucket, Key=key, Body=json.dumps(record, sort_keys=True, default=str).encode(),
                                      ContentType='application/json')


class AzureImmutableBlobSink(AuditSink):
    name = 'azure'

    def __init__(self, connection_string: str, container: str):
        self.connection_string, self.container = connection_string, container

    def write(self, record: dict) -> None:
        from azure.storage.blob import BlobServiceClient  # lazy

        client = BlobServiceClient.from_connection_string(self.connection_string)
        blob = client.get_blob_client(self.container, f"{record['tenant_id']}/{record['id']:012d}.json")
        blob.upload_blob(json.dumps(record, sort_keys=True, default=str).encode(), overwrite=False)


def build_sinks(settings: Settings) -> list[AuditSink]:
    sinks: list[AuditSink] = []
    if settings.audit_jsonl_path:
        sinks.append(JsonlSink(settings.audit_jsonl_path))
    if settings.audit_s3_bucket:
        sinks.append(S3ObjectLockSink(settings.audit_s3_bucket, settings.audit_s3_prefix))
    if settings.audit_azure_container and settings.audit_azure_connection_string:
        sinks.append(AzureImmutableBlobSink(settings.audit_azure_connection_string, settings.audit_azure_container))
    return sinks


_sinks: list[AuditSink] = []
_signing_key: bytes = b''
_signing_keys: dict[str, bytes] = {}
_signing_kid: str = ''


def configure(settings: Settings) -> None:
    global _sinks, _signing_key, _signing_keys, _signing_kid
    _sinks = build_sinks(settings)
    keys: dict[str, bytes] = {}
    order: list[str] = []
    for item in (settings.audit_signing_keys or '').split(','):
        item = item.strip()
        if not item:
            continue
        kid, _, value = item.partition('=')
        if not value:
            kid, value = 'k1', kid
        keys[kid.strip()] = value.strip().encode()
        order.append(kid.strip())
    if settings.audit_signing_key and 'k1' not in keys:
        keys['k1'] = settings.audit_signing_key.encode()
        order.append('k1')
    _signing_keys = keys
    _signing_kid = order[0] if order else ''
    _signing_key = keys.get(_signing_kid, b'')


def _ts(value: datetime) -> str:
    """Canonical timestamp independent of whether the driver returned an aware or naive datetime."""
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.isoformat(timespec='microseconds')


def _entry_hash(tenant_id: str, previous_hash: str, actor: str, action: str, subject: str, detail: str, created_at: str) -> str:
    material = '|'.join([tenant_id, previous_hash, actor, action, subject, detail, created_at])
    return hashlib.sha256(material.encode()).hexdigest()


def _sign(entry_hash: str) -> str:
    if not _signing_key:
        return ''
    return _signing_kid + ':' + hmac.new(_signing_key, entry_hash.encode(), hashlib.sha256).hexdigest()


def _signature_valid(entry_hash: str, signature: str) -> bool:
    """Verifies against the key id embedded in the signature, so rotated keys keep old entries valid."""
    if not signature:
        return not _signing_keys
    kid, sep, digest = signature.partition(':')
    if not sep:  # legacy unprefixed signature from before key ids existed
        kid, digest = 'k1', signature
    key = _signing_keys.get(kid)
    if key is None:
        return False
    return hmac.compare_digest(digest, hmac.new(key, entry_hash.encode(), hashlib.sha256).hexdigest())


def record_audit(db: Session, actor: Principal | str, action: str, subject: str = '', detail: dict[str, Any] | str | None = None,
                 *, tenant_id: str | None = None, actor_kind: str | None = None, request_id: str = '') -> AuditEntry:
    if isinstance(actor, Principal):
        tenant = tenant_id or actor.tenant_id
        actor_name = actor.actor
        kind = actor_kind or ('api_key' if actor.auth == 'api_key' else 'system' if actor.auth == 'system' else 'user')
        request_id = request_id or actor.request_id
    else:
        tenant = tenant_id or ''
        actor_name = actor
        kind = actor_kind or ('system' if actor in {'system', 'scanner', 'scheduler', 'agent', 'broker'} else 'user')
    if isinstance(detail, dict):
        detail_text = dumps({k: (redact(v) if isinstance(v, str) else v) for k, v in detail.items()}, limit=4000)
    else:
        detail_text = dumps({'text': redact(detail or '')}, limit=4000)
    with _lock:
        last = db.execute(select(AuditEntry).where(AuditEntry.tenant_id == tenant).order_by(AuditEntry.id.desc()).limit(1)).scalar_one_or_none()
        previous = last.entry_hash if last else '0' * 64
        created_at = utcnow()
        entry_hash = _entry_hash(tenant, previous, actor_name, action, subject, detail_text, _ts(created_at))
        entry = AuditEntry(tenant_id=tenant, actor=actor_name[:200], actor_kind=kind, action=action[:100], subject=str(subject)[:200],
                           detail=detail_text, request_id=request_id[:64], previous_hash=previous, entry_hash=entry_hash,
                           signature=_sign(entry_hash), created_at=created_at)
        db.add(entry)
        db.flush()
    record = {'id': entry.id, 'tenant_id': tenant, 'actor': actor_name, 'actor_kind': kind, 'action': action, 'subject': subject,
              'detail': detail_text, 'previous_hash': previous, 'entry_hash': entry_hash, 'signature': entry.signature,
              'created_at': created_at.isoformat()}
    for sink in _sinks:
        try:
            sink.write(record)
        except Exception:  # a sink outage must never block the operation; it is itself logged
            log.exception('audit sink %s failed', sink.name)
    return entry


def verify_chain(db: Session, tenant_id: str) -> dict:
    previous = '0' * 64
    count = 0
    for entry in db.execute(select(AuditEntry).where(AuditEntry.tenant_id == tenant_id).order_by(AuditEntry.id.asc())).scalars():
        expected = _entry_hash(tenant_id, previous, entry.actor, entry.action, entry.subject, entry.detail, _ts(entry.created_at))
        if entry.previous_hash != previous or entry.entry_hash != expected:
            return {'valid': False, 'checked': count, 'broken_at': entry.id}
        if _signing_keys and not _signature_valid(entry.entry_hash, entry.signature):
            return {'valid': False, 'checked': count, 'broken_at': entry.id, 'reason': 'signature'}
        previous = entry.entry_hash
        count += 1
    return {'valid': True, 'checked': count, 'signed': bool(_signing_key), 'key_id': _signing_kid}
