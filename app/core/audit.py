"""Hash-chained audit log with optional external append-only sinks.

The chain is per tenant. Each entry hashes (tenant, previous_hash, actor, action, subject,
detail, created_at). AUDIT_SIGNING_KEY adds an HMAC so a database admin cannot silently
rewrite history without the key. Sinks mirror every entry out of the database.
"""
from __future__ import annotations

import contextvars
import hashlib
import hmac
import json
import logging
import socket
import threading
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import event, func, select, text
from sqlalchemy.orm import Session

from ..models import AuditEntry, AuditOutbox, dumps, loads, utcnow
from .config import Settings
from .rbac import Principal
from .security import redact

log = logging.getLogger('argus.audit')
_lock = threading.Lock()
_request_ctx: contextvars.ContextVar[dict[str, str] | None] = contextvars.ContextVar('argus_audit_req_ctx', default=None)


def set_audit_request_context(*, source_ip: str = '', user_agent: str = '', session_id: str = '', request_id: str = '') -> contextvars.Token:
    return _request_ctx.set({
        'source_ip': (source_ip or '')[:64],
        'user_agent': (user_agent or '')[:256],
        'session_id': (session_id or '')[:64],
        'request_id': (request_id or '')[:64],
    })


def reset_audit_request_context(token: contextvars.Token) -> None:
    _request_ctx.reset(token)


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
        try:
            import boto3  # noqa: F401  (lazy elsewhere; verified here so a dead sink fails at startup, not silently)
        except ImportError as exc:
            raise RuntimeError('AUDIT_S3_BUCKET is set but boto3 is not installed; use the -extras image or install requirements-optional.txt') from exc
        self.bucket, self.prefix = bucket, prefix

    def write(self, record: dict) -> None:
        import boto3  # lazy

        key = f"{self.prefix}{record['tenant_id']}/{record['id']:012d}.json"
        boto3.client('s3').put_object(Bucket=self.bucket, Key=key, Body=json.dumps(record, sort_keys=True, default=str).encode(),
                                      ContentType='application/json')


class AzureImmutableBlobSink(AuditSink):
    name = 'azure'

    def __init__(self, connection_string: str, container: str):
        try:
            from azure.storage.blob import BlobServiceClient  # noqa: F401
        except ImportError as exc:
            raise RuntimeError('AUDIT_AZURE_CONTAINER is set but azure-storage-blob is not installed; use the -extras image or install requirements-optional.txt') from exc
        self.connection_string, self.container = connection_string, container

    def write(self, record: dict) -> None:
        from azure.storage.blob import BlobServiceClient  # lazy

        client = BlobServiceClient.from_connection_string(self.connection_string)
        blob = client.get_blob_client(self.container, f"{record['tenant_id']}/{record['id']:012d}.json")
        blob.upload_blob(json.dumps(record, sort_keys=True, default=str).encode(), overwrite=False)


class SiemHttpSink(AuditSink):
    """Forwards audit records over HTTPS to a customer SIEM (Splunk HEC, Datadog, Sentinel, generic webhook)."""

    name = 'siem_http'

    def __init__(self, url: str, token: str = ''):
        self.url, self.token = url, token

    def write(self, record: dict) -> None:
        body = json.dumps({'event': record, 'source': 'argus.audit'}, sort_keys=True, default=str).encode('utf-8')
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        req = urllib.request.Request(self.url, data=body, headers=headers, method='POST')  # noqa: S310
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            resp.read()


class SyslogSink(AuditSink):
    """RFC 5424 UDP syslog forwarder for SIEM collectors."""

    name = 'syslog'

    def __init__(self, host: str, port: int = 514):
        self.host, self.port = host, int(port)

    def write(self, record: dict) -> None:
        ts = record.get('created_at') or datetime.now(UTC).isoformat()
        payload = json.dumps(record, sort_keys=True, default=str)
        line = f'<134>1 {ts} argus argus-audit - - - {payload}\n'.encode()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(line[:65000], (self.host, self.port))


def build_sinks(settings: Settings) -> list[AuditSink]:
    sinks: list[AuditSink] = []
    if settings.audit_jsonl_path:
        sinks.append(JsonlSink(settings.audit_jsonl_path))
    if settings.audit_s3_bucket:
        sinks.append(S3ObjectLockSink(settings.audit_s3_bucket, settings.audit_s3_prefix))
    if settings.audit_azure_container and settings.audit_azure_connection_string:
        sinks.append(AzureImmutableBlobSink(settings.audit_azure_connection_string, settings.audit_azure_container))
    if getattr(settings, 'audit_siem_url', ''):
        sinks.append(SiemHttpSink(settings.audit_siem_url, getattr(settings, 'audit_siem_token', '')))
    if getattr(settings, 'audit_syslog_host', ''):
        sinks.append(SyslogSink(settings.audit_syslog_host, getattr(settings, 'audit_syslog_port', 514)))
    return sinks


_sinks: list[AuditSink] = []
_OUTBOX = 'argus_audit_outbox'
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
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value.isoformat(timespec='microseconds')


def _len_prefix(field: str) -> str:
    return f'{len(field)}:{field}'


def _entry_hash_v1(tenant_id: str, previous_hash: str, actor: str, action: str, subject: str, detail: str, created_at: str) -> str:
    material = '|'.join([tenant_id, previous_hash, actor, action, subject, detail, created_at])
    return hashlib.sha256(material.encode()).hexdigest()


def _entry_hash(tenant_id: str, previous_hash: str, actor: str, action: str, subject: str, detail: str, created_at: str,
                actor_kind: str = 'user', request_id: str = '', *, source_ip: str = '', user_agent: str = '',
                session_id: str = '', version: int = 2) -> str:
    if version == 1:
        return _entry_hash_v1(tenant_id, previous_hash, actor, action, subject, detail, created_at)
    fields = (tenant_id, previous_hash, actor, actor_kind, action, subject, detail, request_id,
              source_ip, user_agent, session_id, created_at)
    material = 'v2:' + ''.join(_len_prefix(str(f)) for f in fields)
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
                 *, tenant_id: str | None = None, actor_kind: str | None = None, request_id: str = '',
                 source_ip: str = '', user_agent: str = '', session_id: str = '') -> AuditEntry:
    req_ctx = _request_ctx.get() or {}
    if isinstance(actor, Principal):
        tenant = tenant_id or actor.tenant_id
        actor_name = actor.actor
        kind = actor_kind or ('api_key' if actor.auth == 'api_key' else 'system' if actor.auth == 'system' else 'user')
        request_id = request_id or actor.request_id or req_ctx.get('request_id', '')
    else:
        tenant = tenant_id or ''
        actor_name = actor
        kind = actor_kind or ('system' if actor in {'system', 'scanner', 'scheduler', 'agent', 'broker'} else 'user')
        request_id = request_id or req_ctx.get('request_id', '')
    source_ip = source_ip or req_ctx.get('source_ip', '')
    user_agent = user_agent or req_ctx.get('user_agent', '')
    session_id = session_id or req_ctx.get('session_id', '')
    if isinstance(detail, dict):
        detail_text = dumps({k: (redact(v) if isinstance(v, str) else v) for k, v in detail.items()}, limit=4000)
    else:
        detail_text = dumps({'text': redact(detail or '')}, limit=4000)
    actor_str = str(actor_name)[:200]
    kind_str = str(kind)[:16]
    action_str = str(action)[:100]
    subject_str = str(subject)[:200]
    request_id_str = str(request_id or '')[:64]
    source_ip_str = str(source_ip or '')[:64]
    user_agent_str = str(user_agent or '')[:256]
    session_id_str = str(session_id or '')[:64]
    # Database lock first, then the in-process lock. The reverse order deadlocks: a worker that already holds the
    # SQLite write lock waits here for _lock while a request thread holding _lock waits for the write lock.
    _serialize_tenant(db, tenant)
    with _lock:
        last = db.execute(select(AuditEntry).where(AuditEntry.tenant_id == tenant).order_by(AuditEntry.id.desc()).limit(1)).scalar_one_or_none()
        previous = last.entry_hash if last else '0' * 64
        created_at = utcnow()
        entry_hash = _entry_hash(tenant, previous, actor_str, action_str, subject_str, detail_text, _ts(created_at),
                                 actor_kind=kind_str, request_id=request_id_str,
                                 source_ip=source_ip_str, user_agent=user_agent_str, session_id=session_id_str)
        entry = AuditEntry(tenant_id=tenant, actor=actor_str, actor_kind=kind_str, action=action_str, subject=subject_str,
                           detail=detail_text, request_id=request_id_str, source_ip=source_ip_str, user_agent=user_agent_str,
                           session_id=session_id_str, previous_hash=previous, entry_hash=entry_hash,
                           signature=_sign(entry_hash), created_at=created_at)
        db.add(entry)
        db.flush()
    record = {'id': entry.id, 'tenant_id': tenant, 'actor': actor_str, 'actor_kind': kind_str, 'action': action_str, 'subject': subject_str,
              'detail': detail_text, 'request_id': request_id_str, 'source_ip': source_ip_str, 'user_agent': user_agent_str,
              'session_id': session_id_str, 'previous_hash': previous, 'entry_hash': entry_hash,
              'signature': entry.signature, 'created_at': created_at.isoformat()}
    if _sinks:
        outbox_rows: list[tuple[str, AuditOutbox]] = []
        for sink in _sinks:
            row = AuditOutbox(tenant_id=tenant, entry_id=entry.id, sink_name=sink.name, payload_json=dumps(record))
            db.add(row)
            outbox_rows.append((sink.name, row))
        db.flush()
        outbox_ids = {name: row.id for name, row in outbox_rows}
        # Mirrored after the transaction commits (see _flush_outbox): a rolled-back request must not leave phantom entries in a WORM sink.
        db.info.setdefault(_OUTBOX, []).append((record, outbox_ids))
    return entry


def _serialize_tenant(db: Session, tenant_id: str) -> None:
    """Transaction-scoped lock so concurrent writers (request threads, workers, replicas) cannot fork the chain by
    reading the same last entry. Taken before the process-local _lock and held until the transaction ends.

    PostgreSQL: a per-tenant advisory lock. SQLite (development and tests): the database write lock, taken with a
    no-op UPDATE, which waits out the busy timeout without holding _lock. SQLite has a single writer, so this also
    serializes every tenant's chain."""
    bind = db.get_bind()
    dialect = bind.dialect.name if bind is not None else ''
    if dialect == 'postgresql':
        db.execute(text('SELECT pg_advisory_xact_lock(hashtext(:tenant))'), {'tenant': tenant_id})
    elif dialect == 'sqlite':
        db.execute(text(f'UPDATE {AuditEntry.__tablename__} SET id = id WHERE 0'))  # noqa: S608 - tablename from ORM metadata, no user input


def _flush_outbox(session: Session) -> None:
    items = session.info.pop(_OUTBOX, None)
    if not items:
        return
    bind = session.get_bind()
    engine: Any = getattr(bind, 'engine', bind) if bind is not None else None
    for item in items:
        record, outbox_ids = item if isinstance(item, tuple) else (item, {})
        tenant_id = str(record.get('tenant_id') or '')
        for sink in _sinks:
            row_id = outbox_ids.get(sink.name)
            try:
                sink.write(record)
                if row_id and engine is not None:
                    with engine.begin() as conn:
                        if engine.dialect.name == 'postgresql' and tenant_id:
                            conn.execute(text("SELECT set_config('app.tenant_id', :tid, true)"), {'tid': tenant_id})
                        conn.execute(text('UPDATE audit_outbox SET delivered_at = :now, attempts = attempts + 1, last_error = \'\' WHERE id = :id'),
                                     {'now': utcnow(), 'id': row_id})
            except Exception as exc:  # a sink outage must never block the operation; it remains in audit_outbox for retry
                log.exception('audit sink %s failed', sink.name)
                if row_id and engine is not None:
                    try:
                        with engine.begin() as conn:
                            if engine.dialect.name == 'postgresql' and tenant_id:
                                conn.execute(text("SELECT set_config('app.tenant_id', :tid, true)"), {'tid': tenant_id})
                            conn.execute(
                                text('UPDATE audit_outbox SET attempts = attempts + 1, last_error = :err, next_attempt_at = :nxt WHERE id = :id'),
                                {'err': f'{type(exc).__name__}: {exc}'[:500], 'nxt': utcnow() + timedelta(seconds=30), 'id': row_id},
                            )
                    except Exception:
                        log.debug('could not record audit_outbox failure', exc_info=True)


def flush_outbox_backlog(db: Session, *, limit: int = 200) -> dict[str, int]:
    """Deliver pending rows from `audit_outbox` with retries. Returns counts of delivered and failed rows."""
    now = utcnow()
    sink_map = {s.name: s for s in _sinks}
    rows = db.execute(
        select(AuditOutbox)
        .where(AuditOutbox.delivered_at.is_(None), (AuditOutbox.next_attempt_at.is_(None)) | (AuditOutbox.next_attempt_at <= now))
        .order_by(AuditOutbox.created_at.asc())
        .limit(limit)
    ).scalars().all()
    delivered = failed = 0
    for row in rows:
        sink = sink_map.get(row.sink_name)
        if sink is None:
            continue
        record = loads(row.payload_json, {})
        row.attempts = (row.attempts or 0) + 1
        try:
            sink.write(record)
            row.delivered_at = utcnow()
            row.last_error = ''
            row.next_attempt_at = None
            delivered += 1
        except Exception as exc:
            row.last_error = f'{type(exc).__name__}: {exc}'[:500]
            backoff = min(3600, 15 * (2 ** min(row.attempts, 8)))
            row.next_attempt_at = utcnow() + timedelta(seconds=backoff)
            failed += 1
    db.flush()
    return {'delivered': delivered, 'failed': failed, 'backlog': outbox_backlog_count(db)}


def outbox_backlog_count(db: Session) -> int:
    return int(db.scalar(select(func.count()).select_from(AuditOutbox).where(AuditOutbox.delivered_at.is_(None))) or 0)


def write_chain_head(db: Session, tenant_id: str) -> dict[str, Any]:
    """Anchor the current chain head to all configured external sinks so tail deletion is detectable."""
    last = db.execute(select(AuditEntry).where(AuditEntry.tenant_id == tenant_id).order_by(AuditEntry.id.desc()).limit(1)).scalar_one_or_none()
    count = int(db.scalar(select(func.count()).select_from(AuditEntry).where(AuditEntry.tenant_id == tenant_id)) or 0)
    head_hash = last.entry_hash if last else '0' * 64
    head_id = last.id if last else 0
    anchor = {
        'kind': 'chain_head_anchor',
        'id': head_id,
        'tenant_id': tenant_id,
        'head_entry_id': head_id,
        'head_entry_hash': head_hash,
        'entry_count': count,
        'signature': _sign(f'anchor:{tenant_id}:{head_id}:{head_hash}:{count}'),
        'anchored_at': utcnow().isoformat(),
    }
    for sink in _sinks:
        try:
            sink.write(anchor)
        except Exception:
            log.exception('chain head anchor write to %s failed', sink.name)
    return anchor


def _discard_outbox(session: Session) -> None:
    session.info.pop(_OUTBOX, None)


event.listen(Session, 'after_commit', _flush_outbox)
event.listen(Session, 'after_rollback', _discard_outbox)


def verify_chain(db: Session, tenant_id: str) -> dict:
    previous = '0' * 64
    count = 0
    breaks: list[dict[str, Any]] = []
    for entry in db.execute(select(AuditEntry).where(AuditEntry.tenant_id == tenant_id).order_by(AuditEntry.id.asc())).scalars():
        ts = _ts(entry.created_at)
        expected_v2 = _entry_hash(tenant_id, entry.previous_hash, entry.actor, entry.action, entry.subject, entry.detail, ts,
                                  actor_kind=entry.actor_kind, request_id=entry.request_id,
                                  source_ip=entry.source_ip or '', user_agent=entry.user_agent or '',
                                  session_id=entry.session_id or '', version=2)
        expected_v1 = _entry_hash_v1(tenant_id, entry.previous_hash, entry.actor, entry.action, entry.subject, entry.detail, ts)
        reasons: list[str] = []
        if entry.previous_hash != previous:
            reasons.append('previous_hash')
        if entry.entry_hash not in (expected_v2, expected_v1):
            reasons.append('hash')
        if _signing_keys and not _signature_valid(entry.entry_hash, entry.signature):
            reasons.append('signature')
        if reasons:
            breaks.append({'id': entry.id, 'reason': reasons[0], 'reasons': reasons})
        previous = entry.entry_hash
        count += 1
    if breaks:
        return {'valid': False, 'checked': count, 'broken_at': breaks[0]['id'], 'reason': breaks[0]['reason'],
                'breaks': breaks, 'broken_ids': [b['id'] for b in breaks]}
    return {'valid': True, 'checked': count, 'signed': bool(_signing_key), 'key_id': _signing_kid,
            'breaks': [], 'broken_ids': []}
