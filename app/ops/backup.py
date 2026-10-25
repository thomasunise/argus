"""Encrypted logical backups of the whole Argus database, restore into an empty database, and verification.

Why logical and not pg_dump: the same code backs up SQLite (development) and PostgreSQL, needs no client
binaries in the image, records the Alembic revision so a backup restores onto the schema it was taken from,
and lets restore verify row counts and every tenant's audit chain afterwards.

File format (`*.argus-backup`):

    b'ARGUSBAK' | u32 header length | header JSON | frames...
    frame = u32 length | payload  (payload = AES-256-GCM ciphertext of up to 1 MiB, or plaintext when unencrypted)

The plaintext stream is gzip-compressed JSON lines: one `begin` record, then per table a `table` record
followed by its rows, then an `end` record with per-table row counts. Encryption follows the STREAM
construction: nonce = 7-byte random prefix | u32 frame index | final-frame flag, and the SHA-256 of the
header is the associated data. Reordering, dropping, truncating or editing any frame, or editing the header,
fails decryption. A sidecar `<name>.json` holds the manifest (size, SHA-256, counts) so a backup can be
checked and chosen without the database it came from.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import shutil
import sqlite3
import struct
import tempfile
import zlib
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterator

from sqlalchemy import MetaData, create_engine, func, inspect, select, text
from sqlalchemy.engine import Engine

from ..core import crypto
from ..core.config import Settings

log = logging.getLogger('argus.backup')

MAGIC = b'ARGUSBAK'
FORMAT = 1
FRAME = 1 << 20
SUFFIX = '.argus-backup'
CIPHER = 'aes-256-gcm-stream'
SKIP_TABLES = {'alembic_version'}
INSERT_BATCH = 500
ROOT = Path(__file__).resolve().parents[2]


class BackupError(RuntimeError):
    pass


# ---------------------------------------------------------------- keys


def _hkdf(key: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'argus-backup-v1').derive(key)


def encryption_key(settings: Settings) -> tuple[str, bytes | None]:
    """The key new backups are written with: BACKUP_ENCRYPTION_KEY, else one derived from the current data key."""
    if settings.backup_encryption_key:
        return 'backup', crypto._derive(settings.backup_encryption_key)
    ring, current = crypto.key_ring(settings.data_encryption_keys, settings.data_encryption_key)
    if current:
        return f'data:{current}', _hkdf(ring[current])
    return '', None


def decryption_key(settings: Settings, key_id: str, override: str = '') -> bytes:
    if override:
        return crypto._derive(override) if key_id == 'backup' else _hkdf(crypto._derive(override))
    if key_id == 'backup':
        if not settings.backup_encryption_key:
            raise BackupError('this backup was encrypted with BACKUP_ENCRYPTION_KEY; set it (or pass --key) to read it')
        return crypto._derive(settings.backup_encryption_key)
    if key_id.startswith('data:'):
        kid = key_id.split(':', 1)[1]
        ring, _ = crypto.key_ring(settings.data_encryption_keys, settings.data_encryption_key)
        if kid not in ring:
            raise BackupError(f'this backup was encrypted with data key {kid!r}, which is not in DATA_ENCRYPTION_KEY(S)')
        return _hkdf(ring[kid])
    raise BackupError(f'unknown backup key id {key_id!r}')


# ---------------------------------------------------------------- framing


def _nonce(prefix: bytes, index: int, final: bool) -> bytes:
    return prefix + struct.pack('>I', index) + (b'\x01' if final else b'\x00')


class _FrameWriter:
    def __init__(self, fh, header: dict, key: bytes | None):
        self.fh, self.key = fh, key
        self.prefix = base64.b64decode(header['nonce_prefix']) if key else b''
        raw = json.dumps(header, sort_keys=True).encode()
        self.aad = hashlib.sha256(raw).digest()
        fh.write(MAGIC + struct.pack('>I', len(raw)) + raw)
        self.buffer = bytearray()
        self.index = 0

    def write(self, data: bytes) -> None:
        self.buffer += data
        while len(self.buffer) > FRAME:  # strictly greater: the final frame is never empty unless the stream is
            self._emit(bytes(self.buffer[:FRAME]), final=False)
            del self.buffer[:FRAME]

    def close(self) -> None:
        self._emit(bytes(self.buffer), final=True)
        self.buffer.clear()

    def _emit(self, chunk: bytes, final: bool) -> None:
        if self.key:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            chunk = AESGCM(self.key).encrypt(_nonce(self.prefix, self.index, final), chunk, self.aad)
        else:  # unencrypted streams still flag the last frame so truncation is detected
            chunk = (b'\x01' if final else b'\x00') + chunk
        self.fh.write(struct.pack('>I', len(chunk)) + chunk)
        self.index += 1


def read_header(fh) -> tuple[dict, bytes]:
    if fh.read(len(MAGIC)) != MAGIC:
        raise BackupError('not an Argus backup file')
    (length,) = struct.unpack('>I', fh.read(4))
    if length > 65536:
        raise BackupError('corrupt backup header')
    raw = fh.read(length)
    header = json.loads(raw)
    if header.get('format') != FORMAT:
        raise BackupError(f"unsupported backup format {header.get('format')!r}")
    return header, raw


def _frames(fh, header: dict, raw_header: bytes, key: bytes | None) -> Iterator[bytes]:
    aad = hashlib.sha256(raw_header).digest()
    encrypted = header.get('cipher') == CIPHER
    if encrypted and key is None:
        raise BackupError('backup is encrypted and no key is available')
    prefix = base64.b64decode(header['nonce_prefix']) if encrypted else b''
    index = 0
    final_seen = False
    while True:
        size_raw = fh.read(4)
        if not size_raw:
            break
        if final_seen:
            raise BackupError('data after the final frame')
        if len(size_raw) != 4:
            raise BackupError('backup is truncated')
        (size,) = struct.unpack('>I', size_raw)
        if size > FRAME + 64:
            raise BackupError('corrupt frame length')
        chunk = fh.read(size)
        if len(chunk) != size:
            raise BackupError('backup is truncated')
        if encrypted:
            from cryptography.exceptions import InvalidTag
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            plain = None
            for final in (False, True):
                try:
                    plain = AESGCM(key).decrypt(_nonce(prefix, index, final), chunk, aad)
                    final_seen = final
                    break
                except InvalidTag:
                    continue
            if plain is None:
                raise BackupError('backup failed authentication: wrong key, or the file was modified')
            chunk = plain
        else:
            if not chunk or chunk[:1] not in (b'\x00', b'\x01'):
                raise BackupError('corrupt frame')
            chunk, final_seen = chunk[1:], chunk[:1] == b'\x01'
        index += 1
        yield chunk
    if not final_seen:
        raise BackupError('backup is truncated (no final frame)')


def iter_records(path: Path, settings: Settings, key_override: str = '') -> Iterator[dict]:
    with open(path, 'rb') as fh:
        header, raw = read_header(fh)
        key = decryption_key(settings, header.get('key_id', ''), key_override) if header.get('cipher') == CIPHER else None
        inflater = zlib.decompressobj(wbits=31)
        pending = b''
        for chunk in _frames(fh, header, raw, key):
            pending += inflater.decompress(chunk)
            *lines, pending = pending.split(b'\n')
            for line in lines:
                if line:
                    yield json.loads(line)
        pending += inflater.flush()
        for line in pending.split(b'\n'):
            if line:
                yield json.loads(line)


# ---------------------------------------------------------------- value encoding


def _encode(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:  # Argus stores UTC everywhere; SQLite hands values back naive
            value = value.replace(tzinfo=timezone.utc)
        return {'$dt': value.isoformat()}
    if isinstance(value, date):
        return {'$d': value.isoformat()}
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {'$b': base64.b64encode(bytes(value)).decode()}
    if isinstance(value, Decimal):
        return {'$n': str(value)}
    return value


def _decode(value: Any) -> Any:
    if isinstance(value, dict) and len(value) == 1:
        (tag, raw), = value.items()
        if tag == '$dt':
            return datetime.fromisoformat(raw)
        if tag == '$d':
            return date.fromisoformat(raw)
        if tag == '$b':
            return base64.b64decode(raw)
        if tag == '$n':
            return Decimal(raw)
    return value


# ---------------------------------------------------------------- dump


@dataclass
class DumpResult:
    path: Path
    name: str
    size_bytes: int
    sha256: str
    counts: dict[str, int]
    revision: str
    encrypted: bool
    key_id: str
    created_at: str
    manifest: dict = field(default_factory=dict)

    @property
    def rows(self) -> int:
        return sum(self.counts.values())


def current_revision(engine: Engine) -> str:
    if 'alembic_version' not in inspect(engine).get_table_names():
        return ''
    with engine.connect() as conn:
        return conn.execute(text('SELECT version_num FROM alembic_version')).scalar() or ''


def _sqlite_snapshot(engine: Engine, workdir: Path) -> tuple[Engine, Path]:
    """SQLite has no repeatable-read snapshot across statements, so copy the file with the online backup API."""
    fd, name = tempfile.mkstemp(prefix='argus-snapshot-', suffix='.db', dir=workdir)
    os.close(fd)
    copy = Path(name)
    raw = engine.raw_connection()
    try:
        target = sqlite3.connect(str(copy))
        try:
            raw.driver_connection.backup(target)
        finally:
            target.close()
    finally:
        raw.close()
    return create_engine(f'sqlite:///{copy}', future=True), copy


def dump(engine: Engine, settings: Settings, out_dir: Path, *, app_version: str = '') -> DumpResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    free_mb = shutil.disk_usage(out_dir).free // (1024 * 1024)
    if free_mb < settings.backup_min_free_mb:
        raise BackupError(f'only {free_mb} MB free in {out_dir}; BACKUP_MIN_FREE_MB is {settings.backup_min_free_mb}')
    key_id, key = encryption_key(settings)
    created = datetime.now(timezone.utc)
    name = f"argus-{created.strftime('%Y%m%dT%H%M%S')}Z-{secrets.token_hex(3)}{SUFFIX}"
    final_path = out_dir / name
    partial = out_dir / (name + '.partial')
    header = {'format': FORMAT, 'cipher': CIPHER if key else 'none', 'key_id': key_id if key else '',
              'nonce_prefix': base64.b64encode(secrets.token_bytes(7)).decode() if key else '', 'created_at': created.isoformat()}
    source, snapshot = (engine, None)
    if engine.dialect.name == 'sqlite':
        source, snapshot = _sqlite_snapshot(engine, out_dir)
    counts: dict[str, int] = {}
    try:
        revision = current_revision(source)
        with open(partial, 'wb') as fh:
            writer = _FrameWriter(fh, header, key)
            deflater = zlib.compressobj(6, zlib.DEFLATED, 31)

            def emit(record: dict) -> None:
                data = deflater.compress(json.dumps(record, separators=(',', ':'), default=str).encode() + b'\n')
                if data:
                    writer.write(data)

            with source.connect() as conn:
                if source.dialect.name == 'postgresql':
                    conn = conn.execution_options(isolation_level='REPEATABLE READ')
                with conn.begin():
                    if source.dialect.name == 'postgresql':
                        conn.execute(text('SET TRANSACTION READ ONLY'))
                    meta = MetaData()
                    meta.reflect(bind=conn)
                    tables = [t for t in meta.sorted_tables if t.name not in SKIP_TABLES and not t.name.startswith('sqlite_')]
                    emit({'k': 'begin', 'format': FORMAT, 'created_at': created.isoformat(), 'dialect': source.dialect.name,
                          'revision': revision, 'app_version': app_version, 'tables': [t.name for t in tables]})
                    for table in tables:
                        columns = [c.name for c in table.columns]
                        emit({'k': 'table', 'name': table.name, 'columns': columns})
                        order = list(table.primary_key.columns) or []
                        result = conn.execute(select(table).order_by(*order).execution_options(yield_per=1000))
                        n = 0
                        for row in result:
                            emit({'v': [_encode(v) for v in row]})
                            n += 1
                        counts[table.name] = n
                    emit({'k': 'end', 'counts': counts})
            tail = deflater.flush()
            if tail:
                writer.write(tail)
            writer.close()
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(partial, final_path)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    finally:
        if snapshot is not None:
            source.dispose()
            snapshot.unlink(missing_ok=True)
    digest = _sha256(final_path)
    size = final_path.stat().st_size
    manifest = {'name': name, 'format': FORMAT, 'created_at': created.isoformat(), 'size_bytes': size, 'sha256': digest,
                'encrypted': bool(key), 'key_id': key_id if key else '', 'revision': revision, 'dialect': engine.dialect.name,
                'app_version': app_version, 'tables': len(counts), 'rows': sum(counts.values()), 'counts': counts}
    (out_dir / (name + '.json')).write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding='utf-8')
    return DumpResult(final_path, name, size, digest, counts, revision, bool(key), key_id if key else '', created.isoformat(), manifest)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as fh:
        for block in iter(lambda: fh.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------- verify and restore


def verify_file(path: Path, settings: Settings, key_override: str = '') -> dict:
    """Read the whole file: authenticates every frame and checks per-table counts against the end record."""
    sidecar = path.with_name(path.name + '.json')
    if sidecar.is_file():
        expected = json.loads(sidecar.read_text(encoding='utf-8')).get('sha256')
        if expected and expected != _sha256(path):
            raise BackupError('file SHA-256 does not match its manifest')
    begin: dict | None = None
    end: dict | None = None
    seen: dict[str, int] = {}
    current = None
    for record in iter_records(path, settings, key_override):
        kind = record.get('k')
        if kind == 'begin':
            begin = record
        elif kind == 'table':
            current = record['name']
            seen[current] = 0
        elif kind == 'end':
            end = record
        elif 'v' in record:
            if current is None:
                raise BackupError('row before any table record')
            seen[current] += 1
    if begin is None or end is None:
        raise BackupError('backup is incomplete (missing begin or end record)')
    if end.get('counts') != seen:
        raise BackupError('row counts do not match the end record')
    return {'valid': True, 'revision': begin.get('revision', ''), 'created_at': begin.get('created_at'), 'dialect': begin.get('dialect'),
            'tables': len(seen), 'rows': sum(seen.values()), 'counts': seen}


def _alembic(url: str, revision: str) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option('script_location', str(ROOT / 'alembic'))
    previous = os.environ.get('ALEMBIC_DATABASE_URL')
    os.environ['ALEMBIC_DATABASE_URL'] = url
    try:
        command.upgrade(cfg, revision)
    finally:
        if previous is None:
            os.environ.pop('ALEMBIC_DATABASE_URL', None)
        else:
            os.environ['ALEMBIC_DATABASE_URL'] = previous


def _target_engine(url: str) -> Engine:
    if url.startswith('sqlite'):
        engine = create_engine(url, connect_args={'check_same_thread': False, 'timeout': 30}, future=True)
        from sqlalchemy import event

        @event.listens_for(engine, 'connect')
        def _fk(dbapi_connection, _):
            cursor = dbapi_connection.cursor()
            cursor.execute('PRAGMA foreign_keys=ON')
            cursor.close()

        return engine
    return create_engine(url, future=True)


def restore(path: Path, target_url: str, settings: Settings, *, key_override: str = '', upgrade: bool = True) -> dict:
    """Restore into an EMPTY database: recreate the schema at the backup's revision, load every row, bring the
    schema up to the current head, then check counts and every tenant's audit chain."""
    summary = verify_file(path, settings, key_override)  # authenticate everything before touching the target
    engine = _target_engine(target_url)
    try:
        existing = [t for t in inspect(engine).get_table_names() if not t.startswith('sqlite_')]
        if existing:
            raise BackupError(f'target database is not empty ({len(existing)} tables, e.g. {existing[0]}); restore only into an empty database')
        revision = summary.get('revision') or ''
        if revision:
            try:
                _alembic(target_url, revision)
            except Exception as exc:
                raise BackupError(f'could not create the schema at revision {revision} ({type(exc).__name__}: {exc}); '
                                  'restore with the Argus release that took the backup, or a newer one') from exc
        else:
            from ..models import Base

            Base.metadata.create_all(engine)
        meta = MetaData()
        meta.reflect(bind=engine)
        counts: dict[str, int] = {}
        with engine.begin() as conn:
            table = None
            columns: list[str] = []
            batch: list[dict] = []

            def flush() -> None:
                if batch:
                    conn.execute(table.insert(), batch)
                    batch.clear()

            for record in iter_records(path, settings, key_override):
                kind = record.get('k')
                if kind == 'table':
                    flush()
                    name = record['name']
                    if name not in meta.tables:
                        raise BackupError(f'table {name!r} from the backup does not exist in the target schema')
                    table, columns = meta.tables[name], record['columns']
                    missing = [c for c in columns if c not in table.c]
                    if missing:
                        raise BackupError(f'columns {missing} of {name!r} do not exist in the target schema')
                    counts[name] = 0
                elif 'v' in record:
                    batch.append({c: _decode(v) for c, v in zip(columns, record['v'])})
                    counts[table.name] += 1
                    if len(batch) >= INSERT_BATCH:
                        flush()
            flush()
            if engine.dialect.name == 'postgresql':
                _reset_sequences(conn, meta)
        if revision and upgrade:
            _alembic(target_url, 'head')
        return {'restored': True, 'revision': revision, 'tables': len(counts), 'rows': sum(counts.values()), 'counts': counts,
                'checks': check_database(engine, counts)}
    finally:
        engine.dispose()


def _reset_sequences(conn, meta: MetaData) -> None:
    for table in meta.sorted_tables:
        pk = list(table.primary_key.columns)
        try:
            if len(pk) != 1 or pk[0].type.python_type is not int:
                continue
        except NotImplementedError:
            continue
        seq = conn.execute(text('SELECT pg_get_serial_sequence(:t, :c)'), {'t': table.name, 'c': pk[0].name}).scalar()
        if seq:
            # Table and column names come from reflecting the target database, not from input.
            column, name = pk[0].name, table.name
            query = f'SELECT setval(:seq, COALESCE((SELECT MAX("{column}") FROM "{name}"), 1), (SELECT MAX("{column}") FROM "{name}") IS NOT NULL)'  # nosec B608
            conn.execute(text(query), {'seq': seq})


def check_database(engine: Engine, expected: dict[str, int] | None = None) -> dict:
    """Row counts against the backup and the audit chain of every tenant."""
    from sqlalchemy.orm import Session

    from ..core.audit import verify_chain
    from ..models import AuditEntry

    problems: list[str] = []
    meta = MetaData()
    meta.reflect(bind=engine)
    with engine.connect() as conn:
        for name, n in (expected or {}).items():
            actual = conn.execute(select(func.count()).select_from(meta.tables[name])).scalar() or 0
            if actual != n:
                problems.append(f'{name}: {actual} rows, backup has {n}')
    chains: dict[str, dict] = {}
    with Session(engine) as db:
        for tenant_id in db.execute(select(AuditEntry.tenant_id).distinct()).scalars():
            result = verify_chain(db, tenant_id)
            chains[tenant_id] = result
            if not result.get('valid'):
                problems.append(f'audit chain of tenant {tenant_id} breaks at entry {result.get("broken_at")}')
    return {'ok': not problems, 'problems': problems, 'audit_chains': len(chains),
            'audit_entries': sum(c.get('checked', 0) for c in chains.values())}
