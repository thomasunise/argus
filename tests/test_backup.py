"""Backups: encrypted round trip through the API, restore into a fresh database (create_all and Alembic paths),
tamper / truncation / wrong-key detection, empty-target guard, pruning, S3 store, access control, scheduler."""
from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, inspect, select, text

from app.core.config import Settings
from app.models import AuditEntry, Tenant, User
from app.models.ops import BackupRecord
from app.ops import backup as bk
from app.ops import run_backup, schedule_tick
from app.ops.stores import LocalStore
from conftest import ADMIN_EMAIL, ADMIN_PASSWORD, login, wait_job


@pytest.fixture
def settings(settings, tmp_path):
    return settings.model_copy(update={'backup_dir': tmp_path / 'backups', 'backup_min_free_mb': 1})


def _populate(client, headers, other):
    for i in range(3):
        r = client.post('/api/v1/assets', json={'name': f'web-{i}', 'kind': 'host', 'target': f'10.0.0.{i + 10}', 'environment': 'staging'},
                        headers=headers)
        assert r.status_code in (200, 201), r.text
    r = client.post('/api/v1/canaries', json={'kind': 'token', 'label': 'decoy'}, headers=headers)
    assert r.status_code in (200, 201), r.text
    r = other['client'].post('/api/v1/assets', json={'name': 'acme-db', 'kind': 'host', 'target': '10.9.9.9', 'environment': 'production'},
                             headers=other['headers'])
    assert r.status_code in (200, 201), r.text


def _counts(url: str) -> dict[str, int]:
    engine = create_engine(url)
    try:
        from sqlalchemy import MetaData

        meta = MetaData()
        meta.reflect(bind=engine)
        with engine.connect() as conn:
            return {t.name: conn.execute(select(func.count()).select_from(t)).scalar() for t in meta.sorted_tables if t.name != 'alembic_version'}
    finally:
        engine.dispose()


def test_api_backup_restores_into_a_fresh_database(owner, second_tenant, app, settings, tmp_path, db):
    client, headers = owner
    _populate(client, headers, second_tenant)
    started = client.post('/api/v1/ops/backups', headers=headers)
    assert started.status_code == 202, started.text
    job = wait_job(client, headers, started.json()['job_id'], timeout=60)
    assert job['status'] == 'completed', job
    result = job['result']
    assert result['encrypted'] and result['stores'] == ['local'] and result['rows'] > 0

    listing = client.get('/api/v1/ops/backups', headers=headers).json()
    assert listing['config']['encrypted'] and listing['config']['key_id'] == 'data:k1'
    assert listing['items'][0]['status'] == 'completed' and listing['items'][0]['name'] == result['name']
    assert listing['last_success_at']

    path = Path(settings.backup_dir) / result['name']
    assert path.is_file() and path.with_name(path.name + '.json').is_file()
    assert b'web-0' not in path.read_bytes()  # encrypted, not just compressed
    summary = bk.verify_file(path, settings)
    assert summary['valid'] and summary['counts']['assets'] == 4 and summary['revision'] == ''

    target = f"sqlite:///{tmp_path / 'restored.db'}"
    restored = bk.restore(path, target, settings)
    assert restored['checks']['ok'], restored['checks']
    assert restored['checks']['audit_chains'] >= 2
    source_url = settings.database_url
    before, after = summary['counts'], _counts(target)
    assert {k: v for k, v in after.items() if k in before} == before

    # The restored database is a working Argus: the owner can sign in and sees the same assets.
    from fastapi.testclient import TestClient

    from app.main import create_app

    restored_app = create_app(settings.model_copy(update={'database_url': target}))
    with TestClient(restored_app) as other_client:
        h = login(other_client, ADMIN_EMAIL, ADMIN_PASSWORD)
        names = {a['name'] for a in other_client.get('/api/v1/assets', headers=h).json()['items']}
        assert {'web-0', 'web-1', 'web-2'} <= names and 'acme-db' not in names
        assert other_client.get('/api/v1/audit/verify', headers=h).json()['valid'] is True
    restored_app.state.engine.dispose()
    assert source_url != target


def test_restore_runs_alembic_from_the_backup_revision(tmp_path):
    source_url = f"sqlite:///{tmp_path / 'source.db'}"
    bk._alembic(source_url, 'head')
    s = Settings(database_url=source_url, backup_dir=tmp_path / 'b', backup_min_free_mb=1, data_encryption_key='k-test', db_auto_create=False,
                 session_secret='x' * 40, admin_password='y' * 20)
    engine = create_engine(source_url)
    head = bk.current_revision(engine)
    assert head
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO tenants (id, slug, name, is_active, actions_enabled, settings_json, created_at) "
                          "VALUES ('t1', 'one', 'One', 1, 0, '{}', '2026-10-01 00:00:00.000000')"))
    result = bk.dump(engine, s, s.backup_dir)
    engine.dispose()
    assert result.revision == head and result.counts['tenants'] == 1
    target = f"sqlite:///{tmp_path / 'target.db'}"
    restored = bk.restore(result.path, target, s)
    assert restored['revision'] == head and restored['checks']['ok']
    check = create_engine(target)
    with check.connect() as conn:
        assert conn.execute(text('SELECT version_num FROM alembic_version')).scalar() == head
        assert conn.execute(text("SELECT slug FROM tenants WHERE id = 't1'")).scalar() == 'one'
    check.dispose()


def _small_backup(tmp_path, **overrides) -> tuple[Settings, Path]:
    url = f"sqlite:///{tmp_path / 'small.db'}"
    s = Settings(**({'database_url': url, 'backup_dir': tmp_path / 'b', 'backup_min_free_mb': 1, 'session_secret': 'x' * 40,
                     'admin_password': 'y' * 20, 'data_encryption_key': ''} | overrides))
    engine = create_engine(url)
    from app.models import Base

    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        for i in range(50):
            conn.execute(text(f"INSERT INTO tenants (id, slug, name, is_active, actions_enabled, settings_json, created_at) "
                              f"VALUES ('t{i}', 's{i}', '{'n' * 200}', 1, 0, '{{}}', '2026-10-01 00:00:00')"))
    path = bk.dump(engine, s, s.backup_dir).path
    engine.dispose()
    return s, path


def test_tampering_truncation_and_wrong_key_are_detected(tmp_path):
    s, path = _small_backup(tmp_path, backup_encryption_key='first-key')
    assert bk.verify_file(path, s)['counts']['tenants'] == 50
    data = bytearray(path.read_bytes())
    path.with_name(path.name + '.json').unlink()  # check the cipher itself, not only the manifest hash

    flipped = tmp_path / 'flipped.argus-backup'
    data_flip = bytearray(data)
    data_flip[-20] ^= 0x01
    flipped.write_bytes(bytes(data_flip))
    with pytest.raises(bk.BackupError, match='authentication'):
        bk.verify_file(flipped, s)

    truncated = tmp_path / 'truncated.argus-backup'
    truncated.write_bytes(bytes(data[:-5]))
    with pytest.raises(bk.BackupError, match='truncated'):
        bk.verify_file(truncated, s)

    with pytest.raises(bk.BackupError, match='authentication'):
        bk.verify_file(path, s.model_copy(update={'backup_encryption_key': 'other-key'}))
    with pytest.raises(bk.BackupError, match='BACKUP_ENCRYPTION_KEY'):
        bk.verify_file(path, s.model_copy(update={'backup_encryption_key': ''}))
    assert bk.verify_file(path, s.model_copy(update={'backup_encryption_key': ''}), key_override='first-key')['valid']

    header = tmp_path / 'header.argus-backup'
    data_header = bytearray(data)
    data_header[30] ^= 0x01  # inside the header JSON (it is the associated data of every frame)
    header.write_bytes(bytes(data_header))
    with pytest.raises(Exception):
        bk.verify_file(header, s)


def test_unencrypted_backup_still_detects_truncation(tmp_path):
    s, path = _small_backup(tmp_path)
    assert bk.read_header(open(path, 'rb'))[0]['cipher'] == 'none'
    assert bk.verify_file(path, s)['valid']
    path.with_name(path.name + '.json').unlink()
    path.write_bytes(path.read_bytes()[:-3])
    with pytest.raises(bk.BackupError, match='truncated'):
        bk.verify_file(path, s)


def test_restore_refuses_a_database_that_is_not_empty(tmp_path):
    s, path = _small_backup(tmp_path, backup_encryption_key='k')
    with pytest.raises(bk.BackupError, match='not empty'):
        bk.restore(path, s.database_url, s)


def test_free_space_guard(tmp_path):
    with pytest.raises(bk.BackupError, match='BACKUP_MIN_FREE_MB'):
        _small_backup(tmp_path, backup_min_free_mb=10 ** 9)


def test_local_prune_keeps_the_newest(tmp_path):
    store = LocalStore(tmp_path)
    names = [f'argus-2026100{i}T000000Z-abc123{bk.SUFFIX}' for i in range(1, 6)]
    for name in names:
        (tmp_path / name).write_bytes(b'x')
        (tmp_path / (name + '.json')).write_text('{}')
    (tmp_path / 'unrelated.txt').write_text('keep me')
    assert store.prune(2) == names[:3]
    assert sorted(store.names()) == names[3:]
    assert (tmp_path / 'unrelated.txt').exists() and not (tmp_path / (names[0] + '.json')).exists()
    with pytest.raises(ValueError):
        store.fetch('../etc/passwd', tmp_path)


class _FakeS3:
    objects: dict[str, bytes] = {}

    def upload_file(self, filename, bucket, key):
        self.objects[f'{bucket}/{key}'] = Path(filename).read_bytes()

    def list_objects_v2(self, Bucket, Prefix, ContinuationToken=None):
        keys = sorted(k.split('/', 1)[1] for k in self.objects if k.startswith(f'{Bucket}/{Prefix}'))
        return {'Contents': [{'Key': k} for k in keys], 'IsTruncated': False}

    def download_file(self, bucket, key, filename):
        Path(filename).write_bytes(self.objects[f'{bucket}/{key}'])

    def delete_object(self, Bucket, Key):
        self.objects.pop(f'{Bucket}/{Key}', None)


def test_s3_copy_and_prune(app, client, settings, monkeypatch, tmp_path):
    _FakeS3.objects = {}
    monkeypatch.setitem(sys.modules, 'boto3', types.SimpleNamespace(client=lambda name: _FakeS3()))
    s = settings.model_copy(update={'backup_s3_bucket': 'bk', 'backup_s3_prefix': 'argus/', 'backup_keep': 2})
    results = [run_backup(app.state.db_factory, app.state.engine, s, trigger='cli') for _ in range(3)]
    assert all(r['stores'] == ['local', 's3'] for r in results)
    keys = sorted(_FakeS3.objects)
    assert len(keys) == 4 and all(k.startswith('bk/argus/argus-') for k in keys)  # 2 backups + 2 manifests
    assert results[0]['name'] in results[2]['pruned']['s3'] and results[0]['name'] in results[2]['pruned']['local']
    from app.ops.stores import S3Store

    fetched = S3Store('bk', 'argus/').fetch(results[2]['name'], tmp_path / 'dl')
    assert bk.verify_file(fetched, s)['valid']


def test_failed_upload_marks_the_record_failed(app, client, settings, monkeypatch, db):
    class Broken(_FakeS3):
        def upload_file(self, *a):
            raise ConnectionError('s3 is down')

    monkeypatch.setitem(sys.modules, 'boto3', types.SimpleNamespace(client=lambda name: Broken()))
    s = settings.model_copy(update={'backup_s3_bucket': 'bk'})
    with pytest.raises(bk.BackupError, match='upload to s3 failed'):
        run_backup(app.state.db_factory, app.state.engine, s)
    record = db.execute(select(BackupRecord).order_by(BackupRecord.started_at.desc())).scalars().first()
    assert record.status == 'failed' and 's3 is down' in record.error and record.stores_json == '["local"]'
    actions = set(db.execute(select(AuditEntry.action)).scalars())
    assert 'ops.backup.failed' in actions


def test_only_the_platform_owner_can_see_or_start_backups(owner, second_tenant, api_key, client, make_user):
    other = second_tenant
    assert other['client'].get('/api/v1/ops/backups', headers=other['headers']).status_code == 403
    assert other['client'].post('/api/v1/ops/backups', headers=other['headers']).status_code == 403
    assert client.get('/api/v1/ops/backups', headers={'Authorization': f'Bearer {api_key}'}).status_code == 403
    make_user('admin2@test.local', 'admin2-password-long-1234', 'admin')
    from fastapi.testclient import TestClient

    admin_client = TestClient(client.app)  # no context manager: the app's lifespan is already running
    h = login(admin_client, 'admin2@test.local', 'admin2-password-long-1234')
    assert admin_client.get('/api/v1/ops/backups', headers=h).status_code == 403  # admin, not owner
    c, h = owner
    assert c.get('/api/v1/ops/backups', headers=h).status_code == 200


def test_scheduler_enqueues_once_per_interval(owner, app, db):
    client, headers = owner
    import asyncio

    app.state.settings.backup_enabled = True
    app.state.settings.retention_enabled = True
    try:
        first = asyncio.run(schedule_tick(app))
        assert len(first) == 2  # one backup, one retention run for the only tenant
        for job_id in first:
            assert wait_job(client, headers, job_id, timeout=60)['status'] == 'completed'
        again = asyncio.run(schedule_tick(app))
        assert again == []
        db.expire_all()
        assert db.scalar(select(func.count()).select_from(BackupRecord).where(BackupRecord.status == 'completed')) == 1
        tenant = db.get(Tenant, app.state.default_tenant_id)
        assert 'retention_state' in tenant.settings_json
    finally:
        app.state.settings.backup_enabled = False
        app.state.settings.retention_enabled = False


DRILL_URL = os.getenv('BACKUP_DRILL_DATABASE_URL', '')


@pytest.mark.skipif(not DRILL_URL.startswith('postgresql'), reason='set BACKUP_DRILL_DATABASE_URL to a PostgreSQL server URL')
def test_postgres_backup_and_restore_drill(tmp_path):
    """CI drill: migrate a real PostgreSQL database, fill it through the app, back it up, restore it into a second
    database with Alembic, and check counts, sequences and audit chains."""
    import secrets

    from fastapi.testclient import TestClient

    from app.main import create_app

    admin = create_engine(DRILL_URL, isolation_level='AUTOCOMMIT')
    suffix = secrets.token_hex(4)
    source_db, target_db = f'argus_drill_src_{suffix}', f'argus_drill_dst_{suffix}'
    base = DRILL_URL.rsplit('/', 1)[0]
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE {source_db}'))
        conn.execute(text(f'CREATE DATABASE {target_db}'))
    try:
        source_url, target_url = f'{base}/{source_db}', f'{base}/{target_db}'
        bk._alembic(source_url, 'head')
        s = Settings(database_url=source_url, db_auto_create=False, backup_dir=tmp_path / 'b', backup_min_free_mb=1,
                     data_encryption_key='drill-data-key', audit_signing_key='drill-signing-key', session_secret='s' * 40,
                     admin_email=ADMIN_EMAIL, admin_password=ADMIN_PASSWORD, ai_provider='none', metrics_enabled=False,
                     intel_enrichment_enabled=False, scan_root=tmp_path / 'repos')
        application = create_app(s)
        with TestClient(application) as c:
            h = login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
            for i in range(5):
                assert c.post('/api/v1/assets', json={'name': f'pg-{i}', 'kind': 'host', 'target': f'10.1.0.{i}', 'environment': 'staging'},
                              headers=h).status_code in (200, 201)
            result = run_backup(application.state.db_factory, application.state.engine, s, trigger='cli')
        application.state.engine.dispose()
        path = Path(s.backup_dir) / result['name']
        restored = bk.restore(path, target_url, s)
        assert restored['checks']['ok'], restored['checks']
        assert restored['revision'] and restored['counts']['assets'] == 5
        # The audit id sequence continues after the restored rows instead of colliding with them.
        restored_app = create_app(s.model_copy(update={'database_url': target_url}))
        with TestClient(restored_app) as c:
            h = login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
            assert c.post('/api/v1/assets', json={'name': 'after', 'kind': 'host', 'target': '10.1.1.1', 'environment': 'staging'},
                          headers=h).status_code in (200, 201)
            assert c.get('/api/v1/audit/verify', headers=h).json()['valid'] is True
        restored_app.state.engine.dispose()
    finally:
        with admin.connect() as conn:
            for name in (source_db, target_db):
                conn.execute(text(f'DROP DATABASE IF EXISTS {name} WITH (FORCE)'))
        admin.dispose()


def test_users_and_encrypted_columns_survive_byte_for_byte(owner, app, settings, tmp_path, db):
    user = db.execute(select(User).where(User.email == ADMIN_EMAIL)).scalar_one()
    user.totp_secret = 'JBSWY3DPEHPK3PXP'  # EncryptedText: stored as an enc:v1: envelope
    db.commit()
    result = run_backup(app.state.db_factory, app.state.engine, settings, trigger='cli')
    target = f"sqlite:///{tmp_path / 'r.db'}"
    bk.restore(Path(settings.backup_dir) / result['name'], target, settings)
    src = create_engine(settings.database_url)
    dst = create_engine(target)
    query = text('SELECT email, password_hash, totp_secret FROM users ORDER BY email')
    with src.connect() as a, dst.connect() as b:
        assert a.execute(query).all() == b.execute(query).all()
    with dst.connect() as b:
        assert b.execute(text("SELECT totp_secret FROM users WHERE totp_secret != ''")).scalar().startswith('enc:v1:')
    src.dispose()
    dst.dispose()
    assert 'users' in inspect(create_engine(target)).get_table_names()
    assert db.execute(select(User).where(User.email == ADMIN_EMAIL)).scalar_one()
