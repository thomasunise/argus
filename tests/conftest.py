"""Shared fixtures. Every test runs against a fresh SQLite database with the in-memory queue.

Fixtures:
  settings       Settings for the test app
  app            FastAPI app (lifespan managed by `client`)
  client         TestClient, unauthenticated
  owner          (client, headers) logged in as the bootstrap owner of the default tenant
  authed         alias of owner for older tests
  second_tenant  dict(tenant_id, slug, headers, email) a separate tenant with its own owner session on a separate client
  api_key        plaintext operator API key for the default tenant
  ingest_key     plaintext ingest-scoped API key for the default tenant
  db             a Session bound to the test database
  wait_job(client, headers, job_id) and wait_for(predicate) helpers for queued work
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

os.environ.setdefault('SENTINEL_LAZY_APP', '1')
os.environ['ADMIN_PASSWORD'] = 'test-password-very-long-123456'
os.environ['ADMIN_EMAIL'] = 'admin@test.local'
os.environ['SESSION_SECRET'] = 'session-secret-testing-longer-than-32-characters'
os.environ['INGEST_API_KEY'] = 'ingest-key-testing-longer-than-24-characters'
os.environ.pop('AI_PROVIDER', None)
os.environ.pop('REDIS_URL', None)

from app.core.config import Settings  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Membership, Tenant, User  # noqa: E402

ADMIN_EMAIL = 'admin@test.local'
ADMIN_PASSWORD = 'test-password-very-long-123456'


TEST_DATABASE_URL = os.getenv('TEST_DATABASE_URL', '')
TEST_REDIS_URL = os.getenv('TEST_REDIS_URL', '')


@pytest.fixture
def settings(tmp_path) -> Settings:
    database_url = TEST_DATABASE_URL or f'sqlite:///{tmp_path}/test.db'
    return Settings(database_url=database_url, redis_url=TEST_REDIS_URL, scan_root=tmp_path / 'repos', autoscan_enabled=False,
                    enable_trivy=False, ai_provider='none', allow_private_targets=False, metrics_enabled=False,
                    audit_jsonl_path=str(tmp_path / 'audit.jsonl'), audit_signing_keys='k2=test-signing-key-2,k1=test-signing-key',
                    data_encryption_key='test-data-encryption-key', app_env='development', secret_env_allowlist='*', secrets_dir=tmp_path / 'secrets',
                    workers_inprocess=True, worker_concurrency=2, actions_kill_switch=False)


@pytest.fixture
def app(settings):
    application = create_app(settings)
    if TEST_DATABASE_URL:
        # Shared external database: start every test from empty tables.
        from app.models import Base

        Base.metadata.drop_all(application.state.engine)
        Base.metadata.create_all(application.state.engine)
    if TEST_REDIS_URL:
        import redis as _redis

        _redis.from_url(TEST_REDIS_URL).flushdb()
    yield application
    if TEST_DATABASE_URL:
        application.state.engine.dispose()


@pytest.fixture
def client(app):
    with TestClient(app) as client:
        yield client


def login(client: TestClient, email: str, password: str, tenant: str = '') -> dict:
    response = client.post('/api/v1/auth/login', json={'email': email, 'password': password, 'tenant': tenant})
    assert response.status_code == 200, response.text
    return {'X-CSRF-Token': response.json()['csrf']}


@pytest.fixture
def owner(client):
    return client, login(client, ADMIN_EMAIL, ADMIN_PASSWORD)


@pytest.fixture
def authed(owner):
    return owner


@pytest.fixture
def db(app):
    session = app.state.db_factory()
    try:
        yield session
        session.commit()
    finally:
        session.close()


@pytest.fixture
def default_tenant_id(app, client) -> str:
    return app.state.default_tenant_id


@pytest.fixture
def second_tenant(app, client):
    """A second tenant with its own owner, logged in on a separate client so cookies do not mix."""
    with app.state.db_factory() as db:
        tenant = Tenant(slug='acme', name='Acme Corp')
        db.add(tenant)
        db.flush()
        user = User(email='owner@acme.test', display_name='Acme Owner', password_hash=hash_password('acme-password-long-123456'))
        db.add(user)
        db.flush()
        db.add(Membership(user_id=user.id, tenant_id=tenant.id, role='owner'))
        db.commit()
        tenant_id = tenant.id
    other = TestClient(app)
    headers = login(other, 'owner@acme.test', 'acme-password-long-123456')
    return {'tenant_id': tenant_id, 'slug': 'acme', 'client': other, 'headers': headers, 'email': 'owner@acme.test'}


@pytest.fixture
def make_user(app):
    """Factory: make_user(email, password, role, tenant_id=None) -> user id. Default tenant unless given."""

    def factory(email: str, password: str, role: str, tenant_id: str | None = None) -> str:
        with app.state.db_factory() as db:
            tid = tenant_id or app.state.default_tenant_id
            user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
            if not user:
                user = User(email=email, display_name=email.split('@')[0], password_hash=hash_password(password))
                db.add(user)
                db.flush()
            db.add(Membership(user_id=user.id, tenant_id=tid, role=role))
            db.commit()
            return user.id

    return factory


@pytest.fixture
def api_key(owner) -> str:
    client, headers = owner
    response = client.post('/api/v1/auth/api-keys', json={'name': 'ops', 'role': 'operator'}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()['key']


@pytest.fixture
def ingest_key(owner) -> str:
    client, headers = owner
    response = client.post('/api/v1/auth/api-keys', json={'name': 'sensor', 'role': 'viewer', 'scopes': ['ingest']}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()['key']


def wait_job(client: TestClient, headers: dict, job_id: str, timeout: float = 20) -> dict:
    """Poll the ops endpoint until a queue job is terminal. Workers run on the app loop thread."""
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        response = client.get(f'/api/v1/ops/jobs/{job_id}', headers=headers)
        assert response.status_code == 200, response.text
        job = response.json()
        if job['status'] in {'completed', 'failed', 'cancelled'}:
            return job
        time.sleep(0.05)
    raise AssertionError(f'job {job_id} did not finish in {timeout}s')


def wait_for(predicate, timeout: float = 20, interval: float = 0.05):
    """Poll predicate() until truthy. Returns its value."""
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError('condition not met in time')
