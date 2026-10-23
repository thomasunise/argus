import os
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

os.environ['ADMIN_PASSWORD']='test-password-very-long-123456'
os.environ['SESSION_SECRET']='session-secret-testing-longer-than-32-characters'
os.environ['INGEST_API_KEY']='ingest-key-testing-longer-than-24-characters'

from app.config import get_settings
from app.main import create_app


@pytest.fixture
def client(tmp_path):
    settings = replace(get_settings(), database_url=f'sqlite:///{tmp_path}/test.db',
                       scan_root=tmp_path / 'repos', autoscan_enabled=False, enable_trivy=False,
                       ai_provider='none', allow_private_targets=False)
    app = create_app(settings)
    with TestClient(app) as client:
        yield client


@pytest.fixture
def authed(client):
    login=client.post('/api/login', json={'password':'test-password-very-long-123456'})
    assert login.status_code == 200, login.text
    token=login.json()['csrf']
    return client, {'X-CSRF-Token':token}
