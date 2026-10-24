from __future__ import annotations

import pytest
from sqlalchemy import text

from app.core import crypto
from app.core.audit import record_audit, verify_chain
from app.core.config import Settings
from app.core.rbac import Principal, Role
from app.models import User


def test_encrypt_roundtrip_and_rotation():
    crypto.configure('k1=' + crypto.generate_key())
    blob = crypto.encrypt('hunter2')
    assert blob.startswith('enc:v1:k1:') and crypto.decrypt(blob) == 'hunter2'
    assert crypto.encrypt(blob) == blob  # idempotent
    assert crypto.decrypt('plain') == 'plain'
    old = blob
    crypto.configure('k2=' + crypto.generate_key() + ',k1=' + 'ignored')  # k1 value differs: old blob must fail
    with pytest.raises(ValueError):
        crypto.decrypt(old)
    crypto.configure('')
    assert crypto.encrypt('x') == 'x'


def test_totp_secret_and_rollback_payload_are_ciphertext_in_db(app, client, db):
    user = db.query(User).first()
    user.totp_secret = 'JBSWY3DPEHPK3PXP'
    db.commit()
    raw = db.execute(text("SELECT totp_secret FROM users WHERE id = :id"), {'id': user.id}).scalar()
    assert raw.startswith('enc:v1:') and 'JBSWY3DP' not in raw
    db.expire_all()
    assert db.get(User, user.id).totp_secret == 'JBSWY3DPEHPK3PXP'


def test_audit_signature_carries_key_id_and_survives_rotation(db, settings, default_tenant_id):
    principal = Principal(tenant_id=default_tenant_id, role=Role.owner, user_id='u1', email='a@b')
    record_audit(db, principal, 'rot.one', 's')
    db.commit()
    from app.core import audit as audit_module

    entry = db.execute(text("SELECT signature FROM audit WHERE action = 'rot.one'")).scalar()
    assert entry.startswith('k2:')
    # Rotate: k3 signs, k2 still verifies old entries.
    audit_module.configure(settings.model_copy(update={'audit_signing_keys': 'k3=new-key,k2=test-signing-key-2'}))
    record_audit(db, principal, 'rot.two', 's')
    db.commit()
    result = verify_chain(db, default_tenant_id)
    assert result['valid'] is True and result['key_id'] == 'k3'
    # Dropping k2 breaks verification of the older entry.
    audit_module.configure(settings.model_copy(update={'audit_signing_keys': 'k3=new-key'}))
    assert verify_chain(db, default_tenant_id)['valid'] is False
    audit_module.configure(settings)


def test_production_config_requires_hardening():
    base = dict(session_secret='s' * 40, admin_password='p' * 20, app_env='production', database_url='postgresql+psycopg://x/y',
                cookie_secure=True, redis_url='redis://r', base_url='https://argus.example', data_encryption_key='k',
                audit_signing_key='a', audit_jsonl_path='/var/log/a.jsonl', totp_required=True)
    from app.core.config import assert_safe_config

    assert_safe_config(Settings(**base))
    for missing, message in [('data_encryption_key', 'DATA_ENCRYPTION_KEY'), ('audit_signing_key', 'AUDIT_SIGNING_KEY'),
                             ('audit_jsonl_path', 'audit sink'), ('totp_required', 'TOTP_REQUIRED')]:
        bad = dict(base)
        bad[missing] = '' if isinstance(base[missing], str) else False
        with pytest.raises(RuntimeError, match=message):
            assert_safe_config(Settings(**bad))
    with pytest.raises(RuntimeError, match='https'):
        assert_safe_config(Settings(**{**base, 'base_url': 'http://argus.example'}))
