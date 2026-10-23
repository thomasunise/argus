"""First-run provisioning: default tenant, owner account, bootstrap ingest key."""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ApiKey, Membership, Tenant, User
from .audit import record_audit
from .config import Settings
from .security import hash_api_key, hash_password, parse_api_key, verify_password

log = logging.getLogger('sentinel.bootstrap')


def bootstrap(db: Session, settings: Settings) -> Tenant:
    tenant = db.execute(select(Tenant).where(Tenant.slug == settings.default_tenant_slug)).scalar_one_or_none()
    if not tenant:
        tenant = Tenant(slug=settings.default_tenant_slug, name=settings.default_tenant_name)
        db.add(tenant)
        db.flush()
        record_audit(db, 'system', 'tenant.created', tenant.id, {'slug': tenant.slug}, tenant_id=tenant.id)
    email = settings.admin_email.lower()
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user:
        user = User(email=email, display_name='Administrator', password_hash=hash_password(settings.admin_password))
        db.add(user)
        db.flush()
        record_audit(db, 'system', 'user.created', user.id, {'email': email, 'bootstrap': True}, tenant_id=tenant.id)
    elif settings.admin_password_reset and settings.admin_password and not verify_password(settings.admin_password, user.password_hash):
        # Recovery path for the bootstrap owner, opt-in: otherwise a password rotated through the API would be
        # silently reverted to the environment value on every restart.
        user.password_hash = hash_password(settings.admin_password)
        record_audit(db, 'system', 'user.password_reset', user.id, {'bootstrap': True}, tenant_id=tenant.id)
    membership = db.execute(select(Membership).where(Membership.user_id == user.id, Membership.tenant_id == tenant.id)).scalar_one_or_none()
    if not membership:
        db.add(Membership(user_id=user.id, tenant_id=tenant.id, role='owner'))
    if settings.ingest_api_key:
        prefix = parse_api_key(settings.ingest_api_key)  # format is enforced by assert_safe_config
        key_hash = hash_api_key(settings.ingest_api_key)
        existing = db.execute(select(ApiKey).where(ApiKey.key_hash == key_hash)).scalar_one_or_none()
        if not existing and prefix:
            db.add(ApiKey(tenant_id=tenant.id, name='bootstrap-ingest', prefix=prefix, key_hash=key_hash,
                          role='viewer', scopes='ingest', created_by=user.id))
    db.flush()
    return tenant
