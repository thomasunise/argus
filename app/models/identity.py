from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, EncryptedText, UTCDateTime, uid, utcnow


class Tenant(Base):
    __tablename__ = 'tenants'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    settings_json: Mapped[str] = mapped_column(Text, default='{}')
    actions_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class User(Base):
    __tablename__ = 'users'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120), default='')
    password_hash: Mapped[str] = mapped_column(String(512), default='')
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_secret: Mapped[str] = mapped_column(EncryptedText(), default='')
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_last_counter: Mapped[int] = mapped_column(Integer, default=0)  # last accepted time step; a code is never accepted twice
    totp_enrollment_token_hash: Mapped[str] = mapped_column(String(64), default='')
    created_by: Mapped[str] = mapped_column(String(36), default='')
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    sessions_invalidated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class Membership(Base):
    __tablename__ = 'memberships'
    __table_args__ = (UniqueConstraint('user_id', 'tenant_id', name='uq_membership'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey('users.id'), index=True)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey('tenants.id'), index=True)
    role: Mapped[str] = mapped_column(String(16), default='viewer')
    permissions_json: Mapped[str] = mapped_column(Text, default='[]')
    created_by: Mapped[str] = mapped_column(String(36), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class ApiKey(Base):
    __tablename__ = 'api_keys'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey('tenants.id'), index=True)
    name: Mapped[str] = mapped_column(String(120))
    prefix: Mapped[str] = mapped_column(String(16), index=True)
    key_hash: Mapped[str] = mapped_column(String(64))
    role: Mapped[str] = mapped_column(String(16), default='viewer')
    # Comma separated scope strings such as "ingest" or "ingest,findings:read". Empty = role permissions.
    scopes: Mapped[str] = mapped_column(String(512), default='')
    allowed_ips: Mapped[str] = mapped_column(String(512), default='')
    created_by: Mapped[str] = mapped_column(String(36), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class WebAuthnCredential(Base):
    __tablename__ = 'webauthn_credentials'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey('users.id'), index=True)
    credential_id: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    public_key: Mapped[str] = mapped_column(Text)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(120), default='Security Key')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class OidcIdentity(Base):
    __tablename__ = 'oidc_identities'
    __table_args__ = (UniqueConstraint('issuer', 'subject', name='uq_oidc_subject'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey('users.id'), index=True)
    issuer: Mapped[str] = mapped_column(String(256))
    subject: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
