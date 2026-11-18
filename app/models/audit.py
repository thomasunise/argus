from __future__ import annotations

from datetime import datetime

from sqlalchemy import Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, UTCDateTime, uid, utcnow


class AuditEntry(Base):
    __tablename__ = 'audit'
    __table_args__ = (Index('ix_audit_tenant_id_id', 'tenant_id', 'id'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default='')
    actor: Mapped[str] = mapped_column(String(200))
    actor_kind: Mapped[str] = mapped_column(String(16), default='user')  # user, api_key, system, scanner, agent
    action: Mapped[str] = mapped_column(String(100))
    subject: Mapped[str] = mapped_column(String(200), default='')
    detail: Mapped[str] = mapped_column(Text, default='{}')
    request_id: Mapped[str] = mapped_column(String(64), default='')
    source_ip: Mapped[str] = mapped_column(String(64), default='')
    user_agent: Mapped[str] = mapped_column(String(256), default='')
    session_id: Mapped[str] = mapped_column(String(64), default='')
    previous_hash: Mapped[str] = mapped_column(String(64), default='0' * 64)
    entry_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(128), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class AuditOutbox(Base):
    """Durable transactional outbox for external WORM and SIEM audit sinks."""

    __tablename__ = 'audit_outbox'
    __table_args__ = (Index('ix_audit_outbox_pending', 'delivered_at', 'next_attempt_at'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default='')
    entry_id: Mapped[int] = mapped_column(Integer, index=True, default=0)
    sink_name: Mapped[str] = mapped_column(String(32))
    payload_json: Mapped[str] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(String(500), default='')
    next_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
