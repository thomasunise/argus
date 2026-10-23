from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, utcnow


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
    previous_hash: Mapped[str] = mapped_column(String(64), default='0' * 64)
    entry_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(64), default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
