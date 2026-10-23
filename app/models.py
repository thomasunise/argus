from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def uid() -> str:
    return str(uuid4())


class Base(DeclarativeBase):
    pass


class Asset(Base):
    __tablename__ = 'assets'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(24))  # web, repo, cloud, host, database
    target: Mapped[str] = mapped_column(String(512))
    environment: Mapped[str] = mapped_column(String(20), default='production')
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    __tablename__ = 'findings'
    __table_args__ = (UniqueConstraint('fingerprint', name='uq_fingerprint'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('assets.id'))
    fingerprint: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text, default='')
    evidence: Mapped[str] = mapped_column(Text, default='{}')
    severity: Mapped[str] = mapped_column(String(16), default='medium')
    status: Mapped[str] = mapped_column(String(18), default='open')
    source: Mapped[str] = mapped_column(String(40))
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SecurityEvent(Base):
    __tablename__ = 'events'
    __table_args__ = (UniqueConstraint('source', 'external_id', name='uq_event_source_external'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    source: Mapped[str] = mapped_column(String(30))
    external_id: Mapped[str] = mapped_column(String(128))
    asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('assets.id'))
    severity: Mapped[str] = mapped_column(String(16), default='low')
    title: Mapped[str] = mapped_column(String(300))
    # Selected normalized metadata only. Deliberately avoid raw log storage in DB.
    metadata_json: Mapped[str] = mapped_column(Text, default='{}')
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScanRun(Base):
    __tablename__ = 'runs'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey('assets.id'))
    scanner: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(16), default='queued')
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Investigation(Base):
    __tablename__ = 'investigations'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey('findings.id'))
    model: Mapped[str] = mapped_column(String(80), default='rules-only')
    summary: Mapped[str] = mapped_column(Text, default='')
    recommended_steps: Mapped[str] = mapped_column(Text, default='[]')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Approval(Base):
    __tablename__ = 'approvals'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey('findings.id'))
    action: Mapped[str] = mapped_column(String(64))
    rationale: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default='pending')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditEntry(Base):
    __tablename__ = 'audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(100))
    subject: Mapped[str] = mapped_column(String(128), default='')
    detail: Mapped[str] = mapped_column(Text, default='')
    previous_hash: Mapped[str] = mapped_column(String(64), default='0'*64)
    entry_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
