"""Platform operations records. Backups cover the whole database (every tenant), so this table is global and
only the platform owner (an owner of the bootstrap tenant) can read it through the API."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, UTCDateTime, uid, utcnow

BACKUP_STATUSES = ('running', 'completed', 'failed')


class BackupRecord(Base):
    __tablename__ = 'backup_records'
    __table_args__ = (Index('ix_backup_records_started', 'started_at'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120), default='')
    status: Mapped[str] = mapped_column(String(12), default='running')
    trigger: Mapped[str] = mapped_column(String(16), default='manual')  # manual, schedule, cli
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    sha256: Mapped[str] = mapped_column(String(64), default='')
    tables: Mapped[int] = mapped_column(Integer, default=0)
    rows: Mapped[int] = mapped_column(BigInteger, default=0)
    encrypted: Mapped[bool] = mapped_column(default=False)
    key_id: Mapped[str] = mapped_column(String(40), default='')
    revision: Mapped[str] = mapped_column(String(40), default='')
    stores_json: Mapped[str] = mapped_column(Text, default='[]')  # where copies landed, e.g. ["local", "s3"]
    pruned_json: Mapped[str] = mapped_column(Text, default='[]')  # older backups deleted by this run
    error: Mapped[str] = mapped_column(Text, default='')
    requested_by: Mapped[str] = mapped_column(String(200), default='')
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
