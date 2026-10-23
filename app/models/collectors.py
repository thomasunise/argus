from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, uid, utcnow

RUN_STATUSES = ('queued', 'running', 'completed', 'failed')


class CollectorConfig(TenantMixin, Base):
    """One configured instance of a collector (for example "prod AWS account"). Non-secret
    configuration lives in config_json; credentials are stored only as secret references
    ({field: 'env:NAME' | 'file:/path' | 'secrets:KEY'}) and resolved at run time."""

    __tablename__ = 'collector_configs'
    __table_args__ = (Index('ix_collector_configs_tenant_enabled', 'tenant_id', 'enabled'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120))
    collector: Mapped[str] = mapped_column(String(40), index=True)
    config_json: Mapped[str] = mapped_column(Text, default='{}')
    secret_refs_json: Mapped[str] = mapped_column(Text, default='{}')
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    schedule_minutes: Mapped[int] = mapped_column(Integer, default=0)  # 0 = manual only
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str] = mapped_column(Text, default='')
    created_by: Mapped[str] = mapped_column(String(36), default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectorRun(TenantMixin, Base):
    __tablename__ = 'collector_runs'
    __table_args__ = (Index('ix_collector_runs_tenant_config', 'tenant_id', 'config_id', 'created_at'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    config_id: Mapped[str] = mapped_column(String(36), ForeignKey('collector_configs.id'), index=True)
    status: Mapped[str] = mapped_column(String(16), default='queued')  # queued running completed failed
    stats_json: Mapped[str] = mapped_column(Text, default='{}')
    warnings_json: Mapped[str] = mapped_column(Text, default='[]')
    error: Mapped[str] = mapped_column(Text, default='')
    job_id: Mapped[str] = mapped_column(String(36), default='')
    triggered_by: Mapped[str] = mapped_column(String(36), default='')  # user id, api key id or 'scheduler'
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
