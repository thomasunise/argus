"""Discovery tables: one run, and the endpoints/technologies it found.

A Discovery is a fact about one asset (an endpoint, a technology, an open port) with the source
that produced it. Deduplication is per (tenant, asset, kind, value) so repeated runs accumulate
`last_seen` instead of duplicating rows.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, UTCDateTime, uid, utcnow

DISCOVERY_KINDS = ('endpoint', 'technology', 'port', 'secret')
DISCOVERY_STATUSES = ('new', 'queued_for_test', 'tested', 'ignored')
RUN_STATUSES = ('queued', 'running', 'completed', 'failed', 'denied')


class DiscoveryRun(TenantMixin, Base):
    __tablename__ = 'discovery_runs'
    __table_args__ = (Index('ix_discovery_runs_tenant_created', 'tenant_id', 'created_at'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey('assets.id'), index=True)
    scope_id: Mapped[str] = mapped_column(String(36), ForeignKey('test_scopes.id'), index=True)
    status: Mapped[str] = mapped_column(String(12), default='queued')
    discovery_count: Mapped[int] = mapped_column(Integer, default=0)
    follow_up_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default='')
    job_id: Mapped[str] = mapped_column(String(36), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class Discovery(TenantMixin, Base):
    __tablename__ = 'discoveries'
    __table_args__ = (UniqueConstraint('tenant_id', 'asset_id', 'kind', 'value', name='uq_discovery_fact'),
                      Index('ix_discoveries_tenant_status', 'tenant_id', 'status'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey('assets.id'), index=True)
    run_id: Mapped[str] = mapped_column(String(36), ForeignKey('discovery_runs.id'), index=True)
    kind: Mapped[str] = mapped_column(String(16), default='endpoint')
    value: Mapped[str] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(String(64), default='recon')
    confidence: Mapped[str] = mapped_column(String(8), default='medium')
    status: Mapped[str] = mapped_column(String(16), default='new')
    test_run_id: Mapped[str] = mapped_column(String(36), default='')
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class RequestCapture(TenantMixin, Base):
    """One request the browser issued. Method, path, status, and whether auth was present - never bodies or header values."""

    __tablename__ = 'request_captures'
    __table_args__ = (UniqueConstraint('tenant_id', 'asset_id', 'method', 'path', name='uq_capture_request'),
                      Index('ix_captures_tenant_seen', 'tenant_id', 'last_seen'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey('assets.id'), index=True)
    run_id: Mapped[str] = mapped_column(String(36), ForeignKey('discovery_runs.id'))
    scope_id: Mapped[str] = mapped_column(String(36), ForeignKey('test_scopes.id'))
    method: Mapped[str] = mapped_column(String(8), default='GET')
    path: Mapped[str] = mapped_column(String(512))
    status: Mapped[int] = mapped_column(Integer, default=0)
    content_type: Mapped[str] = mapped_column(String(120), default='')
    has_auth: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
