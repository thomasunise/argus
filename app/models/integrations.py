"""Integration models: inbound/outbound integration configs, outbound deliveries, ingest batches."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, UTCDateTime, uid, utcnow

DELIVERY_STATUSES = ('queued', 'sent', 'failed', 'skipped')


class IntegrationConfig(TenantMixin, Base):
    """One configured integration. `kind` is either an inbound source name (for webhook secrets and
    pull jobs such as the Wazuh indexer sync) or an outbound channel kind. Non-secret settings live in
    config_json; credentials are stored only as references ({field: 'env:NAME' | 'file:/path' |
    'secrets:KEY'}) in secret_refs_json and resolved at send time. topics_json lists the event topics
    an outbound integration subscribes to ('finding.*', 'detection.created', ...)."""

    __tablename__ = 'integration_configs'
    __table_args__ = (Index('ix_integration_configs_tenant_kind', 'tenant_id', 'kind'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(40), index=True)
    config_json: Mapped[str] = mapped_column(Text, default='{}')
    secret_refs_json: Mapped[str] = mapped_column(Text, default='{}')
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    topics_json: Mapped[str] = mapped_column(Text, default='[]')
    min_severity: Mapped[str] = mapped_column(String(16), default='low')
    state_json: Mapped[str] = mapped_column(Text, default='{}')  # cursor state for pull integrations (e.g. last sync time)
    last_delivery_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_error: Mapped[str] = mapped_column(Text, default='')
    created_by: Mapped[str] = mapped_column(String(36), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class WebhookDelivery(TenantMixin, Base):
    """One attempt series to deliver one event to one outbound integration."""

    __tablename__ = 'webhook_deliveries'
    __table_args__ = (Index('ix_webhook_deliveries_tenant_status', 'tenant_id', 'status', 'created_at'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    integration_id: Mapped[str] = mapped_column(String(36), ForeignKey('integration_configs.id'), index=True)
    topic: Mapped[str] = mapped_column(String(80))
    payload_hash: Mapped[str] = mapped_column(String(64), default='')
    payload_json: Mapped[str] = mapped_column(Text, default='{}')
    status: Mapped[str] = mapped_column(String(16), default='queued')  # queued sent failed skipped
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5)
    last_error: Mapped[str] = mapped_column(Text, default='')
    response_code: Mapped[int | None] = mapped_column(Integer)
    external_ref: Mapped[str] = mapped_column(String(200), default='')  # ticket key, incident number, message ts
    job_id: Mapped[str] = mapped_column(String(36), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    next_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class IngestBatch(TenantMixin, Base):
    """Statistics for one call to POST /api/v1/ingest/{source} (or one pull job)."""

    __tablename__ = 'ingest_batches'
    __table_args__ = (Index('ix_ingest_batches_tenant_source', 'tenant_id', 'source', 'created_at'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    source: Mapped[str] = mapped_column(String(40))
    accepted: Mapped[int] = mapped_column(Integer, default=0)
    duplicates: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    error_samples_json: Mapped[str] = mapped_column(Text, default='[]')
    received: Mapped[int] = mapped_column(Integer, default=0)
    api_key_id: Mapped[str] = mapped_column(String(36), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
