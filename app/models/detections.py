"""Detection workstream tables: detections, baselines, canaries, canary hits, per-tenant rule
state and run history. Every table is tenant scoped."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, uid, utcnow

DETECTION_STATUSES = ('open', 'investigating', 'resolved', 'false_positive')
BASELINE_DIMENSIONS = ('actor_rate', 'entity_rate', 'actor_novel_actions', 'action_rate', 'source_rate')
CANARY_KINDS = ('token', 'url', 'credential', 'file', 'dns', 'aws_key', 'api_key', 'document')


class Detection(TenantMixin, Base):
    __tablename__ = 'detections'
    __table_args__ = (UniqueConstraint('tenant_id', 'fingerprint', name='uq_detection_fingerprint'),
                      Index('ix_detections_tenant_status', 'tenant_id', 'status'),
                      Index('ix_detections_tenant_rule', 'tenant_id', 'rule_id'),
                      Index('ix_detections_tenant_last_seen', 'tenant_id', 'last_seen_at'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    rule_id: Mapped[str] = mapped_column(String(80))
    fingerprint: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text, default='')
    severity: Mapped[str] = mapped_column(String(16), default='medium')
    status: Mapped[str] = mapped_column(String(18), default='open')
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    entity: Mapped[str] = mapped_column(String(200), default='')
    entity_kind: Mapped[str] = mapped_column(String(32), default='')  # identity, asset, host, canary, action, source
    evidence_json: Mapped[str] = mapped_column(Text, default='{}')
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    finding_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('findings.id'))
    tags_json: Mapped[str] = mapped_column(Text, default='[]')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Baseline(TenantMixin, Base):
    """Rolling per-window statistics maintained with Welford's online algorithm.

    `variance` is the population variance (M2 / samples). `last_bucket_at` is the start of
    the most recent window folded in, so repeated updates for the same window are idempotent.
    """

    __tablename__ = 'baselines'
    __table_args__ = (UniqueConstraint('tenant_id', 'dimension', 'key', 'window_minutes', name='uq_baseline_key'),
                      Index('ix_baselines_tenant_dimension', 'tenant_id', 'dimension'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    dimension: Mapped[str] = mapped_column(String(32))
    key: Mapped[str] = mapped_column(String(200))
    window_minutes: Mapped[int] = mapped_column(Integer, default=5)
    mean: Mapped[float] = mapped_column(Float, default=0.0)
    variance: Mapped[float] = mapped_column(Float, default=0.0)
    samples: Mapped[int] = mapped_column(Integer, default=0)
    last_value: Mapped[float] = mapped_column(Float, default=0.0)
    last_bucket_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Canary(TenantMixin, Base):
    __tablename__ = 'canaries'
    __table_args__ = (Index('ix_canaries_tenant_kind', 'tenant_id', 'kind'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    kind: Mapped[str] = mapped_column(String(16))
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(120))
    placement: Mapped[str] = mapped_column(Text, default='')
    metadata_json: Mapped[str] = mapped_column(Text, default='{}')
    created_by: Mapped[str] = mapped_column(String(200), default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CanaryHit(TenantMixin, Base):
    __tablename__ = 'canary_hits'
    __table_args__ = (Index('ix_canary_hits_tenant_received', 'tenant_id', 'received_at'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    canary_id: Mapped[str] = mapped_column(String(36), ForeignKey('canaries.id'), index=True)
    source_ip: Mapped[str] = mapped_column(String(64), default='')
    user_agent: Mapped[str] = mapped_column(String(300), default='')
    headers_json: Mapped[str] = mapped_column(Text, default='{}')
    payload_json: Mapped[str] = mapped_column(Text, default='{}')
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DetectionRuleState(TenantMixin, Base):
    """Per-tenant override of a registry rule: enabled flag and parameter overrides."""

    __tablename__ = 'detection_rule_states'
    __table_args__ = (UniqueConstraint('tenant_id', 'rule_id', name='uq_detection_rule_state'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    rule_id: Mapped[str] = mapped_column(String(80))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    params_json: Mapped[str] = mapped_column(Text, default='{}')
    updated_by: Mapped[str] = mapped_column(String(200), default='')
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DetectionRun(TenantMixin, Base):
    """One row per engine run so /stats can report the last run and operators can see errors."""

    __tablename__ = 'detection_runs'
    __table_args__ = (Index('ix_detection_runs_tenant_started', 'tenant_id', 'started_at'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    trigger: Mapped[str] = mapped_column(String(24), default='scheduler')  # scheduler, api, job
    since: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rules_run: Mapped[int] = mapped_column(Integer, default=0)
    detections_created: Mapped[int] = mapped_column(Integer, default=0)
    detections_updated: Mapped[int] = mapped_column(Integer, default=0)
    events_scanned: Mapped[int] = mapped_column(Integer, default=0)
    errors_json: Mapped[str] = mapped_column(Text, default='[]')
