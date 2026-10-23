from __future__ import annotations

from datetime import datetime

from sqlalchemy import Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, UTCDateTime, uid, utcnow

SEVERITIES = ('critical', 'high', 'medium', 'low', 'informational')
FINDING_STATUSES = ('open', 'investigating', 'resolved', 'accepted', 'false_positive')


class Finding(TenantMixin, Base):
    __tablename__ = 'findings'
    __table_args__ = (UniqueConstraint('tenant_id', 'fingerprint', name='uq_finding_fingerprint'),
                      Index('ix_findings_tenant_status', 'tenant_id', 'status'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('assets.id'))
    detection_id: Mapped[str | None] = mapped_column(String(36))
    fingerprint: Mapped[str] = mapped_column(String(64))
    rule: Mapped[str] = mapped_column(String(160), default='')
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text, default='')
    evidence: Mapped[str] = mapped_column(Text, default='{}')
    severity: Mapped[str] = mapped_column(String(16), default='medium')
    status: Mapped[str] = mapped_column(String(18), default='open')
    source: Mapped[str] = mapped_column(String(40))
    cve_ids: Mapped[str] = mapped_column(String(512), default='')  # comma separated
    cvss: Mapped[float | None] = mapped_column(Float)
    epss: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[int] = mapped_column(Integer, default=0)
    assignee: Mapped[str] = mapped_column(String(36), default='')
    tags_json: Mapped[str] = mapped_column(Text, default='[]')
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class SecurityEvent(TenantMixin, Base):
    __tablename__ = 'events'
    __table_args__ = (UniqueConstraint('tenant_id', 'source', 'external_id', name='uq_event_source_external'),
                      Index('ix_events_tenant_received', 'tenant_id', 'received_at'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    source: Mapped[str] = mapped_column(String(30))
    external_id: Mapped[str] = mapped_column(String(128))
    asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('assets.id'))
    severity: Mapped[str] = mapped_column(String(16), default='low')
    category: Mapped[str] = mapped_column(String(40), default='')  # auth, process, network, cloud_api, k8s, code, canary
    actor: Mapped[str] = mapped_column(String(200), default='')     # identity that acted, if known
    entity: Mapped[str] = mapped_column(String(200), default='')    # thing acted upon
    action: Mapped[str] = mapped_column(String(120), default='')
    title: Mapped[str] = mapped_column(String(300))
    metadata_json: Mapped[str] = mapped_column(Text, default='{}')
    occurred_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class ScanRun(TenantMixin, Base):
    """Legacy single-asset scan record. New work goes through testing.TestRun; kept for compatibility."""

    __tablename__ = 'runs'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey('assets.id'))
    scanner: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(16), default='queued')
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default='')
    job_id: Mapped[str] = mapped_column(String(36), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class Investigation(TenantMixin, Base):
    __tablename__ = 'investigations'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey('findings.id'), index=True)
    agent_run_id: Mapped[str | None] = mapped_column(String(36))
    model: Mapped[str] = mapped_column(String(80), default='rules-only')
    summary: Mapped[str] = mapped_column(Text, default='')
    confidence: Mapped[str] = mapped_column(String(8), default='low')
    recommended_steps: Mapped[str] = mapped_column(Text, default='[]')
    limitations: Mapped[str] = mapped_column(Text, default='[]')
    created_by: Mapped[str] = mapped_column(String(64), default='')  # user id or api_key:<id>
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class Approval(TenantMixin, Base):
    """Legacy record-only approval. Executable approvals live in actions.ActionApproval."""

    __tablename__ = 'approvals'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey('findings.id'))
    action: Mapped[str] = mapped_column(String(64))
    rationale: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default='pending')
    requested_by: Mapped[str] = mapped_column(String(36), default='')
    decided_by: Mapped[str] = mapped_column(String(36), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
