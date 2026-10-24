"""Autonomous-response tables: playbooks and the record of every decision they took.

A ResponsePlaybook maps detections (rule ids, severity, confidence, entity kind) to one typed
action from the broker catalog with a parameter template. An AutoresponseExecution row is
written for every (playbook, detection) pair that matched, whatever the outcome (skipped,
shadow, escalated, enforced, denied, failed), so operators can see what the system did and
what it would have done. Both tables are tenant scoped.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Float, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, UTCDateTime, uid, utcnow

PLAYBOOK_MODES = ('shadow', 'enforce')
EXECUTION_OUTCOMES = ('skipped', 'shadow', 'escalated', 'enforced', 'denied', 'failed')
ROLLBACK_STATES = ('', 'pending', 'kept', 'requested', 'done', 'failed', 'not_needed')


class ResponsePlaybook(TenantMixin, Base):
    __tablename__ = 'response_playbooks'
    __table_args__ = (Index('ix_response_playbooks_tenant_enabled', 'tenant_id', 'enabled'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default='')
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    mode: Mapped[str] = mapped_column(String(8), default='shadow')  # shadow | enforce
    rule_ids_json: Mapped[str] = mapped_column(Text, default='[]')  # empty = any rule
    min_severity: Mapped[str] = mapped_column(String(16), default='high')
    min_confidence: Mapped[float] = mapped_column(Float, default=0.8)
    entity_kind: Mapped[str] = mapped_column(String(32), default='')  # empty = any
    action_type: Mapped[str] = mapped_column(String(80))
    params_template_json: Mapped[str] = mapped_column(Text, default='{}')
    max_per_hour: Mapped[int] = mapped_column(Integer, default=5)
    max_blast_radius: Mapped[int] = mapped_column(Integer, default=1)
    rollback_after_minutes: Mapped[int] = mapped_column(Integer, default=60)  # 0 = never roll back automatically
    allow_high_risk: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(64), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_triggered_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class AutoresponseExecution(TenantMixin, Base):
    __tablename__ = 'autoresponse_executions'
    __table_args__ = (UniqueConstraint('tenant_id', 'playbook_id', 'detection_id', name='uq_autoresponse_playbook_detection'),
                      Index('ix_autoresponse_executions_tenant_created', 'tenant_id', 'created_at'),
                      Index('ix_autoresponse_executions_tenant_rollback', 'tenant_id', 'rollback_state'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    playbook_id: Mapped[str] = mapped_column(String(36), index=True)  # not a foreign key: the history outlives a deleted playbook
    playbook_name: Mapped[str] = mapped_column(String(120), default='')
    detection_id: Mapped[str] = mapped_column(String(36))
    rule_id: Mapped[str] = mapped_column(String(80), default='')
    action_type: Mapped[str] = mapped_column(String(80), default='')
    mode: Mapped[str] = mapped_column(String(8), default='shadow')
    outcome: Mapped[str] = mapped_column(String(16), default='skipped')
    reason: Mapped[str] = mapped_column(Text, default='')
    params_json: Mapped[str] = mapped_column(Text, default='{}')
    dry_run_json: Mapped[str] = mapped_column(Text, default='{}')
    action_request_id: Mapped[str | None] = mapped_column(String(36))
    action_run_id: Mapped[str | None] = mapped_column(String(36))
    rollback_state: Mapped[str] = mapped_column(String(16), default='')
    rollback_due_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    rolled_back_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    kept_by: Mapped[str] = mapped_column(String(64), default='')
    kept_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
