"""Action-broker tables: requests, approvals and runs.

An ActionRequest is a proposal to change the estate (typed action + params). It is the only
thing an agent can create. ActionApproval rows record human decisions; ActionRun rows record
each execution or rollback attempt with the (redacted) payload needed to undo it. Every
table is tenant scoped; queries go through core.db.scoped().
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, uid, utcnow

REQUEST_STATUSES = ('pending', 'approved', 'rejected', 'executing', 'executed', 'failed', 'rolled_back', 'cancelled', 'auto_approved')
RUN_STATUSES = ('queued', 'running', 'executed', 'failed', 'rolled_back', 'rollback_failed')
RISKS = ('low', 'medium', 'high', 'critical')
EXECUTABLE_STATUSES = ('approved', 'auto_approved')
OPEN_STATUSES = ('pending', 'approved', 'auto_approved')


class ActionRequest(TenantMixin, Base):
    __tablename__ = 'action_requests'
    __table_args__ = (Index('ix_action_requests_tenant_status', 'tenant_id', 'status'),
                      Index('ix_action_requests_tenant_created', 'tenant_id', 'created_at'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    action_type: Mapped[str] = mapped_column(String(80), index=True)
    params_json: Mapped[str] = mapped_column(Text, default='{}')
    reason: Mapped[str] = mapped_column(Text, default='')
    risk: Mapped[str] = mapped_column(String(10), default='medium')
    status: Mapped[str] = mapped_column(String(16), default='pending')
    requested_by: Mapped[str] = mapped_column(String(64), default='')  # user id, api_key:<id> or system
    requested_by_role: Mapped[str] = mapped_column(String(16), default='')
    agent_run_id: Mapped[str | None] = mapped_column(String(36))
    finding_id: Mapped[str | None] = mapped_column(String(36))
    detection_id: Mapped[str | None] = mapped_column(String(36))
    dry_run_json: Mapped[str] = mapped_column(Text, default='{}')
    policy_json: Mapped[str] = mapped_column(Text, default='{}')  # the PolicyDecision taken at request time
    required_approvals: Mapped[int] = mapped_column(Integer, default=1)
    owner_approval_required: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ActionApproval(TenantMixin, Base):
    __tablename__ = 'action_approvals'
    __table_args__ = (Index('ix_action_approvals_request', 'request_id', 'approver_id'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    request_id: Mapped[str] = mapped_column(String(36), ForeignKey('action_requests.id'), index=True)
    approver_id: Mapped[str] = mapped_column(String(64))
    approver_role: Mapped[str] = mapped_column(String(16), default='')
    can_approve_critical: Mapped[bool] = mapped_column(Boolean, default=False)  # held actions:approve_critical when deciding
    decision: Mapped[str] = mapped_column(String(8))  # approve | reject
    comment: Mapped[str] = mapped_column(Text, default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ActionRun(TenantMixin, Base):
    __tablename__ = 'action_runs'
    __table_args__ = (Index('ix_action_runs_tenant_created', 'tenant_id', 'started_at'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    request_id: Mapped[str] = mapped_column(String(36), ForeignKey('action_requests.id'), index=True)
    status: Mapped[str] = mapped_column(String(18), default='queued')
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    result_json: Mapped[str] = mapped_column(Text, default='{}')
    rollback_payload_json: Mapped[str] = mapped_column(Text, default='{}')  # redacted; encryption at rest is out of scope
    error: Mapped[str] = mapped_column(Text, default='')
    executed_by: Mapped[str] = mapped_column(String(64), default='')
    job_id: Mapped[str] = mapped_column(String(36), default='')
    rollback_job_id: Mapped[str] = mapped_column(String(36), default='')
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rolled_back_by: Mapped[str] = mapped_column(String(64), default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
