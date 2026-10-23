from __future__ import annotations

from datetime import datetime

from sqlalchemy import Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, UTCDateTime, uid, utcnow


class AgentRun(TenantMixin, Base):
    __tablename__ = 'agent_runs'
    __table_args__ = (Index('ix_agent_runs_tenant_created', 'tenant_id', 'created_at'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    spec: Mapped[str] = mapped_column(String(64))
    task: Mapped[str] = mapped_column(Text)
    inputs_json: Mapped[str] = mapped_column(Text, default='{}')
    status: Mapped[str] = mapped_column(String(16), default='queued')  # queued running completed failed cancelled refused budget_exhausted
    provider: Mapped[str] = mapped_column(String(24), default='')
    model: Mapped[str] = mapped_column(String(80), default='')
    output_json: Mapped[str] = mapped_column(Text, default='{}')
    error: Mapped[str] = mapped_column(Text, default='')
    steps_count: Mapped[int] = mapped_column(Integer, default=0)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_estimate_usd: Mapped[float] = mapped_column(Float, default=0.0)
    finding_id: Mapped[str | None] = mapped_column(String(36))
    parent_run_id: Mapped[str | None] = mapped_column(String(36))
    job_id: Mapped[str] = mapped_column(String(36), default='')
    created_by: Mapped[str] = mapped_column(String(64), default="")  # user id or api_key:<id>
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class AgentStep(Base):
    __tablename__ = 'agent_steps'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    run_id: Mapped[str] = mapped_column(String(36), ForeignKey('agent_runs.id'), index=True)
    index: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(12))  # model or tool
    name: Mapped[str] = mapped_column(String(80), default='')
    input_json: Mapped[str] = mapped_column(Text, default='{}')
    output_json: Mapped[str] = mapped_column(Text, default='{}')
    input_hash: Mapped[str] = mapped_column(String(64), default='')
    tokens_in: Mapped[int] = mapped_column(Integer, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class EvalRun(TenantMixin, Base):
    __tablename__ = 'eval_runs'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    suite: Mapped[str] = mapped_column(String(64))
    spec: Mapped[str] = mapped_column(String(64), default='')
    status: Mapped[str] = mapped_column(String(16), default='queued')
    total: Mapped[int] = mapped_column(Integer, default=0)
    passed: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    report_json: Mapped[str] = mapped_column(Text, default='{}')
    created_by: Mapped[str] = mapped_column(String(64), default="")  # user id or api_key:<id>
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
