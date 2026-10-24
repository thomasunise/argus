"""Attack-simulator and autonomous-pentest reports. Both live in the real tenant; the simulator's synthetic
data lives (briefly) in a sandbox tenant and is never stored here."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, UTCDateTime, uid, utcnow

SIMULATION_STATUSES = ('queued', 'running', 'completed', 'failed')
AUTOPILOT_STATUSES = ('queued', 'planning', 'running', 'completed', 'failed', 'stopped')


class SimulationRun(TenantMixin, Base):
    __tablename__ = 'simulation_runs'
    __table_args__ = (Index('ix_simulation_runs_tenant_created', 'tenant_id', 'created_at'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    scenarios_json: Mapped[str] = mapped_column(Text, default='[]')
    intensity: Mapped[str] = mapped_column(String(10), default='normal')
    evasion: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(12), default='queued')
    coverage: Mapped[float | None] = mapped_column(Float)
    summary_json: Mapped[str] = mapped_column(Text, default='{}')
    results_json: Mapped[str] = mapped_column(Text, default='[]')
    error: Mapped[str] = mapped_column(Text, default='')
    job_id: Mapped[str] = mapped_column(String(36), default='')
    created_by: Mapped[str] = mapped_column(String(64), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class AutopilotRun(TenantMixin, Base):
    """One autonomous pentest: plan with the red-team specialist, run the scope-checked tests, re-plan from
    what was found, up to `max_rounds`. `steps_json` is the ordered log of decisions and launched test runs."""

    __tablename__ = 'autopilot_runs'
    __table_args__ = (Index('ix_autopilot_runs_tenant_created', 'tenant_id', 'created_at'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    scope_id: Mapped[str] = mapped_column(String(36))
    asset_ids_json: Mapped[str] = mapped_column(Text, default='[]')
    max_tier: Mapped[str] = mapped_column(String(12), default='active')
    max_rounds: Mapped[int] = mapped_column(Integer, default=2)
    status: Mapped[str] = mapped_column(String(12), default='queued')
    rounds_completed: Mapped[int] = mapped_column(Integer, default=0)
    test_runs: Mapped[int] = mapped_column(Integer, default=0)
    findings_new: Mapped[int] = mapped_column(Integer, default=0)
    steps_json: Mapped[str] = mapped_column(Text, default='[]')
    summary_json: Mapped[str] = mapped_column(Text, default='{}')
    error: Mapped[str] = mapped_column(Text, default='')
    stop_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    job_id: Mapped[str] = mapped_column(String(36), default='')
    created_by: Mapped[str] = mapped_column(String(64), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
