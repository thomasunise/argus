"""Testing-harness tables: scopes, plans, runs and results.

A TestScope is the authorization envelope (which assets, which tiers, which environments,
rate/time-window limits). A TestPlan binds adapters to a scope. A TestRun records one
adapter executing against one asset; TestResult rows link the run to the findings it
produced. Every table is tenant scoped; queries go through core.db.scoped().
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, UTCDateTime, uid, utcnow

TIERS = ('passive', 'active', 'intrusive')
RUN_STATUSES = ('queued', 'running', 'completed', 'failed', 'denied')


class TestScope(TenantMixin, Base):
    __test__ = False  # not a pytest test class
    __tablename__ = 'test_scopes'
    __table_args__ = (Index('ix_test_scopes_tenant_name', 'tenant_id', 'name'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120))
    asset_ids_json: Mapped[str] = mapped_column(Text, default='[]')
    allowed_tiers_json: Mapped[str] = mapped_column(Text, default='["passive"]')
    environments_json: Mapped[str] = mapped_column(Text, default='[]')  # empty = any environment the asset already has
    window_start: Mapped[str] = mapped_column(String(5), default='')  # UTC "HH:MM"; empty = no window
    window_end: Mapped[str] = mapped_column(String(5), default='')
    max_rps: Mapped[float] = mapped_column(Float, default=5.0)
    max_concurrency: Mapped[int] = mapped_column(Integer, default=1)
    signed_document_ref: Mapped[str] = mapped_column(String(512), default='')
    created_by: Mapped[str] = mapped_column(String(36), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class TestPlan(TenantMixin, Base):
    __test__ = False  # not a pytest test class
    __tablename__ = 'test_plans'
    __table_args__ = (Index('ix_test_plans_tenant_enabled', 'tenant_id', 'enabled'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120))
    scope_id: Mapped[str] = mapped_column(String(36), ForeignKey('test_scopes.id'), index=True)
    adapters_json: Mapped[str] = mapped_column(Text, default='[]')
    params_json: Mapped[str] = mapped_column(Text, default='{}')
    schedule_minutes: Mapped[int | None] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(36), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class TestRun(TenantMixin, Base):
    __test__ = False  # not a pytest test class
    __tablename__ = 'test_runs'
    __table_args__ = (Index('ix_test_runs_tenant_created', 'tenant_id', 'created_at'),
                      Index('ix_test_runs_asset', 'tenant_id', 'asset_id'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    plan_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('test_plans.id'))
    scope_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('test_scopes.id'))
    adapter: Mapped[str] = mapped_column(String(40))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey('assets.id'), index=True)
    tier: Mapped[str] = mapped_column(String(12), default='passive')
    status: Mapped[str] = mapped_column(String(12), default='queued')
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default='')
    job_id: Mapped[str] = mapped_column(String(36), default='')
    stats_json: Mapped[str] = mapped_column(Text, default='{}')
    triggered_by: Mapped[str] = mapped_column(String(64), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class TestResult(TenantMixin, Base):
    __test__ = False  # not a pytest test class
    __tablename__ = 'test_results'
    __table_args__ = (Index('ix_test_results_run', 'tenant_id', 'run_id'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    run_id: Mapped[str] = mapped_column(String(36), ForeignKey('test_runs.id'), index=True)
    finding_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('findings.id'))
    rule: Mapped[str] = mapped_column(String(160), default='')
    title: Mapped[str] = mapped_column(String(240), default='')
    severity: Mapped[str] = mapped_column(String(16), default='medium')
    evidence_json: Mapped[str] = mapped_column(Text, default='{}')
    raw_hash: Mapped[str] = mapped_column(String(64), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
