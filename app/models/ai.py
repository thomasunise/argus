"""AI gateway and shadow-AI discovery tables.

AIGatewayRequest is one call proxied through the Argus AI gateway (metadata only: never the
prompt, the completion or any key). AIService is one row of the AI-usage inventory: a known AI
service seen on one channel (network, cloud API, OAuth app grant, the gateway) by one actor.
AIDiscoveryState keeps the per-tenant event cursor of the discovery job.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Float, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, UTCDateTime, uid, utcnow

GATEWAY_STATUSES = ('allowed', 'blocked', 'error')
SERVICE_CHANNELS = ('network', 'cloud_api', 'oauth_app', 'gateway')
SERVICE_STATUSES = ('unreviewed', 'sanctioned', 'blocked')


class AIGatewayRequest(TenantMixin, Base):
    __tablename__ = 'ai_gateway_requests'
    __table_args__ = (Index('ix_ai_gateway_requests_tenant_created', 'tenant_id', 'created_at'),
                      Index('ix_ai_gateway_requests_tenant_key', 'tenant_id', 'api_key_id'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    api_key_id: Mapped[str] = mapped_column(String(36), default='')
    user_id: Mapped[str] = mapped_column(String(36), default='')
    actor: Mapped[str] = mapped_column(String(200), default='')
    provider: Mapped[str] = mapped_column(String(20), default='')
    endpoint: Mapped[str] = mapped_column(String(40), default='')  # chat.completions | embeddings | messages | models
    model: Mapped[str] = mapped_column(String(120), default='')
    stream: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(10), default='allowed')
    block_reason: Mapped[str] = mapped_column(String(300), default='')
    dlp_hits_json: Mapped[str] = mapped_column(Text, default='{}')  # {type: count}; never the matched text
    dlp_action: Mapped[str] = mapped_column(String(10), default='')  # '' | logged | redacted | blocked
    prompt_injection: Mapped[bool] = mapped_column(Boolean, default=False)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    upstream_status: Mapped[int | None] = mapped_column(Integer)
    request_bytes: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class AIService(TenantMixin, Base):
    __tablename__ = 'ai_services'
    __table_args__ = (UniqueConstraint('tenant_id', 'service_key', 'channel', 'actor', name='uq_ai_service_actor'),
                      Index('ix_ai_services_tenant_status', 'tenant_id', 'status'),
                      Index('ix_ai_services_tenant_last_seen', 'tenant_id', 'last_seen_at'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    service_key: Mapped[str] = mapped_column(String(60))  # catalog key, e.g. openai.api
    provider: Mapped[str] = mapped_column(String(60))
    service: Mapped[str] = mapped_column(String(120))
    category: Mapped[str] = mapped_column(String(20), default='')  # api | assistant | code | meeting | platform | cloud
    channel: Mapped[str] = mapped_column(String(12))
    actor: Mapped[str] = mapped_column(String(200), default='')
    asset_id: Mapped[str | None] = mapped_column(String(36))
    evidence: Mapped[str] = mapped_column(String(300), default='')  # the matched domain, API action or app name
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    last_event_id: Mapped[str] = mapped_column(String(36), default='')
    status: Mapped[str] = mapped_column(String(12), default='unreviewed')
    notes: Mapped[str] = mapped_column(Text, default='')
    reviewed_by: Mapped[str] = mapped_column(String(200), default='')
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class AIDiscoveryState(TenantMixin, Base):
    __tablename__ = 'ai_discovery_state'
    __table_args__ = (UniqueConstraint('tenant_id', name='uq_ai_discovery_state_tenant'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    cursor: Mapped[datetime | None] = mapped_column(UTCDateTime())  # received_at of the newest event scanned
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    events_scanned: Mapped[int] = mapped_column(Integer, default=0)
    matches: Mapped[int] = mapped_column(Integer, default=0)
