from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, UTCDateTime, uid, utcnow

ASSET_KINDS = {'web', 'repo', 'cloud_account', 'host', 'k8s_cluster', 'database', 'identity_provider', 'saas', 'network'}
ENVIRONMENTS = {'production', 'staging', 'lab', 'development'}


class Asset(TenantMixin, Base):
    __tablename__ = 'assets'
    __table_args__ = (Index('ix_assets_tenant_kind', 'tenant_id', 'kind'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(24))
    target: Mapped[str] = mapped_column(String(512))
    environment: Mapped[str] = mapped_column(String(20), default='production')
    criticality: Mapped[str] = mapped_column(String(12), default='medium')  # low, medium, high, critical
    owner: Mapped[str] = mapped_column(String(120), default='')
    tags_json: Mapped[str] = mapped_column(Text, default='[]')
    source: Mapped[str] = mapped_column(String(40), default='manual')  # manual or a collector name
    external_id: Mapped[str] = mapped_column(String(256), default='')
    approved: Mapped[bool] = mapped_column(Boolean, default=False)  # True when a current authorization exists
    graph_node_id: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_scan_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class AssetAuthorization(TenantMixin, Base):
    """A recorded attestation that the tenant controls the asset and permits testing of a given tier."""

    __tablename__ = 'asset_authorizations'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey('assets.id'), index=True)
    authorized_by: Mapped[str] = mapped_column(String(36))
    attestation: Mapped[str] = mapped_column(Text)
    allow_active: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_intrusive: Mapped[bool] = mapped_column(Boolean, default=False)
    scope_document_ref: Mapped[str] = mapped_column(String(512), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
