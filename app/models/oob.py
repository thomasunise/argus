"""Out-of-band probe tokens.

A blind SSRF, XXE or XSS payload only proves itself when something calls back. Argus issues a
single-use token per probe, embeds it in a URL under /api/v1/oob/<token>, and records the hit
(source address, path, user agent). The token is the credential: it is random, asset-scoped and
expires with the asset's retention.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, UTCDateTime, uid, utcnow


class OobToken(TenantMixin, Base):
    __tablename__ = 'oob_tokens'
    __table_args__ = (Index('ix_oob_tokens_token', 'token', unique=True),
                      Index('ix_oob_tokens_tenant_created', 'tenant_id', 'created_at'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    token: Mapped[str] = mapped_column(String(64))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey('assets.id'), index=True)
    run_id: Mapped[str] = mapped_column(String(36), default='')
    kind: Mapped[str] = mapped_column(String(16), default='ssrf')  # ssrf | xxe | xss | other
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    first_hit_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    source_ip: Mapped[str] = mapped_column(String(64), default='')
    user_agent: Mapped[str] = mapped_column(String(256), default='')
