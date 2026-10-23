"""Helpers shared by the core domain routers (assets, findings, events, investigations,
approvals, audit, reports, admin). Underscore-prefixed so router discovery skips it."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.errors import SentinelError
from ..models import Asset, AssetAuthorization, loads, utcnow


class BadRequest(SentinelError):
    status = 400
    code = 'bad_request'


def aware(value: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes for timezone-aware columns; treat naive as UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_since(value: str | None, *, field: str = 'since') -> datetime | None:
    """Accepts ISO-8601 timestamps or relative windows such as 24h, 7d, 30m."""
    if not value:
        return None
    text = value.strip()
    if len(text) >= 2 and text[-1] in 'hdm' and text[:-1].isdigit():
        amount = int(text[:-1])
        delta = {'h': timedelta(hours=amount), 'd': timedelta(days=amount), 'm': timedelta(minutes=amount)}[text[-1]]
        return utcnow() - delta
    if len(text) > 6 and text[-6] == ' ' and text[-3] == ':':
        text = text[:-6] + '+' + text[-5:]  # an unencoded '+' in a query string arrives as a space
    try:
        return aware(datetime.fromisoformat(text.replace('Z', '+00:00')))
    except ValueError as exc:
        raise BadRequest(f'{field} must be an ISO-8601 timestamp or a window such as 24h or 7d') from exc


def like(value: str) -> str:
    """Escape a user search term for a LIKE pattern."""
    cleaned = value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    return f'%{cleaned}%'


def asset_to_dict(asset: Asset) -> dict[str, Any]:
    return {'id': asset.id, 'name': asset.name, 'kind': asset.kind, 'target': asset.target, 'environment': asset.environment,
            'criticality': asset.criticality, 'owner': asset.owner, 'tags': loads(asset.tags_json, []), 'source': asset.source,
            'external_id': asset.external_id, 'approved': bool(asset.approved), 'graph_node_id': asset.graph_node_id,
            'created_at': asset.created_at, 'last_scan_at': asset.last_scan_at, 'last_seen_at': asset.last_seen_at}


def authorization_to_dict(auth: AssetAuthorization, now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    expires = aware(auth.expires_at)
    active = auth.revoked_at is None and (expires is None or expires > now)
    return {'id': auth.id, 'asset_id': auth.asset_id, 'authorized_by': auth.authorized_by, 'attestation': auth.attestation,
            'allow_active': bool(auth.allow_active), 'allow_intrusive': bool(auth.allow_intrusive), 'scope_document_ref': auth.scope_document_ref,
            'created_at': auth.created_at, 'expires_at': auth.expires_at, 'revoked_at': auth.revoked_at, 'active': active}


def active_authorizations(db: Session, tenant_id: str, asset_id: str, now: datetime | None = None) -> list[AssetAuthorization]:
    now = now or utcnow()
    rows = db.execute(select(AssetAuthorization).where(AssetAuthorization.tenant_id == tenant_id, AssetAuthorization.asset_id == asset_id,
                                                       AssetAuthorization.revoked_at.is_(None))
                      .order_by(AssetAuthorization.created_at.desc())).scalars().all()
    return [r for r in rows if aware(r.expires_at) is None or aware(r.expires_at) > now]


def current_authorization(db: Session, tenant_id: str, asset_id: str) -> AssetAuthorization | None:
    rows = active_authorizations(db, tenant_id, asset_id)
    return rows[0] if rows else None
