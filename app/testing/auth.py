"""Per-asset testing credentials, decrypted for one run and injected as request headers.

Credentials are stored with the encrypted column type, so they are ciphertext at rest. They are
loaded into a HarnessContext for the duration of one adapter run and never written to a finding,
an audit payload or a log: `redact()` is the last line of defence, this is the first.
"""
from __future__ import annotations

import base64

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AssetCredential, utcnow

KINDS = ('header', 'bearer', 'basic', 'cookie')


def _apply_credential_header(headers: dict[str, str], row: AssetCredential) -> None:
    secret = row.secret or ''
    if not secret:
        return
    if row.kind == 'header':
        headers[row.name] = secret
    elif row.kind == 'bearer':
        headers['Authorization'] = f'Bearer {secret}'
    elif row.kind == 'basic':
        token = base64.b64encode(f'{row.name}:{secret}'.encode('utf-8')).decode('ascii')
        headers['Authorization'] = f'Basic {token}'
    elif row.kind == 'cookie':
        headers['Cookie'] = secret


def load_auth_headers(db: Session, tenant_id: str, asset_id: str, *, role: str | None = None) -> dict[str, str]:
    """Headers a request to this asset should carry. Empty when the asset has no live credentials."""
    stmt = select(AssetCredential).where(
        AssetCredential.tenant_id == tenant_id,
        AssetCredential.asset_id == asset_id,
        AssetCredential.revoked_at.is_(None),
    )
    if role is not None:
        stmt = stmt.where(AssetCredential.role == role)
    rows = db.execute(stmt).scalars().all()
    headers: dict[str, str] = {}
    for row in rows:
        _apply_credential_header(headers, row)
    return headers


def load_role_headers(db: Session, tenant_id: str, asset_id: str) -> dict[str, dict[str, str]]:
    """Map of credential `role` -> request headers dict for multi-principal testing (e.g. user_a vs user_b)."""
    rows = db.execute(
        select(AssetCredential).where(
            AssetCredential.tenant_id == tenant_id,
            AssetCredential.asset_id == asset_id,
            AssetCredential.revoked_at.is_(None),
        )
    ).scalars().all()
    by_role: dict[str, dict[str, str]] = {}
    for row in rows:
        role_key = (getattr(row, 'role', '') or 'default').strip() or 'default'
        bucket = by_role.setdefault(role_key, {})
        _apply_credential_header(bucket, row)
    return {k: v for k, v in by_role.items() if v}


def credential_to_dict(row: AssetCredential) -> dict:
    """Metadata only: the secret is never serialised."""
    return {'id': row.id, 'asset_id': row.asset_id, 'kind': row.kind, 'name': row.name,
            'role': getattr(row, 'role', 'default') or 'default',
            'created_by': row.created_by, 'created_at': row.created_at,
            'revoked_at': row.revoked_at, 'active': row.revoked_at is None}
