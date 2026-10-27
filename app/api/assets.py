"""Inventory: assets, testing authorizations, bulk import and the asset's graph neighborhood.

Target validation at create time is syntactic only (`resolve=False`); DNS resolution and
IP-range policy are re-checked by the test harness at scan time. An authorization is an
explicit attestation that the tenant controls the asset; it is what gates active testing.
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.config import Settings
from ..core.db import get_scoped, scoped
from ..core.errors import Conflict, NotFound, PolicyDenied
from ..core.policy import validate_target
from ..core.rbac import Principal
from ..models import Asset, AssetAuthorization, Finding, ScanRun, SecurityEvent, dumps, utcnow
from ..models.inventory import ASSET_KINDS, ENVIRONMENTS
from ._common import BadRequest, active_authorizations, asset_to_dict, authorization_to_dict, like
from .deps import Page, get_db, get_settings, require

log = logging.getLogger('argus.api.assets')

router = APIRouter(prefix='/api/v1/assets', tags=['assets'])

CRITICALITIES = ('low', 'medium', 'high', 'critical')
INTRUSIVE_ENVIRONMENTS = {'staging', 'lab'}
EXPLOIT_ENVIRONMENTS = {'staging', 'lab'}
MAX_IMPORT_ROWS = 1000
MIN_ATTESTATION_CHARS = 20


class AssetBody(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    kind: str = Field(min_length=1, max_length=24)
    target: str = Field(min_length=1, max_length=512)
    environment: str = 'production'
    criticality: str = 'medium'
    owner: str = Field(default='', max_length=120)
    tags: list[str] = []
    external_id: str = Field(default='', max_length=256)

    @field_validator('tags')
    @classmethod
    def _tags(cls, value: list[str]) -> list[str]:
        cleaned = sorted({t.strip()[:40] for t in value if t and t.strip()})
        if len(cleaned) > 30:
            raise ValueError('at most 30 tags')
        return cleaned


class AssetPatch(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    environment: str | None = None
    criticality: str | None = None
    owner: str | None = Field(default=None, max_length=120)
    tags: list[str] | None = None


class AuthorizeBody(BaseModel):
    attestation: str = Field(min_length=1, max_length=4000)
    allow_active: bool = False
    allow_intrusive: bool = False
    allow_exploit: bool = False
    expires_in_days: int = Field(default=90, ge=1, le=365)
    scope_document_ref: str = Field(default='', max_length=512)


class RevokeBody(BaseModel):
    reason: str = Field(default='', max_length=800)


def _check_enums(kind: str | None, environment: str | None, criticality: str | None) -> None:
    if kind is not None and kind not in ASSET_KINDS:
        raise BadRequest(f'kind must be one of {sorted(ASSET_KINDS)}', code='invalid_kind')
    if environment is not None and environment not in ENVIRONMENTS:
        raise BadRequest(f'environment must be one of {sorted(ENVIRONMENTS)}', code='invalid_environment')
    if criticality is not None and criticality not in CRITICALITIES:
        raise BadRequest(f'criticality must be one of {list(CRITICALITIES)}', code='invalid_criticality')


def _normalized_target(kind: str, target: str, settings: Settings) -> str:
    try:
        return validate_target(kind, target, settings, resolve=False)
    except PolicyDenied as exc:
        raise BadRequest(exc.message, code='invalid_target') from exc


def _link_graph(db: Session, asset: Asset) -> None:
    """Best-effort: give the asset a node in the evidence graph when that package is present."""
    try:
        from ..graph.service import link_asset
    except ImportError:
        return
    try:
        link_asset(db, asset)
    except Exception:  # graph enrichment must never block inventory writes
        log.exception('graph link failed for asset %s', asset.id)


def _build_asset(body: AssetBody, principal: Principal, settings: Settings) -> Asset:
    _check_enums(body.kind, body.environment, body.criticality)
    target = _normalized_target(body.kind, body.target, settings)
    return Asset(tenant_id=principal.tenant_id, name=body.name.strip(), kind=body.kind, target=target, environment=body.environment,
                 criticality=body.criticality, owner=body.owner.strip(), tags_json=dumps(body.tags), source='manual',
                 external_id=body.external_id.strip(), approved=False)


def _get_asset(db: Session, principal: Principal, asset_id: str) -> Asset:
    asset = get_scoped(db, Asset, principal, asset_id)
    if asset is None:
        raise NotFound('Asset not found')
    return asset


def _open_finding_counts(db: Session, tenant_id: str, asset_id: str) -> dict[str, int]:
    rows = db.execute(select(Finding.severity, func.count()).where(Finding.tenant_id == tenant_id, Finding.asset_id == asset_id,
                                                                    Finding.status.in_(['open', 'investigating'])).group_by(Finding.severity)).all()
    counts = {severity: int(n) for severity, n in rows}
    counts['total'] = sum(counts.values())
    return counts


def _last_runs(db: Session, tenant_id: str, asset_id: str, limit: int = 5) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {'test_runs': [], 'scan_runs': []}
    try:
        from ..models.testing import TestRun
        from ..testing.service import run_to_dict

        rows = db.execute(select(TestRun).where(TestRun.tenant_id == tenant_id, TestRun.asset_id == asset_id)
                          .order_by(TestRun.created_at.desc()).limit(limit)).scalars().all()
        out['test_runs'] = [run_to_dict(r) for r in rows]
    except ImportError:
        pass
    rows = db.execute(select(ScanRun).where(ScanRun.tenant_id == tenant_id, ScanRun.asset_id == asset_id)
                      .order_by(ScanRun.created_at.desc()).limit(limit)).scalars().all()
    out['scan_runs'] = [{'id': r.id, 'scanner': r.scanner, 'status': r.status, 'result_count': r.result_count, 'error': r.error,
                         'created_at': r.created_at, 'completed_at': r.completed_at} for r in rows]
    return out


def _has_run_history(db: Session, tenant_id: str, asset_id: str) -> bool:
    if db.scalar(select(func.count()).select_from(ScanRun).where(ScanRun.tenant_id == tenant_id, ScanRun.asset_id == asset_id)):
        return True
    try:
        from ..models.testing import TestRun
    except ImportError:
        return False
    return bool(db.scalar(select(func.count()).select_from(TestRun).where(TestRun.tenant_id == tenant_id, TestRun.asset_id == asset_id)))


# ---------------------------------------------------------------- collection


@router.get('')
def list_assets(kind: str | None = None, environment: str | None = None, search: str | None = None, approved: bool | None = None,
                criticality: str | None = None, page: Page = Depends(Page), db: Session = Depends(get_db),
                principal: Principal = Depends(require('assets:read'))):
    stmt = scoped(Asset, principal)
    if kind:
        stmt = stmt.where(Asset.kind == kind)
    if environment:
        stmt = stmt.where(Asset.environment == environment)
    if criticality:
        stmt = stmt.where(Asset.criticality == criticality)
    if approved is not None:
        stmt = stmt.where(Asset.approved.is_(approved))
    if search:
        pattern = like(search.strip())
        stmt = stmt.where(or_(Asset.name.ilike(pattern, escape='\\'), Asset.target.ilike(pattern, escape='\\'), Asset.owner.ilike(pattern, escape='\\')))
    rows = db.execute(page.apply(stmt.order_by(Asset.created_at.desc(), Asset.id))).scalars().all()
    return page.wrap(rows, asset_to_dict)


@router.post('', status_code=201)
def create_asset(body: AssetBody, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                 principal: Principal = Depends(require('assets:write'))):
    asset = _build_asset(body, principal, settings)
    db.add(asset)
    db.flush()
    record_audit(db, principal, 'assets.created', asset.id, {'name': asset.name, 'kind': asset.kind, 'target': asset.target,
                                                             'environment': asset.environment})
    _link_graph(db, asset)
    return asset_to_dict(asset)


@router.post('/import', status_code=200)
def import_assets(rows: list[Any] = Body(...), db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                  principal: Principal = Depends(require('assets:write'))):
    """Bulk import: a JSON array of asset bodies. Each row is validated independently; valid rows
    are created, invalid rows are reported with their error, duplicates (same kind and target) are skipped."""
    if len(rows) > MAX_IMPORT_ROWS:
        raise BadRequest(f'At most {MAX_IMPORT_ROWS} rows per import', code='too_many_rows')
    existing = {(a.kind, a.target): a.id for a in db.execute(scoped(Asset, principal)).scalars()}
    results: list[dict[str, Any]] = []
    created_ids: list[str] = []
    for index, raw in enumerate(rows):
        try:
            if not isinstance(raw, dict):
                raise BadRequest('row must be an object')
            body = AssetBody.model_validate(raw)
            asset = _build_asset(body, principal, settings)
        except BadRequest as exc:
            results.append({'index': index, 'ok': False, 'error': exc.message, 'code': exc.code})
            continue
        except ValueError as exc:  # pydantic validation
            results.append({'index': index, 'ok': False, 'error': str(exc).splitlines()[0][:200], 'code': 'validation'})
            continue
        key = (asset.kind, asset.target)
        if key in existing:
            results.append({'index': index, 'ok': False, 'error': 'asset with this kind and target already exists', 'code': 'exists',
                            'id': existing[key]})
            continue
        db.add(asset)
        db.flush()
        existing[key] = asset.id
        created_ids.append(asset.id)
        _link_graph(db, asset)
        results.append({'index': index, 'ok': True, 'id': asset.id})
    record_audit(db, principal, 'assets.imported', '', {'received': len(rows), 'created': len(created_ids),
                                                         'failed': len(rows) - len(created_ids), 'ids': created_ids[:200]})
    return {'received': len(rows), 'created': len(created_ids), 'failed': len(rows) - len(created_ids), 'results': results}


# ---------------------------------------------------------------- single asset


@router.get('/{asset_id}')
def get_asset(asset_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('assets:read'))):
    asset = _get_asset(db, principal, asset_id)
    active = active_authorizations(db, principal.tenant_id, asset.id)
    total_auths = db.scalar(select(func.count()).select_from(AssetAuthorization).where(AssetAuthorization.tenant_id == principal.tenant_id,
                                                                                         AssetAuthorization.asset_id == asset.id)) or 0
    data = asset_to_dict(asset)
    data['authorization'] = authorization_to_dict(active[0]) if active else None
    data['authorization_status'] = 'active' if active else ('expired_or_revoked' if asset.approved or total_auths else 'none')
    data['authorizations_count'] = int(total_auths)
    data['open_findings'] = _open_finding_counts(db, principal.tenant_id, asset.id)
    data['last_runs'] = _last_runs(db, principal.tenant_id, asset.id)
    return data


@router.patch('/{asset_id}')
def patch_asset(asset_id: str, body: AssetPatch, db: Session = Depends(get_db), principal: Principal = Depends(require('assets:write'))):
    asset = _get_asset(db, principal, asset_id)
    _check_enums(None, body.environment, body.criticality)
    changes: dict[str, Any] = {}
    if body.name is not None and body.name.strip() != asset.name:
        changes['name'] = {'from': asset.name, 'to': body.name.strip()}
        asset.name = body.name.strip()
    if body.environment is not None and body.environment != asset.environment:
        if body.environment not in INTRUSIVE_ENVIRONMENTS and any(a.allow_intrusive for a in active_authorizations(db, principal.tenant_id, asset.id)):
            raise Conflict('Revoke the intrusive-testing authorization before moving this asset out of staging/lab')
        changes['environment'] = {'from': asset.environment, 'to': body.environment}
        asset.environment = body.environment
    if body.criticality is not None and body.criticality != asset.criticality:
        changes['criticality'] = {'from': asset.criticality, 'to': body.criticality}
        asset.criticality = body.criticality
    if body.owner is not None and body.owner.strip() != asset.owner:
        changes['owner'] = {'from': asset.owner, 'to': body.owner.strip()}
        asset.owner = body.owner.strip()
    if body.tags is not None:
        tags = sorted({t.strip()[:40] for t in body.tags if t and t.strip()})
        if dumps(tags) != asset.tags_json:
            changes['tags'] = {'to': tags}
            asset.tags_json = dumps(tags)
    if changes:
        record_audit(db, principal, 'assets.updated', asset.id, {'changes': changes})
    return asset_to_dict(asset)


@router.delete('/{asset_id}')
def delete_asset(asset_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('assets:write'))):
    asset = _get_asset(db, principal, asset_id)
    if _has_run_history(db, principal.tenant_id, asset.id):
        raise Conflict('This asset has test or scan history; it is preserved for audit integrity')
    # Keep evidence; detach findings and events before removing the inventory row.
    detached = 0
    for model in (Finding, SecurityEvent):
        for row in db.execute(select(model).where(model.tenant_id == principal.tenant_id, model.asset_id == asset.id)).scalars():
            row.asset_id = None
            detached += 1
    for auth in db.execute(select(AssetAuthorization).where(AssetAuthorization.tenant_id == principal.tenant_id,
                                                            AssetAuthorization.asset_id == asset.id)).scalars():
        db.delete(auth)
    from ..models import AssetCredential
    for credential in db.execute(select(AssetCredential).where(AssetCredential.tenant_id == principal.tenant_id,
                                                              AssetCredential.asset_id == asset.id)).scalars():
        db.delete(credential)
    record_audit(db, principal, 'assets.deleted', asset.id, {'name': asset.name, 'kind': asset.kind, 'target': asset.target, 'detached': detached})
    db.delete(asset)
    return {'ok': True, 'detached': detached}


# ---------------------------------------------------------------- authorization


@router.post('/{asset_id}/authorize', status_code=201)
def authorize_asset(asset_id: str, body: AuthorizeBody, db: Session = Depends(get_db), principal: Principal = Depends(require('assets:authorize'))):
    asset = _get_asset(db, principal, asset_id)
    attestation = body.attestation.strip()
    if len(attestation) < MIN_ATTESTATION_CHARS:
        raise BadRequest(f'attestation must be at least {MIN_ATTESTATION_CHARS} characters and state that you control this asset',
                         code='attestation_required')
    if body.allow_intrusive and asset.environment not in INTRUSIVE_ENVIRONMENTS:
        raise PolicyDenied('Intrusive testing can only be authorized for staging or lab assets')
    if body.allow_intrusive and not body.allow_active:
        raise BadRequest('allow_intrusive requires allow_active', code='invalid_tiers')
    if body.allow_exploit:
        if asset.kind != 'web':
            raise BadRequest('Exploit authoring is only available for web assets', code='invalid_kind')
        if not body.allow_active:
            raise BadRequest('allow_exploit requires allow_active', code='invalid_tiers')
        if asset.environment not in EXPLOIT_ENVIRONMENTS and not body.scope_document_ref.strip():
            raise BadRequest('Exploit authorization outside staging/lab requires a signed scope_document_ref',
                             code='scope_document_required')
    now = utcnow()
    superseded = []
    for previous in active_authorizations(db, principal.tenant_id, asset.id, now):
        previous.revoked_at = now
        superseded.append(previous.id)
    auth = AssetAuthorization(tenant_id=principal.tenant_id, asset_id=asset.id, authorized_by=principal.user_id or principal.actor,
                              attestation=attestation, allow_active=body.allow_active, allow_intrusive=body.allow_intrusive,
                              allow_exploit=body.allow_exploit,
                              scope_document_ref=body.scope_document_ref.strip(), expires_at=now + timedelta(days=body.expires_in_days))
    db.add(auth)
    asset.approved = True
    db.flush()
    record_audit(db, principal, 'assets.authorized', asset.id, {'authorization_id': auth.id, 'attestation': attestation,
                                                                'allow_active': body.allow_active, 'allow_intrusive': body.allow_intrusive,
                                                                'allow_exploit': body.allow_exploit,
                                                                'expires_at': auth.expires_at.isoformat(), 'scope_document_ref': auth.scope_document_ref,
                                                                'superseded': superseded})
    return {**asset_to_dict(asset), 'authorization': authorization_to_dict(auth, now)}


@router.post('/{asset_id}/revoke-authorization')
def revoke_authorization(asset_id: str, body: RevokeBody | None = None, db: Session = Depends(get_db),
                         principal: Principal = Depends(require('assets:authorize'))):
    asset = _get_asset(db, principal, asset_id)
    now = utcnow()
    revoked = []
    for auth in active_authorizations(db, principal.tenant_id, asset.id, now):
        auth.revoked_at = now
        revoked.append(auth.id)
    asset.approved = False
    record_audit(db, principal, 'assets.authorization_revoked', asset.id, {'revoked': revoked, 'reason': (body.reason if body else '')})
    return {**asset_to_dict(asset), 'revoked': revoked}


@router.get('/{asset_id}/authorizations')
def list_authorizations(asset_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require('assets:read'))):
    asset = _get_asset(db, principal, asset_id)
    now = utcnow()
    rows = db.execute(select(AssetAuthorization).where(AssetAuthorization.tenant_id == principal.tenant_id, AssetAuthorization.asset_id == asset.id)
                      .order_by(AssetAuthorization.created_at.desc())).scalars().all()
    return {'items': [authorization_to_dict(r, now) for r in rows], 'next_cursor': None}


@router.get('/{asset_id}/graph')
def asset_graph(asset_id: str, depth: int = 1, db: Session = Depends(get_db), principal: Principal = Depends(require('assets:read', 'graph:read'))):
    asset = _get_asset(db, principal, asset_id)
    try:
        from ..graph.service import neighbors
    except ImportError:
        return {'available': False, 'node_id': None, 'nodes': [], 'edges': []}
    if not asset.graph_node_id:
        return {'available': True, 'node_id': None, 'nodes': [], 'edges': []}
    data = neighbors(db, principal.tenant_id, asset.graph_node_id, depth=max(1, min(3, depth)))
    return {'available': True, 'node_id': asset.graph_node_id, **data}


# ---------------------------------------------------------------- testing credentials


class CredentialBody(BaseModel):
    kind: str = Field(default='header', max_length=8)
    name: str = Field(default='', max_length=120)
    role: str = Field(default='default', max_length=40)
    value: str = Field(min_length=1, max_length=4000)


@router.post('/{asset_id}/credentials', status_code=201)
def add_credential(asset_id: str, body: CredentialBody, db: Session = Depends(get_db),
                   principal: Principal = Depends(require('assets:authorize'))):
    """Store a credential used only to reach this asset during authorized testing (encrypted at rest)."""
    from ..models import AssetCredential
    from ..testing.auth import KINDS, credential_to_dict

    asset = _get_asset(db, principal, asset_id)
    if body.kind not in KINDS:
        raise BadRequest(f'kind must be one of {list(KINDS)}', code='invalid_kind')
    if body.kind in ('header', 'basic') and not body.name.strip():
        raise BadRequest('a header or basic credential needs a name', code='invalid_name')
    row = AssetCredential(tenant_id=principal.tenant_id, asset_id=asset.id, kind=body.kind,
                          name=body.name.strip(), role=body.role.strip() or 'default', secret=body.value, created_by=principal.actor[:64])
    db.add(row)
    db.flush()
    record_audit(db, principal, 'assets.credential.added', asset.id,
                 {'credential_id': row.id, 'kind': row.kind, 'name': row.name})
    return credential_to_dict(row)


@router.get('/{asset_id}/credentials')
def list_credentials(asset_id: str, db: Session = Depends(get_db),
                     principal: Principal = Depends(require('assets:read'))):
    from ..models import AssetCredential
    from ..testing.auth import credential_to_dict

    asset = _get_asset(db, principal, asset_id)
    rows = db.execute(select(AssetCredential).where(AssetCredential.tenant_id == principal.tenant_id,
                                                    AssetCredential.asset_id == asset.id)
                      .order_by(AssetCredential.created_at.desc())).scalars().all()
    return {'items': [credential_to_dict(row) for row in rows]}


@router.delete('/{asset_id}/credentials/{credential_id}')
def revoke_credential(asset_id: str, credential_id: str, db: Session = Depends(get_db),
                      principal: Principal = Depends(require('assets:authorize'))):
    from ..models import AssetCredential

    asset = _get_asset(db, principal, asset_id)
    row = db.execute(select(AssetCredential).where(AssetCredential.id == credential_id,
                                                   AssetCredential.tenant_id == principal.tenant_id,
                                                   AssetCredential.asset_id == asset.id)).scalar_one_or_none()
    if row is None:
        raise NotFound('credential not found')
    row.revoked_at = utcnow()
    record_audit(db, principal, 'assets.credential.revoked', asset.id, {'credential_id': row.id, 'kind': row.kind})
    return {'ok': True, 'id': row.id}
