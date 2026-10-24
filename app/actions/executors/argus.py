"""Internal actions that change Argus's own records. Low risk, reversible, no network.
They still go through the broker so the change is proposed, approved and audited like any other."""
from __future__ import annotations

from sqlalchemy import select

from ...models import Asset, AssetAuthorization, Finding, utcnow
from ...models.findings import FINDING_STATUSES
from ..catalog import ActionError, ActionType, DryRunResult, ExecContext, ExecResult, entities, register

_ID = {'type': 'string', 'minLength': 1, 'maxLength': 36}


def _db(ctx: ExecContext):
    if ctx.db is None:
        raise ActionError('internal action needs a database session')
    return ctx.db


@register
class UpdateFindingStatus(ActionType):
    name = 'argus.finding.update_status'
    description = 'Change the status of a Argus finding (open, investigating, resolved, accepted, false_positive).'
    params_schema = {'properties': {'finding_id': _ID, 'status': {'type': 'string', 'enum': list(FINDING_STATUSES)},
                                    'note': {'type': 'string', 'maxLength': 2000, 'default': ''}},
                     'required': ['finding_id', 'status']}
    risk = 'low'
    reversible = True
    platforms = ['argus']
    category = 'internal'

    @staticmethod
    def _plan(params: dict, current_status: str = '') -> dict:
        warnings = [f'finding is already {current_status}'] if current_status and current_status == params['status'] else []
        return {'table': 'findings', 'set': {'status': params['status']}, 'where': {'id': params['finding_id']}, 'warnings': warnings,
                'blast_radius': entities(1, 'finding', [params['finding_id']])}

    def _find(self, ctx: ExecContext, finding_id: str) -> Finding | None:
        return _db(ctx).execute(select(Finding).where(Finding.id == finding_id, Finding.tenant_id == ctx.tenant_id)).scalar_one_or_none()

    def _load(self, ctx: ExecContext, finding_id: str) -> Finding:
        finding = self._find(ctx, finding_id)
        if finding is None:
            raise ActionError('finding not found in this tenant')
        return finding

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        finding = self._find(ctx, params['finding_id'])
        plan = self._plan(params, finding.status if finding else '')
        if finding is None:
            return DryRunResult(ok=False, summary='finding not found in this tenant', blast_radius=plan['blast_radius'])
        return DryRunResult(ok=True, summary=f'set finding {finding.id} from {finding.status} to {params["status"]}',
                            blast_radius=plan['blast_radius'], warnings=plan['warnings'],
                            details={'title': finding.title, 'severity': finding.severity, 'current_status': finding.status})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        finding = self._load(ctx, params['finding_id'])
        previous = finding.status
        finding.status, finding.updated_at = params['status'], utcnow()
        _db(ctx).flush()
        return ExecResult(ok=True, summary=f'finding {finding.id}: {previous} -> {params["status"]}',
                          rollback_payload={'finding_id': finding.id, 'previous_status': previous}, details={'note': params.get('note', '')})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        finding = self._load(ctx, payload['finding_id'])
        previous = payload.get('previous_status') or 'open'
        if previous not in FINDING_STATUSES:
            raise ActionError('rollback payload has an invalid status')
        current = finding.status
        finding.status, finding.updated_at = previous, utcnow()
        _db(ctx).flush()
        return ExecResult(ok=True, summary=f'finding {finding.id}: {current} -> {previous}')


@register
class RevokeAssetAuthorization(ActionType):
    name = 'argus.asset.revoke_authorization'
    description = 'Revoke the active testing authorization(s) of an asset so no further active tests can run against it.'
    params_schema = {'properties': {'asset_id': _ID, 'authorization_id': {'type': 'string', 'maxLength': 36},
                                    'reason': {'type': 'string', 'maxLength': 1000, 'default': ''}},
                     'required': ['asset_id']}
    risk = 'low'
    reversible = True
    platforms = ['argus']
    category = 'internal'

    @staticmethod
    def _plan(params: dict, authorization_ids: list[str] | None = None) -> dict:
        ids = list(authorization_ids or ([params['authorization_id']] if params.get('authorization_id') else []))
        return {'table': 'asset_authorizations', 'set': {'revoked_at': 'now'}, 'where': {'asset_id': params['asset_id'], 'ids': ids},
                'blast_radius': entities(len(ids), 'asset_authorization', ids, asset_id=params['asset_id'])}

    def _targets(self, ctx: ExecContext, params: dict) -> tuple[Asset | None, list[AssetAuthorization]]:
        db = _db(ctx)
        asset = db.execute(select(Asset).where(Asset.id == params['asset_id'], Asset.tenant_id == ctx.tenant_id)).scalar_one_or_none()
        if asset is None:
            return None, []
        stmt = select(AssetAuthorization).where(AssetAuthorization.asset_id == asset.id, AssetAuthorization.tenant_id == ctx.tenant_id,
                                                AssetAuthorization.revoked_at.is_(None))
        if params.get('authorization_id'):
            stmt = stmt.where(AssetAuthorization.id == params['authorization_id'])
        return asset, list(db.execute(stmt).scalars().all())

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        asset, auths = self._targets(ctx, params)
        plan = self._plan(params, [a.id for a in auths])
        if asset is None:
            return DryRunResult(ok=False, summary='asset not found in this tenant', blast_radius=plan['blast_radius'])
        if not auths:
            return DryRunResult(ok=False, summary='no active authorization to revoke', blast_radius=plan['blast_radius'])
        return DryRunResult(ok=True, summary=f'revoke {len(auths)} authorization(s) on asset {asset.name}', blast_radius=plan['blast_radius'])

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        asset, auths = self._targets(ctx, params)
        if asset is None:
            raise ActionError('asset not found in this tenant')
        if not auths:
            raise ActionError('no active authorization to revoke')
        now = utcnow()
        for auth in auths:
            auth.revoked_at = now
        previous_approved = bool(asset.approved)
        db = _db(ctx)
        db.flush()
        remaining = db.execute(select(AssetAuthorization).where(AssetAuthorization.asset_id == asset.id, AssetAuthorization.tenant_id == ctx.tenant_id,
                                                                AssetAuthorization.revoked_at.is_(None))).scalars().first()
        asset.approved = remaining is not None
        db.flush()
        return ExecResult(ok=True, summary=f'revoked {len(auths)} authorization(s) on asset {asset.name}',
                          rollback_payload={'asset_id': asset.id, 'authorization_ids': [a.id for a in auths], 'previous_approved': previous_approved})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        db = _db(ctx)
        asset = db.execute(select(Asset).where(Asset.id == payload['asset_id'], Asset.tenant_id == ctx.tenant_id)).scalar_one_or_none()
        if asset is None:
            raise ActionError('asset not found in this tenant')
        ids = list(payload.get('authorization_ids') or [])
        auths = list(db.execute(select(AssetAuthorization).where(AssetAuthorization.id.in_(ids), AssetAuthorization.tenant_id == ctx.tenant_id)).scalars())
        for auth in auths:
            auth.revoked_at = None
        asset.approved = bool(payload.get('previous_approved', True))
        db.flush()
        return ExecResult(ok=True, summary=f'restored {len(auths)} authorization(s) on asset {asset.name}')
