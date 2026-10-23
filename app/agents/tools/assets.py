"""Read-only asset inventory tools."""
from __future__ import annotations

from ...core.db import scoped
from ...models import Asset, SecurityEvent
from ._common import (asset_authorizations, asset_dict, authorization_dict, clamp_limit, compact_event, compact_finding, event_time, load_asset,
                      open_findings_for_asset, optional_module, serialize, since)
from .registry import ToolContext, registry


@registry.tool('get_asset', 'Fetch one asset (name, kind, target, environment, criticality, owner) with its testing authorizations.',
               {'properties': {'asset_id': {'type': 'string'}}, 'required': ['asset_id']}, tags=('assets',))
def get_asset(args: dict, ctx: ToolContext) -> dict:
    asset = load_asset(ctx, args['asset_id'])
    if asset is None:
        return {'found': False, 'asset_id': args['asset_id']}
    return {'found': True, **asset_dict(asset), 'authorizations': [authorization_dict(a) for a in asset_authorizations(ctx, asset.id)]}


@registry.tool('list_assets', 'List assets in the inventory, optionally filtered by kind (web, repo, cloud_account, host, k8s_cluster, database, identity_provider, saas, network) or environment.',
               {'properties': {'kind': {'type': 'string'}, 'environment': {'type': 'string'}, 'limit': {'type': 'integer'}}, 'required': []},
               tags=('assets',))
def list_assets(args: dict, ctx: ToolContext) -> dict:
    stmt = scoped(Asset, ctx.principal)
    if args.get('kind'):
        stmt = stmt.where(Asset.kind == args['kind'])
    if args.get('environment'):
        stmt = stmt.where(Asset.environment == args['environment'])
    rows = ctx.db.execute(stmt.order_by(Asset.name.asc()).limit(clamp_limit(args.get('limit'), default=100, maximum=500))).scalars().all()
    return {'count': len(rows), 'items': [asset_dict(a) for a in rows]}


def graph_context_for_asset(ctx: ToolContext, asset: Asset) -> dict:
    """Graph neighbours of the asset's node, when the graph package is present."""
    service = optional_module('app.graph.service')
    if service is None:
        return {'available': False, 'reason': 'graph package not installed'}
    try:
        node_id = asset.graph_node_id
        if not node_id and hasattr(service, 'query'):
            for key in (asset.id, asset.target, asset.name):
                nodes = service.query(ctx.db, ctx.principal.tenant_id, kind='asset', key=key, limit=1) or []
                if nodes:
                    node_id = getattr(nodes[0], 'id', None) or (nodes[0].get('id') if isinstance(nodes[0], dict) else None)
                    break
        if not node_id:
            return {'available': True, 'node_id': None, 'neighbors': []}
        neighbors = service.neighbors(ctx.db, ctx.principal.tenant_id, node_id, depth=1)
        return {'available': True, 'node_id': node_id, 'neighbors': serialize(neighbors)}
    except Exception as exc:  # degrade, never crash the agent
        return {'available': False, 'reason': f'{type(exc).__name__}: {exc}'[:200]}


@registry.tool('asset_context', 'Everything known about one asset: record, authorizations, open findings, events from the last 7 days and graph neighbours when the evidence graph is available.',
               {'properties': {'asset_id': {'type': 'string'}, 'days': {'type': 'integer', 'description': 'event look-back, default 7'}},
                'required': ['asset_id']}, tags=('assets',))
def asset_context(args: dict, ctx: ToolContext) -> dict:
    asset = load_asset(ctx, args['asset_id'])
    if asset is None:
        return {'found': False, 'asset_id': args['asset_id']}
    days = clamp_limit(args.get('days'), default=7, maximum=90)
    events = ctx.db.execute(scoped(SecurityEvent, ctx.principal).where(SecurityEvent.asset_id == asset.id, event_time() >= since(days=days))
                            .order_by(event_time().desc()).limit(50)).scalars().all()
    authorizations = [authorization_dict(a) for a in asset_authorizations(ctx, asset.id)]
    return {'found': True, 'asset': asset_dict(asset), 'authorizations': authorizations,
            'authorized': any(a['valid'] for a in authorizations),
            'open_findings': [compact_finding(f) for f in open_findings_for_asset(ctx, asset.id)],
            'recent_events': [compact_event(e) for e in events], 'graph': graph_context_for_asset(ctx, asset)}
