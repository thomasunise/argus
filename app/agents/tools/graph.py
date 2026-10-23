"""Read-only evidence-graph tools. The graph package (app.graph) is built by another workstream;
every tool degrades to {'available': False} when it is missing."""
from __future__ import annotations

import json
from typing import Any

from ._common import clamp_limit, like, optional_attr, optional_module, serialize, unavailable
from .registry import ToolContext, registry

NODE_KINDS = 'asset, identity, role, permission, network, exposure, vuln, secret, data_store, finding, event, canary'


def _service():
    return optional_module('app.graph.service')


def _tenant_ok(item: Any, tenant_id: str) -> bool:
    owner = getattr(item, 'tenant_id', None) if not isinstance(item, dict) else item.get('tenant_id')
    return owner is None or owner == tenant_id


def _call(ctx: ToolContext, name: str, *args, **kwargs) -> tuple[Any, dict | None]:
    service = _service()
    if service is None or not hasattr(service, name):
        return None, unavailable(f'graph service not installed or has no {name}()')
    try:
        return getattr(service, name)(ctx.db, ctx.principal.tenant_id, *args, **kwargs), None
    except Exception as exc:
        return None, unavailable(f'graph {name} failed: {type(exc).__name__}: {str(exc)[:200]}')


def _node_dict(node: Any) -> dict:
    service = _service()
    to_dict = getattr(service, 'node_to_dict', None) if service is not None else None
    if to_dict is not None and not isinstance(node, dict):
        try:
            return to_dict(node)
        except Exception:
            pass
    return serialize(node)


def _query_nodes(ctx: ToolContext, kind: str | None, key: str | None, search: str, limit: int) -> tuple[list[dict] | None, dict | None]:
    """Prefer the graph package's query(); otherwise read GraphNode rows directly (tenant scoped)."""
    for module_name in ('app.graph.service', 'app.graph.queries'):
        query = optional_attr(module_name, 'query')
        if query is not None:
            try:
                rows = query(ctx.db, ctx.principal.tenant_id, kind=kind, key=key, limit=max(limit, 200))
            except Exception as exc:
                return None, unavailable(f'graph query failed: {type(exc).__name__}: {str(exc)[:200]}')
            items = [_node_dict(n) for n in rows or [] if _tenant_ok(n, ctx.principal.tenant_id)]
            if search:
                items = [n for n in items if search in json.dumps(n, default=str).lower()]
            return items, None
    GraphNode = optional_attr('app.models.graph', 'GraphNode')
    if GraphNode is None:
        return None, unavailable('graph package not installed')
    from sqlalchemy import or_

    from ...core.db import scoped

    stmt = scoped(GraphNode, ctx.principal)
    if kind:
        stmt = stmt.where(GraphNode.kind == kind)
    if key:
        stmt = stmt.where(GraphNode.key == key)
    if search:
        pattern = like(search)
        stmt = stmt.where(or_(GraphNode.key.ilike(pattern, escape='\\'), GraphNode.label.ilike(pattern, escape='\\'), GraphNode.props_json.ilike(pattern, escape='\\')))
    rows = ctx.db.execute(stmt.limit(limit)).scalars().all()
    return [_node_dict(n) for n in rows], None


@registry.tool('graph_query', f'Search evidence-graph nodes by kind ({NODE_KINDS}), exact key, or a free-text search over keys, labels and properties.',
               {'properties': {'kind': {'type': 'string'}, 'key': {'type': 'string'}, 'search': {'type': 'string'}, 'limit': {'type': 'integer'}},
                'required': []}, tags=('graph',))
def graph_query(args: dict, ctx: ToolContext) -> dict:
    limit = clamp_limit(args.get('limit'), default=50, maximum=200)
    items, problem = _query_nodes(ctx, args.get('kind') or None, args.get('key') or None, (args.get('search') or '').lower(), limit)
    if problem:
        return problem
    return {'available': True, 'count': len(items[:limit]), 'items': items[:limit]}


@registry.tool('graph_neighbors', 'Nodes and edges reachable from a graph node within N hops (owns, can_assume, has_permission, exposes, runs, connects_to, affected_by, accessed, triggered).',
               {'properties': {'node_id': {'type': 'string'}, 'depth': {'type': 'integer', 'description': '1-3, default 1'}}, 'required': ['node_id']},
               tags=('graph',))
def graph_neighbors(args: dict, ctx: ToolContext) -> dict:
    depth = clamp_limit(args.get('depth'), default=1, maximum=3)
    result, problem = _call(ctx, 'neighbors', args['node_id'], depth=depth)
    if problem:
        return problem
    data = serialize(result)
    if isinstance(data, list):
        data = [n for n in data if _tenant_ok(n, ctx.principal.tenant_id)]
    elif isinstance(data, dict):
        for key in ('nodes', 'edges'):
            if isinstance(data.get(key), list):
                data[key] = [n for n in data[key] if _tenant_ok(n, ctx.principal.tenant_id)]
    return {'available': True, 'node_id': args['node_id'], 'depth': depth, 'result': data}


@registry.tool('attack_paths', 'Computed attack paths from exposures to sensitive data stores, with hops, score and status (open, accepted, resolved).',
               {'properties': {'status': {'type': 'string', 'description': 'filter by path status; default all'}, 'limit': {'type': 'integer'}},
                'required': []}, tags=('graph',))
def attack_paths(args: dict, ctx: ToolContext) -> dict:
    paths, problem = _call(ctx, 'attack_paths')
    if problem:
        return problem
    service = _service()
    to_dict = getattr(service, 'path_to_dict', None)
    items: list[Any] = []
    for path in paths or []:
        if not _tenant_ok(path, ctx.principal.tenant_id):
            continue
        try:
            items.append(to_dict(path) if to_dict is not None and not isinstance(path, dict) else serialize(path))
        except Exception:
            items.append(serialize(path))
    status = (args.get('status') or '').lower()
    if status:
        items = [p for p in items if not isinstance(p, dict) or str(p.get('status', '')).lower() == status]
    limit = clamp_limit(args.get('limit'), default=25, maximum=100)
    return {'available': True, 'count': len(items), 'items': items[:limit]}


@registry.tool('exposure', 'Exposure score (0-100) of a graph node: how reachable it is from the internet or untrusted identities.',
               {'properties': {'node_id': {'type': 'string'}}, 'required': ['node_id']}, tags=('graph',))
def exposure(args: dict, ctx: ToolContext) -> dict:
    score, problem = _call(ctx, 'exposure_score', args['node_id'])
    if problem:
        return problem
    try:
        value = float(score)
    except (TypeError, ValueError):
        value = 0.0
    return {'available': True, 'node_id': args['node_id'], 'exposure_score': value, 'scale': '0-100'}
