"""Evidence graph service: the write path used by collectors (`apply`), node/edge upserts,
bounded reads, attack paths, exposure scoring and serializers.

Collectors describe what they saw as `NodeDraft` / `EdgeDraft` objects keyed by (kind, key)
and never deal with ids. `apply()` resolves keys, upserts, links inventory assets, and marks
nodes from the same source that were not re-asserted as stale.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from ..core.events import publish_soon
from ..core.security import redact
from ..models import Asset, dumps, loads, utcnow
from ..models.graph import CRITICALITIES, AttackPath, GraphEdge, GraphNode
from .attack_paths import compute_attack_paths
from .queries import build_index, count_by, expand, query, subgraph_index
from .scoring import REACH_RELS, VULN_REL, exposure_score_for

log = logging.getLogger('argus.graph')

__all__ = ['NodeDraft', 'EdgeDraft', 'GraphResult', 'upsert_node', 'upsert_edge', 'apply', 'mark_stale', 'query', 'neighbors',
           'attack_paths', 'exposure_score', 'recompute_exposure', 'recompute', 'stats', 'link_asset', 'node_to_dict', 'edge_to_dict',
           'path_to_dict']


@dataclass
class NodeDraft:
    kind: str
    key: str
    props: dict[str, Any] = field(default_factory=dict)
    label: str = ''
    criticality: str | None = None


@dataclass
class EdgeDraft:
    """Endpoints are (kind, key) pairs so collectors never need node ids."""

    src: tuple[str, str]
    dst: tuple[str, str]
    rel: str
    props: dict[str, Any] = field(default_factory=dict)


class GraphResult(Protocol):
    nodes: list[NodeDraft]
    edges: list[EdgeDraft]


def _clean_props(props: dict[str, Any] | None) -> dict[str, Any]:
    return {str(k): (redact(v) if isinstance(v, str) else v) for k, v in (props or {}).items()}


def _criticality(value: str | None) -> str | None:
    if value is None:
        return None
    value = str(value).lower()
    return value if value in CRITICALITIES else None


# ---------------------------------------------------------------- writes


def upsert_node(db: Session, tenant_id: str, kind: str, key: str, props: dict[str, Any] | None, source: str, *, label: str = '',
                criticality: str | None = None) -> GraphNode:
    """Create or refresh a node. Props merge (new keys win), last_seen_at bumps, staleness clears."""
    kind, key = kind[:24], key[:512]
    node = db.execute(select(GraphNode).where(GraphNode.tenant_id == tenant_id, GraphNode.kind == kind, GraphNode.key == key)).scalar_one_or_none()
    clean = _clean_props(props)
    now = utcnow()
    if node is None:
        node = GraphNode(tenant_id=tenant_id, kind=kind, key=key, label=redact(label or '')[:240], props_json=dumps(clean, limit=16000),
                         source=source[:40], criticality=_criticality(criticality) or 'medium', first_seen_at=now, last_seen_at=now,
                         is_stale=False)
        db.add(node)
    else:
        merged = loads(node.props_json)
        merged.update(clean)
        node.props_json = dumps(merged, limit=16000)
        if label:
            node.label = redact(label)[:240]
        if _criticality(criticality):
            node.criticality = _criticality(criticality)
        if source:
            node.source = source[:40]
        node.last_seen_at = now
        node.is_stale = False
    db.flush()
    return node


def upsert_edge(db: Session, tenant_id: str, src_id: str, dst_id: str, rel: str, props: dict[str, Any] | None, source: str) -> GraphEdge:
    rel = rel[:24]
    edge = db.execute(select(GraphEdge).where(GraphEdge.tenant_id == tenant_id, GraphEdge.src_id == src_id, GraphEdge.dst_id == dst_id,
                                              GraphEdge.rel == rel)).scalar_one_or_none()
    clean = _clean_props(props)
    now = utcnow()
    if edge is None:
        edge = GraphEdge(tenant_id=tenant_id, src_id=src_id, dst_id=dst_id, rel=rel, props_json=dumps(clean, limit=8000), source=source[:40],
                         first_seen_at=now, last_seen_at=now)
        db.add(edge)
    else:
        merged = loads(edge.props_json)
        merged.update(clean)
        edge.props_json = dumps(merged, limit=8000)
        if source:
            edge.source = source[:40]
        edge.last_seen_at = now
    db.flush()
    return edge


def _link_node_to_asset(db: Session, tenant_id: str, node: GraphNode, asset_id: str) -> bool:
    asset = db.get(Asset, asset_id)
    if asset is None or asset.tenant_id != tenant_id:
        return False
    if asset.graph_node_id != node.id:
        asset.graph_node_id = node.id
        return True
    return False


def mark_stale(db: Session, tenant_id: str, source: str, seen_keys: Iterable[tuple[str, str]]) -> int:
    """Mark nodes from `source` whose (kind, key) was not seen as stale. Returns how many changed."""
    seen = set(seen_keys)
    stale_ids: list[str] = []
    stmt = select(GraphNode.id, GraphNode.kind, GraphNode.key).where(GraphNode.tenant_id == tenant_id, GraphNode.source == source,
                                                                     GraphNode.is_stale.is_(False))
    for node_id, kind, key in db.execute(stmt).all():
        if (kind, key) not in seen:
            stale_ids.append(node_id)
    for start in range(0, len(stale_ids), 400):
        chunk = stale_ids[start:start + 400]
        db.execute(update(GraphNode).where(GraphNode.tenant_id == tenant_id, GraphNode.id.in_(chunk)).values(is_stale=True))
    return len(stale_ids)


def apply(db: Session, tenant_id: str, result: GraphResult, source: str) -> dict[str, int]:
    """Apply a collector result. Returns counters. Edges whose endpoints are unknown are skipped
    (counted), edges from this source between two re-seen nodes that were not re-asserted are removed."""
    stats = {'nodes_created': 0, 'nodes_updated': 0, 'edges_created': 0, 'edges_updated': 0, 'edges_skipped': 0, 'edges_removed': 0,
             'stale_marked': 0, 'assets_linked': 0}
    ids: dict[tuple[str, str], str] = {}
    for draft in result.nodes:
        existed = db.execute(select(func.count()).select_from(GraphNode).where(GraphNode.tenant_id == tenant_id, GraphNode.kind == draft.kind[:24],
                                                                              GraphNode.key == draft.key[:512])).scalar_one() > 0
        node = upsert_node(db, tenant_id, draft.kind, draft.key, draft.props, source, label=draft.label, criticality=draft.criticality)
        ids[(node.kind, node.key)] = node.id
        stats['nodes_updated' if existed else 'nodes_created'] += 1
        asset_id = (draft.props or {}).get('asset_id')
        if isinstance(asset_id, str) and asset_id and _link_node_to_asset(db, tenant_id, node, asset_id):
            stats['assets_linked'] += 1

    def resolve(ref: tuple[str, str]) -> str | None:
        kind, key = ref[0][:24], ref[1][:512]
        if (kind, key) in ids:
            return ids[(kind, key)]
        found = db.execute(select(GraphNode.id).where(GraphNode.tenant_id == tenant_id, GraphNode.kind == kind, GraphNode.key == key)).scalar_one_or_none()
        if found:
            ids[(kind, key)] = found
        return found

    asserted: set[tuple[str, str, str]] = set()
    for draft in result.edges:
        src_id, dst_id = resolve(tuple(draft.src)), resolve(tuple(draft.dst))
        if not src_id or not dst_id:
            stats['edges_skipped'] += 1
            continue
        existed = db.execute(select(func.count()).select_from(GraphEdge).where(GraphEdge.tenant_id == tenant_id, GraphEdge.src_id == src_id,
                                                                              GraphEdge.dst_id == dst_id, GraphEdge.rel == draft.rel[:24])).scalar_one() > 0
        edge = upsert_edge(db, tenant_id, src_id, dst_id, draft.rel, draft.props, source)
        asserted.add((edge.src_id, edge.dst_id, edge.rel))
        stats['edges_updated' if existed else 'edges_created'] += 1

    seen_node_ids = {ids[(d.kind[:24], d.key[:512])] for d in result.nodes if (d.kind[:24], d.key[:512]) in ids}
    if seen_node_ids:
        seen_list = sorted(seen_node_ids)
        for start in range(0, len(seen_list), 400):
            chunk = seen_list[start:start + 400]
            stmt = select(GraphEdge).where(GraphEdge.tenant_id == tenant_id, GraphEdge.source == source, GraphEdge.src_id.in_(chunk))
            for edge in db.execute(stmt).scalars().all():
                if edge.dst_id in seen_node_ids and (edge.src_id, edge.dst_id, edge.rel) not in asserted:
                    db.delete(edge)
                    stats['edges_removed'] += 1
    stats['stale_marked'] = mark_stale(db, tenant_id, source, [(d.kind[:24], d.key[:512]) for d in result.nodes])
    db.flush()
    log.info('graph apply source=%s tenant=%s %s', source, tenant_id, stats)
    publish_soon('graph.applied', {'tenant_id': tenant_id, 'source': source, **stats})
    return stats


def link_asset(db: Session, asset: Asset) -> GraphNode:
    """Ensure an `asset` node exists for an inventory Asset and point asset.graph_node_id at it."""
    node = db.get(GraphNode, asset.graph_node_id) if asset.graph_node_id else None
    if node is not None and node.tenant_id == asset.tenant_id:
        return node
    props = {'asset_id': asset.id, 'asset_kind': asset.kind, 'target': asset.target, 'environment': asset.environment, 'owner': asset.owner,
             'tags': loads(asset.tags_json, [])}
    node = upsert_node(db, asset.tenant_id, 'asset', f'inventory:{asset.id}', props, 'inventory', label=asset.name,
                       criticality=asset.criticality)
    asset.graph_node_id = node.id
    db.flush()
    return node


# ---------------------------------------------------------------- reads


def neighbors(db: Session, tenant_id: str, node_id: str, rels: Iterable[str] | None = None, depth: int = 1, direction: str = 'both',
              limit: int = 500) -> dict[str, list[dict]]:
    nodes, edges = expand(db, tenant_id, [node_id], rels=rels, depth=depth, direction=direction, limit=max(1, min(limit, 5000)))
    return {'nodes': [node_to_dict(n) for n in nodes.values()], 'edges': [edge_to_dict(e) for e in edges]}


def attack_paths(db: Session, tenant_id: str, from_kind: str = 'exposure', to_kind: str = 'data_store', max_hops: int = 6,
                 limit: int = 50) -> list[AttackPath]:
    return compute_attack_paths(db, tenant_id, from_kind=from_kind, to_kind=to_kind, max_hops=max_hops, limit=limit)


def exposure_score(db: Session, tenant_id: str, node_id: str) -> float:
    """0..100 for one node, computed from a bounded neighborhood and stored on the node."""
    node = db.execute(select(GraphNode).where(GraphNode.tenant_id == tenant_id, GraphNode.id == node_id)).scalar_one_or_none()
    if node is None:
        return 0.0
    index = subgraph_index(db, tenant_id, node_id)
    score = exposure_score_for(index, node_id)
    node.exposure_score = score
    db.flush()
    return score


def recompute_exposure(db: Session, tenant_id: str) -> int:
    """Score every non-stale node from one in-memory index. Returns the number scored."""
    index = build_index(db, tenant_id, rels=list(REACH_RELS | {VULN_REL}))
    scores = {nid: exposure_score_for(index, nid) for nid in index.nodes}
    for nid, score in scores.items():
        db.execute(update(GraphNode).where(GraphNode.tenant_id == tenant_id, GraphNode.id == nid).values(exposure_score=score))
    db.flush()
    return len(scores)


def recompute(db: Session, tenant_id: str, *, from_kind: str = 'exposure', to_kind: str = 'data_store', max_hops: int = 6,
              limit: int = 50) -> dict[str, Any]:
    paths = attack_paths(db, tenant_id, from_kind=from_kind, to_kind=to_kind, max_hops=max_hops, limit=limit)
    scored = recompute_exposure(db, tenant_id)
    return {'attack_paths': len(paths), 'nodes_scored': scored}


def stats(db: Session, tenant_id: str) -> dict[str, Any]:
    stale = db.scalar(select(func.count()).select_from(GraphNode).where(GraphNode.tenant_id == tenant_id, GraphNode.is_stale.is_(True))) or 0
    open_paths = db.scalar(select(func.count()).select_from(AttackPath).where(AttackPath.tenant_id == tenant_id, AttackPath.status == 'open')) or 0
    top = db.execute(select(GraphNode).where(GraphNode.tenant_id == tenant_id, GraphNode.is_stale.is_(False), GraphNode.exposure_score > 0)
                     .order_by(GraphNode.exposure_score.desc(), GraphNode.id).limit(10)).scalars().all()
    return {'nodes_by_kind': count_by(db, GraphNode.kind, tenant_id, GraphNode), 'edges_by_rel': count_by(db, GraphEdge.rel, tenant_id, GraphEdge),
            'stale_nodes': int(stale), 'attack_paths_open': int(open_paths),
            'top_exposed': [{'id': n.id, 'kind': n.kind, 'key': n.key, 'label': n.label, 'criticality': n.criticality,
                             'exposure_score': n.exposure_score} for n in top]}


# ---------------------------------------------------------------- serializers


def node_to_dict(node: GraphNode) -> dict[str, Any]:
    return {'id': node.id, 'kind': node.kind, 'key': node.key, 'label': node.label, 'props': loads(node.props_json), 'source': node.source,
            'criticality': node.criticality, 'exposure_score': node.exposure_score, 'first_seen_at': node.first_seen_at,
            'last_seen_at': node.last_seen_at, 'is_stale': bool(node.is_stale)}


def edge_to_dict(edge: GraphEdge) -> dict[str, Any]:
    return {'id': edge.id, 'src_id': edge.src_id, 'dst_id': edge.dst_id, 'rel': edge.rel, 'props': loads(edge.props_json), 'source': edge.source,
            'first_seen_at': edge.first_seen_at, 'last_seen_at': edge.last_seen_at}


def path_to_dict(path: AttackPath) -> dict[str, Any]:
    return {'id': path.id, 'from_node_id': path.from_node_id, 'to_node_id': path.to_node_id, 'hops': loads(path.hops_json, []),
            'score': path.score, 'summary': path.summary, 'status': path.status, 'computed_at': path.computed_at}
