"""Bounded read queries over the evidence graph: node search, neighborhoods, index loading."""
from __future__ import annotations

import json
from typing import Any, Iterable

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..models import loads
from ..models.graph import GraphEdge, GraphNode
from .scoring import GraphIndex, NodeView

IN_CHUNK = 400  # keep IN (...) lists under SQLite's bound-parameter limits
MAX_INDEX_EDGES = 200_000
MAX_INDEX_NODES = 100_000


def _chunks(items: list[str], size: int = IN_CHUNK) -> Iterable[list[str]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


def node_view(node: GraphNode) -> NodeView:
    return NodeView(id=node.id, kind=node.kind, key=node.key, label=node.label, criticality=node.criticality,
                    props=loads(node.props_json), is_stale=bool(node.is_stale))


def _props_fragments(props_filter: dict[str, Any]) -> list[str]:
    """props_json is compact, key-sorted JSON (models.base.dumps), so `"k":<json v>` is a reliable substring match."""
    return [json.dumps({k: v}, default=str, sort_keys=True, separators=(',', ':'))[1:-1] for k, v in props_filter.items()]


def query(db: Session, tenant_id: str, kind: str | None = None, key: str | None = None, props_filter: dict[str, Any] | None = None,
          search: str | None = None, limit: int = 200, offset: int = 0, *, include_stale: bool = True) -> list[GraphNode]:
    stmt = select(GraphNode).where(GraphNode.tenant_id == tenant_id)
    if kind:
        stmt = stmt.where(GraphNode.kind == kind)
    if key:
        stmt = stmt.where(GraphNode.key == key)
    if not include_stale:
        stmt = stmt.where(GraphNode.is_stale.is_(False))
    for fragment in _props_fragments(props_filter or {}):
        stmt = stmt.where(GraphNode.props_json.contains(fragment, autoescape=True))
    if search:
        needle = f'%{search.strip()}%'
        stmt = stmt.where(or_(GraphNode.label.ilike(needle), GraphNode.key.ilike(needle)))
    stmt = stmt.order_by(GraphNode.last_seen_at.desc(), GraphNode.id).offset(max(0, offset)).limit(max(1, min(1000, limit)))
    return list(db.execute(stmt).scalars().all())


def load_nodes(db: Session, tenant_id: str, ids: Iterable[str]) -> dict[str, GraphNode]:
    wanted = list(dict.fromkeys(ids))
    found: dict[str, GraphNode] = {}
    for chunk in _chunks(wanted):
        for node in db.execute(select(GraphNode).where(GraphNode.tenant_id == tenant_id, GraphNode.id.in_(chunk))).scalars():
            found[node.id] = node
    return found


def expand(db: Session, tenant_id: str, seeds: Iterable[str], *, rels: Iterable[str] | None = None, depth: int = 1,
           direction: str = 'both', limit: int = 500) -> tuple[dict[str, GraphNode], list[GraphEdge]]:
    """Frontier BFS over edges. Loads only edges touching the frontier at each level and at most
    `limit` edges in total; never scans the whole graph."""
    rel_list = [r for r in (rels or []) if r]
    seen_nodes: set[str] = set(seeds)
    frontier: list[str] = list(seen_nodes)
    edges: dict[str, GraphEdge] = {}
    for _ in range(max(1, min(depth, 6))):
        if not frontier or len(edges) >= limit:
            break
        discovered: set[str] = set()
        for chunk in _chunks(frontier):
            if direction == 'out':
                cond = GraphEdge.src_id.in_(chunk)
            elif direction == 'in':
                cond = GraphEdge.dst_id.in_(chunk)
            else:
                cond = or_(GraphEdge.src_id.in_(chunk), GraphEdge.dst_id.in_(chunk))
            stmt = select(GraphEdge).where(GraphEdge.tenant_id == tenant_id, cond)
            if rel_list:
                stmt = stmt.where(GraphEdge.rel.in_(rel_list))
            stmt = stmt.order_by(GraphEdge.last_seen_at.desc()).limit(limit - len(edges) + 1)
            for edge in db.execute(stmt).scalars():
                if len(edges) >= limit:
                    break
                if edge.id in edges:
                    continue
                edges[edge.id] = edge
                for nid in (edge.src_id, edge.dst_id):
                    if nid not in seen_nodes:
                        discovered.add(nid)
        seen_nodes |= discovered
        frontier = sorted(discovered)
    nodes = load_nodes(db, tenant_id, seen_nodes)
    return nodes, list(edges.values())


def count_by(db: Session, column, tenant_id: str, model) -> dict[str, int]:
    rows = db.execute(select(column, func.count()).where(model.tenant_id == tenant_id).group_by(column)).all()
    return {str(k): int(n) for k, n in rows}


def build_index(db: Session, tenant_id: str, *, rels: Iterable[str] | None = None, include_stale: bool = False) -> GraphIndex:
    """Load the tenant's graph into memory for batch analysis. Bounded by MAX_INDEX_* constants;
    the caller should expect truncation on pathological tenants and log it."""
    index = GraphIndex()
    stmt = select(GraphNode).where(GraphNode.tenant_id == tenant_id)
    if not include_stale:
        stmt = stmt.where(GraphNode.is_stale.is_(False))
    for node in db.execute(stmt.limit(MAX_INDEX_NODES)).scalars():
        index.add_node(node_view(node))
    estmt = select(GraphEdge.src_id, GraphEdge.dst_id, GraphEdge.rel).where(GraphEdge.tenant_id == tenant_id)
    rel_list = [r for r in (rels or []) if r]
    if rel_list:
        estmt = estmt.where(GraphEdge.rel.in_(rel_list))
    for src, dst, rel in db.execute(estmt.limit(MAX_INDEX_EDGES)).all():
        if src in index.nodes and dst in index.nodes:
            index.add_edge(src, dst, rel)
    return index


def subgraph_index(db: Session, tenant_id: str, node_id: str, *, depth: int = 3, limit: int = 2000) -> GraphIndex:
    """Index of the outbound neighborhood of one node plus the inbound `exposes` edges that
    tell us whether something internet-facing points at it."""
    nodes, edges = expand(db, tenant_id, [node_id], depth=depth, direction='out', limit=limit)
    inbound_nodes, inbound_edges = expand(db, tenant_id, [node_id], rels=['exposes'], depth=1, direction='in', limit=200)
    index = GraphIndex()
    for node in list(nodes.values()) + list(inbound_nodes.values()):
        index.add_node(node_view(node))
    seen: set[str] = set()
    for edge in edges + inbound_edges:
        if edge.id in seen:
            continue
        seen.add(edge.id)
        index.add_edge(edge.src_id, edge.dst_id, edge.rel)
    return index
