"""Attack path enumeration: bounded DFS over reachability relations from one node kind to another,
scored and persisted as AttackPath rows (one best path per (from, to) pair)."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..models import dumps, utcnow
from ..models.graph import AttackPath, GraphNode
from .queries import build_index
from .scoring import REACH_RELS, VULN_REL, GraphIndex, NodeView, is_internet_facing, path_score, vuln_weight

log = logging.getLogger('sentinel.graph')

MAX_EXPANSIONS_PER_SOURCE = 20_000
MAX_EXPANSIONS_TOTAL = 400_000


@dataclass
class FoundPath:
    from_id: str
    to_id: str
    node_ids: list[str]
    rels: list[str]  # rels[i] is how node_ids[i+1] was reached
    score: float
    summary: str

    def hops(self, index: GraphIndex) -> list[dict]:
        hops = []
        for position, nid in enumerate(self.node_ids):
            node = index.nodes[nid]
            hops.append({'node_id': nid, 'kind': node.kind, 'key': node.key, 'label': node.label,
                         'rel': self.rels[position - 1] if position else None})
        return hops


def _describe(node: NodeView) -> str:
    return f'{node.kind} "{node.label or node.key}"'


def _score_path(index: GraphIndex, node_ids: list[str], vuln_cache: dict[str, tuple[float, bool]]) -> tuple[float, str]:
    source, target = index.nodes[node_ids[0]], index.nodes[node_ids[-1]]
    max_cvss, kev, has_vuln = 0.0, False, False
    for nid in node_ids:
        if nid not in vuln_cache:
            vulns = index.vulns_of(nid)
            vuln_cache[nid] = vuln_weight(vulns) if vulns else (0.0, False)
        cvss, node_kev = vuln_cache[nid]
        if cvss > 0:
            has_vuln = True
            max_cvss = max(max_cvss, cvss)
            kev = kev or node_kev
    internet = is_internet_facing(source)
    hops = len(node_ids) - 1
    score = path_score(target, hops, has_vuln=has_vuln, max_cvss=max_cvss, kev=kev, internet_facing=internet)
    notes = [f'{hops} hop{"s" if hops != 1 else ""}', f'{target.criticality} target']
    if internet:
        notes.append('internet facing')
    if has_vuln:
        notes.append('KEV vuln on path' if kev else f'vuln on path (cvss {max_cvss:.1f})')
    chain = ' -> '.join(_describe(index.nodes[nid]) for nid in node_ids)
    return score, f'{chain} ({", ".join(notes)})'


def enumerate_paths(index: GraphIndex, from_kind: str, to_kind: str, max_hops: int = 6) -> list[FoundPath]:
    """Simple-path DFS from every non-stale `from_kind` node to any `to_kind` node, keeping the
    best scoring path per (from, to) pair. Expansion budgets keep dense graphs bounded."""
    sources = [n.id for n in index.nodes.values() if n.kind == from_kind and not n.is_stale]
    best: dict[tuple[str, str], FoundPath] = {}
    vuln_cache: dict[str, tuple[float, bool]] = {}
    total_expansions = 0
    max_hops = max(1, min(max_hops, 10))
    for source in sources:
        expansions = 0
        stack: list[tuple[str, list[str], list[str]]] = [(source, [source], [])]
        while stack:
            current, path, rels = stack.pop()
            if expansions >= MAX_EXPANSIONS_PER_SOURCE or total_expansions >= MAX_EXPANSIONS_TOTAL:
                break
            for dst, rel in index.out.get(current, ()):
                if rel not in REACH_RELS or dst in path:
                    continue
                node = index.nodes.get(dst)
                if node is None or node.is_stale:
                    continue
                expansions += 1
                total_expansions += 1
                new_path, new_rels = path + [dst], rels + [rel]
                if node.kind == to_kind:
                    score, summary = _score_path(index, new_path, vuln_cache)
                    pair = (source, dst)
                    if pair not in best or score > best[pair].score or (score == best[pair].score and len(new_path) < len(best[pair].node_ids)):
                        best[pair] = FoundPath(source, dst, new_path, new_rels, score, summary)
                    continue  # a data store is a terminal; do not route through it
                if len(new_path) - 1 < max_hops:
                    stack.append((dst, new_path, new_rels))
    if total_expansions >= MAX_EXPANSIONS_TOTAL:
        log.warning('attack path enumeration hit the expansion budget; results are partial')
    return sorted(best.values(), key=lambda p: (-p.score, len(p.node_ids), p.from_id, p.to_id))


def compute_attack_paths(db: Session, tenant_id: str, from_kind: str = 'exposure', to_kind: str = 'data_store', max_hops: int = 6,
                         limit: int = 50) -> list[AttackPath]:
    """Enumerate, score and persist. For each (from, to) pair: an accepted path is refreshed in place
    and stays accepted; open paths are replaced; pairs that are no longer reachable are resolved."""
    index = build_index(db, tenant_id, rels=list(REACH_RELS | {VULN_REL}))
    found = enumerate_paths(index, from_kind, to_kind, max_hops)
    found_pairs = {(p.from_id, p.to_id) for p in found}
    now = utcnow()

    from_node, to_node = GraphNode.__table__.alias('from_node'), GraphNode.__table__.alias('to_node')
    existing_stmt = (select(AttackPath).join(from_node, from_node.c.id == AttackPath.from_node_id).join(to_node, to_node.c.id == AttackPath.to_node_id)
                     .where(AttackPath.tenant_id == tenant_id, AttackPath.status.in_(['open', 'accepted']),
                            from_node.c.kind == from_kind, to_node.c.kind == to_kind))
    existing: dict[tuple[str, str], list[AttackPath]] = {}
    for row in db.execute(existing_stmt).scalars():
        existing.setdefault((row.from_node_id, row.to_node_id), []).append(row)

    for pair, rows in existing.items():
        if pair not in found_pairs:
            for row in rows:
                if row.status == 'open':
                    row.status, row.computed_at = 'resolved', now

    persisted: list[AttackPath] = []
    for path in found[: max(1, limit)]:
        pair = (path.from_id, path.to_id)
        rows = existing.get(pair, [])
        accepted = next((r for r in rows if r.status == 'accepted'), None)
        hops_json = dumps(path.hops(index))
        if accepted is not None:
            accepted.hops_json, accepted.score, accepted.summary, accepted.computed_at = hops_json, path.score, path.summary, now
            for row in rows:
                if row is not accepted and row.status == 'open':
                    db.delete(row)
            persisted.append(accepted)
            continue
        open_ids = [r.id for r in rows if r.status == 'open']
        if open_ids:
            db.execute(delete(AttackPath).where(AttackPath.tenant_id == tenant_id, AttackPath.id.in_(open_ids)))
        record = AttackPath(tenant_id=tenant_id, from_node_id=path.from_id, to_node_id=path.to_id, hops_json=hops_json, score=path.score,
                            summary=path.summary[:4000], status='open', computed_at=now)
        db.add(record)
        persisted.append(record)
    db.flush()
    return persisted
