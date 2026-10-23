"""Pure scoring functions for the evidence graph.

Everything here works on an in-memory view of a (sub)graph so the same code serves the
single-node `exposure_score()` call and the batch recompute job. No database access.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

# Relations along which an attacker who controls the source can plausibly reach the target.
REACH_RELS: frozenset[str] = frozenset({'exposes', 'can_assume', 'has_permission', 'connects_to', 'reaches', 'runs', 'stores', 'member_of', 'trusts'})
VULN_REL = 'affected_by'

CRITICALITY_BASE = {'low': 30.0, 'medium': 50.0, 'high': 70.0, 'critical': 90.0}
CRITICALITY_BONUS = {'low': 5.0, 'medium': 10.0, 'high': 15.0, 'critical': 20.0}
PRIVILEGED_KINDS = frozenset({'role', 'permission', 'identity'})
INTERNET_PROPS = ('internet_facing', 'public', 'public_ip', 'exposed_to_internet', 'internet')


@dataclass
class NodeView:
    id: str
    kind: str
    key: str
    label: str
    criticality: str
    props: dict[str, Any]
    is_stale: bool = False


@dataclass
class GraphIndex:
    """Adjacency over a set of nodes. Built once per tenant for batch work, or from a bounded
    neighborhood for single-node scoring."""

    nodes: dict[str, NodeView] = field(default_factory=dict)
    out: dict[str, list[tuple[str, str]]] = field(default_factory=lambda: defaultdict(list))  # src -> [(dst, rel)]
    inc: dict[str, list[tuple[str, str]]] = field(default_factory=lambda: defaultdict(list))  # dst -> [(src, rel)]

    def add_node(self, node: NodeView) -> None:
        self.nodes[node.id] = node

    def add_edge(self, src_id: str, dst_id: str, rel: str) -> None:
        self.out[src_id].append((dst_id, rel))
        self.inc[dst_id].append((src_id, rel))

    def vulns_of(self, node_id: str) -> list[NodeView]:
        return [self.nodes[d] for d, rel in self.out.get(node_id, ()) if rel == VULN_REL and d in self.nodes and self.nodes[d].kind == 'vuln']

    def reachable(self, node_id: str, depth: int, rels: Iterable[str] = REACH_RELS, limit: int = 2000) -> dict[str, int]:
        """BFS along `rels` from node_id. Returns {node_id: distance} excluding the start node and stale nodes."""
        allowed = set(rels)
        seen: dict[str, int] = {node_id: 0}
        frontier = [node_id]
        for distance in range(1, depth + 1):
            nxt: list[str] = []
            for current in frontier:
                for dst, rel in self.out.get(current, ()):
                    if rel not in allowed or dst in seen:
                        continue
                    node = self.nodes.get(dst)
                    if node is None or node.is_stale:
                        continue
                    seen[dst] = distance
                    nxt.append(dst)
                    if len(seen) > limit:
                        break
            frontier = nxt
            if not frontier or len(seen) > limit:
                break
        seen.pop(node_id, None)
        return seen


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {'1', 'true', 'yes', 'y', 'public', 'internet', '0.0.0.0/0', '::/0'}
    return bool(value)


def is_internet_facing(node: NodeView) -> bool:
    props = node.props or {}
    for name in INTERNET_PROPS:
        if name in props and _truthy(props[name]):
            return True
    if node.kind == 'exposure':
        scope = str(props.get('scope') or props.get('cidr') or props.get('source') or '').lower()
        if scope in {'internet', 'public', '0.0.0.0/0', '::/0', 'any'}:
            return True
    return False


def is_privileged(node: NodeView) -> bool:
    props = node.props or {}
    if any(_truthy(props.get(name)) for name in ('admin', 'privileged', 'is_admin', 'wildcard')):
        return True
    text = f'{node.key} {node.label} {props.get("name", "")}'.lower()
    return node.kind in PRIVILEGED_KINDS and any(token in text for token in ('admin', 'root', 'owner', 'cluster-admin', '*'))


def vuln_weight(vulns: Iterable[NodeView]) -> tuple[float, bool]:
    """(max cvss, any kev) across vuln nodes. Missing cvss counts as 5.0 so an unscored vuln still matters."""
    max_cvss, kev = 0.0, False
    for vuln in vulns:
        props = vuln.props or {}
        try:
            cvss = float(props.get('cvss') or props.get('cvss_score') or 5.0)
        except (TypeError, ValueError):
            cvss = 5.0
        max_cvss = max(max_cvss, min(10.0, cvss))
        kev = kev or _truthy(props.get('kev'))
    return max_cvss, kev


def _clamp(value: float) -> float:
    return round(max(0.0, min(100.0, value)), 2)


def exposure_score_for(index: GraphIndex, node_id: str) -> float:
    """0..100: internet exposure + attached vulns (cvss/kev) + privileges reachable + own criticality."""
    node = index.nodes.get(node_id)
    if node is None:
        return 0.0
    score = 0.0
    internet = is_internet_facing(node) or any(
        rel == 'exposes' and src in index.nodes and index.nodes[src].kind == 'exposure' and is_internet_facing(index.nodes[src])
        for src, rel in index.inc.get(node_id, ()))
    if internet:
        score += 30.0
    elif node.kind == 'exposure' or any(rel == 'exposes' for _, rel in index.inc.get(node_id, ())):
        score += 12.0
    vulns = index.vulns_of(node_id)
    if vulns:
        max_cvss, kev = vuln_weight(vulns)
        score += min(25.0, max_cvss * 2.5) + (10.0 if kev else 0.0)
    reach = index.reachable(node_id, depth=3)
    privileged = sum(1 for nid in reach if is_privileged(index.nodes[nid]))
    stores = sum(1 for nid in reach if index.nodes[nid].kind == 'data_store')
    score += min(20.0, 6.0 * privileged + 4.0 * stores + 0.5 * len(reach))
    score += CRITICALITY_BONUS.get(node.criticality, 10.0)
    return _clamp(score)


def path_score(target: NodeView, hops: int, *, has_vuln: bool, max_cvss: float, kev: bool, internet_facing: bool) -> float:
    """0..100: target criticality attenuated by path length, boosted by vulns on the path and internet reachability."""
    base = CRITICALITY_BASE.get(target.criticality, 50.0)
    score = base * max(0.4, 1.0 - 0.1 * max(0, hops - 1))
    if internet_facing:
        score += 10.0
    if has_vuln:
        score += 8.0 + min(7.0, max_cvss * 0.7)
        if kev:
            score += 5.0
    return _clamp(score)
