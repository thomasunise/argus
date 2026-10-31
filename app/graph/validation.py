"""Explain which attack-path edges have verifiable test evidence attached.

A graph route is a reachability hypothesis, not proof of compromise. We call it
'evidence_linked' only when each edge references a completed, tenant-owned test
result. This does not claim exploit feasibility or successful exploitation.
"""
from __future__ import annotations

from sqlalchemy import select

from ..models import loads
from ..models.graph import GraphNode, GraphEdge
from ..models.testing import TestResult, TestRun


def validate_path(db, tenant_id: str, path) -> dict:
    hops = loads(path.hops_json, [])
    edges = []
    for src, dst in zip(hops, hops[1:]):
        src_id, dst_id, rel = src.get('node_id'), dst.get('node_id'), dst.get('rel')
        edge = db.execute(select(GraphEdge).where(GraphEdge.tenant_id == tenant_id,
                         GraphEdge.src_id == src_id, GraphEdge.dst_id == dst_id,
                         GraphEdge.rel == rel)).scalar_one_or_none()
        nodes = db.execute(select(GraphNode).where(GraphNode.tenant_id == tenant_id,
                           GraphNode.id.in_([src_id, dst_id]))).scalars().all()
        stale = len(nodes) != 2 or any(n.is_stale for n in nodes)
        status = 'missing_edge' if edge is None else 'stale' if stale else 'unverified'
        evidence_id = None
        if edge is not None and not stale:
            reference = str(loads(edge.props_json, {}).get('test_result_id') or '')
            result = db.get(TestResult, reference) if reference else None
            run = db.get(TestRun, result.run_id) if result is not None and result.tenant_id == tenant_id else None
            if run is not None and run.tenant_id == tenant_id and run.status == 'completed' and run.asset_id:
                evidence_id = result.id
                status = 'evidence_linked'
        edges.append({'from_node_id': src_id, 'to_node_id': dst_id, 'relation': rel,
                      'status': status, 'test_result_id': evidence_id})
    if not edges or any(e['status'] in {'stale', 'missing_edge'} for e in edges):
        state = 'incomplete'
    elif all(e['status'] == 'evidence_linked' for e in edges):
        state = 'evidence_linked'
    elif any(e['status'] == 'evidence_linked' for e in edges):
        state = 'partially_supported'
    else:
        state = 'unverified'
    return {'path_id': path.id, 'validation_status': state,
            'heuristic_score': path.score, 'score_is_proof': False,
            'exploitability_verified': False, 'edges': edges}
