"""Evidence graph: nodes, edges and computed attack paths.

Nodes carry a stable natural key per kind (for example `aws:iam:user:arn:...`) so collectors
can upsert without knowing ids. Edges are typed relations between nodes. Attack paths are
materialized results of reachability analysis from one node kind to another.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Float, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, UTCDateTime, uid, utcnow

NODE_KINDS = ('asset', 'identity', 'role', 'permission', 'network', 'exposure', 'vuln', 'secret', 'data_store', 'finding', 'event',
              'canary', 'host', 'container', 'k8s_workload', 'cloud_resource', 'repo')
EDGE_RELS = ('owns', 'can_assume', 'has_permission', 'exposes', 'runs', 'connects_to', 'affected_by', 'accessed', 'triggered',
             'member_of', 'trusts', 'stores', 'reaches')
CRITICALITIES = ('low', 'medium', 'high', 'critical')
ATTACK_PATH_STATUSES = ('open', 'accepted', 'resolved')


class GraphNode(TenantMixin, Base):
    __tablename__ = 'graph_nodes'
    __table_args__ = (UniqueConstraint('tenant_id', 'kind', 'key', name='uq_graph_node_kind_key'),
                      Index('ix_graph_nodes_tenant_kind', 'tenant_id', 'kind'),
                      Index('ix_graph_nodes_tenant_source', 'tenant_id', 'source'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    kind: Mapped[str] = mapped_column(String(24))
    key: Mapped[str] = mapped_column(String(512))
    label: Mapped[str] = mapped_column(String(240), default='')
    props_json: Mapped[str] = mapped_column(Text, default='{}')
    source: Mapped[str] = mapped_column(String(40), default='')  # collector or package name
    criticality: Mapped[str] = mapped_column(String(12), default='medium')  # low, medium, high, critical
    exposure_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0..100, refreshed by graph.recompute
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    is_stale: Mapped[bool] = mapped_column(Boolean, default=False)


class GraphEdge(TenantMixin, Base):
    __tablename__ = 'graph_edges'
    __table_args__ = (UniqueConstraint('tenant_id', 'src_id', 'dst_id', 'rel', name='uq_graph_edge'),
                      Index('ix_graph_edges_tenant_rel', 'tenant_id', 'rel'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    src_id: Mapped[str] = mapped_column(String(36), ForeignKey('graph_nodes.id', ondelete='CASCADE'), index=True)
    dst_id: Mapped[str] = mapped_column(String(36), ForeignKey('graph_nodes.id', ondelete='CASCADE'), index=True)
    rel: Mapped[str] = mapped_column(String(24))
    props_json: Mapped[str] = mapped_column(Text, default='{}')
    source: Mapped[str] = mapped_column(String(40), default='')
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class AttackPath(TenantMixin, Base):
    __tablename__ = 'attack_paths'
    __table_args__ = (Index('ix_attack_paths_tenant_status', 'tenant_id', 'status'),
                      Index('ix_attack_paths_tenant_pair', 'tenant_id', 'from_node_id', 'to_node_id'))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    from_node_id: Mapped[str] = mapped_column(String(36), ForeignKey('graph_nodes.id', ondelete='CASCADE'))
    to_node_id: Mapped[str] = mapped_column(String(36), ForeignKey('graph_nodes.id', ondelete='CASCADE'))
    hops_json: Mapped[str] = mapped_column(Text, default='[]')  # ordered [{node_id, kind, key, label, rel}], rel is how the hop was reached
    score: Mapped[float] = mapped_column(Float, default=0.0)
    summary: Mapped[str] = mapped_column(Text, default='')
    status: Mapped[str] = mapped_column(String(12), default='open')  # open, accepted, resolved
    computed_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
