from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from sqlalchemy import select

from app.graph import service
from app.graph.service import EdgeDraft, NodeDraft
from app.models import Asset, AuditEntry
from app.models.graph import AttackPath, GraphEdge, GraphNode
from tests.conftest import wait_job


@dataclass
class Result:
    nodes: list[NodeDraft] = field(default_factory=list)
    edges: list[EdgeDraft] = field(default_factory=list)


def estate(prefix: str = '') -> Result:
    """exposure -> host -> role -> data_store (critical) plus a second, low-criticality store and a KEV vuln on the host."""
    p = prefix
    return Result(
        nodes=[
            NodeDraft('exposure', f'{p}sg:0.0.0.0/0:22', {'internet_facing': True, 'port': 22}, label='ssh from anywhere'),
            NodeDraft('host', f'{p}aws:ec2:i-1', {'ip': '10.0.0.5'}, label='web-1', criticality='high'),
            NodeDraft('role', f'{p}aws:iam:role/admin', {'admin': True}, label='admin role'),
            NodeDraft('data_store', f'{p}aws:rds:customers', {'engine': 'postgres'}, label='customer-db', criticality='critical'),
            NodeDraft('data_store', f'{p}aws:s3:logs', {}, label='logs-bucket', criticality='low'),
            NodeDraft('vuln', f'{p}cve:CVE-2024-3094', {'cvss': 10.0, 'kev': True}, label='CVE-2024-3094'),
        ],
        edges=[
            EdgeDraft(('exposure', f'{p}sg:0.0.0.0/0:22'), ('host', f'{p}aws:ec2:i-1'), 'exposes'),
            EdgeDraft(('host', f'{p}aws:ec2:i-1'), ('role', f'{p}aws:iam:role/admin'), 'can_assume'),
            EdgeDraft(('role', f'{p}aws:iam:role/admin'), ('data_store', f'{p}aws:rds:customers'), 'has_permission', {'actions': ['rds:*']}),
            EdgeDraft(('role', f'{p}aws:iam:role/admin'), ('data_store', f'{p}aws:s3:logs'), 'has_permission'),
            EdgeDraft(('host', f'{p}aws:ec2:i-1'), ('vuln', f'{p}cve:CVE-2024-3094'), 'affected_by'),
        ],
    )


def node_id(db, tenant_id: str, kind: str, key: str) -> str:
    return db.execute(select(GraphNode.id).where(GraphNode.tenant_id == tenant_id, GraphNode.kind == kind, GraphNode.key == key)).scalar_one()


# ---------------------------------------------------------------- service


def test_upsert_node_idempotent_and_merges_props(db, default_tenant_id):
    first = service.upsert_node(db, default_tenant_id, 'identity', 'aws:iam:user:alice', {'a': 1, 'token': 'Bearer abcdefghijklmnopqrstuvwxyz'},
                                'aws', label='alice')
    second = service.upsert_node(db, default_tenant_id, 'identity', 'aws:iam:user:alice', {'b': 2}, 'aws', criticality='high')
    assert first.id == second.id
    props = service.node_to_dict(second)['props']
    assert props['a'] == 1 and props['b'] == 2 and 'abcdefghijklmnopqrstuvwxyz' not in props['token']
    assert second.label == 'alice' and second.criticality == 'high' and second.is_stale is False
    assert second.last_seen_at >= first.first_seen_at
    assert db.scalar(select(GraphNode.id).where(GraphNode.kind == 'identity')) and \
        len(db.execute(select(GraphNode).where(GraphNode.tenant_id == default_tenant_id, GraphNode.kind == 'identity')).scalars().all()) == 1
    other = service.upsert_node(db, default_tenant_id, 'identity', 'aws:iam:user:alice', {}, 'aws')
    edge1 = service.upsert_edge(db, default_tenant_id, first.id, other.id, 'trusts', {'x': 1}, 'aws')
    edge2 = service.upsert_edge(db, default_tenant_id, first.id, other.id, 'trusts', {'y': 2}, 'aws')
    assert edge1.id == edge2.id and service.edge_to_dict(edge2)['props'] == {'x': 1, 'y': 2}


def test_apply_marks_unseen_nodes_stale_and_removes_dropped_edges(db, default_tenant_id):
    stats = service.apply(db, default_tenant_id, estate(), 'aws')
    assert stats['nodes_created'] == 6 and stats['edges_created'] == 5 and stats['stale_marked'] == 0
    # Second run: the logs bucket disappeared and the host no longer assumes the admin role.
    smaller = estate()
    smaller.nodes = [n for n in smaller.nodes if n.key != 'aws:s3:logs']
    smaller.edges = [e for e in smaller.edges if not (e.rel == 'can_assume') and e.dst[1] != 'aws:s3:logs']
    stats = service.apply(db, default_tenant_id, smaller, 'aws')
    assert stats['nodes_updated'] == 5 and stats['nodes_created'] == 0 and stats['stale_marked'] == 1 and stats['edges_removed'] == 1
    logs = db.execute(select(GraphNode).where(GraphNode.key == 'aws:s3:logs')).scalar_one()
    assert logs.is_stale is True
    host, role = node_id(db, default_tenant_id, 'host', 'aws:ec2:i-1'), node_id(db, default_tenant_id, 'role', 'aws:iam:role/admin')
    assert db.execute(select(GraphEdge).where(GraphEdge.src_id == host, GraphEdge.dst_id == role)).scalar_one_or_none() is None
    # A different source does not touch this source's nodes; unknown endpoints are skipped.
    stats = service.apply(db, default_tenant_id, Result(nodes=[NodeDraft('identity', 'okta:user:bob')],
                                                        edges=[EdgeDraft(('identity', 'okta:user:bob'), ('role', 'missing'), 'member_of')]), 'okta')
    assert stats['edges_skipped'] == 1 and stats['stale_marked'] == 0
    assert db.execute(select(GraphNode).where(GraphNode.key == 'aws:ec2:i-1')).scalar_one().is_stale is False
    # Re-seeing the bucket clears staleness.
    service.apply(db, default_tenant_id, estate(), 'aws')
    db.refresh(logs)
    assert logs.is_stale is False
    assert service.query(db, default_tenant_id, kind='data_store', props_filter={'engine': 'postgres'})[0].key == 'aws:rds:customers'
    assert [n.key for n in service.query(db, default_tenant_id, search='customer')] == ['aws:rds:customers']


def test_neighbors_depth_two_is_bounded(db, default_tenant_id):
    service.apply(db, default_tenant_id, estate(), 'aws')
    exposure = node_id(db, default_tenant_id, 'exposure', 'sg:0.0.0.0/0:22')
    one = service.neighbors(db, default_tenant_id, exposure, depth=1)
    assert {n['kind'] for n in one['nodes']} == {'exposure', 'host'} and len(one['edges']) == 1
    two = service.neighbors(db, default_tenant_id, exposure, depth=2)
    assert {n['kind'] for n in two['nodes']} == {'exposure', 'host', 'role', 'vuln'}
    assert {e['rel'] for e in two['edges']} == {'exposes', 'can_assume', 'affected_by'}
    out_only = service.neighbors(db, default_tenant_id, exposure, depth=2, direction='out', rels=['exposes'])
    assert {n['kind'] for n in out_only['nodes']} == {'exposure', 'host'}
    capped = service.neighbors(db, default_tenant_id, exposure, depth=4, limit=2)
    assert len(capped['edges']) == 2


def test_attack_paths_found_and_ordered_by_score(db, default_tenant_id):
    service.apply(db, default_tenant_id, estate(), 'aws')
    paths = service.attack_paths(db, default_tenant_id)
    assert len(paths) == 2
    first, second = (service.path_to_dict(p) for p in paths)
    assert [h['kind'] for h in first['hops']] == ['exposure', 'host', 'role', 'data_store']
    assert [h['rel'] for h in first['hops']] == [None, 'exposes', 'can_assume', 'has_permission']
    assert first['hops'][-1]['label'] == 'customer-db' and second['hops'][-1]['label'] == 'logs-bucket'
    assert first['score'] > second['score'] > 0 and 'KEV' in first['summary'] and 'internet facing' in first['summary']
    # Recompute replaces open paths instead of duplicating them; accepted paths survive.
    paths[1].status = 'accepted'
    db.flush()
    again = service.attack_paths(db, default_tenant_id)
    assert len(again) == 2 and len(db.execute(select(AttackPath).where(AttackPath.tenant_id == default_tenant_id)).scalars().all()) == 2
    assert {p.status for p in again} == {'open', 'accepted'}
    # When the route disappears the open path is resolved.
    for edge in db.execute(select(GraphEdge).where(GraphEdge.rel == 'can_assume')).scalars():
        db.delete(edge)
    db.flush()
    assert service.attack_paths(db, default_tenant_id) == []
    statuses = {p.hops_json.count('customer-db') > 0: p.status for p in db.execute(select(AttackPath)).scalars()}
    assert statuses[True] == 'resolved'


def test_exposure_score_and_stats_and_link_asset(db, default_tenant_id):
    service.apply(db, default_tenant_id, estate(), 'aws')
    host = node_id(db, default_tenant_id, 'host', 'aws:ec2:i-1')
    logs = node_id(db, default_tenant_id, 'data_store', 'aws:s3:logs')
    host_score, logs_score = service.exposure_score(db, default_tenant_id, host), service.exposure_score(db, default_tenant_id, logs)
    assert 0 < logs_score < host_score <= 100
    assert service.exposure_score(db, default_tenant_id, 'nope') == 0.0
    asset = Asset(tenant_id=default_tenant_id, name='web-1', kind='host', target='10.0.0.5', criticality='high')
    db.add(asset)
    db.flush()
    node = service.link_asset(db, asset)
    assert node.kind == 'asset' and asset.graph_node_id == node.id and service.link_asset(db, asset).id == node.id
    # apply() links a collector node that names the asset id when the asset is not linked yet.
    asset2 = Asset(tenant_id=default_tenant_id, name='db', kind='database', target='rds', criticality='critical')
    db.add(asset2)
    db.flush()
    stats = service.apply(db, default_tenant_id, Result(nodes=[NodeDraft('cloud_resource', 'aws:rds:db', {'asset_id': asset2.id})]), 'aws-rds')
    assert stats['assets_linked'] == 1 and asset2.graph_node_id == node_id(db, default_tenant_id, 'cloud_resource', 'aws:rds:db')
    summary = service.stats(db, default_tenant_id)
    assert summary['nodes_by_kind']['data_store'] == 2 and summary['edges_by_rel']['has_permission'] == 2
    assert summary['top_exposed'][0]['id'] == host and summary['stale_nodes'] == 0


# ---------------------------------------------------------------- API


@pytest.fixture
def seeded(owner, db, default_tenant_id):
    service.apply(db, default_tenant_id, estate(), 'aws')
    service.attack_paths(db, default_tenant_id)
    service.recompute_exposure(db, default_tenant_id)
    db.commit()
    client, headers = owner
    return client, headers


def test_graph_endpoints(seeded, db, default_tenant_id):
    client, headers = seeded
    nodes = client.get('/api/v1/graph/nodes?kind=data_store').json()
    assert {n['label'] for n in nodes['items']} == {'customer-db', 'logs-bucket'} and nodes['next_cursor'] is None
    paged = client.get('/api/v1/graph/nodes?limit=2').json()
    assert len(paged['items']) == 2 and paged['next_cursor'] == '2'
    assert client.get('/api/v1/graph/nodes?search=web').json()['items'][0]['key'] == 'aws:ec2:i-1'
    host = node_id(db, default_tenant_id, 'host', 'aws:ec2:i-1')
    assert client.get(f'/api/v1/graph/nodes/{host}').json()['label'] == 'web-1'
    nb = client.get(f'/api/v1/graph/nodes/{host}/neighbors?depth=2&rels=can_assume,has_permission&direction=out').json()
    assert {n['kind'] for n in nb['nodes']} == {'host', 'role', 'data_store'}
    assert client.get(f'/api/v1/graph/nodes/{host}/neighbors?depth=9').status_code == 422
    paths = client.get('/api/v1/graph/attack-paths?status=open').json()['items']
    assert len(paths) == 2 and paths[0]['score'] >= paths[1]['score']
    assert client.get(f"/api/v1/graph/attack-paths/{paths[0]['id']}").json()['id'] == paths[0]['id']
    patched = client.patch(f"/api/v1/graph/attack-paths/{paths[0]['id']}", json={'status': 'accepted', 'comment': 'bastion only'}, headers=headers)
    assert patched.status_code == 200 and patched.json()['status'] == 'accepted'
    assert client.patch(f"/api/v1/graph/attack-paths/{paths[0]['id']}", json={'status': 'bogus'}, headers=headers).status_code == 400
    assert len(client.get('/api/v1/graph/attack-paths?status=open').json()['items']) == 1
    assert db.execute(select(AuditEntry).where(AuditEntry.action == 'graph.attack_path_status')).scalar_one().subject == paths[0]['id']
    exposures = client.get('/api/v1/graph/exposures?limit=3').json()['items']
    assert exposures[0]['id'] == host and exposures[0]['exposure_score'] >= exposures[-1]['exposure_score']
    stats = client.get('/api/v1/graph/stats').json()
    assert stats['nodes_by_kind']['host'] == 1 and stats['attack_paths_open'] == 1 and stats['top_exposed'][0]['id'] == host


def test_recompute_job_completes(seeded, db, default_tenant_id):
    client, headers = seeded
    for row in db.execute(select(AttackPath)).scalars():
        db.delete(row)
    db.commit()
    assert client.post('/api/v1/graph/recompute', json={}).status_code == 403  # CSRF
    queued = client.post('/api/v1/graph/recompute', json={}, headers=headers)
    assert queued.status_code == 202, queued.text
    job = wait_job(client, headers, queued.json()['job_id'])
    assert job['status'] == 'completed', job
    assert job['result']['attack_paths'] == 2 and job['result']['nodes_scored'] == 6
    assert len(client.get('/api/v1/graph/attack-paths?status=open').json()['items']) == 2
    assert db.execute(select(AuditEntry).where(AuditEntry.action == 'graph.recompute')).scalar_one()


def test_viewer_cannot_recompute(client, make_user, seeded):
    from tests.conftest import login

    make_user('viewer@test.local', 'viewer-password-long-1', 'viewer')
    headers = login(client, 'viewer@test.local', 'viewer-password-long-1')
    assert client.get('/api/v1/graph/stats', headers=headers).status_code == 200
    assert client.post('/api/v1/graph/recompute', json={}, headers=headers).status_code == 403


def test_cross_tenant_isolation_on_every_endpoint(seeded, second_tenant, db, default_tenant_id):
    client, headers = seeded
    other, other_headers = second_tenant['client'], second_tenant['headers']
    host = node_id(db, default_tenant_id, 'host', 'aws:ec2:i-1')
    path_id = client.get('/api/v1/graph/attack-paths').json()['items'][0]['id']
    assert other.get('/api/v1/graph/nodes').json()['items'] == []
    assert other.get('/api/v1/graph/nodes?search=web').json()['items'] == []
    assert other.get(f'/api/v1/graph/nodes/{host}').status_code == 404
    assert other.get(f'/api/v1/graph/nodes/{host}/neighbors').status_code == 404
    assert other.get('/api/v1/graph/attack-paths').json()['items'] == []
    assert other.get(f'/api/v1/graph/attack-paths/{path_id}').status_code == 404
    assert other.patch(f'/api/v1/graph/attack-paths/{path_id}', json={'status': 'resolved'}, headers=other_headers).status_code == 404
    assert other.get('/api/v1/graph/exposures').json()['items'] == []
    stats = other.get('/api/v1/graph/stats').json()
    assert stats['nodes_by_kind'] == {} and stats['attack_paths_open'] == 0 and stats['top_exposed'] == []
    # Service-level: the other tenant's graph is invisible to queries and traversal even with a known id.
    assert service.neighbors(db, second_tenant['tenant_id'], host) == {'nodes': [], 'edges': []}
    assert service.exposure_score(db, second_tenant['tenant_id'], host) == 0.0
    # Same natural keys in the other tenant create separate nodes and separate paths.
    service.apply(db, second_tenant['tenant_id'], estate(), 'aws')
    db.commit()
    assert len(service.attack_paths(db, second_tenant['tenant_id'])) == 2
    db.commit()
    assert len(client.get('/api/v1/graph/attack-paths').json()['items']) == 2
    assert len(other.get('/api/v1/graph/attack-paths').json()['items']) == 2
    assert other.patch(f'/api/v1/graph/attack-paths/{path_id}', json={'status': 'resolved'}, headers=other_headers).status_code == 404
    assert client.get(f'/api/v1/graph/attack-paths/{path_id}').json()['status'] == 'open'
