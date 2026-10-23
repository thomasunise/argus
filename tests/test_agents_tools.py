"""Agent tools against seeded data, graceful degradation for missing sibling packages, and
tenant isolation."""
from __future__ import annotations

import types

import httpx
import pytest
from sqlalchemy import select

from app.agents.tools import actions, assets, detections, events, findings, graph, intel, memory, tests_tool  # noqa: F401
from app.agents.tools.registry import registry
from app.core.audit import record_audit
from app.core.rbac import Role
from app.models import AuditEntry
from tests.test_agents_support import fake_modules, module, no_network, principal_for, seed_estate, tool_ctx  # noqa: F401



async def call(ctx, name, **args):
    tool = registry.get(name)
    assert not tool.validate(args), tool.validate(args)
    return await tool.invoke(args, ctx)


@pytest.fixture
def estate(app, db, default_tenant_id):
    ids = seed_estate(db, default_tenant_id)
    db.commit()
    return ids


def test_registry_contents():
    names = registry.names()
    expected = {'get_finding', 'list_findings', 'find_similar_findings', 'get_finding_history', 'recent_events', 'actor_timeline', 'event_stats',
                'get_asset', 'list_assets', 'asset_context', 'graph_query', 'graph_neighbors', 'attack_paths', 'exposure', 'list_detections',
                'get_detection', 'detection_rules', 'cve_lookup', 'kev_check', 'epss_scores', 'list_test_runs', 'test_results',
                'available_test_adapters', 'action_catalog', 'propose_action', 'note', 'recall'}
    assert expected <= set(names)
    assert [t.name for t in registry.all() if t.risk == 'propose'] == ['propose_action']
    for tool in registry.all():
        assert tool.input_schema['additionalProperties'] is False


@pytest.mark.asyncio
async def test_finding_tools(app, db, default_tenant_id, estate):
    ctx = tool_ctx(app, db, default_tenant_id)
    got = await call(ctx, 'get_finding', finding_id=estate['f1'])
    assert got['found'] and got['kev'] is True and got['cve_ids'] == ['CVE-2099-0001'] and got['asset_id'] == estate['web']
    assert (await call(ctx, 'get_finding', finding_id='missing'))['found'] is False
    listed = await call(ctx, 'list_findings', severity='high')
    assert {f['id'] for f in listed['items']} == {estate['f1'], estate['f2'], estate['f4']}
    assert listed['items'][0]['severity'] == 'high'
    by_asset = await call(ctx, 'list_findings', asset_id=estate['repo'], status='open', limit=1)
    assert by_asset['count'] == 1
    similar = await call(ctx, 'find_similar_findings', finding_id=estate['f1'])
    assert [f['id'] for f in similar['same_rule']] == [estate['f2']]
    assert estate['f4'] in {f['id'] for f in similar['same_asset']} and estate['f2'] not in {f['id'] for f in similar['same_asset']}
    record_audit(db, principal_for(default_tenant_id), 'findings.status_changed', estate['f1'], {'from': 'open', 'to': 'investigating'})
    history = await call(ctx, 'get_finding_history', finding_id=estate['f1'])
    assert history['found'] and any(a['action'] == 'findings.status_changed' for a in history['audit'])


@pytest.mark.asyncio
async def test_event_tools(app, db, default_tenant_id, estate):
    ctx = tool_ctx(app, db, default_tenant_id)
    recent = await call(ctx, 'recent_events', minutes=60)
    assert recent['count'] == 13 and all('metadata' in e for e in recent['items'])
    assert (await call(ctx, 'recent_events', minutes=60, actor='mallory'))['count'] == 4
    assert (await call(ctx, 'recent_events', minutes=60, category='cloud_api', entity='bucket-1'))['count'] == 1
    assert (await call(ctx, 'recent_events', minutes=60 * 24 * 7, source='osquery'))['count'] == 1
    assert (await call(ctx, 'recent_events', minutes=60, source='osquery'))['count'] == 0
    timeline = await call(ctx, 'actor_timeline', actor='svc-backup', hours=2)
    assert timeline['count'] == 6 and timeline['distinct_entities'] == 6 and timeline['actions'] == {'s3.GetObject': 6}
    assert [e['at'] for e in timeline['timeline']] == sorted(e['at'] for e in timeline['timeline'])
    stats = await call(ctx, 'event_stats', hours=1)
    assert stats['total'] == 13 and stats['by_category']['auth'] == 7 and stats['by_source']['cloudtrail'] == 6
    assert stats['top_actors']['svc-backup'] == 6


@pytest.mark.asyncio
async def test_asset_tools(app, db, default_tenant_id, estate):
    ctx = tool_ctx(app, db, default_tenant_id)
    web = await call(ctx, 'get_asset', asset_id=estate['web'])
    assert web['found'] and web['authorizations'][0]['valid'] and web['authorizations'][0]['allow_active'] and not web['authorizations'][0]['allow_intrusive']
    assert (await call(ctx, 'get_asset', asset_id=estate['repo']))['authorizations'] == []
    assert {a['name'] for a in (await call(ctx, 'list_assets', environment='production'))['items']} == {'est-web'}
    assert (await call(ctx, 'list_assets', kind='host'))['count'] == 1
    context = await call(ctx, 'asset_context', asset_id=estate['web'])
    assert context['authorized'] and {f['id'] for f in context['open_findings']} == {estate['f1'], estate['f4']}
    assert len(context['recent_events']) == 4 and 'available' in context['graph']


@pytest.mark.asyncio
async def test_graph_tools_with_fake_and_missing_service(app, db, default_tenant_id, estate, monkeypatch):
    ctx = tool_ctx(app, db, default_tenant_id)
    node = {'id': 'n1', 'kind': 'data_store', 'key': 'customers-db', 'tenant_id': default_tenant_id}
    foreign = {'id': 'n2', 'kind': 'data_store', 'key': 'other', 'tenant_id': 'someone-else'}
    path = types.SimpleNamespace(id='p1', status='open', score=80.0, tenant_id=default_tenant_id, summary='exposure -> customers-db')
    fake = module('app.graph.service',
                  query=lambda db, tenant_id, kind=None, key=None, limit=200: [node, foreign],
                  neighbors=lambda db, tenant_id, node_id, depth=1: {'nodes': [node, foreign], 'edges': []},
                  attack_paths=lambda db, tenant_id: [path, types.SimpleNamespace(id='p2', status='accepted', tenant_id=default_tenant_id)],
                  exposure_score=lambda db, tenant_id, node_id: 42.5)
    with fake_modules(monkeypatch, app__graph__service=fake):
        q = await call(ctx, 'graph_query', kind='data_store', search='customers')
        assert q['available'] and [n['id'] for n in q['items']] == ['n1']
        n = await call(ctx, 'graph_neighbors', node_id='n1', depth=2)
        assert n['available'] and [x['id'] for x in n['result']['nodes']] == ['n1']
        p = await call(ctx, 'attack_paths', status='open')
        assert p['available'] and p['count'] == 1 and p['items'][0]['summary'] == 'exposure -> customers-db'
        assert (await call(ctx, 'exposure', node_id='n1'))['exposure_score'] == 42.5
    with fake_modules(monkeypatch, app__graph__service=None, app__graph__queries=None, app__models__graph=None):
        for name, args in (('graph_query', {}), ('graph_neighbors', {'node_id': 'n1'}), ('attack_paths', {}), ('exposure', {'node_id': 'n1'})):
            result = await call(ctx, name, **args)
            assert result['available'] is False and result['reason']


@pytest.mark.asyncio
async def test_detection_tools_degrade_and_rule_catalog(app, db, default_tenant_id, monkeypatch):
    ctx = tool_ctx(app, db, default_tenant_id)
    with fake_modules(monkeypatch, app__models__detections=None):
        assert (await call(ctx, 'list_detections'))['available'] is False
        assert (await call(ctx, 'get_detection', detection_id='x'))['available'] is False
    rule = types.SimpleNamespace(id='swarm.fanout', name='Identity fan-out', severity='high', description='many entities', tags=['swarm'])
    with fake_modules(monkeypatch, app__detections__rules=module('app.detections.rules', RULES=[rule])):
        rules = await call(ctx, 'detection_rules')
        assert rules['available'] and rules['items'][0]['id'] == 'swarm.fanout'
    with fake_modules(monkeypatch, app__detections__rules=None, app__detections__engine=None, app__detections=None):
        assert (await call(ctx, 'detection_rules'))['available'] is False


@pytest.mark.asyncio
async def test_intel_tools(app, db, default_tenant_id, no_network):
    ctx = tool_ctx(app, db, default_tenant_id)
    # Network failure never raises.
    failed = await call(ctx, 'cve_lookup', cve_id='CVE-2024-3094')
    assert failed['available'] is False and 'unreachable' in failed['reason']
    assert (await call(ctx, 'kev_check', cve_ids=['CVE-2024-3094']))['available'] is False
    assert (await call(ctx, 'epss_scores', cve_ids=['CVE-2024-3094']))['available'] is False
    assert (await call(ctx, 'cve_lookup', cve_id='../etc/passwd'))['available'] is False
    no_network.data[intel.NVD_URL] = {'vulnerabilities': [{'cve': {'id': 'CVE-2024-3094', 'published': '2024-03-29', 'vulnStatus': 'Analyzed', 'cisaExploitAdd': '2024-03-29',
                                                                     'descriptions': [{'lang': 'en', 'value': 'xz backdoor'}],
                                                                     'metrics': {'cvssMetricV31': [{'cvssData': {'version': '3.1', 'baseScore': 10.0, 'baseSeverity': 'CRITICAL', 'vectorString': 'AV:N', 'attackVector': 'NETWORK'}}]},
                                                                     'weaknesses': [{'description': [{'value': 'CWE-506'}]}], 'references': [{}, {}]}}]}
    no_network.data[intel.KEV_URL] = {'catalogVersion': '2026.10.01', 'vulnerabilities': [{'cveID': 'CVE-2024-3094', 'dateAdded': '2024-03-29', 'dueDate': '2024-04-19',
                                                                                             'vendorProject': 'Tukaani', 'product': 'XZ Utils', 'knownRansomwareCampaignUse': 'Unknown'}]}
    no_network.data[intel.EPSS_URL] = {'data': [{'cve': 'CVE-2024-3094', 'epss': '0.93', 'percentile': '0.99', 'date': '2026-10-01'}]}
    cve = await call(ctx, 'cve_lookup', cve_id='cve-2024-3094')
    assert cve['found'] and cve['cvss']['score'] == 10.0 and cve['cwes'] == ['CWE-506'] and cve['kev'] is True and cve['description'] == 'xz backdoor'
    kev = await call(ctx, 'kev_check', cve_ids=['CVE-2024-3094', 'CVE-2099-9999', 'junk'])
    assert kev['available'] and 'CVE-2024-3094' in kev['in_kev'] and kev['not_in_kev'] == ['CVE-2099-9999'] and kev['invalid'] == ['JUNK']
    epss = await call(ctx, 'epss_scores', cve_ids=['CVE-2024-3094'])
    assert epss['scores']['CVE-2024-3094']['epss'] == 0.93
    calls_before = len(no_network.calls)
    await call(ctx, 'kev_check', cve_ids=['CVE-2024-3094'])
    await call(ctx, 'cve_lookup', cve_id='CVE-2024-3094')
    assert len(no_network.calls) == calls_before, 'second lookups must be served from cache'


@pytest.mark.asyncio
async def test_tests_tools(app, db, default_tenant_id, monkeypatch):
    ctx = tool_ctx(app, db, default_tenant_id)
    with fake_modules(monkeypatch, app__models__testing=None):
        assert (await call(ctx, 'list_test_runs'))['available'] is False
        assert (await call(ctx, 'test_results', run_id='r'))['available'] is False
    adapter = types.SimpleNamespace(name='nuclei', tier='active', target_kinds=['web'], available=lambda: False, description='templates')
    with fake_modules(monkeypatch, app__testing__harness=module('app.testing.harness', ADAPTERS={'nuclei': adapter})):
        result = await call(ctx, 'available_test_adapters')
        assert result['items'] == [{'name': 'nuclei', 'tier': 'active', 'target_kinds': ['web'], 'available': False, 'description': 'templates'}]
    with fake_modules(monkeypatch, app__testing__harness=None, app__testing__adapters=None, app__testing=None):
        assert (await call(ctx, 'available_test_adapters'))['available'] is False


@pytest.mark.asyncio
async def test_action_tools(app, db, default_tenant_id, estate, second_tenant, monkeypatch):
    ctx = tool_ctx(app, db, default_tenant_id)
    with fake_modules(monkeypatch, app__actions__broker=None, app__actions__catalog=None, app__actions=None):
        assert (await call(ctx, 'action_catalog'))['available'] is False
        missing = await call(ctx, 'propose_action', action_type='block_ip', params={'ip': '203.0.113.5'}, reason='test')
        assert missing['available'] is False
    seen: list[dict] = []
    action = types.SimpleNamespace(name='block_ip', description='Block an address at the edge', risk='low', reversible=True, platforms=['cloudflare'], params_schema={'type': 'object'})

    def request(db_, principal, action_type, params, reason, finding_id=None, agent_run_id=None):
        seen.append({'tenant': principal.tenant_id, 'action_type': action_type, 'params': params, 'reason': reason, 'finding_id': finding_id, 'agent_run_id': agent_run_id})
        if action_type == 'explode':
            raise PermissionError('policy denies')
        return types.SimpleNamespace(id='req-1', status='pending')

    broker = module('app.actions.broker', request=request, catalog=types.SimpleNamespace(all=lambda: [action]))
    with fake_modules(monkeypatch, app__actions__broker=broker, app__actions__catalog=None):
        catalog = await call(ctx, 'action_catalog')
        assert catalog['items'][0]['name'] == 'block_ip' and catalog['items'][0]['reversible'] is True
        created = await call(ctx, 'propose_action', action_type='block_ip', params={'ip': '203.0.113.5'}, reason='4 failed logins; password=hunter2secret', finding_id=estate['f1'])
        assert created['created'] and created['request_id'] == 'req-1' and created['status'] == 'pending'
        assert seen[-1]['agent_run_id'] == ctx.run_id and seen[-1]['finding_id'] == estate['f1'] and 'hunter2secret' not in seen[-1]['reason']
        audit = db.execute(select(AuditEntry).where(AuditEntry.action == 'agents.propose_action')).scalars().all()
        assert len(audit) == 1 and audit[0].tenant_id == default_tenant_id and audit[0].subject == 'req-1'
        rejected = await call(ctx, 'propose_action', action_type='explode', params={}, reason='x')
        assert rejected['created'] is False and 'policy denies' in rejected['reason']
        # A finding from another tenant cannot be attached to a proposal.
        other_ids = seed_estate(db, second_tenant['tenant_id'], prefix='acme')
        before = len(seen)
        foreign = await call(ctx, 'propose_action', action_type='block_ip', params={}, reason='x', finding_id=other_ids['f1'])
        assert foreign['created'] is False and len(seen) == before


@pytest.mark.asyncio
async def test_memory_tools(app, db, default_tenant_id):
    ctx = tool_ctx(app, db, default_tenant_id)
    assert (await call(ctx, 'recall'))['notes'] == []
    assert (await call(ctx, 'note', text='actor mallory looks hostile'))['saved']
    assert (await call(ctx, 'note', text='   '))['saved'] is False
    assert (await call(ctx, 'note', text='check bucket-3 token=abcdefghijk'))['saved']
    recalled = await call(ctx, 'recall')
    assert recalled['notes'][0] == 'actor mallory looks hostile' and 'abcdefghijk' not in recalled['notes'][1] and recalled['count'] == 2
    other = tool_ctx(app, db, default_tenant_id)  # a different run sees nothing
    assert (await call(other, 'recall'))['count'] == 0
    foreign = tool_ctx(app, db, 'tenant-b', run_id=ctx.run_id)  # wrong tenant for this run id
    assert (await call(foreign, 'recall'))['count'] == 0 and (await call(foreign, 'note', text='x'))['saved'] is False


@pytest.mark.asyncio
async def test_tools_are_tenant_isolated(app, db, default_tenant_id, estate, second_tenant):
    other_ids = seed_estate(db, second_tenant['tenant_id'], prefix='acme')
    db.commit()
    b = tool_ctx(app, db, second_tenant['tenant_id'], role=Role.owner)
    assert (await call(b, 'get_finding', finding_id=estate['f1']))['found'] is False
    assert (await call(b, 'find_similar_findings', finding_id=estate['f1']))['found'] is False
    assert (await call(b, 'get_finding_history', finding_id=estate['f1']))['found'] is False
    listed = {f['id'] for f in (await call(b, 'list_findings', limit=200))['items']}
    assert other_ids['f1'] in listed and not listed & {estate['f1'], estate['f2'], estate['f3'], estate['f4']}
    assert (await call(b, 'get_asset', asset_id=estate['web']))['found'] is False
    assert (await call(b, 'asset_context', asset_id=estate['web']))['found'] is False
    assert {a['name'] for a in (await call(b, 'list_assets'))['items']} == {'acme-web', 'acme-repo', 'acme-lab'}
    recent = await call(b, 'recent_events', minutes=60)
    assert recent['count'] == 13 and all(e['id'] not in estate['events'].values() for e in recent['items'])
    assert (await call(b, 'actor_timeline', actor='mallory', hours=2))['count'] == 4  # acme's own mallory events only
    assert (await call(b, 'event_stats', hours=1))['total'] == 13
    a = tool_ctx(app, db, default_tenant_id)
    assert (await call(a, 'get_finding', finding_id=other_ids['f1']))['found'] is False
    assert (await call(a, 'event_stats', hours=1))['total'] == 13


@pytest.mark.asyncio
async def test_tool_argument_validation_and_timeout_safety():
    tool = registry.get('recent_events')
    assert tool.validate({'minutes': 'ten'}) == ["argument 'minutes' should be integer"]
    assert tool.validate({'nope': 1}) == ["unknown argument 'nope'"]
    assert registry.get('propose_action').validate({'action_type': 'x'}) == ["missing required argument 'params'", "missing required argument 'reason'"]
    assert isinstance(intel.TIMEOUT_SECONDS, float) and intel.TIMEOUT_SECONDS <= 10
    assert isinstance(httpx.ConnectError('x'), httpx.HTTPError)
