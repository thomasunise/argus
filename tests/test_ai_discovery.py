"""Shadow-AI discovery: event classification, inventory upserts and cursor, review API, the
unsanctioned-AI detection rule, the agent tool and tenant isolation."""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.ai import catalog
from app.ai.discovery import classify, discover, upsert_service
from app.core.findings import EventDraft, upsert_event
from app.models import SecurityEvent, utcnow
from app.models.ai import AIService
from app.models.detections import Detection
from tests.conftest import wait_job

RULE = 'agentic.unsanctioned_ai_service'


def seed(db, tenant_id: str) -> None:
    now = utcnow() - timedelta(minutes=5)
    drafts = [
        EventDraft(source='netflow', external_id='n1', title='Outbound connection', category='network', actor='10.0.0.5', entity='api.openai.com',
                   action='connection', occurred_at=now, metadata={'dst_port': 443}),
        EventDraft(source='netflow', external_id='n2', title='Outbound connection', category='network', actor='10.0.0.6', entity='203.0.113.9',
                   action='connection', occurred_at=now, metadata={'sni': 'chat.deepseek.com'}),
        EventDraft(source='aws_cloudtrail', external_id='c1', title='bedrock InvokeModel', category='cloud_api',
                   actor='arn:aws:iam::111122223333:role/app', entity='anthropic.claude-v5', action='bedrock.invoke_model', occurred_at=now,
                   metadata={'event_source': 'bedrock.amazonaws.com', 'service': 'bedrock'}),
        EventDraft(source='okta', external_id='o1', title='User granted consent to OAuth app', category='identity', actor='alice@corp.test',
                   entity='Otter.ai', action='app.oauth2.as.consent.grant', occurred_at=now, metadata={'event_type': 'app.oauth2.as.consent.grant'}),
        EventDraft(source='netflow', external_id='n3', title='Outbound connection', category='network', actor='10.0.0.7', entity='example.com',
                   action='connection', occurred_at=now),
        EventDraft(source='okta', external_id='o2', title='User login', category='identity', actor='bob@corp.test', entity='Claude', action='user.session.start',
                   occurred_at=now),
    ]
    for draft in drafts:
        upsert_event(db, tenant_id, draft)
    db.commit()


def event(**kwargs) -> SecurityEvent:
    base = {'source': 'generic', 'external_id': 'x', 'title': '', 'category': '', 'actor': '', 'entity': '', 'action': '', 'metadata_json': '{}'}
    base.update(kwargs)
    return SecurityEvent(**base)


def test_classify_signatures():
    assert classify(event(source='azure', action='microsoft.cognitiveservices/accounts/deployments/write')).service.key == 'azure.openai'
    assert classify(event(source='gcp', action='google.cloud.aiplatform.v1.PredictionService.GenerateContent')).service.key == 'gcp.vertex'
    match = classify(event(source='osquery', category='host', title='curl https://api.anthropic.com/v1/messages'))
    assert match.service.key == 'anthropic.api' and match.channel == 'network'
    match = classify(event(source='entra', category='auth', action='consent_to_application', entity='ChatGPT'))
    assert match.service.key == 'openai.chatgpt' and match.channel == 'oauth_app'
    assert classify(event(source='netflow', category='network', entity='notopenai.com')) is None
    assert classify(event(source='okta', category='identity', action='user.session.start', entity='Claude')) is None  # not a grant
    assert catalog.match_domain('eu.api.openai.com')[0].key == 'openai.api'


def test_discover_builds_inventory_and_advances_cursor(db, default_tenant_id):
    seed(db, default_tenant_id)
    result = discover(db, default_tenant_id)
    db.commit()
    assert result['events_scanned'] == 6 and result['matched'] == 4 and result['new_services'] == 4
    rows = {r.service_key: r for r in db.execute(select(AIService)).scalars()}
    assert set(rows) == {'openai.api', 'deepseek.api', 'aws.bedrock', 'otter'}
    assert rows['openai.api'].channel == 'network' and rows['openai.api'].actor == '10.0.0.5' and rows['openai.api'].evidence == 'api.openai.com'
    assert rows['aws.bedrock'].channel == 'cloud_api' and rows['otter'].channel == 'oauth_app' and rows['otter'].actor == 'alice@corp.test'
    assert all(r.status == 'unreviewed' and r.event_count == 1 for r in rows.values())
    again = discover(db, default_tenant_id)
    assert again['events_scanned'] == 0
    upsert_event(db, default_tenant_id, EventDraft(source='netflow', external_id='n9', title='conn', category='network', actor='10.0.0.5',
                                                   entity='api.openai.com', action='connection'))
    assert discover(db, default_tenant_id)['matched'] == 1
    db.commit()
    assert db.execute(select(AIService).where(AIService.service_key == 'openai.api')).scalar_one().event_count == 2


def test_api_review_rule_and_isolation(owner, api_key, client, db, default_tenant_id, second_tenant):
    client_, headers = owner
    seed(db, default_tenant_id)
    queued = client_.post('/api/v1/ai/discover', headers=headers)
    assert queued.status_code == 202, queued.text
    job = wait_job(client_, headers, queued.json()['job_id'])
    assert job['status'] == 'completed' and job['result']['matched'] == 4, job
    listing = client_.get('/api/v1/ai/services', headers=headers).json()['items']
    assert len(listing) == 4
    assert len(client_.get('/api/v1/ai/services?channel=oauth_app', headers=headers).json()['items']) == 1
    stats = client_.get('/api/v1/ai/services/stats', headers=headers).json()
    assert stats['total'] == 4 and stats['by_status'] == {'unreviewed': 4} and stats['by_channel']['network'] == 2
    assert client_.get('/api/v1/ai/discovery', headers=headers).json()['events_scanned'] == 6
    assert any(item['key'] == 'openai.chatgpt' for item in client_.get('/api/v1/ai/catalog', headers=headers).json()['items'])

    # The rule raises detections for unreviewed services (low for network, medium for cloud API and OAuth grants).
    run = client_.post('/api/v1/detections/run', json={'rule_ids': [RULE], 'since_minutes': 120}, headers=headers)
    assert run.status_code == 202, run.text
    assert wait_job(client_, headers, run.json()['job_id'])['result']['detections_created'] == 4
    db.expire_all()
    severities = {d.entity: d.severity for d in db.execute(select(Detection).where(Detection.rule_id == RULE)).scalars()}
    assert severities == {'OpenAI API': 'low', 'DeepSeek': 'low', 'Amazon Bedrock': 'medium', 'Otter.ai': 'medium'}
    assert any(r['id'] == RULE for r in client_.get('/api/v1/detections/rules', headers=headers).json()['items'])

    # Review: operators cannot, admins can; the decision applies to every actor of the service and to new actors.
    openai_row = next(r for r in listing if r['service_key'] == 'openai.api')
    assert client.patch(f"/api/v1/ai/services/{openai_row['id']}", json={'status': 'sanctioned'},
                        headers={'Authorization': f'Bearer {api_key}'}).status_code == 403
    assert client.post('/api/v1/ai/discover', headers={'Authorization': f'Bearer {api_key}'}).status_code == 403
    reviewed = client_.patch(f"/api/v1/ai/services/{openai_row['id']}", json={'status': 'sanctioned', 'notes': 'enterprise contract'}, headers=headers)
    assert reviewed.status_code == 200 and reviewed.json()['status'] == 'sanctioned' and reviewed.json()['reviewed_by']
    otter = next(r for r in listing if r['service_key'] == 'otter')
    assert client_.patch(f"/api/v1/ai/services/{otter['id']}", json={'status': 'blocked'}, headers=headers).json()['status'] == 'blocked'
    assert client_.patch(f"/api/v1/ai/services/{otter['id']}", json={'status': 'bogus'}, headers=headers).status_code == 422
    service = catalog.BY_KEY['openai.api']
    row, created = upsert_service(db, default_tenant_id, service, 'network', '10.0.0.99')
    db.commit()
    assert created and row.status == 'sanctioned'

    # Isolation.
    other, other_headers = second_tenant['client'], second_tenant['headers']
    assert other.get('/api/v1/ai/services', headers=other_headers).json()['items'] == []
    assert other.get(f"/api/v1/ai/services/{openai_row['id']}", headers=other_headers).status_code == 404
    assert other.patch(f"/api/v1/ai/services/{openai_row['id']}", json={'status': 'blocked'}, headers=other_headers).status_code == 404
    assert other.get('/api/v1/ai/services/stats', headers=other_headers).json()['total'] == 0
    assert other.get('/api/v1/ai/discovery', headers=other_headers).json()['events_scanned'] == 0


def test_rule_skips_sanctioned_and_gateway_and_flags_blocked(db, default_tenant_id):
    from app.detections.engine import run

    now = utcnow()
    upsert_service(db, default_tenant_id, catalog.BY_KEY['openai.api'], 'gateway', 'api-key:gw', status='sanctioned', seen_at=now)
    upsert_service(db, default_tenant_id, catalog.BY_KEY['anthropic.claude'], 'network', '10.0.0.1', status='sanctioned', seen_at=now)
    upsert_service(db, default_tenant_id, catalog.BY_KEY['deepseek.api'], 'network', '10.0.0.2', status='blocked', seen_at=now)
    db.commit()
    result = run(db, default_tenant_id, rule_ids=[RULE])
    assert result['detections_created'] == 1
    detection = db.execute(select(Detection).where(Detection.rule_id == RULE)).scalar_one()
    assert detection.severity == 'high' and detection.entity == 'DeepSeek' and 'Blocked' in detection.title


@pytest.mark.asyncio
async def test_agent_tool_lists_inventory(app, client, db, default_tenant_id):
    from app.agents.tools.registry import ToolContext, registry
    from app.core.rbac import Role, Principal

    upsert_service(db, default_tenant_id, catalog.BY_KEY['perplexity'], 'network', '10.0.0.3', seen_at=utcnow())
    db.commit()
    principal = Principal(tenant_id=default_tenant_id, role=Role.analyst)
    ctx = ToolContext(db=db, principal=principal, settings=app.state.settings, run_id='', spec_name='test')
    result = await registry.get('ai_inventory').invoke({'status': 'unreviewed'}, ctx)
    assert result['count'] == 1 and result['items'][0]['service'] == 'Perplexity'
    other = ToolContext(db=db, principal=Principal(tenant_id='other-tenant', role=Role.analyst), settings=app.state.settings, run_id='', spec_name='test')
    assert (await registry.get('ai_inventory').invoke({}, other))['count'] == 0
