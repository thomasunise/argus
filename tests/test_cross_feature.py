"""End to end across the new features: an AI agent uses a planted LLM key, the canary tripwire fires, and an
enforcing autonomous-response playbook blocks the source address at Cloudflare, with an automatic rollback due."""
from __future__ import annotations

import json
from functools import partial

import httpx
import pytest
import respx
from sqlalchemy import select

from app.actions import autoresponse
from app.detections import canaries, run
from app.models.actions import ActionRun
from app.models.detections import Detection
from tests.conftest import wait_for, wait_job

ZONE = 'c' * 32
CF = 'https://api.cloudflare.com/client/v4'


@pytest.fixture
def settings(settings):
    settings.autoresponse_enabled = True
    return settings


def test_agent_canary_hit_triggers_autonomous_block(owner, app, db, default_tenant_id, monkeypatch):
    client, headers = owner
    monkeypatch.setenv('ACTIONS_CLOUDFLARE_TOKEN', 'cf-token')
    assert client.post('/api/v1/actions/kill-switch', json={'enabled': False}, headers=headers).status_code == 200
    assert client.put('/api/v1/autoresponse/settings', json={'enabled': True}, headers=headers).json()['effective'] is True
    playbook = client.post('/api/v1/autoresponse/playbooks', headers=headers, json={
        'name': 'block agents that touch canaries', 'mode': 'enforce', 'rule_ids': ['canary.tripwire'], 'min_severity': 'high', 'min_confidence': 0.9,
        'action_type': 'cloudflare.waf.block_ip', 'params_template': {'zone_id': ZONE, 'ip': '{{evidence.src_ip}}'}, 'rollback_after_minutes': 60})
    assert playbook.status_code == 201, playbook.text

    canary = canaries.create_canary(db, default_tenant_id, kind='llm_api_key', label='ml team .env', placement='file share', settings=app.state.settings)
    canaries.record_hit(db, canary, source_ip='203.0.113.50', user_agent='OpenAI/Python 1.40.0', payload={'model': 'gpt-4o'})
    run(db, default_tenant_id, rule_ids=['canary.tripwire'], settings=app.state.settings)
    db.commit()
    detection = db.execute(select(Detection).where(Detection.tenant_id == default_tenant_id, Detection.rule_id == 'canary.tripwire')).scalar_one()
    assert 'ai-agent' in json.loads(detection.tags_json) and json.loads(detection.evidence_json)['src_ip'] == '203.0.113.50'

    with respx.mock(base_url=CF, assert_all_called=False) as mock:
        mock.get(f'/zones/{ZONE}').mock(return_value=httpx.Response(200, json={'success': True, 'result': {'id': ZONE}}))
        mock.get(f'/zones/{ZONE}/firewall/access_rules/rules').mock(return_value=httpx.Response(200, json={'success': True, 'result': []}))
        block = mock.post(f'/zones/{ZONE}/firewall/access_rules/rules').mock(
            return_value=httpx.Response(200, json={'success': True, 'result': {'id': 'rule-9'}}))
        job = client.portal.call(partial(app.state.queue.enqueue, autoresponse.JOB_KIND, {'detection_id': detection.id}, tenant_id=default_tenant_id))
        assert wait_job(client, headers, job.id)['status'] == 'completed'
        executions = client.get('/api/v1/autoresponse/executions', params={'detection_id': detection.id}, headers=headers).json()['items']
        assert executions[0]['outcome'] == 'enforced', executions
        run_id = executions[0]['action_run_id']

        def executed():
            with app.state.db_factory() as session:
                row = session.get(ActionRun, run_id)
                return row is not None and row.status == 'executed'

        wait_for(executed, timeout=30)
    assert json.loads(block.calls.last.request.content)['configuration'] == {'target': 'ip', 'value': '203.0.113.50'}
    assert executions[0]['rollback_due_at']
    audit = client.get('/api/v1/audit', params={'action': 'actions.requested'}, headers=headers).json()['items']
    assert audit and audit[0]['detail'].get('autonomous_playbook') == 'block agents that touch canaries'
