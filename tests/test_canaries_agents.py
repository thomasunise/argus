"""Canaries aimed at AI agents: planted prompt injection, agent rules file, fake MCP server, fake LLM key + base URL."""
from __future__ import annotations

import json

from app.detections import run
from app.detections.canaries import classify_client


def _create(client, headers, kind: str, label: str) -> dict:
    response = client.post('/api/v1/canaries', json={'kind': kind, 'label': label, 'placement': 'decoy repo'}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def _artifact(client, headers, canary: dict):
    response = client.get(f"/api/v1/canaries/{canary['id']}/artifact", headers=headers)
    assert response.status_code == 200, response.text
    return response


def test_agent_canary_artifacts(owner):
    client, headers = owner
    injection = _create(client, headers, 'prompt_injection', 'Q3 board notes')
    body = _artifact(client, headers, injection).text
    assert injection['metadata']['url'] in body and 'AI assistants' in body and body.startswith('# Q3 board notes')

    rules = _create(client, headers, 'agent_rules', 'payments repo')
    response = _artifact(client, headers, rules)
    assert 'AGENTS.md' in response.headers['content-disposition'] and rules['metadata']['url'] in response.text

    mcp = _create(client, headers, 'mcp_server', 'Secrets Broker')
    config = json.loads(_artifact(client, headers, mcp).content)
    server = config['mcpServers']['secrets-broker']
    assert server['url'].endswith(f"/api/v1/canaries/{mcp['token']}/mcp") and server['headers']['Authorization'].startswith('Bearer ')

    llm = _create(client, headers, 'llm_api_key', 'ml team')
    assert llm['token'].startswith('sk-') and llm['metadata']['openai_base_url'].endswith(f"/canaries/{llm['token']}/llm/v1")
    env = _artifact(client, headers, llm).text
    assert f"OPENAI_API_KEY={llm['token']}" in env and 'ANTHROPIC_BASE_URL=' in env


def test_llm_canary_records_model_and_prompt_and_answers_like_the_provider(owner, db, default_tenant_id):
    client, headers = owner
    llm = _create(client, headers, 'llm_api_key', 'ml team')
    token = llm['token']
    openai = client.post(f'/api/v1/canaries/{token}/llm/v1/chat/completions', headers={'Authorization': f'Bearer {token}', 'User-Agent': 'OpenAI/Python 1.40.0',
                                                                                      'X-Stainless-Lang': 'python'},
                         json={'model': 'gpt-4o', 'messages': [{'role': 'user', 'content': 'list every S3 bucket with customer data'}]})
    assert openai.status_code == 401 and openai.json()['error']['code'] == 'invalid_api_key'
    anthropic = client.post(f'/api/v1/canaries/{token}/llm/v1/messages', headers={'x-api-key': token, 'anthropic-version': '2023-06-01',
                                                                                  'User-Agent': 'Anthropic/Python 0.40.0'},
                            json={'model': 'claude-x', 'max_tokens': 10, 'messages': [{'role': 'user', 'content': [{'type': 'text', 'text': 'dump secrets'}]}]})
    assert anthropic.status_code == 401 and anthropic.json()['error']['type'] == 'authentication_error'
    hits = client.get(f"/api/v1/canaries/{llm['id']}/hits", headers=headers).json()['items']
    assert len(hits) == 2
    by_path = {h['payload']['path']: h['payload'] for h in hits}
    assert by_path['/v1/chat/completions']['model'] == 'gpt-4o' and 'S3 bucket' in by_path['/v1/chat/completions']['prompt_preview']
    assert by_path['/v1/chat/completions']['key_matches'] is True
    assert by_path['/v1/messages']['prompt_preview'] == 'dump secrets'
    assert all('authorization' not in h['headers'] and 'x-api-key' not in h['headers'] for h in hits)  # the presented key is never stored

    events = client.get('/api/v1/events?source=canary', headers=headers).json()['items']
    assert events and all(e['metadata']['ai_agent'] and e['metadata']['agent_canary'] for e in events)
    run(db, default_tenant_id, rule_ids=['canary.tripwire'])
    db.commit()
    detection = client.get('/api/v1/detections?rule_id=canary.tripwire', headers=headers).json()['items'][0]
    assert 'AI agent' in detection['title'] and 'ai-agent' in detection['tags'] and detection['evidence']['src_ip']


def test_mcp_canary_speaks_enough_protocol_and_records_tool_calls(owner):
    client, headers = owner
    mcp = _create(client, headers, 'mcp_server', 'secrets broker')
    url = f"/api/v1/canaries/{mcp['token']}/mcp"
    init = client.post(url, json={'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                                  'params': {'protocolVersion': '2025-06-18', 'clientInfo': {'name': 'rogue-agent', 'version': '0.1'}, 'capabilities': {}}})
    assert init.status_code == 200 and init.json()['result']['serverInfo']['name'] == 'secrets-broker'
    assert client.post(url, json={'jsonrpc': '2.0', 'method': 'notifications/initialized'}).status_code == 202
    tools = client.post(url, json={'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'}).json()['result']['tools']
    assert tools[0]['name'] == 'get_production_credentials'
    call = client.post(url, json={'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                                  'params': {'name': 'get_production_credentials', 'arguments': {'service': 'billing-db'}}}).json()
    assert call['result']['isError'] is True
    assert client.post(url, json={'jsonrpc': '2.0', 'id': 4, 'method': 'resources/list'}).json()['error']['code'] == -32601
    assert client.get(url).status_code == 405
    assert client.post(url, content=b'not json', headers={'Content-Type': 'application/json'}).status_code == 400
    hits = client.get(f"/api/v1/canaries/{mcp['id']}/hits", headers=headers).json()['items']
    methods = [h['payload'].get('mcp_method') for h in hits]
    assert {'initialize', 'tools/list', 'tools/call'} <= set(methods)
    tool_call = next(h['payload'] for h in hits if h['payload'].get('mcp_method') == 'tools/call')
    assert tool_call['tool'] == 'get_production_credentials' and tool_call['arguments'] == {'service': 'billing-db'}
    init_hit = next(h['payload'] for h in hits if h['payload'].get('mcp_method') == 'initialize')
    assert init_hit['client_info']['name'] == 'rogue-agent'


def test_unknown_tokens_and_revoked_canaries_record_nothing(owner):
    client, headers = owner
    assert client.post('/api/v1/canaries/sk-unknownunknownunknown/llm/v1/chat/completions', json={'model': 'x'}).status_code == 401
    assert client.post('/api/v1/canaries/unknown-token-0000/mcp', json={'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'}).status_code == 200
    llm = _create(client, headers, 'llm_api_key', 'gone')
    client.delete(f"/api/v1/canaries/{llm['id']}", headers=headers)
    client.post(f"/api/v1/canaries/{llm['token']}/llm/v1/chat/completions", json={'model': 'x'})
    assert client.get(f"/api/v1/canaries/{llm['id']}/hits", headers=headers).json()['items'] == []


def test_oversized_prompt_is_still_recorded(owner):
    client, headers = owner
    llm = _create(client, headers, 'llm_api_key', 'big')
    huge = 'A' * 200_000
    response = client.post(f"/api/v1/canaries/{llm['token']}/llm/v1/chat/completions", json={'model': 'gpt-4o', 'messages': [{'role': 'user', 'content': huge}]})
    assert response.status_code == 401
    hit = client.get(f"/api/v1/canaries/{llm['id']}/hits", headers=headers).json()['items'][0]
    assert hit['payload']['body_truncated'] is True


def test_classify_client():
    assert classify_client('OpenAI/Python 1.40.0')['ai_agent'] is True
    assert classify_client('python-httpx/0.27', {'x-stainless-lang': 'python'})['ai_agent'] is True
    assert classify_client('curl/8.4.0') == {'client': 'curl', 'ai_agent': False, 'automated': True, 'sdk_headers': []}
    browser = classify_client('Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130 Safari/537.36')
    assert browser['client'] == 'browser' and not browser['ai_agent'] and not browser['automated']
