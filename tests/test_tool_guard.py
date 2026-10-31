"""Tool guard policy, tenant isolation and runtime interception smoke tests."""
from __future__ import annotations

import pytest

from app.ai.tool_guard import evaluate, policy_for, validate_policy
from app.models import Tenant, dumps, loads


def test_tool_guard_monitor_and_enforce():
    policy = {'mode': 'monitor', 'deny_tools': ['*delete*'], 'deny_risks': ['execute_testing']}
    verdict = evaluate('delete_resource', 'read', {}, policy)
    assert verdict.allowed and verdict.would_block and verdict.reasons == ('denied_tool',)
    verdict = evaluate('delete_resource', 'read', {}, {**policy, 'mode': 'enforce'})
    assert not verdict.allowed and verdict.would_block
    assert evaluate('list_findings', 'read', {}, {**policy, 'mode': 'enforce'}).allowed


def test_guard_rejects_host_suffix_tricks_and_malformed_policy():
    policy = {'mode': 'enforce', 'allow_hosts': ['safe.example.org']}
    assert evaluate('call_mcp', 'read', {'url': 'https://safe.example.org/api'}, policy).allowed
    assert evaluate('call_mcp', 'read', {'url': 'https://sub.safe.example.org/api'}, policy).allowed
    assert not evaluate('call_mcp', 'read', {'url': 'https://safe.example.org.evil.test'}, policy).allowed
    assert not evaluate('call_mcp', 'read', {'url': 'https://evil-safe.example.org'}, policy).allowed
    with pytest.raises(ValueError):
        validate_policy({'mode': 'disable_security'})


def test_tenant_tool_guard_policy_is_scoped(db, default_tenant_id):
    tenant = db.get(Tenant, default_tenant_id)
    original = loads(tenant.settings_json, {})
    tenant.settings_json = dumps({**original, 'tool_guard': {'mode': 'enforce', 'deny_tools': ['run_test']}})
    db.flush()
    assert policy_for(db, default_tenant_id)['deny_tools'] == ['run_test']
    assert policy_for(db, 'different-tenant') == {}


def test_tool_guard_api(owner):
    client, headers = owner
    body = {'mode': 'enforce', 'deny_tools': ['run_test'], 'deny_risks': ['execute_testing']}
    r = client.put('/api/v1/ai/tool-guard/policy', json=body, headers=headers)
    assert r.status_code == 200, r.text
    assert client.get('/api/v1/ai/tool-guard/policy', headers=headers).json()['mode'] == 'enforce'
    # Owner can evaluate; external callers must honor the decision.
    r = client.post('/api/v1/ai/tool-guard/evaluate', json={'tool': 'run_test', 'risk': 'execute_testing'}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()['allowed'] is False
