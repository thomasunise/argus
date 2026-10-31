"""Enforcing proxy must never forward rejected or unverified tool calls."""
from app.ai.mcp_proxy import _validate_argus_url, gate_message
import pytest


def call(name='fs.read_file', id=7):
    return {'jsonrpc': '2.0', 'id': id, 'method': 'tools/call',
            'params': {'name': name, 'arguments': {'path': '/tmp/demo'}}}


def test_enforce_permits_only_authenticated_allow():
    assert gate_message(call(), lambda *args: {'mode': 'enforce', 'allowed': True}) == (True, None)
    forward, refusal = gate_message(call(), lambda *args: {'mode': 'enforce', 'allowed': False})
    assert forward is False and refusal['id'] == 7 and refusal['error']['code'] == -32003
    forward, refusal = gate_message(call(), lambda *args: {'mode': 'monitor', 'allowed': True})
    assert not forward and refusal


def test_fails_closed_on_policy_error_and_notifications():
    def failure(*args):
        raise RuntimeError('offline')
    assert not gate_message(call(), failure)[0]
    note = call()
    note.pop('id')
    assert gate_message(note, failure) == (False, None)
    assert gate_message({'method': 'tools/list', 'id': 6}, failure) == (True, None)


def test_invalid_call_blocked_and_argus_url_validation():
    msg = call()
    msg['params']['arguments'] = 'not-an-object'
    assert not gate_message(msg, lambda *a: {'mode': 'enforce', 'allowed': True})[0]
    assert _validate_argus_url('https://argus.example').endswith('/api/v1/ai/tool-guard/evaluate')
    assert _validate_argus_url('http://127.0.0.1:8000')
    with pytest.raises(ValueError):
        _validate_argus_url('http://public.example')
    with pytest.raises(ValueError):
        _validate_argus_url('https://user:pass@argus.example')
