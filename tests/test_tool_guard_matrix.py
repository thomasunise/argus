"""Deterministic deny/allow policy matrix. Not a substitute for model red-teaming."""
import pytest
from app.ai.tool_guard import evaluate


@pytest.mark.parametrize('name', [
    'aws.delete_bucket', 'filesystem.delete_file', 'database.drop_table',
    'shell.execute_command', 'cloud.delete_instance', 'k8s.delete_namespace',
    'token.export', 'vault.read_secret', 'identity.disable_user',
    'remote.run_code', 'secrets.dump', 'iam.create_access_key',
])
def test_denied_tools_are_blocked(name):
    result = evaluate(name, 'unknown', {},
                      {'mode': 'enforce', 'deny_tools': ['*delete*', '*drop*', '*execute*',
                                                     '*export*', '*read_secret*', '*disable*',
                                                     '*run_code*', '*dump*', '*create_access_key*']})
    assert not result.allowed
    assert result.would_block


@pytest.mark.parametrize('host', [
    'exfil.example', 'sub.exfil.example', 'EXFIL.EXAMPLE',
    'docs.exfil.example', 'steal.sub.exfil.example',
])
def test_denied_host_and_subdomains(host):
    result = evaluate('http.request', 'read', {'endpoint': 'https://' + host + '/endpoint'},
                      {'mode': 'enforce', 'deny_hosts': ['exfil.example']})
    assert not result.allowed


@pytest.mark.parametrize('risk', ['write', 'execute', 'execute_testing', 'unknown'])
def test_denied_risks(risk):
    result = evaluate('thirdparty.tool', risk, {}, {'mode': 'enforce', 'deny_risks': [risk]})
    assert not result.allowed


@pytest.mark.parametrize('host', ['safe.example.org', 'api.safe.example.org'])
def test_allowed_domains(host):
    result = evaluate('web.request', 'read', {'url': 'https://' + host + '/v1'},
                      {'mode': 'enforce', 'allow_hosts': ['safe.example.org']})
    assert result.allowed


def test_monitor_mode_reports_violations_without_blocking():
    d = evaluate('dangerous.delete', 'execute', {'url': 'https://exfil.example'},
                 {'mode': 'monitor', 'deny_tools': ['*delete*'], 'deny_risks': ['execute']})
    assert d.allowed and d.would_block
