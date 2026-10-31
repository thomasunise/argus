"""Enforcing MCP stdio proxy for one explicitly configured tool server.

Use: ARGUS_API_KEY=... python -m app.ai.mcp_proxy --argus-url https://argus.example \
         -- python -m my_trusted_mcp_server

Clients attach to *this* process's stdin/stdout, never the unguarded server.
ARGUS_API_KEY is removed from the child server environment. Every tools/call is
checked before forwarding, and network errors fail closed. Existing Argus policy
must be in enforce mode; monitor mode cannot silently allow calls via this proxy.
No external server can be secured unless clients actually use this proxy.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlsplit

MAX_MESSAGE_BYTES = 1_048_576
MAX_POLICY_BYTES = 64_000


def gate_message(message: dict, check, *, risk: str = 'unknown') -> tuple[bool, dict | None]:
    """Decide whether to forward a JSON-RPC message. No arbitrary commands run here."""
    if not isinstance(message, dict) or message.get('method') != 'tools/call':
        return True, None
    params = message.get('params')
    params = params if isinstance(params, dict) else {}
    name = params.get('name')
    args = params.get('arguments') or {}
    reason = 'policy_denied'
    if isinstance(name, str) and name and isinstance(args, dict):
        try:
            decision = check(name, risk, args)
            if isinstance(decision, dict) and decision.get('mode') == 'enforce' and decision.get('allowed') is True:
                return True, None
        except (ValueError, RuntimeError, TimeoutError, OSError):
            reason = 'policy_unavailable'
    else:
        reason = 'invalid_tool_call'
    # Notifications have no response ID. They must still be blocked.
    if 'id' not in message:
        return False, None
    return False, {'jsonrpc': '2.0', 'id': message['id'],
                   'error': {'code': -32003, 'message': 'ARGUS tool-call enforcement blocked this request',
                             'data': {'reason': reason}}}


def _validate_argus_url(base: str) -> str:
    parsed = urlsplit(base)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Expected absolute http(s) ARGUS URL without userinfo or fragment')
    if parsed.scheme != 'https' and parsed.hostname not in {'localhost', '127.0.0.1', '::1'}:
        raise ValueError('An HTTP ARGUS connection is permitted only on loopback')
    if parsed.query:
        raise ValueError('ARGUS URL must not contain a query string')
    if parsed.path not in ('', '/'):
        raise ValueError('ARGUS URL must be the service root')
    return base.rstrip('/') + '/api/v1/ai/tool-guard/evaluate'


def make_policy_check(base_url: str, api_key: str):
    """Build a fail-closed checker. Secret is held only in this process."""
    if not api_key:
        raise ValueError('ARGUS_API_KEY must not be empty')
    endpoint = _validate_argus_url(base_url)

    def check(tool: str, risk: str, arguments: dict) -> dict:
        data = json.dumps({'tool': tool, 'risk': risk, 'arguments': arguments}, separators=(',', ':')).encode()
        if len(data) > MAX_MESSAGE_BYTES:
            raise ValueError('Tool call exceeds policy request limit')
        parsed = urlsplit(endpoint)
        conn = (HTTPSConnection if parsed.scheme == 'https' else HTTPConnection)(
            parsed.hostname, parsed.port, timeout=5)
        try:
            # http.client does not follow redirects; a policy result must come from ARGUS.
            conn.request('POST', parsed.path, body=data,
                         headers={'X-API-Key': api_key, 'Content-Type': 'application/json',
                                  'Accept': 'application/json'})
            response = conn.getresponse()
            if response.status != 200:
                raise RuntimeError('ARGUS policy endpoint rejected the request')
            raw = response.read(MAX_POLICY_BYTES + 1)
            if len(raw) > MAX_POLICY_BYTES:
                raise ValueError('ARGUS policy response too large')
            answer = json.loads(raw)
        except (OSError, TimeoutError) as exc:
            raise RuntimeError('ARGUS policy endpoint unavailable') from exc
        finally:
            conn.close()
        if not isinstance(answer, dict) or not isinstance(answer.get('allowed'), bool):
            raise ValueError('ARGUS policy response malformed')
        return answer

    return check


def run_proxy(server_command: list[str], check, *, risk: str = 'unknown') -> int:
    if not server_command:
        raise ValueError('A trusted MCP server command is required')
    child_env = dict(os.environ)
    child_env.pop('ARGUS_API_KEY', None)
    # The child is explicitly configured by the operator. No shell or command interpolation.
    proc = subprocess.Popen(server_command, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=sys.stderr, env=child_env, bufsize=0)

    def read_server():
        assert proc.stdout is not None
        for line in proc.stdout:
            try:
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
            except (BrokenPipeError, OSError):
                break

    reader = threading.Thread(target=read_server, name='mcp-proxy-output', daemon=True)
    reader.start()
    try:
        assert proc.stdin is not None
        while True:
            line = sys.stdin.buffer.readline(MAX_MESSAGE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_MESSAGE_BYTES:
                # A too-large frame cannot be safely forwarded; terminate connection.
                return 2
            try:
                msg = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                # Invalid JSON-RPC input should not reach the child.
                continue
            forward, error = gate_message(msg, check, risk=risk)
            if forward:
                proc.stdin.write(line)
                proc.stdin.flush()
            elif error is not None:
                sys.stdout.buffer.write(json.dumps(error, separators=(',', ':')).encode() + b'\n')
                sys.stdout.buffer.flush()
    except (BrokenPipeError, OSError):
        return 1
    finally:
        if proc.stdin is not None:
            proc.stdin.close()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        reader.join(timeout=1)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Fail-closed ARGUS tool-call enforcing proxy for MCP stdio servers')
    parser.add_argument('--argus-url', required=True)
    parser.add_argument('--risk', choices=['read', 'write', 'execute', 'unknown'], default='unknown')
    parser.add_argument('server_command', nargs=argparse.REMAINDER)
    options = parser.parse_args(argv)
    command = list(options.server_command)
    if command and command[0] == '--':
        command.pop(0)
    try:
        check = make_policy_check(options.argus_url, os.environ.get('ARGUS_API_KEY', ''))
        return run_proxy(command, check, risk=options.risk)
    except ValueError as exc:
        parser.error(str(exc))
    return 2


if __name__ == '__main__':
    sys.exit(main())
