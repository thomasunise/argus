"""SentinelOne endpoint network quarantine over the Management API v2.1 (httpx).

Credentials: ACTIONS_SENTINELONE_API_URL (the console origin, https://<tenant>.sentinelone.net) and
ACTIONS_SENTINELONE_TOKEN (API token of a user or service user allowed to disconnect endpoints).
Disconnecting isolates the endpoint from the network except for the management console; rollback
reconnects it.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from ..catalog import ActionError, ActionType, DryRunResult, ExecContext, ExecResult, entities, register
from ._common import body, http, one_of

API = '/web/api/v2.1'
_AGENT_ID = {'type': 'string', 'pattern': r'^[0-9]{6,24}$', 'description': 'SentinelOne agent id'}
_NAME = {'type': 'string', 'minLength': 1, 'maxLength': 255, 'pattern': r'^[A-Za-z0-9._-]+$'}


def _base(ctx: ExecContext) -> str:
    base = ctx.require_credential('api_url').rstrip('/')
    parts = urlsplit(base)
    if parts.scheme != 'https' or not (parts.hostname or '').endswith('.sentinelone.net') or parts.path not in ('', '/'):
        raise ActionError('ACTIONS_SENTINELONE_API_URL must be an https://<tenant>.sentinelone.net origin')
    return base


async def s1(ctx: ExecContext, method: str, path: str, *, json: Any = None, params: dict | None = None, allow: tuple[int, ...] = ()):
    token = ctx.require_credential('token')
    return await http(method, f'{_base(ctx)}{API}{path}', json=json, params=params, allow=allow, label='sentinelone',
                      headers={'Authorization': f'ApiToken {token}', 'Accept': 'application/json', 'Content-Type': 'application/json'})


async def _agents(ctx: ExecContext, params: dict) -> list[dict]:
    key = one_of(params, 'agent_id', 'computer_name')
    query = {'ids': params['agent_id']} if key == 'agent_id' else {'computerName': params['computer_name']}
    data = body(await s1(ctx, 'GET', '/agents', params={**query, 'limit': 10}))
    return [a for a in (data or {}).get('data') or [] if isinstance(a, dict)]


def _label(agent: dict) -> str:
    return f'{agent.get("computerName") or "?"} ({agent.get("id", "")})'


@register
class DisconnectEndpoint(ActionType):
    name = 'sentinelone.endpoint.disconnect'
    description = ('Disconnect a SentinelOne endpoint from the network (POST /agents/actions/disconnect); it keeps its console connection. '
                   'Rollback reconnects it. Servers are refused unless allow_servers is true.')
    params_schema = {'properties': {'agent_id': _AGENT_ID, 'computer_name': _NAME, 'allow_servers': {'type': 'boolean', 'default': False}},
                     'required': []}
    risk = 'high'
    reversible = True
    platforms = ['sentinelone']
    category = 'containment'

    @staticmethod
    def _plan(agent: dict, action: str = 'disconnect') -> dict:
        return {'method': 'POST', 'path': f'/agents/actions/{action}', 'json': {'filter': {'ids': [str(agent['id'])]}},
                'blast_radius': entities(1, 'host', [_label(agent)], os=agent.get('osType', ''))}

    async def _target(self, params: dict, ctx: ExecContext) -> tuple[dict | None, str]:
        agents = await _agents(ctx, params)
        if not agents:
            return None, 'no SentinelOne endpoint matches'
        if len(agents) > 1:
            return None, f'{len(agents)} endpoints share that computer name; use agent_id'
        return agents[0], ''

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        agent, problem = await self._target(params, ctx)
        if agent is None:
            return DryRunResult(ok=False, summary=problem, blast_radius=entities(0, 'host'))
        plan = self._plan(agent)
        status = str(agent.get('networkStatus') or 'connected')
        if status != 'connected':
            return DryRunResult(ok=False, summary=f'endpoint network status is {status}; only connected endpoints can be disconnected',
                                blast_radius=plan['blast_radius'])
        warnings = []
        if str(agent.get('machineType') or '').lower() == 'server':
            if not params.get('allow_servers'):
                return DryRunResult(ok=False, summary=f'{_label(agent)} is a server; set allow_servers to disconnect it', blast_radius=plan['blast_radius'])
            warnings.append(f'{_label(agent)} is a server: disconnecting it interrupts every service it provides')
        warnings.append('the endpoint keeps its console connection only; users on it lose network access until it is reconnected')
        return DryRunResult(ok=True, summary=f'disconnect {_label(agent)} ({agent.get("osType", "")})', blast_radius=plan['blast_radius'],
                            warnings=warnings, details={'agent_id': str(agent['id']), 'network_status': status})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        agent, problem = await self._target(params, ctx)
        if agent is None:
            raise ActionError(problem)
        plan = self._plan(agent)
        data = body(await s1(ctx, plan['method'], plan['path'], json=plan['json']))
        affected = int(((data or {}).get('data') or {}).get('affected', 0) or 0)
        if affected < 1:
            raise ActionError('sentinelone reported no endpoint affected')
        return ExecResult(ok=True, summary=f'{_label(agent)} disconnected from the network',
                          rollback_payload={'agent_id': str(agent['id']), 'computer_name': agent.get('computerName', '')})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan({'id': payload['agent_id'], 'computerName': payload.get('computer_name', '')}, 'connect')
        data = body(await s1(ctx, plan['method'], plan['path'], json=plan['json']))
        affected = int(((data or {}).get('data') or {}).get('affected', 0) or 0)
        if affected < 1:
            raise ActionError('sentinelone reported no endpoint reconnected')
        return ExecResult(ok=True, summary=f'{payload.get("computer_name") or payload["agent_id"]} reconnected to the network')
