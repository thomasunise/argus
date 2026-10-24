"""CrowdStrike Falcon host containment (network isolation) over the Falcon API (httpx).

Credentials: ACTIONS_CROWDSTRIKE_CLIENT_ID, ACTIONS_CROWDSTRIKE_CLIENT_SECRET (API client with the
Hosts: Read and Write scopes) and optionally ACTIONS_CROWDSTRIKE_BASE_URL (default
https://api.crowdstrike.com; use api.us-2 / api.eu-1 / api.laggar.gcw for other clouds).
Containment cuts the host off the network except for the Falcon cloud; rollback lifts it.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from ..catalog import ActionError, ActionType, DryRunResult, ExecContext, ExecResult, entities, register
from ._common import body, http, one_of

DEFAULT_BASE = 'https://api.crowdstrike.com'
SERVER_TYPES = {'server', 'domain controller'}
_AID = {'type': 'string', 'pattern': r'^[0-9a-fA-F]{32}$', 'description': 'Falcon agent id (aid)'}
_HOST = {'type': 'string', 'minLength': 1, 'maxLength': 255, 'pattern': r'^[A-Za-z0-9._-]+$'}


def _base(ctx: ExecContext) -> str:
    base = (ctx.credential('base_url') or DEFAULT_BASE).rstrip('/')
    parts = urlsplit(base)
    if parts.scheme != 'https' or not (parts.hostname or '').endswith('.crowdstrike.com') or parts.path not in ('', '/'):
        raise ActionError('ACTIONS_CROWDSTRIKE_BASE_URL must be an https://api*.crowdstrike.com origin')
    return base


async def _token(ctx: ExecContext, base: str) -> str:
    response = await http('POST', f'{base}/oauth2/token', label='crowdstrike',
                          data={'client_id': ctx.require_credential('client_id'), 'client_secret': ctx.require_credential('client_secret')},
                          headers={'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'})
    token = (body(response) or {}).get('access_token')
    if not token:
        raise ActionError('crowdstrike did not return an access token')
    return str(token)


async def falcon(ctx: ExecContext, method: str, path: str, *, json: Any = None, params: dict | None = None, allow: tuple[int, ...] = ()):
    base = _base(ctx)
    token = await _token(ctx, base)
    return await http(method, f'{base}{path}', json=json, params=params, allow=allow, label='crowdstrike',
                      headers={'Authorization': f'Bearer {token}', 'Accept': 'application/json', 'Content-Type': 'application/json'})


def _errors(data: Any) -> str:
    errors = (data or {}).get('errors') if isinstance(data, dict) else None
    return '; '.join(str(e.get('message', e)) for e in errors[:3]) if errors else ''


async def _resolve(ctx: ExecContext, params: dict) -> list[dict]:
    """Device records matching the params (device_id or hostname)."""
    key = one_of(params, 'device_id', 'hostname')
    if key == 'device_id':
        ids = [params['device_id'].lower()]
    else:
        hostname = params['hostname'].replace("'", '')
        found = body(await falcon(ctx, 'GET', '/devices/queries/devices/v1', params={'filter': f"hostname:'{hostname}'", 'limit': 10}))
        ids = [str(i) for i in (found or {}).get('resources') or []]
        if not ids:
            return []
    response = await falcon(ctx, 'GET', '/devices/entities/devices/v2', params={'ids': ids}, allow=(404,))
    data = body(response)
    return [d for d in (data or {}).get('resources') or [] if isinstance(d, dict)]


def _label(device: dict) -> str:
    return f'{device.get("hostname") or "?"} ({device.get("device_id", "")[:12]})'


@register
class ContainHost(ActionType):
    name = 'crowdstrike.host.contain'
    description = ('Network-contain a Falcon host (POST /devices/entities/devices-actions/v2?action_name=contain): the host can only reach the '
                   'Falcon cloud. Rollback lifts containment. Servers and domain controllers are refused unless allow_servers is true.')
    params_schema = {'properties': {'device_id': _AID, 'hostname': _HOST,
                                    'allow_servers': {'type': 'boolean', 'default': False}},
                     'required': []}
    risk = 'high'
    reversible = True
    platforms = ['crowdstrike']
    category = 'containment'

    @staticmethod
    def _plan(device: dict, action_name: str = 'contain') -> dict:
        return {'method': 'POST', 'path': '/devices/entities/devices-actions/v2', 'params': {'action_name': action_name},
                'json': {'ids': [device['device_id']]}, 'blast_radius': entities(1, 'host', [_label(device)], platform=device.get('platform_name', ''))}

    async def _target(self, params: dict, ctx: ExecContext) -> tuple[dict | None, str]:
        devices = await _resolve(ctx, params)
        if not devices:
            return None, 'no Falcon host matches'
        if len(devices) > 1:
            return None, f'{len(devices)} Falcon hosts share that hostname; use device_id'
        return devices[0], ''

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        device, problem = await self._target(params, ctx)
        if device is None:
            return DryRunResult(ok=False, summary=problem, blast_radius=entities(0, 'host'))
        plan = self._plan(device)
        status = str(device.get('status') or 'normal')
        if status != 'normal':
            return DryRunResult(ok=False, summary=f'host is {status}; only hosts in normal state can be contained', blast_radius=plan['blast_radius'])
        kind = str(device.get('product_type_desc') or '').lower()
        warnings = []
        if kind in SERVER_TYPES:
            if not params.get('allow_servers'):
                return DryRunResult(ok=False, summary=f'{_label(device)} is a {kind}; set allow_servers to contain it', blast_radius=plan['blast_radius'])
            warnings.append(f'{_label(device)} is a {kind}: containment interrupts every service it provides')
        warnings.append('the host keeps its Falcon connection only; users on it lose network access until containment is lifted')
        return DryRunResult(ok=True, summary=f'contain {_label(device)} ({device.get("platform_name", "")}, last seen {device.get("last_seen", "?")})',
                            blast_radius=plan['blast_radius'], warnings=warnings, details={'device_id': device['device_id'], 'status': status})

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        device, problem = await self._target(params, ctx)
        if device is None:
            raise ActionError(problem)
        plan = self._plan(device)
        data = body(await falcon(ctx, plan['method'], plan['path'], params=plan['params'], json=plan['json']))
        if _errors(data):
            raise ActionError(f'crowdstrike refused containment: {_errors(data)}')
        return ExecResult(ok=True, summary=f'containment requested for {_label(device)}',
                          rollback_payload={'device_id': device['device_id'], 'hostname': device.get('hostname', '')})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan({'device_id': payload['device_id'], 'hostname': payload.get('hostname', '')}, 'lift_containment')
        data = body(await falcon(ctx, plan['method'], plan['path'], params=plan['params'], json=plan['json']))
        if _errors(data):
            raise ActionError(f'crowdstrike refused to lift containment: {_errors(data)}')
        return ExecResult(ok=True, summary=f'containment lifted for {payload.get("hostname") or payload["device_id"]}')
