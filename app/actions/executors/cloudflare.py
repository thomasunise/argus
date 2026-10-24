"""Cloudflare executors over the v4 API (httpx). Credential: ACTIONS_CLOUDFLARE_TOKEN
(API token with Firewall Services:Edit on the zone or account)."""
from __future__ import annotations

import ipaddress
from typing import Any

from ..catalog import ActionError, ActionType, DryRunResult, ExecContext, ExecResult, entities, register
from ._common import body, http

API = 'https://api.cloudflare.com/client/v4'
_ID = {'type': 'string', 'pattern': r'^[0-9a-f]{32}$'}


async def cf(ctx: ExecContext, method: str, path: str, *, json: Any = None, params: dict | None = None, allow: tuple[int, ...] = ()):
    token = ctx.require_credential('token')
    return await http(method, f'{API}{path}', json=json, params=params, allow=allow, label='cloudflare',
                      headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'})


def _result(response) -> Any:
    data = body(response)
    if isinstance(data, dict) and data.get('success') is False:
        errors = '; '.join(str(e.get('message', '')) for e in data.get('errors', [])[:3])
        raise ActionError(f'cloudflare rejected the request: {errors}')
    return data.get('result') if isinstance(data, dict) else data


@register
class BlockIp(ActionType):
    name = 'cloudflare.waf.block_ip'
    description = 'Create an IP Access Rule in block mode for an IP or CIDR on a zone or account (POST firewall/access_rules/rules). Rollback deletes the rule.'
    params_schema = {'properties': {'zone_id': _ID, 'account_id': _ID, 'ip': {'type': 'string', 'minLength': 7, 'maxLength': 64},
                                    'note': {'type': 'string', 'maxLength': 500, 'default': 'Blocked by Argus action broker'}},
                     'required': ['ip']}
    risk = 'medium'
    reversible = True
    platforms = ['cloudflare']
    category = 'containment'

    @staticmethod
    def _plan(params: dict) -> dict:
        if bool(params.get('zone_id')) == bool(params.get('account_id')):
            raise ActionError('exactly one of zone_id or account_id is required')
        scope = f'/zones/{params["zone_id"]}' if params.get('zone_id') else f'/accounts/{params["account_id"]}'
        raw = params['ip'].strip()
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ActionError('ip must be an IPv4/IPv6 address or CIDR') from exc
        single = network.num_addresses == 1
        if single:
            target, value = 'ip', str(network.network_address)
        else:
            allowed = {16, 24} if network.version == 4 else {32, 48, 64}
            if network.prefixlen not in allowed:
                raise ActionError(f'Cloudflare only accepts /{"/".join(str(p) for p in sorted(allowed))} ranges for IPv{network.version}')
            target, value = 'ip_range', str(network)
        return {'method': 'POST', 'path': f'{scope}/firewall/access_rules/rules', 'scope_path': scope,
                'json': {'mode': 'block', 'configuration': {'target': target, 'value': value}, 'notes': params.get('note', '')},
                'blast_radius': entities(1, target, [value], scope=scope.split('/')[1], addresses=network.num_addresses)}

    async def _existing(self, ctx: ExecContext, plan: dict) -> list[dict]:
        config = plan['json']['configuration']
        response = await cf(ctx, 'GET', plan['path'], params={'configuration.target': config['target'], 'configuration.value': config['value'], 'per_page': 50})
        return [r for r in (_result(response) or []) if (r.get('configuration') or {}).get('value') == config['value']]

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:
        plan = self._plan(params)
        scope = await cf(ctx, 'GET', plan['scope_path'], allow=(403, 404))
        if scope.status_code in (403, 404):
            return DryRunResult(ok=False, summary='zone/account not found or token not permitted', blast_radius=plan['blast_radius'])
        existing = await self._existing(ctx, plan)
        warnings = [f'{len(existing)} access rule(s) already target this value ({", ".join(r.get("mode", "") for r in existing)})'] if existing else []
        return DryRunResult(ok=True, summary=f'block {plan["json"]["configuration"]["value"]} on {plan["scope_path"]}', blast_radius=plan['blast_radius'],
                            warnings=warnings)

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:
        plan = self._plan(params)
        rule = _result(await cf(ctx, 'POST', plan['path'], json=plan['json'])) or {}
        if not rule.get('id'):
            raise ActionError('cloudflare did not return a rule id')
        return ExecResult(ok=True, summary=f'access rule {rule["id"]} blocks {plan["json"]["configuration"]["value"]}',
                          rollback_payload={'scope_path': plan['scope_path'], 'rule_id': rule['id'], 'value': plan['json']['configuration']['value']})

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        await cf(ctx, 'DELETE', f'{payload["scope_path"]}/firewall/access_rules/rules/{payload["rule_id"]}', allow=(404,))
        return ExecResult(ok=True, summary=f'access rule {payload["rule_id"]} deleted; {payload.get("value", "")} unblocked')
