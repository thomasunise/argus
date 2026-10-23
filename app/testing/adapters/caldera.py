"""MITRE CALDERA adapter (intrusive, adversary emulation).

Drives a CALDERA server over its v2 REST API: start an operation for a chosen adversary
against a group, poll until it finishes, then fetch the operation report and turn each
executed ability (validated TTP) into a finding. Intrusive tier only, which scope.check
restricts to authorized staging/lab assets with allow_intrusive authorizations.

Requires CALDERA_URL and CALDERA_API_KEY. Because it emulates an adversary it is the most
dangerous adapter in the harness; it never runs without a current intrusive authorization.
"""
from __future__ import annotations

import asyncio

import httpx

from ...core.config import Settings
from ...core.errors import Unavailable
from ...core.security import resolve_secret
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register

_MAX_POLLS = 1200


def parse_report(report: dict) -> list[NormalizedFinding]:
    """Map executed links in a CALDERA operation report to findings (one per validated TTP)."""
    findings: list[NormalizedFinding] = []
    seen: set[str] = set()
    steps = report.get('steps') or {}
    # v2 report: {"steps": {"<host>": {"steps": [ {ability, link_id, status, attack...}, ... ]}}}
    for host, host_block in steps.items():
        for step in (host_block.get('steps') or [])[:2000]:
            if int(step.get('status', 1)) != 0:  # 0 == success in CALDERA
                continue
            attack = step.get('attack') or {}
            technique = str(attack.get('technique_id') or '')
            ability = str(step.get('name') or step.get('ability_id') or 'ability')
            key = f'{technique}:{ability}:{host}'
            if key in seen:
                continue
            seen.add(key)
            findings.append(NormalizedFinding(
                rule=f'caldera:{technique or ability}'[:160],
                title=f'Adversary technique executed: {ability}'[:240],
                description=f'CALDERA successfully executed ability {ability} on {host} '
                            f'(tactic {attack.get("tactic", "?")}, technique {technique or "?"}).',
                remediation='Harden the host and add detection/response coverage for this ATT&CK technique.',
                severity='high',
                evidence={'host': str(host), 'ability': ability, 'tactic': str(attack.get('tactic') or ''),
                          'technique_id': technique, 'technique_name': str(attack.get('technique_name') or '')}))
    return findings


class CalderaAdapter(TestAdapter):
    name = 'caldera'
    tier = 'intrusive'
    target_kinds = ('host',)
    description = 'MITRE CALDERA adversary emulation (intrusive; requires an authorized agent group).'

    def available(self, settings: Settings) -> bool:
        return bool(settings.caldera_url and settings.caldera_api_key)

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        settings = ctx.settings
        if not settings.caldera_url or not settings.caldera_api_key:
            raise Unavailable('CALDERA_URL and CALDERA_API_KEY must be configured')
        adversary_id = str(plan_params.get('adversary_id') or '')
        group = str(plan_params.get('group') or asset.target)
        if not adversary_id:
            raise Unavailable('caldera requires an adversary_id in plan params')
        api_key = resolve_secret(settings.caldera_api_key, settings) if settings.caldera_api_key.startswith(
            ('env:', 'file:', 'secrets:', 'literal:')) else settings.caldera_api_key
        base = settings.caldera_url.rstrip('/')
        headers = {'KEY': api_key, 'Content-Type': 'application/json'}

        async with httpx.AsyncClient(base_url=base, trust_env=False, timeout=httpx.Timeout(30.0),
                                     headers=headers, limits=httpx.Limits(max_connections=2)) as client:
            await ctx.rate_limiter.acquire()
            created = await client.post('/api/v2/operations', json={
                'name': f'sentinel-{ctx.run_id[:8]}', 'adversary': {'adversary_id': adversary_id},
                'group': group, 'auto_close': True, 'state': 'running'})
            created.raise_for_status()
            op = created.json()
            op_id = op.get('id') or op.get('operation_id')
            if not op_id:
                raise Unavailable('CALDERA did not return an operation id')
            for _ in range(_MAX_POLLS):
                await ctx.rate_limiter.acquire()
                state_resp = await client.get(f'/api/v2/operations/{op_id}')
                state_resp.raise_for_status()
                if str(state_resp.json().get('state') or '') in {'finished', 'cleanup', 'out_of_time'}:
                    break
                await ctx.heartbeat()
                await asyncio.sleep(2.0)
            else:
                raise Unavailable('CALDERA operation did not finish in time')
            report_resp = await client.post(f'/api/v2/operations/{op_id}/report', json={'enable_agent_output': False})
            report_resp.raise_for_status()
        return parse_report(report_resp.json())


register(CalderaAdapter())
