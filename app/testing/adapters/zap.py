"""OWASP ZAP adapter (active or intrusive, web).

Drives a ZAP daemon over its JSON API via httpx:
  - spider the target (passive crawl)                              [active + intrusive]
  - run the active scanner (ascan)                                 [intrusive only]
  - read alerts and map them to findings

At tier 'active' this behaves as a passive/baseline crawl (spider + alerts, NO active
scan). The active scanner only runs when the run tier is 'intrusive', which scope.check
already restricts to authorized staging/lab assets.
"""
from __future__ import annotations

import asyncio

import httpx

from ...core.config import Settings
from ...core.errors import Unavailable
from ...core.security import resolve_secret
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register

_RISK = {'High': 'high', 'Medium': 'medium', 'Low': 'low', 'Informational': 'informational'}
_MAX_POLLS = 600


class ZapAdapter(TestAdapter):
    name = 'zap'
    tier = 'active'  # nominal; a run may be 'intrusive' (enables the active scanner)
    target_kinds = ('web',)
    description = 'OWASP ZAP spider + (intrusive) active scan over the ZAP JSON API.'

    def available(self, settings: Settings) -> bool:
        return bool(settings.zap_url)

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        settings = ctx.settings
        if not settings.zap_url:
            raise Unavailable('ZAP_URL is not configured')
        target = ctx.target or asset.target
        if settings.zap_api_key.startswith('literal:') and not getattr(settings, 'allow_literal_secret_refs', True):
            raise Unavailable('ZAP_API_KEY uses a literal: reference, which is disabled on this deployment (ALLOW_LITERAL_SECRET_REFS)')
        api_key = resolve_secret(settings.zap_api_key, settings) if settings.zap_api_key.startswith(('env:', 'file:', 'secrets:', 'literal:')) else settings.zap_api_key
        base = settings.zap_url.rstrip('/')
        params = {'apikey': api_key} if api_key else {}

        async with httpx.AsyncClient(base_url=base, trust_env=False, timeout=httpx.Timeout(30.0),
                                     limits=httpx.Limits(max_connections=2)) as client:

            async def _get(path: str, extra: dict) -> dict:
                await ctx.rate_limiter.acquire()
                resp = await client.get(path, params={**params, **extra})
                resp.raise_for_status()
                return resp.json()

            # 1) spider (crawl) and poll to completion
            spider = await _get('/JSON/spider/action/scan/', {'url': target})
            spider_id = str(spider.get('scan', '0'))
            await self._poll(_get, '/JSON/spider/view/status/', {'scanId': spider_id}, ctx)

            # 2) active scan — intrusive tier only
            if ctx.tier == 'intrusive':
                ascan = await _get('/JSON/ascan/action/scan/', {'url': target, 'recurse': 'true'})
                ascan_id = str(ascan.get('scan', '0'))
                await self._poll(_get, '/JSON/ascan/view/status/', {'scanId': ascan_id}, ctx)

            # 3) collect alerts
            data = await _get('/JSON/core/view/alerts/', {'baseurl': target})
        return self._parse(data)

    @staticmethod
    async def _poll(getter, path: str, extra: dict, ctx: HarnessContext) -> None:
        for _ in range(_MAX_POLLS):
            status = await getter(path, extra)
            if int(str(status.get('status', '0')) or '0') >= 100:
                return
            await ctx.heartbeat()
            await asyncio.sleep(1.0)
        raise Unavailable('ZAP scan did not complete within the allotted time')

    @staticmethod
    def _parse(data: dict) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        seen: set[str] = set()
        for alert in (data.get('alerts') or [])[:2000]:
            plugin = str(alert.get('pluginId') or alert.get('alertRef') or 'zap')
            name = str(alert.get('alert') or alert.get('name') or 'ZAP alert')
            url = str(alert.get('url') or '')
            param = str(alert.get('param') or '')
            cwe = str(alert.get('cweid') or '')
            key = f'{plugin}:{name}:{param}:{cwe}'
            if key in seen:
                continue
            seen.add(key)
            findings.append(NormalizedFinding(
                rule=f'zap:{plugin}:{name}'[:160], title=name[:240],
                description=str(alert.get('description') or name)[:2000],
                remediation=str(alert.get('solution') or 'Review the ZAP alert detail and remediate.')[:2000],
                severity=_RISK.get(str(alert.get('risk') or 'Informational'), 'low'),
                evidence={'url': url, 'param': param, 'cwe': cwe, 'confidence': str(alert.get('confidence') or '')}))
        return findings


register(ZapAdapter())
