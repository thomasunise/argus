"""Governed Strix adapter: real offensive depth inside Argus's authorization envelope.

Strix runs as an engine job in the sandbox executor, not on the Argus worker. The adapter renders
the engine envelope, submits it, and maps the wrapper's normalized `ARGUS_FINDINGS` lines into
Argus findings. It never runs a shell itself and the scope gate applies exactly as it does to
every other test tier.

The adapter requires tier `exploit`: the scope must list the tier, the asset must carry an
authorization with allow_exploit, and the environment must be permitted (production also needs a
signed scope document reference).
"""
from __future__ import annotations

import json
import socket

from ...core.config import Settings
from ...core.errors import ScopeDenied, Unavailable
from ...exploit import engine
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register

FINDINGS_MARKER = 'ARGUS_FINDINGS '
ENGINE_TRAILER = 'ARGUS_ENGINE '
DEFAULT_PROVIDER_HOSTS = 'api.anthropic.com,api.openai.com,openrouter.ai'
_SEVERITIES = {'critical', 'high', 'medium', 'low', 'informational', 'info'}


def parse_findings(text: str) -> list[NormalizedFinding]:
    """Map the wrapper's normalized lines to findings. Malformed lines are skipped, never guessed."""
    findings: list[NormalizedFinding] = []
    for line in (text or '').splitlines():
        stripped = line.strip()
        if not stripped.startswith(FINDINGS_MARKER):
            continue
        try:
            item = json.loads(stripped[len(FINDINGS_MARKER):])
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        title = str(item.get('title') or item.get('name') or '')
        if not title:
            continue
        severity = str(item.get('severity') or 'medium').lower()
        evidence = item.get('evidence') if isinstance(item.get('evidence'), dict) else {}
        poc = item.get('poc') or item.get('proof_of_concept') or ''
        if poc:
            evidence = {**evidence, 'poc': str(poc)[:4000]}
        findings.append(NormalizedFinding(
            rule=f"strix:{str(item.get('rule') or item.get('id') or item.get('category') or 'finding')[:120]}",
            title=title[:240],
            description=str(item.get('description') or item.get('details') or title)[:4000],
            severity=severity if severity in _SEVERITIES else 'medium',
            remediation=str(item.get('remediation') or item.get('fix') or 'Review the Strix PoC and remediate.')[:4000],
            evidence={**evidence, 'url': str(item.get('url') or '')[:500]},
            cve_ids=[c for c in (item.get('cve_ids') or []) if isinstance(c, str)][:10],
            cvss=float(item['cvss']) if isinstance(item.get('cvss'), (int, float)) else None,
        ))
    return findings


def engine_exit_code(text: str) -> int | None:
    for line in (text or '').splitlines():
        if line.strip().startswith(ENGINE_TRAILER):
            try:
                payload = json.loads(line.strip()[len(ENGINE_TRAILER):])
            except ValueError:
                return None
            return int(payload.get('exit_code') or 0)
    return None


def _ips(hosts: list[str], port: int) -> list[tuple[str, int]]:
    pairs: list[tuple[str, int]] = []
    for host in hosts:
        host = (host or '').strip()
        if not host:
            continue
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ScopeDenied(f'could not resolve {host!r}: {exc}') from exc
        for info in infos:
            ip = info[4][0]
            if ':' in ip:  # the engine profile is IPv4-only for now
                continue
            pair = (ip, port)
            if pair not in pairs:
                pairs.append(pair)
    return pairs


class StrixAdapter(TestAdapter):
    name = 'strix'
    tier = 'exploit'
    optional = True  # never listed or proposed unless configured
    target_kinds = ('web',)
    description = 'Autonomous offensive engine (Strix) in the sandbox executor, scoped to one asset origin.'

    def available(self, settings: Settings) -> bool:
        return bool(getattr(settings, 'strix_enabled', False) and getattr(settings, 'exploit_executor_url', '')
                    and getattr(settings, 'strix_image', ''))

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        settings = ctx.settings
        if not self.available(settings):
            raise Unavailable('Strix engine is not configured (STRIX_ENABLED, EXPLOIT_EXECUTOR_URL, STRIX_IMAGE)')
        client = engine.client_for(settings)
        if client is None:
            raise Unavailable('no executor is configured for engine jobs')
        if ctx.tier != 'exploit':
            raise ScopeDenied('the Strix engine only runs at tier exploit')

        target = ctx.target or asset.target
        host = target.split('://', 1)[-1].split('/', 1)[0].split(':')[0]
        port = 8443 if target.endswith(':8443') else 443
        providers = [h.strip() for h in str(getattr(settings, 'strix_egress_hosts', DEFAULT_PROVIDER_HOSTS)).split(',') if h.strip()]
        egress = _ips([host], port) + _ips(providers, 443)
        if not egress:
            raise ScopeDenied('the engine has no permitted egress destination')

        budget = float(getattr(settings, 'strix_max_budget_usd', 25.0))
        wall = int(getattr(settings, 'strix_max_wall_seconds', 3600))
        job = engine.EngineJob(
            run_id=ctx.run_id, tenant_id=ctx.tenant_id, image=str(settings.strix_image),
            argv=['--target', target, '--budget', str(budget), '--run-id', ctx.run_id],
            env={'STRIX_LLM': str(getattr(settings, 'strix_model', '')),
                 'LLM_API_KEY': str(getattr(settings, 'strix_llm_api_key', '')),
                 'LLM_API_BASE': str(getattr(settings, 'strix_llm_api_base', '')),
                 'ARGUS_TARGET': target, 'ARGUS_MAX_BUDGET_USD': str(budget), 'ARGUS_RUN_ID': ctx.run_id,
                 'ARGUS_STRIX_EXTRA_ARGS': str(getattr(settings, 'strix_extra_args', ''))},
            target_host=host, egress=egress,
            limits=engine.EngineLimits(wall_seconds=wall, cpu=float(getattr(settings, 'strix_max_cpu', 2.0)),
                                       memory_mb=int(getattr(settings, 'strix_max_memory_mb', 2048)),
                                       pids=int(getattr(settings, 'strix_max_pids', 512)),
                                       max_output_bytes=int(getattr(settings, 'exploit_max_artifact_bytes', 5 * 1024 * 1024))))
        result = await client.run(job)
        findings = parse_findings(result.stdout)
        exit_code = engine_exit_code(result.stdout)
        if result.timed_out:
            raise Unavailable('the Strix engine hit its wall-clock limit; partial results were discarded')
        if exit_code not in (None, 0) and not findings:
            raise Unavailable(f'the Strix engine exited {exit_code} without a report')
        if not findings:
            ctx.logger.info('strix run %s finished with no findings (exit=%s)', ctx.run_id, exit_code)
        return findings


register(StrixAdapter())
