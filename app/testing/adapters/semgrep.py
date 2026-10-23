"""Semgrep adapter (passive, repo): `semgrep --config auto --json --metrics=off <path>`.

Results are mapped to findings with the Semgrep rule id, file, line and a severity mapping.
"""
from __future__ import annotations

import json
import re

from ...core.config import Settings
from ...core.errors import ScopeDenied, Unavailable
from ...core import policy
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register, run_tool

_SEV_MAP = {'ERROR': 'high', 'WARNING': 'medium', 'INFO': 'low', 'INVENTORY': 'informational', 'EXPERIMENT': 'informational'}
# `--config` accepts local files and URLs, which would let a plan author read arbitrary files or make the worker
# fetch arbitrary URLs. Only "auto" and registry rule packs (p/<name>, r/<name>) are allowed from plan params.
_CONFIG_RE = re.compile(r'^(auto|[pr]/[A-Za-z0-9][A-Za-z0-9_.-]{0,120})$')


def safe_config(value: object) -> str:
    text = str(value or 'auto').strip()
    if not _CONFIG_RE.match(text):
        raise ScopeDenied('semgrep config must be "auto" or a registry pack such as p/ci; local paths and URLs are not allowed')
    return text


def parse_report(report: dict) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for item in (report.get('results') or [])[:2000]:
        check_id = str(item.get('check_id') or 'semgrep')
        start = (item.get('start') or {}).get('line')
        path = str(item.get('path') or 'unknown')[:300]
        extra = item.get('extra') or {}
        meta = extra.get('metadata') or {}
        cwe = meta.get('cwe')
        cwe_list = cwe if isinstance(cwe, list) else ([cwe] if cwe else [])
        findings.append(NormalizedFinding(
            rule=f'{check_id}:{path}:{start}', title=str(extra.get('message') or check_id)[:240],
            description=f'{extra.get("message") or check_id}'[:2000] + f' ({path}:{start})',
            remediation=str((extra.get('fix') or meta.get('references') or 'Review and remediate the flagged code path.'))[:2000],
            severity=_SEV_MAP.get(str(extra.get('severity') or '').upper(), 'medium'),
            evidence={'check_id': check_id, 'file': path, 'line': start, 'cwe': cwe_list[:5],
                      'owasp': (meta.get('owasp') if isinstance(meta.get('owasp'), list) else [meta.get('owasp')] if meta.get('owasp') else [])[:5]}))
    return findings


class SemgrepAdapter(TestAdapter):
    name = 'semgrep'
    tier = 'passive'
    target_kinds = ('repo',)
    description = 'Semgrep static analysis (auto config).'

    def available(self, settings: Settings) -> bool:
        import shutil

        return bool(shutil.which(settings.semgrep_bin))

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        settings = ctx.settings
        path = policy.validate_repo_target(asset.target, settings)
        config = safe_config(plan_params.get('config'))
        argv = [settings.semgrep_bin, '--config', config, '--json', '--metrics=off', '--quiet', '--disable-version-check', str(path)]
        await ctx.rate_limiter.acquire()
        code, out, err = await run_tool(argv, timeout=settings.test_tool_timeout_seconds)
        if not out.strip():
            raise Unavailable(f'semgrep produced no output (exit {code})')
        try:
            report = json.loads(out)
        except (ValueError, UnicodeDecodeError) as exc:
            raise Unavailable('semgrep returned invalid JSON') from exc
        return parse_report(report)


register(SemgrepAdapter())
