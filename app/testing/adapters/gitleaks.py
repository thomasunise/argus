"""Gitleaks adapter (passive, repo): `gitleaks detect --no-git -f json -r <tmpfile> -s <path>`.

Gitleaks writes its JSON report to the -r file. Findings carry the rule, file, line and
fingerprint; the detected secret value (`Secret`/`Match`) is NEVER ingested.
"""
from __future__ import annotations

import json
import os
import tempfile

from ...core.config import Settings
from ...core.errors import Unavailable
from ...core import policy
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register, run_tool


def parse_report(report: list) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for item in (report or [])[:2000]:
        rule = str(item.get('RuleID') or item.get('Rule') or 'secret')
        file = str(item.get('File') or 'unknown')[:300]
        line = item.get('StartLine')
        fingerprint = str(item.get('Fingerprint') or '')[:200]
        findings.append(NormalizedFinding(
            rule=f'gitleaks:{rule}:{fingerprint or file}', title=f'Potential secret: {rule}',
            description=f'Gitleaks matched rule {rule} in {file}' + (f' at line {line}' if line else '')
                        + '. The secret value was not ingested.',
            remediation='Rotate the exposed credential if confirmed, remove it from history, and add a pre-commit secret scan.',
            severity='high',
            evidence={'rule': rule, 'file': file, 'line': line, 'fingerprint': fingerprint,
                      'description': str(item.get('Description') or '')[:200]}))
    return findings


class GitleaksAdapter(TestAdapter):
    name = 'gitleaks'
    tier = 'passive'
    target_kinds = ('repo',)
    description = 'Gitleaks secret scanning (filesystem mode).'

    def available(self, settings: Settings) -> bool:
        import shutil

        return bool(shutil.which(settings.gitleaks_bin))

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        settings = ctx.settings
        path = policy.validate_repo_target(asset.target, settings)
        fd, report_path = tempfile.mkstemp(prefix='gitleaks-', suffix='.json')
        os.close(fd)
        try:
            argv = [settings.gitleaks_bin, 'detect', '--no-git', '-f', 'json', '-r', report_path, '-s', str(path), '--exit-code', '0']
            await ctx.rate_limiter.acquire()
            code, out, err = await run_tool(argv, timeout=settings.test_tool_timeout_seconds)
            try:
                with open(report_path, encoding='utf-8') as fh:
                    raw = fh.read()
            except OSError as exc:
                raise Unavailable('gitleaks did not produce a report file') from exc
            if not raw.strip():
                return []
            try:
                report = json.loads(raw)
            except (ValueError, UnicodeDecodeError) as exc:
                raise Unavailable('gitleaks returned invalid JSON') from exc
            return parse_report(report if isinstance(report, list) else [])
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass


register(GitleaksAdapter())
