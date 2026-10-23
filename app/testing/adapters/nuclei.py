"""Nuclei adapter (active, web).

`nuclei -u <target> -jsonl -severity low,medium,high,critical -rate-limit <rps> -timeout 10
-no-interactsh -silent` (plus `-t <templates>` when configured). Output is JSONL, one
finding per line. The configured rate limit is derived from scope.max_rps.
"""
from __future__ import annotations

import json
import re

from ...core.config import Settings
from ...core.errors import ScopeDenied, Unavailable
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register, run_tool

_SEV = {'critical', 'high', 'medium', 'low', 'info'}
# Template selectors are relative template-directory paths or tags (e.g. "http/cves", "cves/2024"). Never absolute
# paths, parent traversal, URLs or anything that nuclei would parse as a flag.
_TEMPLATE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_./-]{0,255}$')


def safe_templates(value: object) -> str:
    """Validate a plan-supplied template selector (comma separated). Raises ScopeDenied on anything unsafe."""
    text = str(value or '').strip()
    if not text:
        return ''
    parts = [p.strip() for p in text.split(',') if p.strip()]
    for part in parts:
        if not _TEMPLATE_RE.match(part) or '..' in part or '://' in part or part.startswith(('-', '/', '~')):
            raise ScopeDenied('nuclei templates must be relative template paths or tags; absolute paths, traversal, URLs and flags are not allowed')
    return ','.join(parts)


def parse_jsonl(text: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        info = item.get('info') or {}
        template_id = str(item.get('template-id') or item.get('templateID') or 'nuclei')
        matched = str(item.get('matched-at') or item.get('host') or '')
        classification = info.get('classification') or {}
        cve_ids = [c for c in (classification.get('cve-id') or []) if isinstance(c, str)]
        cvss = classification.get('cvss-score')
        severity = str(info.get('severity') or 'info').lower()
        findings.append(NormalizedFinding(
            rule=f'nuclei:{template_id}', title=str(info.get('name') or template_id)[:240],
            description=str(info.get('description') or info.get('name') or template_id)[:2000],
            remediation=str(info.get('remediation') or 'Review the matched template and remediate the underlying issue.')[:2000],
            severity='informational' if severity == 'info' else (severity if severity in _SEV else 'low'),
            evidence={'template_id': template_id, 'matched_at': matched, 'type': str(item.get('type') or ''),
                      'tags': (info.get('tags') or [])[:10]},
            cve_ids=cve_ids, cvss=float(cvss) if isinstance(cvss, (int, float)) else None))
    return findings


class NucleiAdapter(TestAdapter):
    name = 'nuclei'
    tier = 'active'
    target_kinds = ('web',)
    description = 'Nuclei template-based active web scanner (rate-limited to the scope).'

    def available(self, settings: Settings) -> bool:
        import shutil

        return bool(shutil.which(settings.nuclei_bin))

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        settings = ctx.settings
        target = ctx.target or asset.target
        rps = max(1, int(scope.max_rps if scope else settings.test_rate_limit_rps))
        argv = [settings.nuclei_bin, '-u', target, '-jsonl', '-severity', 'low,medium,high,critical',
                '-rate-limit', str(rps), '-timeout', '10', '-no-interactsh', '-silent']
        templates = safe_templates(plan_params.get('templates')) if plan_params.get('templates') else settings.nuclei_templates
        if templates:
            argv += ['-t', str(templates)]
        await ctx.rate_limiter.acquire()
        code, out, err = await run_tool(argv, timeout=settings.test_tool_timeout_seconds)
        if not out.strip() and code not in (0,):
            raise Unavailable(f'nuclei exited {code} with no output')
        return parse_jsonl(out)


register(NucleiAdapter())
