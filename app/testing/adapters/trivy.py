"""Trivy adapter (passive).

Repo assets: `trivy fs --format json --scanners vuln,misconfig,secret <path>`.
Host assets whose target starts with `image:`: `trivy image --format json ... <ref>`.

Vulnerabilities carry CVE ids and CVSS; misconfigurations carry the rule and location;
secrets carry title + file + line ONLY — the detected secret value is never ingested.
"""
from __future__ import annotations

import json

from ...core.config import Settings
from ...core.errors import Unavailable
from ...core import policy
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register, run_tool

_SEV_MAP = {'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low', 'UNKNOWN': 'informational'}


def _cvss_score(item: dict) -> float | None:
    cvss = item.get('CVSS') or {}
    for vendor in ('nvd', 'redhat', 'ghsa'):
        data = cvss.get(vendor) or {}
        score = data.get('V3Score') or data.get('V2Score')
        if isinstance(score, (int, float)):
            return float(score)
    return None


def parse_report(report: dict) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for result in (report.get('Results') or [])[:500]:
        location = str(result.get('Target') or 'unknown')[:200]
        for item in (result.get('Vulnerabilities') or [])[:1000]:
            vid = str(item.get('VulnerabilityID') or 'CVE-UNKNOWN')
            pkg = str(item.get('PkgName') or 'package')[:120]
            fixed = str(item.get('FixedVersion') or 'not specified')[:120]
            cve_ids = [vid] if vid.upper().startswith('CVE-') else []
            findings.append(NormalizedFinding(
                rule=f'vuln:{location}:{vid}', title=f'{vid} in {pkg}',
                description=f'Affected package {pkg} (installed {item.get("InstalledVersion", "?")}). Fixed version: {fixed}.',
                remediation='Upgrade the affected package to a vendor-supported fixed version, then rescan.',
                severity=_SEV_MAP.get(str(item.get('Severity') or '').upper(), 'medium'),
                evidence={'target': location, 'package': pkg, 'installed': str(item.get('InstalledVersion') or ''),
                          'fixed_version': fixed, 'primary_url': str(item.get('PrimaryURL') or '')},
                cve_ids=cve_ids, cvss=_cvss_score(item)))
        for item in (result.get('Misconfigurations') or [])[:1000]:
            mid = str(item.get('ID') or 'misconfiguration')
            findings.append(NormalizedFinding(
                rule=f'misconfig:{location}:{mid}', title=str(item.get('Title') or mid)[:240],
                description=f'{item.get("Description") or item.get("Message") or ""}'[:2000] + f' (location: {location})',
                remediation=str(item.get('Resolution') or 'Review and correct the affected configuration.')[:2000],
                severity=_SEV_MAP.get(str(item.get('Severity') or '').upper(), 'medium'),
                evidence={'target': location, 'id': mid, 'status': str(item.get('Status') or '')}))
        for item in (result.get('Secrets') or [])[:1000]:
            rid = str(item.get('RuleID') or 'secret')
            line = item.get('StartLine')
            # Never ingest the secret value (Match / Code). Title + file + line only.
            findings.append(NormalizedFinding(
                rule=f'secret:{location}:{rid}:{line}', title=f'Potential secret exposure: {str(item.get("Title") or rid)[:120]}',
                description=f'A potential secret was detected in {location}' + (f' at line {line}' if line else '') + '. The secret value was not ingested.',
                remediation='Inspect the source securely, revoke any confirmed credential, and prevent recurrence.',
                severity=_SEV_MAP.get(str(item.get('Severity') or '').upper(), 'high'),
                evidence={'target': location, 'rule_id': rid, 'line': line, 'category': str(item.get('Category') or '')}))
    return findings


class TrivyAdapter(TestAdapter):
    name = 'trivy'
    tier = 'passive'
    target_kinds = ('repo', 'host')
    description = 'Trivy filesystem and container-image scanner (vulns, misconfigurations, secrets).'

    def available(self, settings: Settings) -> bool:
        import shutil

        return bool(settings.enable_trivy and shutil.which(settings.trivy_bin))

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        settings = ctx.settings
        if asset.kind == 'host':
            if not asset.target.startswith('image:'):
                raise Unavailable('trivy host assets must have a target of the form image:<ref>')
            ref = asset.target.split(':', 1)[1]
            argv = [settings.trivy_bin, 'image', '--format', 'json', '--scanners', 'vuln,misconfig,secret',
                    '--quiet', '--no-progress', ref]
        else:
            path = policy.validate_repo_target(asset.target, settings)
            argv = [settings.trivy_bin, 'fs', '--format', 'json', '--scanners', 'vuln,misconfig,secret',
                    '--quiet', '--no-progress', str(path)]
        await ctx.rate_limiter.acquire()
        code, out, err = await run_tool(argv, timeout=settings.test_tool_timeout_seconds)
        if code != 0 and not out.strip():
            raise Unavailable(f'trivy exited {code}; verify the vulnerability DB is available')
        try:
            report = json.loads(out)
        except (ValueError, UnicodeDecodeError) as exc:
            raise Unavailable('trivy returned invalid JSON') from exc
        return parse_report(report)


register(TrivyAdapter())
