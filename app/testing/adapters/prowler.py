"""Prowler adapter (passive, cloud_account): `prowler <aws|azure|gcp> -M json ...`.

Runs Prowler against an authorized cloud account (credentials resolved from the asset's
provider via environment / ambient role; Prowler is read-only). Only FAIL checks become
findings. The JSON report is written to a temp directory and parsed; the native Prowler
JSON shape (a list of check objects) is supported.
"""
from __future__ import annotations

import glob
import json
import os
import tempfile

from ...core.config import Settings
from ...core.errors import Unavailable
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register, run_tool

_PROVIDERS = {'aws', 'azure', 'gcp'}
_SEV_MAP = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low', 'informational': 'informational'}


def parse_report(checks: list) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for item in (checks or [])[:5000]:
        status = str(item.get('Status') or item.get('status') or '').upper()
        if status not in {'FAIL', 'FAILED'}:
            continue
        check_id = str(item.get('CheckID') or item.get('check_id') or 'prowler')
        title = str(item.get('CheckTitle') or item.get('check_title') or check_id)
        region = str(item.get('Region') or item.get('region') or '')
        resource = str(item.get('ResourceId') or item.get('resource_id') or item.get('ResourceArn') or '')
        remediation = item.get('Remediation') or {}
        if isinstance(remediation, dict):
            rec = (remediation.get('Recommendation') or {})
            remediation_text = str(rec.get('Text') or '') if isinstance(rec, dict) else str(remediation)
        else:
            remediation_text = str(remediation)
        findings.append(NormalizedFinding(
            rule=f'prowler:{check_id}:{region}:{resource}'[:160], title=title[:240],
            description=str(item.get('StatusExtended') or item.get('status_extended') or title)[:2000],
            remediation=(remediation_text or 'Apply the control recommended by the CIS/CSP benchmark.')[:2000],
            severity=_SEV_MAP.get(str(item.get('Severity') or item.get('severity') or 'medium').lower(), 'medium'),
            evidence={'check_id': check_id, 'region': region, 'resource': resource,
                      'service': str(item.get('ServiceName') or item.get('service_name') or '')}))
    return findings


def _load_reports(directory: str) -> list:
    checks: list = []
    for path in glob.glob(os.path.join(directory, '*.json')):
        try:
            with open(path, encoding='utf-8') as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(data, list):
            checks.extend(data)
        elif isinstance(data, dict) and isinstance(data.get('findings'), list):
            checks.extend(data['findings'])
    return checks


class ProwlerAdapter(TestAdapter):
    name = 'prowler'
    tier = 'passive'
    target_kinds = ('cloud_account',)
    description = 'Prowler cloud security posture checks (AWS/Azure/GCP, read-only).'

    def available(self, settings: Settings) -> bool:
        import shutil

        return bool(shutil.which(settings.prowler_bin))

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        settings = ctx.settings
        provider = str(plan_params.get('provider') or asset.target or 'aws').lower()
        if provider not in _PROVIDERS:
            raise Unavailable(f'prowler provider must be one of {sorted(_PROVIDERS)}')
        out_dir = tempfile.mkdtemp(prefix='prowler-')
        try:
            argv = [settings.prowler_bin, provider, '-M', 'json', '--output-directory', out_dir, '-q']
            await ctx.rate_limiter.acquire()
            code, out, err = await run_tool(argv, timeout=settings.test_tool_timeout_seconds)
            checks = _load_reports(out_dir)
            if not checks and code not in (0, 3):  # prowler exits 3 when findings are present
                raise Unavailable(f'prowler exited {code} and produced no report')
            return parse_report(checks)
        finally:
            for path in glob.glob(os.path.join(out_dir, '*')):
                try:
                    os.unlink(path)
                except OSError:
                    pass
            try:
                os.rmdir(out_dir)
            except OSError:
                pass


register(ProwlerAdapter())
