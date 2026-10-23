"""Trivy JSON reports (schema v2): vulnerabilities, misconfigurations and secrets become findings;
detected secrets also become `secret_detected` events. Secret values (Match/Code) are never stored."""
from __future__ import annotations

import re
from typing import Any

from ...core.findings import EventDraft
from . import registry
from ._common import FindingDraft, ParseContext, Parser, as_float, event, stable_id

_CVE = re.compile(r'^CVE-\d{4}-\d{4,}$')
MAX_RESULTS = 250
MAX_ITEMS_PER_RESULT = 500
MAX_FINDINGS = 2000


class TrivyParser(Parser):
    name = 'trivy'
    source = 'trivy'
    description = 'Trivy JSON report (filesystem, image, repository or config scan).'
    kind = 'both'
    example = 'tests/fixtures/integrations/trivy/report.json'

    def items(self, payload: Any) -> list[Any]:
        if isinstance(payload, dict) and isinstance(payload.get('Results'), list):
            return [payload]
        if isinstance(payload, list):
            return payload
        return [payload]

    def parse_item(self, item: dict, ctx: ParseContext) -> list[EventDraft]:
        artifact = str(item.get('ArtifactName') or 'artifact')[:200]
        drafts: list[EventDraft] = []
        for result in (item.get('Results') or [])[:MAX_RESULTS]:
            if not isinstance(result, dict):
                continue
            target = str(result.get('Target') or 'unknown')[:200]
            for secret in (result.get('Secrets') or [])[:MAX_ITEMS_PER_RESULT]:
                if not isinstance(secret, dict):
                    continue
                rule_id = str(secret.get('RuleID') or 'secret')
                line = secret.get('StartLine')
                drafts.append(event(self.source, stable_id('secret', artifact, target, rule_id, line), f'Secret detected: {secret.get("Title") or rule_id}',
                                    severity=str(secret.get('Severity') or 'high'), category='code', actor='', entity=artifact, action='secret_detected',
                                    occurred_at=item.get('CreatedAt'), metadata={'secret_type': rule_id, 'category': secret.get('Category') or '', 'file': target, 'line': line,
                                              'repo': artifact, 'scanner': 'trivy', 'service': 'trivy'}))
        return drafts

    def findings_for_item(self, item: dict, ctx: ParseContext) -> list[FindingDraft]:
        artifact = str(item.get('ArtifactName') or 'artifact')[:200]
        out: list[FindingDraft] = []
        for result in (item.get('Results') or [])[:MAX_RESULTS]:
            if not isinstance(result, dict):
                continue
            target = str(result.get('Target') or 'unknown')[:200]
            for vuln in (result.get('Vulnerabilities') or [])[:MAX_ITEMS_PER_RESULT]:
                if not isinstance(vuln, dict):
                    continue
                ident = str(vuln.get('VulnerabilityID') or 'unknown')
                pkg = str(vuln.get('PkgName') or 'package')[:90]
                cvss = None
                for vendor in (vuln.get('CVSS') or {}).values() if isinstance(vuln.get('CVSS'), dict) else []:
                    if isinstance(vendor, dict):
                        cvss = as_float(vendor.get('V3Score')) or cvss
                out.append(FindingDraft(
                    source=self.source, rule=f'vuln:{target}:{ident}', title=f'{ident} in {pkg}',
                    description=(f'{str(vuln.get("Title") or "")[:300]} Affected package: {pkg} {str(vuln.get("InstalledVersion") or "")[:60]}. '
                                 f'Location: {target}. Fixed version: {str(vuln.get("FixedVersion") or "not specified")[:60]}.').strip(),
                    remediation='Upgrade the affected package to a vendor-supported fixed version, then rescan.',
                    severity=str(vuln.get('Severity') or 'medium'), cvss=cvss, cve_ids=[ident] if _CVE.match(ident) else [],
                    evidence={'target': target, 'identifier': ident, 'kind': 'vuln', 'package': pkg, 'installed': vuln.get('InstalledVersion'),
                              'fixed': vuln.get('FixedVersion'), 'artifact': artifact, 'primary_url': vuln.get('PrimaryURL')},
                    tags=['trivy', 'vuln']))
                if len(out) >= MAX_FINDINGS:
                    ctx.errors.append(f'finding cap of {MAX_FINDINGS} reached; remaining results dropped')
                    return out
            for mis in (result.get('Misconfigurations') or [])[:MAX_ITEMS_PER_RESULT]:
                if not isinstance(mis, dict):
                    continue
                ident = str(mis.get('ID') or 'misconfiguration')
                out.append(FindingDraft(
                    source=self.source, rule=f'misconfig:{target}:{ident}', title=str(mis.get('Title') or ident)[:240],
                    description=f'Configuration issue in {target}. {str(mis.get("Message") or mis.get("Description") or "")[:500]}',
                    remediation=str(mis.get('Resolution') or 'Review and correct the affected configuration.')[:500],
                    severity=str(mis.get('Severity') or 'medium'),
                    evidence={'target': target, 'identifier': ident, 'kind': 'misconfig', 'type': mis.get('Type'), 'artifact': artifact,
                              'primary_url': mis.get('PrimaryURL')},
                    tags=['trivy', 'misconfig']))
                if len(out) >= MAX_FINDINGS:
                    return out
            for secret in (result.get('Secrets') or [])[:MAX_ITEMS_PER_RESULT]:
                if not isinstance(secret, dict):
                    continue
                ident = str(secret.get('RuleID') or 'secret')
                out.append(FindingDraft(
                    source=self.source, rule=f'secret:{target}:{ident}', title=f'Potential secret exposure: {str(secret.get("Category") or ident)[:90]}',
                    description=f'Potential credential ({str(secret.get("Title") or ident)[:120]}) found in {target}. Secret contents were not imported.',
                    remediation='Inspect the source securely, revoke exposed credentials if confirmed, and prevent recurrence with a pre-commit scanner.',
                    severity=str(secret.get('Severity') or 'high'),
                    evidence={'target': target, 'identifier': ident, 'kind': 'secret', 'category': secret.get('Category'), 'line': secret.get('StartLine'),
                              'artifact': artifact},
                    tags=['trivy', 'secret']))
                if len(out) >= MAX_FINDINGS:
                    return out
        return out


registry.register(TrivyParser())
