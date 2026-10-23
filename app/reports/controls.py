"""Compliance evidence mapping. A static catalog maps framework controls to the automated
evidence checks in `evidence.py`. The output is an evidence inventory an auditor can start
from; it is explicitly NOT a certification, attestation or legal opinion.

Status rules per control:
  satisfied  every automated evidence item is ok
  partial    some, but not all, evidence items are ok
  missing    automated evidence exists but none of it is ok
  manual     the control has no automated evidence on this deployment (none, or all undeterminable)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from ..core.config import Settings
from .evidence import Evidence, run_check, utcnow

DISCLAIMER = ('Automated evidence mapping only. Statuses reflect signals Sentinel can observe about its own configuration and the '
              'tenant data it holds. They are not a certification, attestation or audit opinion for any framework.')


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    description: str
    evidence: tuple[str, ...]
    manual_guidance: str = ''


SOC2: tuple[Control, ...] = (
    Control('CC6.1', 'Logical access security', 'Logical access to systems and data is restricted to authorized users through identity, authentication and authorization controls.',
            ('sso_configured', 'mfa_enforced', 'api_key_rotation', 'session_controls')),
    Control('CC6.2', 'User registration and authorization', 'New users are registered and authorized before access is granted; access is removed when no longer needed.',
            ('rbac_roles_in_use', 'admin_changes_audited')),
    Control('CC6.3', 'Role-based access and least privilege', 'Access is granted based on role and least privilege, and reviewed.',
            ('rbac_roles_in_use', 'least_privilege_owners')),
    Control('CC6.6', 'Boundary protection', 'Logical access from outside the system boundary is protected.', ('transport_security', 'session_controls')),
    Control('CC6.7', 'Transmission and movement of information', 'Information is protected during transmission and removal.', ('transport_security',)),
    Control('CC6.8', 'Unauthorized software and change prevention', 'Controls prevent or detect unauthorized or malicious software and changes.',
            ('detections_enabled', 'collector_secrets_by_reference')),
    Control('CC7.1', 'Vulnerability and configuration monitoring', 'Configuration changes and new vulnerabilities are identified.',
            ('asset_inventory', 'coverage', 'collectors_configured', 'testing_authorized')),
    Control('CC7.2', 'Anomaly monitoring', 'System components are monitored for anomalies indicative of malicious acts or errors.',
            ('detections_enabled', 'detections_recent_run', 'event_telemetry', 'canaries_deployed')),
    Control('CC7.3', 'Security event evaluation', 'Security events are evaluated to determine whether they are incidents.', ('incident_workflow', 'detection_volume_trend')),
    Control('CC7.4', 'Incident response', 'Incidents are responded to, contained and remediated.', ('incident_workflow', 'vulnerability_sla', 'mttr', 'action_governance')),
    Control('CC8.1', 'Change management', 'Changes to infrastructure, data and software are authorized, tested, approved and implemented.',
            ('action_governance', 'admin_changes_audited', 'audit_chain_valid')),
    Control('CC9.2', 'Vendor and business partner risk', 'Risks from vendors and partners are assessed and managed.', (), 'Record vendor assessments outside Sentinel.'),
    Control('A1.2', 'Availability: recovery infrastructure', 'Backup and recovery infrastructure and processes are in place.', (),
            'Database and audit-sink backups are operated outside Sentinel.'),
    Control('C1.1', 'Confidentiality: identification and protection', 'Confidential information is identified and protected.',
            ('collector_secrets_by_reference', 'audit_external_sink', 'retention_policy')),
)

NIST_800_171: tuple[Control, ...] = (
    Control('3.1.1', 'Limit system access to authorized users', 'Access limited to authorized users, processes and devices.', ('sso_configured', 'rbac_roles_in_use', 'api_key_rotation')),
    Control('3.1.2', 'Limit access to permitted transactions and functions', 'Users may only perform the functions their role permits.', ('rbac_roles_in_use', 'least_privilege_owners')),
    Control('3.1.5', 'Least privilege', 'Least privilege including for privileged accounts.', ('least_privilege_owners', 'action_governance')),
    Control('3.1.7', 'Prevent non-privileged users executing privileged functions', 'Privileged functions are restricted and their execution audited.',
            ('action_governance', 'admin_changes_audited')),
    Control('3.1.11', 'Terminate sessions', 'Sessions terminate automatically after a defined condition.', ('session_controls',)),
    Control('3.3.1', 'Create and retain audit records', 'System audit logs and records are created and retained.', ('audit_chain_valid', 'audit_external_sink', 'retention_policy')),
    Control('3.3.2', 'Trace actions to individual users', 'Actions of individual users can be uniquely traced.', ('admin_changes_audited', 'sso_configured')),
    Control('3.3.8', 'Protect audit information from unauthorized modification', 'Audit information and tools are protected from modification and deletion.',
            ('audit_chain_valid', 'audit_signing', 'audit_external_sink')),
    Control('3.4.1', 'Baseline configurations and inventories', 'Baseline configurations and system inventories are established and maintained.',
            ('asset_inventory', 'asset_ownership', 'collectors_configured')),
    Control('3.5.3', 'Multifactor authentication', 'MFA for local and network access to privileged accounts and network access to non-privileged accounts.', ('mfa_enforced',)),
    Control('3.6.1', 'Incident-handling capability', 'Operational incident handling: preparation, detection, analysis, containment, recovery.',
            ('detections_enabled', 'incident_workflow', 'action_governance')),
    Control('3.6.2', 'Track, document and report incidents', 'Incidents are tracked, documented and reported.', ('incident_workflow', 'audit_chain_valid')),
    Control('3.11.2', 'Scan for vulnerabilities', 'Periodic vulnerability scanning of systems and applications.', ('testing_authorized', 'coverage', 'event_telemetry')),
    Control('3.11.3', 'Remediate vulnerabilities', 'Vulnerabilities are remediated in accordance with risk assessments.', ('vulnerability_sla', 'mttr')),
    Control('3.13.8', 'Cryptographic protection of CUI in transit', 'Mechanisms prevent unauthorized disclosure during transmission.', ('transport_security',)),
    Control('3.13.11', 'FIPS-validated cryptography', 'FIPS-validated cryptography is employed to protect CUI.', (), 'Validate the TLS terminator and database encryption modules.'),
    Control('3.14.1', 'Identify, report and correct flaws', 'System flaws are identified, reported and corrected in a timely manner.', ('vulnerability_sla', 'mttr', 'detection_volume_trend')),
    Control('3.14.6', 'Monitor systems to detect attacks', 'Systems, inbound and outbound traffic are monitored for attacks and indicators.',
            ('detections_enabled', 'detections_recent_run', 'canaries_deployed', 'event_telemetry')),
    Control('3.14.7', 'Identify unauthorized use', 'Unauthorized use of organizational systems is identified.', ('detections_enabled', 'canaries_deployed', 'exposure')),
)

ISO27001: tuple[Control, ...] = (
    Control('A.5.9', 'Inventory of information and other associated assets', 'An inventory of assets with owners is developed and maintained.', ('asset_inventory', 'asset_ownership')),
    Control('A.5.15', 'Access control', 'Rules to control access are established based on business and security requirements.', ('rbac_roles_in_use', 'sso_configured')),
    Control('A.5.16', 'Identity management', 'The full life cycle of identities is managed.', ('sso_configured', 'admin_changes_audited')),
    Control('A.5.17', 'Authentication information', 'Allocation and management of authentication information is controlled.', ('mfa_enforced', 'api_key_rotation')),
    Control('A.5.18', 'Access rights', 'Access rights are provisioned, reviewed, modified and removed per policy.', ('rbac_roles_in_use', 'least_privilege_owners')),
    Control('A.5.24', 'Incident management planning and preparation', 'Processes, roles and responsibilities for incident management are defined.', ('incident_workflow', 'detections_enabled')),
    Control('A.5.26', 'Response to information security incidents', 'Incidents are responded to in accordance with documented procedures.', ('incident_workflow', 'action_governance', 'mttr')),
    Control('A.5.28', 'Collection of evidence', 'Procedures for identification, collection and preservation of evidence.', ('audit_chain_valid', 'audit_external_sink')),
    Control('A.5.30', 'ICT readiness for business continuity', 'ICT readiness is planned, implemented and tested.', (), 'Document continuity tests outside Sentinel.'),
    Control('A.8.2', 'Privileged access rights', 'Allocation and use of privileged access rights is restricted and managed.', ('least_privilege_owners', 'action_governance')),
    Control('A.8.5', 'Secure authentication', 'Secure authentication technologies and procedures are implemented.', ('mfa_enforced', 'session_controls')),
    Control('A.8.8', 'Management of technical vulnerabilities', 'Information about technical vulnerabilities is obtained and remediated.', ('testing_authorized', 'vulnerability_sla', 'coverage')),
    Control('A.8.9', 'Configuration management', 'Configurations of hardware, software, services and networks are managed.', ('collectors_configured', 'collector_secrets_by_reference')),
    Control('A.8.15', 'Logging', 'Logs recording activities, exceptions, faults and events are produced, stored, protected and analysed.',
            ('audit_chain_valid', 'audit_signing', 'event_telemetry', 'retention_policy')),
    Control('A.8.16', 'Monitoring activities', 'Networks, systems and applications are monitored for anomalous behaviour.',
            ('detections_enabled', 'detections_recent_run', 'canaries_deployed')),
    Control('A.8.24', 'Use of cryptography', 'Rules for the effective use of cryptography are defined and implemented.', ('transport_security', 'audit_signing')),
    Control('A.8.32', 'Change management', 'Changes to information processing facilities and systems are subject to change management.', ('action_governance', 'admin_changes_audited')),
)

FRAMEWORKS: dict[str, dict[str, Any]] = {
    'soc2': {'name': 'SOC 2 (AICPA Trust Services Criteria 2017)', 'controls': SOC2},
    'nist-800-171': {'name': 'NIST SP 800-171 Rev. 2', 'controls': NIST_800_171},
    'iso27001': {'name': 'ISO/IEC 27001:2022 Annex A', 'controls': ISO27001},
}


def _status(items: list[Evidence]) -> str:
    determined = [e for e in items if e.ok is not None]
    if not determined:
        return 'manual'
    ok = sum(1 for e in determined if e.ok)
    if ok == len(determined):
        return 'satisfied'
    return 'partial' if ok else 'missing'


def compliance(db: Session, tenant_id: str, framework: str, settings: Settings) -> dict[str, Any]:
    spec = FRAMEWORKS[framework]
    cache: dict[str, Evidence] = {}

    def evidence_for(key: str) -> Evidence:
        if key not in cache:
            cache[key] = run_check(key, db, tenant_id, settings)
        return cache[key]

    controls_out = []
    totals = {'satisfied': 0, 'partial': 0, 'missing': 0, 'manual': 0}
    for control in spec['controls']:
        items = [evidence_for(k) for k in control.evidence]
        status = _status(items)
        totals[status] += 1
        controls_out.append({'id': control.id, 'title': control.title, 'description': control.description, 'status': status,
                             'evidence': [e.to_dict() for e in items], 'manual_guidance': control.manual_guidance})
    automated = len(spec['controls']) - totals['manual']
    return {'framework': framework, 'name': spec['name'], 'generated_at': utcnow(), 'tenant_id': tenant_id, 'disclaimer': DISCLAIMER,
            'totals': {**totals, 'controls': len(spec['controls']), 'automated': automated,
                       'satisfied_ratio': round(totals['satisfied'] / automated, 3) if automated else None},
            'controls': controls_out}


def catalog() -> dict[str, Any]:
    return {key: {'name': spec['name'], 'controls': [{'id': c.id, 'title': c.title, 'evidence': list(c.evidence), 'automated': bool(c.evidence)}
                                                     for c in spec['controls']]} for key, spec in FRAMEWORKS.items()}
