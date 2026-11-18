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

DISCLAIMER = ('Automated evidence mapping only. Statuses reflect signals Argus can observe about its own configuration and the '
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
    Control('CC9.2', 'Vendor and business partner risk', 'Risks from vendors and partners are assessed and managed.', (), 'Record vendor assessments outside Argus.'),
    Control('A1.2', 'Availability: recovery infrastructure', 'Backup and recovery infrastructure and processes are in place.', (),
            'Database and audit-sink backups are operated outside Argus.'),
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
    Control('A.5.30', 'ICT readiness for business continuity', 'ICT readiness is planned, implemented and tested.', (), 'Document continuity tests outside Argus.'),
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

PCI_DSS: tuple[Control, ...] = (
    Control('PCI-2.2', 'System components configured securely', 'Configuration standards are developed, implemented and maintained.',
            ('asset_inventory', 'collectors_configured', 'collector_secrets_by_reference')),
    Control('PCI-6.3', 'Security vulnerabilities identified and addressed', 'Vulnerabilities are identified and addressed within risk-ranked SLAs.',
            ('testing_authorized', 'vulnerability_sla', 'mttr')),
    Control('PCI-7.2', 'Access appropriately defined and assigned', 'Access to system components and data is limited by role and least privilege.',
            ('rbac_roles_in_use', 'least_privilege_owners')),
    Control('PCI-8.3', 'Strong authentication for users and administrators', 'MFA is implemented for all access into the CDE and administrative access.',
            ('mfa_enforced', 'sso_configured', 'session_controls', 'api_key_rotation')),
    Control('PCI-10.2', 'Audit logs implemented to support detection and forensics', 'Audit logs record user actions, invalid access attempts, and privilege changes.',
            ('audit_chain_valid', 'audit_signing', 'audit_external_sink', 'admin_changes_audited')),
    Control('PCI-11.3', 'External and internal vulnerabilities regularly identified', 'Vulnerability scans and penetration testing are performed under authorization.',
            ('testing_authorized', 'coverage')),
    Control('PCI-12.10', 'Suspected and confirmed security incidents responded to immediately', 'Incident response plan, detections and containment actions are operational.',
            ('detections_enabled', 'incident_workflow', 'action_governance')),
)

GLBA_FFIEC: tuple[Control, ...] = (
    Control('GLBA-314.4(c)(1)', 'Access controls and authentication', 'Implement and periodically review access controls and multi-factor authentication.',
            ('sso_configured', 'mfa_enforced', 'rbac_roles_in_use', 'least_privilege_owners')),
    Control('GLBA-314.4(c)(2)', 'Inventory and data classification', 'Identify and manage data, personnel, devices, systems and facilities.',
            ('asset_inventory', 'asset_ownership', 'coverage')),
    Control('GLBA-314.4(c)(3)', 'Encryption in transit and at rest', 'Encrypt customer information held or transmitted.',
            ('transport_security', 'collector_secrets_by_reference')),
    Control('GLBA-314.4(c)(6)', 'Audit trails and monitoring', 'Log activity of authorized users and detect unauthorized access or tampering.',
            ('audit_chain_valid', 'audit_signing', 'audit_external_sink', 'detections_enabled')),
    Control('GLBA-314.4(d)', 'Continuous monitoring and vulnerability assessment', 'Monitor effectiveness of key controls through continuous monitoring or periodic testing.',
            ('detections_recent_run', 'testing_authorized', 'vulnerability_sla')),
    Control('GLBA-314.4(h)', 'Incident response plan', 'Establish a written incident response plan to respond to and recover from security events.',
            ('incident_workflow', 'action_governance', 'mttr')),
)

NYDFS_500: tuple[Control, ...] = (
    Control('500.06', 'Audit trail', 'Maintain systems designed to reconstruct material financial transactions and audit trails for cybersecurity events.',
            ('audit_chain_valid', 'audit_signing', 'audit_external_sink', 'retention_policy')),
    Control('500.07', 'Access privileges and privileged accounts', 'Limit user access privileges and periodically review privileged accounts.',
            ('rbac_roles_in_use', 'least_privilege_owners', 'admin_changes_audited')),
    Control('500.09', 'Risk assessment and asset posture', 'Conduct periodic risk assessments of information systems and assets.',
            ('asset_inventory', 'asset_ownership', 'exposure')),
    Control('500.12', 'Multi-factor authentication', 'Require MFA for any individual accessing information systems.',
            ('mfa_enforced', 'sso_configured', 'session_controls')),
    Control('500.14', 'Monitoring and training', 'Implement risk-based controls designed to monitor the activity of authorized users and detect unauthorized access.',
            ('detections_enabled', 'detections_recent_run', 'canaries_deployed', 'event_telemetry')),
    Control('500.15', 'Encryption of nonpublic information', 'Encrypt nonpublic information held or transmitted.',
            ('transport_security', 'collector_secrets_by_reference')),
    Control('500.16', 'Incident response plan', 'Establish a written incident response plan and governed containment workflow.',
            ('incident_workflow', 'action_governance', 'vulnerability_sla')),
)

DORA: tuple[Control, ...] = (
    Control('DORA-Art.8', 'Identification of ICT assets and dependencies', 'Identify, classify and document all ICT supported business functions and assets.',
            ('asset_inventory', 'asset_ownership', 'coverage')),
    Control('DORA-Art.9', 'Protection and prevention', 'Continuously monitor and control the security and functioning of ICT systems and tools.',
            ('mfa_enforced', 'rbac_roles_in_use', 'transport_security', 'action_governance')),
    Control('DORA-Art.10', 'Detection of anomalous activities', 'Promptly detect anomalous activities, including ICT network performance and ICT-related incidents.',
            ('detections_enabled', 'detections_recent_run', 'canaries_deployed', 'event_telemetry')),
    Control('DORA-Art.11', 'Response and recovery', 'Comprehensive ICT business continuity policy and governed response/rollback procedures.',
            ('incident_workflow', 'action_governance', 'mttr')),
    Control('DORA-Art.17', 'ICT-related incident management process', 'Record, classify and preserve audit evidence for all ICT-related incidents.',
            ('incident_workflow', 'audit_chain_valid', 'audit_external_sink')),
    Control('DORA-Art.24', 'General requirements for digital operational resilience testing', 'Regularly test ICT tools and systems for vulnerabilities under scope governance.',
            ('testing_authorized', 'vulnerability_sla')),
)

HIPAA: tuple[Control, ...] = (
    Control('164.308(a)(1)', 'Security management process', 'Implement policies and procedures to prevent, detect, contain and correct security violations.',
            ('detections_enabled', 'vulnerability_sla', 'action_governance', 'incident_workflow')),
    Control('164.308(a)(3)', 'Workforce security and authorization', 'Ensure all workforce members have appropriate access to ePHI and terminate access when employment ends.',
            ('rbac_roles_in_use', 'least_privilege_owners', 'admin_changes_audited')),
    Control('164.308(a)(5)', 'Security awareness and login monitoring', 'Procedures for monitoring log-in attempts and reporting discrepancies.',
            ('mfa_enforced', 'session_controls', 'event_telemetry')),
    Control('164.308(a)(6)', 'Security incident procedures', 'Identify and respond to suspected or known security incidents; mitigate harmful effects and document outcomes.',
            ('incident_workflow', 'action_governance', 'mttr')),
    Control('164.312(a)(1)', 'Access control', 'Assign a unique name/number for identifying and tracking user identity and automatic logoff.',
            ('sso_configured', 'session_controls', 'rbac_roles_in_use')),
    Control('164.312(b)', 'Audit controls', 'Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems containing ePHI.',
            ('audit_chain_valid', 'audit_signing', 'audit_external_sink', 'retention_policy')),
    Control('164.312(c)(1)', 'Integrity', 'Protect ePHI from improper alteration or destruction using cryptographic verification.',
            ('audit_chain_valid', 'audit_signing')),
    Control('164.312(d)', 'Person or entity authentication', 'Verify that a person or entity seeking access to ePHI is the one claimed.',
            ('mfa_enforced', 'sso_configured', 'api_key_rotation')),
    Control('164.312(e)(1)', 'Transmission security', 'Technical security measures to guard against unauthorized access to ePHI transmitted over an electronic communications network.',
            ('transport_security',)),
)

NIST_800_53: tuple[Control, ...] = (
    Control('AC-2', 'Account management', 'Manage system accounts, group/role memberships, and audit account creation, modification and removal.',
            ('sso_configured', 'rbac_roles_in_use', 'admin_changes_audited', 'api_key_rotation')),
    Control('AC-3', 'Access enforcement', 'Enforce approved authorizations for logical access to information and system resources.',
            ('rbac_roles_in_use', 'least_privilege_owners')),
    Control('AC-5', 'Separation of duties', 'Separate duties of individuals to prevent malevolent activity without collusion.',
            ('least_privilege_owners', 'action_governance')),
    Control('AC-6', 'Least privilege', 'Employ the principle of least privilege, allowing only authorized accesses for users and processes.',
            ('least_privilege_owners', 'action_governance')),
    Control('AC-12', 'Session termination', 'Automatically terminate a user session after defined conditions or inactivity.',
            ('session_controls',)),
    Control('AU-2', 'Event logging', 'Identify and log security-relevant events across the system.',
            ('audit_chain_valid', 'event_telemetry', 'admin_changes_audited')),
    Control('AU-9', 'Protection of audit information', 'Protect audit information and audit logging tools from unauthorized access, modification and deletion.',
            ('audit_chain_valid', 'audit_signing', 'audit_external_sink')),
    Control('AU-11', 'Audit record retention', 'Retain audit records to provide support for after-the-fact investigations.',
            ('retention_policy', 'audit_external_sink')),
    Control('CM-8', 'System component inventory', 'Develop and document an inventory of system components with assigned owners.',
            ('asset_inventory', 'asset_ownership', 'collectors_configured')),
    Control('IA-2', 'Identification and authentication (organizational users)', 'Uniquely identify and authenticate organizational users with multifactor authentication.',
            ('mfa_enforced', 'sso_configured')),
    Control('IR-4', 'Incident handling', 'Implement incident handling capability for preparation, detection, analysis, containment, eradication, and recovery.',
            ('detections_enabled', 'incident_workflow', 'action_governance', 'mttr')),
    Control('RA-5', 'Vulnerability monitoring and scanning', 'Monitor and scan for vulnerabilities in the system and hosted applications.',
            ('testing_authorized', 'coverage', 'vulnerability_sla')),
    Control('SC-8', 'Transmission confidentiality and integrity', 'Protect the confidentiality and integrity of transmitted information.',
            ('transport_security',)),
    Control('SI-4', 'System monitoring', 'Monitor the system to detect attacks, indicators of potential attacks, and unauthorized connections.',
            ('detections_enabled', 'detections_recent_run', 'canaries_deployed', 'event_telemetry')),
)

FRAMEWORKS: dict[str, dict[str, Any]] = {
    'soc2': {'name': 'SOC 2 (AICPA Trust Services Criteria 2017)', 'controls': SOC2},
    'nist-800-171': {'name': 'NIST SP 800-171 Rev. 2', 'controls': NIST_800_171},
    'iso27001': {'name': 'ISO/IEC 27001:2022 Annex A', 'controls': ISO27001},
}

SECTOR_FRAMEWORKS: dict[str, dict[str, Any]] = {
    'pci-dss': {'name': 'PCI DSS v4.0 (Financial & Cardholder Data)', 'sector': 'financial', 'controls': PCI_DSS},
    'glba-ffiec': {'name': 'GLBA Safeguards Rule & FFIEC (Banking & Insurance)', 'sector': 'financial', 'controls': GLBA_FFIEC},
    'nydfs-500': {'name': 'NYDFS 23 NYCRR Part 500 (Financial Services)', 'sector': 'financial', 'controls': NYDFS_500},
    'dora': {'name': 'EU DORA Regulation (EU) 2022/2554 (Financial Entities)', 'sector': 'financial', 'controls': DORA},
    'hipaa': {'name': 'HIPAA Security Rule 45 CFR Part 164 (Healthcare)', 'sector': 'healthcare', 'controls': HIPAA},
    'nist-800-53': {'name': 'NIST SP 800-53 Rev. 5 / FedRAMP (Government)', 'sector': 'government', 'controls': NIST_800_53},
}

ALL_FRAMEWORKS: dict[str, dict[str, Any]] = {**FRAMEWORKS, **SECTOR_FRAMEWORKS}


def _status(items: list[Evidence]) -> str:
    determined = [e for e in items if e.ok is not None]
    if not determined:
        return 'manual'
    ok = sum(1 for e in determined if e.ok)
    if ok == len(determined):
        return 'satisfied'
    return 'partial' if ok else 'missing'


def compliance(db: Session, tenant_id: str, framework: str, settings: Settings) -> dict[str, Any]:
    spec = ALL_FRAMEWORKS[framework]
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


def catalog(*, include_sector: bool = False) -> dict[str, Any]:
    source = ALL_FRAMEWORKS if include_sector else FRAMEWORKS
    return {key: {'name': spec['name'], 'controls': [{'id': c.id, 'title': c.title, 'evidence': list(c.evidence), 'automated': bool(c.evidence)}
                                                     for c in spec['controls']]} for key, spec in source.items()}
