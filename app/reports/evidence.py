"""Automated evidence queries shared by the posture score and the compliance mapping.

Each check returns an `Evidence` whose `ok` is True (control signal present), False (absent)
or None (cannot be determined automatically on this deployment, for example because the
package that would produce the evidence is not installed or no data exists yet)."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.audit import verify_chain
from ..core.config import Settings
from ..models import AgentRun, ApiKey, Asset, Finding, Investigation, Membership, SecurityEvent, Tenant, User, loads

log = logging.getLogger('argus.reports')

OPEN_STATES = ('open', 'investigating')
API_KEY_MAX_AGE_DAYS = 90
CRITICAL_SLA_DAYS = 7
HIGH_SLA_DAYS = 30
MTTR_TARGET_DAYS = 30

# Asset kinds that a collector of the given kind inventories. Used for coverage.
ASSET_KIND_TO_COLLECTOR_KIND = {'cloud_account': 'cloud', 'identity_provider': 'identity', 'repo': 'code', 'host': 'endpoint',
                                'k8s_cluster': 'k8s', 'network': 'network', 'saas': 'identity'}


def aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Evidence:
    key: str
    ok: bool | None
    summary: str
    value: Any = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {'key': self.key, 'ok': self.ok, 'summary': self.summary, 'value': self.value, 'detail': self.detail}


Check = Callable[[Session, str, Settings], Evidence]
CHECKS: dict[str, Check] = {}


def check(key: str):
    def decorator(fn: Check) -> Check:
        CHECKS[key] = fn
        return fn
    return decorator


def run_check(key: str, db: Session, tenant_id: str, settings: Settings) -> Evidence:
    fn = CHECKS[key]
    try:
        return fn(db, tenant_id, settings)
    except Exception as exc:  # one failing query must not take the whole report down
        log.exception('evidence check %s failed', key)
        return Evidence(key, None, f'check failed: {type(exc).__name__}')


def tenant_settings(db: Session, tenant_id: str) -> dict[str, Any]:
    tenant = db.get(Tenant, tenant_id)
    return loads(tenant.settings_json) if tenant else {}


def count(db: Session, model, *where) -> int:
    return int(db.scalar(select(func.count()).select_from(model).where(*where)) or 0)


# ---------------------------------------------------------------- identity and access


@check('sso_configured')
def sso_configured(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    ok = bool(settings.oidc_issuer and settings.oidc_client_id)
    return Evidence('sso_configured', ok, 'OIDC single sign-on is configured' if ok else 'No OIDC issuer configured; local passwords only',
                    value=settings.oidc_issuer or None)


@check('mfa_enforced')
def mfa_enforced(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    rows = db.execute(select(User.totp_enabled).join(Membership, Membership.user_id == User.id)
                      .where(Membership.tenant_id == tenant_id, User.is_active.is_(True))).scalars().all()
    total, enabled = len(rows), sum(1 for r in rows if r)
    ok = bool(settings.totp_required) or (total > 0 and enabled == total)
    return Evidence('mfa_enforced', ok, f'{enabled}/{total} active members have TOTP enabled' + ('; TOTP_REQUIRED=true' if settings.totp_required else ''),
                    value={'enabled': enabled, 'total': total, 'required': bool(settings.totp_required)})


@check('api_key_rotation')
def api_key_rotation(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    rows = db.execute(select(ApiKey.created_at).where(ApiKey.tenant_id == tenant_id, ApiKey.revoked_at.is_(None))).scalars().all()
    if not rows:
        return Evidence('api_key_rotation', True, 'No active API keys', value={'active': 0})
    now = utcnow()
    ages = [(now - aware(c)).days for c in rows]
    oldest = max(ages)
    stale = sum(1 for a in ages if a > API_KEY_MAX_AGE_DAYS)
    return Evidence('api_key_rotation', stale == 0, f'{len(rows)} active keys, oldest {oldest} days, {stale} older than {API_KEY_MAX_AGE_DAYS} days',
                    value={'active': len(rows), 'oldest_days': oldest, 'stale': stale, 'max_age_days': API_KEY_MAX_AGE_DAYS})


@check('rbac_roles_in_use')
def rbac_roles_in_use(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    rows = db.execute(select(Membership.role, func.count()).where(Membership.tenant_id == tenant_id).group_by(Membership.role)).all()
    roles = {r: int(n) for r, n in rows}
    total = sum(roles.values())
    non_owner = total - roles.get('owner', 0)
    ok = total == 1 or non_owner > 0
    return Evidence('rbac_roles_in_use', ok, f'{total} members across roles {sorted(roles)}', value=roles)


@check('least_privilege_owners')
def least_privilege_owners(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    total = count(db, Membership, Membership.tenant_id == tenant_id)
    owners = count(db, Membership, Membership.tenant_id == tenant_id, Membership.role == 'owner')
    allowed = max(2, round(total * 0.25))
    ok = owners <= allowed
    return Evidence('least_privilege_owners', ok, f'{owners} owners of {total} members (threshold {allowed})', value={'owners': owners, 'total': total})


@check('session_controls')
def session_controls(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    ok = settings.session_max_age <= 12 * 3600 and settings.login_max_attempts <= 10 and (settings.cookie_secure or not settings.is_production)
    return Evidence('session_controls', ok, f'session max age {settings.session_max_age}s, login throttle {settings.login_max_attempts}/{settings.login_window_seconds}s, '
                    f'secure cookies {settings.cookie_secure}', value={'session_max_age': settings.session_max_age,
                                                                      'login_max_attempts': settings.login_max_attempts, 'cookie_secure': settings.cookie_secure})


@check('transport_security')
def transport_security(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    https = settings.base_url.lower().startswith('https://')
    ok = https and settings.cookie_secure
    if not settings.is_production and not ok:
        return Evidence('transport_security', None, 'Non-production deployment; TLS is terminated by the reverse proxy in production',
                        value={'base_url_https': https, 'cookie_secure': settings.cookie_secure})
    return Evidence('transport_security', ok, 'HTTPS base URL and secure cookies' if ok else 'BASE_URL is not https or COOKIE_SECURE is false',
                    value={'base_url_https': https, 'cookie_secure': settings.cookie_secure})


# ---------------------------------------------------------------- audit and logging


@check('audit_chain_valid')
def audit_chain_valid(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    result = verify_chain(db, tenant_id)
    return Evidence('audit_chain_valid', bool(result.get('valid')), f"audit chain {'valid' if result.get('valid') else 'BROKEN'} over {result.get('checked')} entries",
                    value=result)


@check('audit_signing')
def audit_signing(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    ok = bool(settings.audit_signing_key)
    return Evidence('audit_signing', ok, 'audit entries carry an HMAC signature' if ok else 'AUDIT_SIGNING_KEY not set')


@check('audit_external_sink')
def audit_external_sink(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    sinks = [name for name, on in (('jsonl', settings.audit_jsonl_path), ('s3_object_lock', settings.audit_s3_bucket),
                                   ('azure_immutable', settings.audit_azure_container)) if on]
    worm = any(s in sinks for s in ('s3_object_lock', 'azure_immutable'))
    ok = bool(sinks)
    return Evidence('audit_external_sink', ok, f"audit mirrored to {sinks or 'no external sink'}" + ('' if worm else '; no WORM sink'),
                    value={'sinks': sinks, 'worm': worm})


@check('retention_policy')
def retention_policy(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    days = tenant_settings(db, tenant_id).get('retention_days')
    ok = isinstance(days, int) and days > 0
    return Evidence('retention_policy', ok, f'retention_days={days}' if ok else 'retention_days not set in tenant settings', value=days)


@check('admin_changes_audited')
def admin_changes_audited(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    from ..models import AuditEntry

    n = count(db, AuditEntry, AuditEntry.tenant_id == tenant_id, AuditEntry.action.like('admin.%'))
    auth = count(db, AuditEntry, AuditEntry.tenant_id == tenant_id, AuditEntry.action.like('auth.%'))
    return Evidence('admin_changes_audited', True, f'{n} administrative and {auth} authentication audit entries recorded', value={'admin': n, 'auth': auth})


# ---------------------------------------------------------------- inventory and testing


@check('asset_inventory')
def asset_inventory(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    total = count(db, Asset, Asset.tenant_id == tenant_id)
    kinds = db.execute(select(Asset.kind, func.count()).where(Asset.tenant_id == tenant_id).group_by(Asset.kind)).all()
    return Evidence('asset_inventory', total > 0, f'{total} assets inventoried', value={'total': total, 'by_kind': {k: int(n) for k, n in kinds}})


@check('asset_ownership')
def asset_ownership(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    total = count(db, Asset, Asset.tenant_id == tenant_id)
    if total == 0:
        return Evidence('asset_ownership', None, 'no assets yet')
    owned = count(db, Asset, Asset.tenant_id == tenant_id, Asset.owner != '')
    return Evidence('asset_ownership', owned == total, f'{owned}/{total} assets have an owner', value={'owned': owned, 'total': total})


@check('testing_authorized')
def testing_authorized(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    total = count(db, Asset, Asset.tenant_id == tenant_id)
    approved = count(db, Asset, Asset.tenant_id == tenant_id, Asset.approved.is_(True))
    try:
        from ..models.testing import TestRun
    except ImportError:
        return Evidence('testing_authorized', None, 'test harness not installed', value={'assets': total, 'authorized': approved})
    runs = count(db, TestRun, TestRun.tenant_id == tenant_id)
    unscoped = count(db, TestRun, TestRun.tenant_id == tenant_id, TestRun.scope_id.is_(None))
    if runs == 0:
        return Evidence('testing_authorized', None, f'no test runs yet; {approved}/{total} assets authorized', value={'assets': total, 'authorized': approved})
    return Evidence('testing_authorized', unscoped == 0, f'{runs} test runs, {unscoped} without a scope; {approved}/{total} assets authorized',
                    value={'runs': runs, 'unscoped': unscoped, 'assets': total, 'authorized': approved})


@check('collectors_configured')
def collectors_configured(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    try:
        from ..models.collectors import CollectorConfig
    except ImportError:
        return Evidence('collectors_configured', None, 'collectors package not installed')
    rows = db.execute(select(CollectorConfig.collector, CollectorConfig.enabled, CollectorConfig.last_success_at)
                      .where(CollectorConfig.tenant_id == tenant_id)).all()
    enabled = [c for c, on, _ in rows if on]
    week = utcnow() - timedelta(days=7)
    fresh = sum(1 for _, on, last in rows if on and last and aware(last) >= week)
    return Evidence('collectors_configured', bool(enabled), f'{len(enabled)} enabled collectors, {fresh} succeeded in the last 7 days',
                    value={'enabled': sorted(set(enabled)), 'fresh': fresh, 'total': len(rows)})


@check('collector_secrets_by_reference')
def collector_secrets_by_reference(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    try:
        from ..collectors.base import is_secret_ref
        from ..models.collectors import CollectorConfig
    except ImportError:
        return Evidence('collector_secrets_by_reference', None, 'collectors package not installed')
    rows = db.execute(select(CollectorConfig.secret_refs_json).where(CollectorConfig.tenant_id == tenant_id)).scalars().all()
    if not rows:
        return Evidence('collector_secrets_by_reference', None, 'no collectors configured')
    inline = 0
    for raw in rows:
        for value in loads(raw).values():
            if isinstance(value, str) and value and not is_secret_ref(value) or (isinstance(value, str) and value.startswith('literal:')):
                inline += 1
    return Evidence('collector_secrets_by_reference', inline == 0, f'{inline} inline credential values across {len(rows)} collector configs', value=inline)


@check('coverage')
def coverage(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    """Asset kinds present vs collector kinds configured. Web and database assets are covered by the test harness instead."""
    kinds = {k for (k,) in db.execute(select(Asset.kind).where(Asset.tenant_id == tenant_id).distinct()).all()}
    needed = {ASSET_KIND_TO_COLLECTOR_KIND[k] for k in kinds if k in ASSET_KIND_TO_COLLECTOR_KIND}
    if not needed:
        return Evidence('coverage', None, 'no asset kinds that require a collector', value={'needed': [], 'covered': []})
    try:
        from ..collectors import registry
        from ..models.collectors import CollectorConfig
    except ImportError:
        return Evidence('coverage', None, 'collectors package not installed', value={'needed': sorted(needed), 'covered': []})
    configured = db.execute(select(CollectorConfig.collector).where(CollectorConfig.tenant_id == tenant_id, CollectorConfig.enabled.is_(True)).distinct()).scalars().all()
    covered = set()
    for name in configured:
        try:
            covered.add(registry.get(name).kind)
        except Exception:
            continue
    ratio = len(needed & covered) / len(needed)
    return Evidence('coverage', ratio >= 1.0, f'{len(needed & covered)}/{len(needed)} required collector kinds configured',
                    value={'needed': sorted(needed), 'covered': sorted(needed & covered), 'ratio': round(ratio, 3)})


# ---------------------------------------------------------------- detection and response


@check('detections_enabled')
def detections_enabled(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    try:
        from ..detections.engine import registry, rule_states
    except ImportError:
        return Evidence('detections_enabled', None, 'detections package not installed')
    rules = registry.all()
    states = rule_states(db, tenant_id)
    enabled = [r.id for r in rules if states.get(r.id) is None or states[r.id].enabled]
    categories = sorted({r.category for r in rules if r.id in enabled})
    return Evidence('detections_enabled', bool(enabled), f'{len(enabled)}/{len(rules)} detection rules enabled across {categories}',
                    value={'enabled': len(enabled), 'total': len(rules), 'categories': categories})


@check('detections_recent_run')
def detections_recent_run(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    try:
        from ..models.detections import DetectionRun
    except ImportError:
        return Evidence('detections_recent_run', None, 'detections package not installed')
    last = db.execute(select(DetectionRun.started_at).where(DetectionRun.tenant_id == tenant_id).order_by(DetectionRun.started_at.desc()).limit(1)).scalar_one_or_none()
    if last is None:
        return Evidence('detections_recent_run', False, 'the detection engine has not run for this tenant yet')
    age_h = (utcnow() - aware(last)).total_seconds() / 3600
    return Evidence('detections_recent_run', age_h <= 24, f'last detection run {age_h:.1f}h ago', value={'last_run_at': aware(last).isoformat(), 'age_hours': round(age_h, 1)})


@check('detection_volume_trend')
def detection_volume_trend(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    try:
        from ..models.detections import Detection
    except ImportError:
        return Evidence('detection_volume_trend', None, 'detections package not installed')
    now = utcnow()
    recent = count(db, Detection, Detection.tenant_id == tenant_id, Detection.created_at >= now - timedelta(days=7))
    previous = count(db, Detection, Detection.tenant_id == tenant_id, Detection.created_at >= now - timedelta(days=14), Detection.created_at < now - timedelta(days=7))
    open_now = count(db, Detection, Detection.tenant_id == tenant_id, Detection.status.in_(OPEN_STATES))
    ratio = (recent / previous) if previous else (1.0 if recent == 0 else 2.0)
    return Evidence('detection_volume_trend', ratio <= 1.0, f'{recent} detections in the last 7 days vs {previous} before; {open_now} open',
                    value={'last_7d': recent, 'previous_7d': previous, 'ratio': round(ratio, 2), 'open': open_now})


@check('canaries_deployed')
def canaries_deployed(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    try:
        from ..models.detections import Canary
    except ImportError:
        return Evidence('canaries_deployed', None, 'detections package not installed')
    n = count(db, Canary, Canary.tenant_id == tenant_id, Canary.revoked_at.is_(None))
    return Evidence('canaries_deployed', n > 0, f'{n} active canary tokens', value=n)


@check('vulnerability_sla')
def vulnerability_sla(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    now = utcnow()
    rows = db.execute(select(Finding.severity, Finding.created_at).where(Finding.tenant_id == tenant_id, Finding.status.in_(OPEN_STATES),
                                                                         Finding.severity.in_(['critical', 'high']))).all()
    breaches = 0
    for severity, created in rows:
        age = (now - aware(created)).days
        if (severity == 'critical' and age > CRITICAL_SLA_DAYS) or (severity == 'high' and age > HIGH_SLA_DAYS):
            breaches += 1
    return Evidence('vulnerability_sla', breaches == 0, f'{len(rows)} open critical/high findings, {breaches} past SLA '
                    f'({CRITICAL_SLA_DAYS}d critical, {HIGH_SLA_DAYS}d high)', value={'open_crit_high': len(rows), 'breaches': breaches})


@check('mttr')
def mttr(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    since = utcnow() - timedelta(days=90)
    rows = db.execute(select(Finding.created_at, Finding.updated_at).where(Finding.tenant_id == tenant_id, Finding.status == 'resolved',
                                                                           Finding.updated_at >= since).limit(5000)).all()
    if not rows:
        return Evidence('mttr', None, 'no findings resolved in the last 90 days')
    hours = [(aware(u) - aware(c)).total_seconds() / 3600 for c, u in rows]
    mean_h = sum(hours) / len(hours)
    return Evidence('mttr', mean_h <= MTTR_TARGET_DAYS * 24, f'mean time to resolve {mean_h / 24:.1f} days over {len(rows)} findings',
                    value={'mean_hours': round(mean_h, 1), 'sample': len(rows), 'target_days': MTTR_TARGET_DAYS})


@check('incident_workflow')
def incident_workflow(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    findings = count(db, Finding, Finding.tenant_id == tenant_id)
    if findings == 0:
        return Evidence('incident_workflow', None, 'no findings yet')
    worked = count(db, Finding, Finding.tenant_id == tenant_id, Finding.status != 'open')
    investigations = count(db, Investigation, Investigation.tenant_id == tenant_id) + count(db, AgentRun, AgentRun.tenant_id == tenant_id,
                                                                                              AgentRun.spec.in_(['investigate', 'triage']))
    return Evidence('incident_workflow', worked > 0 or investigations > 0, f'{worked}/{findings} findings progressed past open; {investigations} investigations',
                    value={'findings': findings, 'worked': worked, 'investigations': investigations})


@check('event_telemetry')
def event_telemetry(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    since = utcnow() - timedelta(days=7)
    n = count(db, SecurityEvent, SecurityEvent.tenant_id == tenant_id, SecurityEvent.received_at >= since)
    sources = db.execute(select(SecurityEvent.source).where(SecurityEvent.tenant_id == tenant_id, SecurityEvent.received_at >= since).distinct()).scalars().all()
    return Evidence('event_telemetry', n > 0, f'{n} events from {len(sources)} sources in the last 7 days', value={'events_7d': n, 'sources': sorted(sources)})


# ---------------------------------------------------------------- change control


@check('action_governance')
def action_governance(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    tenant = db.get(Tenant, tenant_id)
    enabled = bool(tenant and tenant.actions_enabled)
    detail = {'tenant_actions_enabled': enabled, 'kill_switch': settings.actions_kill_switch, 'two_person_high': settings.actions_require_two_for_high,
              'auto_approve_low': settings.actions_auto_approve_low}
    ok = (not enabled) or settings.actions_require_two_for_high
    return Evidence('action_governance', ok, ('actions disabled for tenant' if not enabled else 'actions enabled with two-person rule for high risk')
                    if ok else 'actions enabled without a two-person rule for high-risk changes', value=detail)


@check('agent_guardrails')
def agent_guardrails(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    detail = {'max_steps': settings.agent_max_steps, 'max_tokens': settings.agent_max_tokens, 'max_seconds': settings.agent_max_seconds,
              'cost_ceiling_usd': settings.agent_cost_ceiling_usd, 'provider': settings.ai_provider}
    ok = settings.agent_max_steps <= 50 and settings.agent_max_seconds <= 3600 and settings.agent_cost_ceiling_usd > 0
    return Evidence('agent_guardrails', ok, 'agent budgets bounded (steps, tokens, time, cost)' if ok else 'agent budgets exceed recommended bounds', value=detail)


@check('exposure')
def exposure(db: Session, tenant_id: str, settings: Settings) -> Evidence:
    try:
        from ..graph.service import stats
    except ImportError:
        return Evidence('exposure', None, 'graph package not installed')
    data = stats(db, tenant_id)
    top = data.get('top_exposed') or []
    nodes = sum((data.get('nodes_by_kind') or {}).values())
    if nodes == 0:
        return Evidence('exposure', None, 'evidence graph is empty', value={'nodes': 0})
    avg_top = sum(n.get('exposure_score', 0) for n in top) / len(top) if top else 0.0
    paths = int(data.get('attack_paths_open') or 0)
    return Evidence('exposure', paths == 0 and avg_top < 50, f'{paths} open attack paths; mean exposure of top nodes {avg_top:.0f}/100',
                    value={'attack_paths_open': paths, 'top_exposure_mean': round(avg_top, 1), 'nodes': nodes, 'stale_nodes': data.get('stale_nodes', 0)})
