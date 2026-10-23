"""Approval and denial policy for action requests.

The decision is pure given (settings, tenant, action, dry run, requester) and is evaluated at
request time and again at execution time (phase='execute'), so a kill switch flipped after
approval still stops the run.

Tenant overrides live in Tenant.settings_json['action_policy']:
  auto_approve_low: bool, require_two_for_high: bool, maintenance_window: "HH:MM-HH:MM",
  deny: ["aws.iam.*", "kubernetes.delete_pod"], max_auto_entities: int (default 1),
  request_ttl_hours: int (default 24)
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import datetime, time, timezone

from ..core.config import Settings
from ..core.rbac import Principal, has
from ..models import Tenant, loads
from .catalog import RISK_RANK, ActionType, DryRunResult

_WINDOW = re.compile(r'^([01]\d|2[0-3]):([0-5]\d)-([01]\d|2[0-3]):([0-5]\d)$')
DEFAULT_TTL_HOURS = 24


@dataclass
class PolicyDecision:
    required_approvals: int = 1
    auto_approve: bool = False
    owner_required: bool = False
    reasons: list[str] = field(default_factory=list)
    denied: bool = False
    deny_reason: str = ''
    maintenance_window: str = ''
    within_window: bool | None = None  # None when no window applies

    def as_dict(self) -> dict:
        return {'required_approvals': self.required_approvals, 'auto_approve': self.auto_approve, 'owner_required': self.owner_required,
                'reasons': list(self.reasons), 'denied': self.denied, 'deny_reason': self.deny_reason,
                'maintenance_window': self.maintenance_window, 'within_window': self.within_window}


def tenant_policy(tenant: Tenant | None) -> dict:
    if tenant is None:
        return {}
    data = loads(tenant.settings_json, {})
    policy = data.get('action_policy') if isinstance(data, dict) else None
    return policy if isinstance(policy, dict) else {}


def tenant_kill_switch(tenant: Tenant | None) -> bool:
    """A tenant whose actions are disabled is treated as having its kill switch engaged."""
    return tenant is None or not bool(tenant.actions_enabled)


def parse_window(spec: str) -> tuple[time, time] | None:
    match = _WINDOW.match((spec or '').strip())
    if not match:
        return None
    h1, m1, h2, m2 = (int(g) for g in match.groups())
    return time(h1, m1), time(h2, m2)


def in_window(spec: str, now: datetime | None = None) -> bool | None:
    """True/False when the spec is valid, None when there is no window. Windows may wrap midnight."""
    parsed = parse_window(spec)
    if parsed is None:
        return None
    start, end = parsed
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).time().replace(second=0, microsecond=0)
    if start <= end:
        return start <= current < end
    return current >= start or current < end


def denied_by_list(action_name: str, patterns: list) -> str | None:
    for pattern in patterns or []:
        if isinstance(pattern, str) and fnmatch.fnmatchcase(action_name, pattern):
            return pattern
    return None


def evaluate(db, tenant: Tenant | None, settings: Settings, action_type: ActionType, params: dict, requester: Principal | None, *,
             dry_run: DryRunResult | None = None, agent_originated: bool = False, phase: str = 'request',
             now: datetime | None = None) -> PolicyDecision:
    """phase is 'request' (deciding how many approvals a new request needs) or 'execute' (gatekeeping a run).
    `db` is accepted for parity with the documented signature; the decision needs only the tenant row."""
    decision = PolicyDecision()
    overrides = tenant_policy(tenant)
    now = now or datetime.now(timezone.utc)

    # -- hard denials
    if settings.actions_kill_switch:
        return _deny(decision, 'global kill switch is engaged (ACTIONS_KILL_SWITCH)')
    if tenant_kill_switch(tenant):
        return _deny(decision, 'actions are disabled for this tenant (kill switch engaged)')
    matched = denied_by_list(action_type.name, overrides.get('deny', []))
    if matched:
        return _deny(decision, f'action type {action_type.name} is denied by tenant policy ({matched})')
    if requester is not None and requester.auth != 'system' and not has(requester, 'actions:request'):
        return _deny(decision, 'requester lacks actions:request')

    risk = action_type.risk
    require_two_high = bool(overrides.get('require_two_for_high', settings.actions_require_two_for_high))
    auto_low = bool(overrides.get('auto_approve_low', settings.actions_auto_approve_low))
    max_auto_entities = int(overrides.get('max_auto_entities', 1) or 1)

    # -- approvals by tier
    if risk == 'critical':
        decision.required_approvals, decision.owner_required = 2, True
        decision.reasons.append('critical risk: two approvals including an owner')
    elif risk == 'high':
        decision.required_approvals = 2 if require_two_high else 1
        decision.reasons.append('high risk: two approvals' if require_two_high else 'high risk: one approval')
    elif risk == 'medium':
        decision.required_approvals = 1
        decision.reasons.append('medium risk: one approval')
    else:
        decision.required_approvals = 1
        decision.reasons.append('low risk: one approval')
        if not auto_low:
            decision.reasons.append('auto-approval of low-risk actions is off')
        elif agent_originated:
            decision.reasons.append('agent-originated requests are never auto-approved')
        elif not action_type.reversible:
            decision.reasons.append('not reversible, so not auto-approved')
        elif dry_run is None or not dry_run.ok:
            decision.reasons.append('no successful dry run, so not auto-approved')
        elif dry_run.entities > max_auto_entities:
            decision.reasons.append(f'dry run touches {dry_run.entities} entities (> {max_auto_entities}), so not auto-approved')
        else:
            decision.auto_approve = True
            decision.required_approvals = 0
            decision.reasons.append('auto-approved: low risk, reversible, blast radius within threshold')

    # -- maintenance window for high and critical
    window = str(overrides.get('maintenance_window', settings.actions_maintenance_window) or '')
    if window and RISK_RANK[risk] >= RISK_RANK['high']:
        if parse_window(window) is None:
            decision.reasons.append(f'maintenance window {window!r} is malformed and was ignored')
        else:
            decision.maintenance_window = window
            decision.within_window = in_window(window, now)
            if decision.within_window:
                decision.reasons.append(f'inside maintenance window {window} UTC')
            elif phase == 'execute':
                return _deny(decision, f'{risk} actions may only execute inside the maintenance window {window} UTC')
            else:
                decision.reasons.append(f'execution is only allowed inside the maintenance window {window} UTC')
    return decision


def _deny(decision: PolicyDecision, reason: str) -> PolicyDecision:
    decision.denied, decision.deny_reason = True, reason
    decision.auto_approve = False
    decision.reasons.append(reason)
    return decision


def can_fill_owner_slot(principal: Principal) -> bool:
    return has(principal, 'actions:approve_critical')


def same_actor(a: str, b: str) -> bool:
    return bool(a) and a == b


def request_ttl_hours(tenant: Tenant | None) -> int:
    try:
        return max(1, int(tenant_policy(tenant).get('request_ttl_hours', DEFAULT_TTL_HOURS)))
    except (TypeError, ValueError):
        return DEFAULT_TTL_HOURS
