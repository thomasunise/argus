"""Scope enforcement for the test harness.

check() is the single gate every test run passes through, both at request time (the router
calls it before enqueuing) and at execution time (execute_run calls it again). It never
trusts a queued job: authorization, tier, environment, time window and target validity are
all re-evaluated against the live scope and authorization records.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..core.config import Settings
from ..core.errors import ScopeDenied
from ..core import policy
from ..models import loads

TIER_RANK = {'passive': 0, 'active': 1, 'intrusive': 2, 'exploit': 3}

INTRUSIVE_ENVIRONMENTS = {'staging', 'lab'}


def _scope_list(scope, attr: str, json_attr: str) -> list:
    """Accept either the harness snapshot (real lists) or a raw TestScope row (JSON columns).

    check() was only ever called with harness._ScopeSnapshot, so a raw row crashed it. Discovery
    passes rows, and any future caller should not have to know the difference.
    """
    value = getattr(scope, attr, None)
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return loads(getattr(scope, json_attr, '[]'), []) or []


def _hhmm(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime('%H:%M')


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _within_window(start: str, end: str, now: datetime) -> bool:
    if not start or not end:
        return True
    current = _hhmm(now)
    if start <= end:
        return start <= current <= end
    # window wraps past midnight, e.g. 22:00-04:00
    return current >= start or current <= end


def check(adapter, asset, scope, authorization, now: datetime, settings: Settings, *, tier: str | None = None) -> str:
    """Raise ScopeDenied if the (adapter, asset) run is not permitted. Returns the normalized
    target string (https origin for web, repo-relative path for repo, raw target otherwise).

    `tier` is the tier the run will execute at; it defaults to the adapter's nominal tier.
    """
    effective_tier = tier or adapter.tier
    if TIER_RANK.get(effective_tier, 0) < TIER_RANK.get(adapter.tier, 0):
        raise ScopeDenied(f'adapter {adapter.name} runs at tier {adapter.tier}; it cannot be run as {effective_tier}')
    now = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)

    if scope is None:
        raise ScopeDenied('no test scope is associated with this run')
    if scope.revoked_at is not None:
        raise ScopeDenied('test scope has been revoked')
    if scope.expires_at is not None and scope.expires_at <= now:
        raise ScopeDenied('test scope has expired')

    if adapter.target_kinds and asset.kind not in adapter.target_kinds:
        raise ScopeDenied(f'adapter {adapter.name} does not support asset kind {asset.kind}')

    if asset.id not in set(_scope_list(scope, 'asset_ids', 'asset_ids_json')):
        raise ScopeDenied('asset is not listed in the test scope')

    scope_environments = set(_scope_list(scope, 'environments', 'environments_json'))
    if scope_environments and asset.environment not in scope_environments:
        raise ScopeDenied(f'asset environment {asset.environment} is outside the scope')

    # Authorization must exist and be current.
    if authorization is None:
        raise ScopeDenied('no current authorization exists for this asset')
    if authorization.revoked_at is not None:
        raise ScopeDenied('asset authorization has been revoked')
    if authorization.expires_at is not None and authorization.expires_at <= now:
        raise ScopeDenied('asset authorization has expired')

    # Tier must be permitted by BOTH the scope and the authorization.
    if effective_tier not in set(_scope_list(scope, 'allowed_tiers', 'allowed_tiers_json')):
        raise ScopeDenied(f'tier {effective_tier} is not allowed by the scope')
    if effective_tier == 'active' and not authorization.allow_active:
        raise ScopeDenied('authorization does not permit active testing')
    if effective_tier == 'intrusive':
        if not authorization.allow_intrusive:
            raise ScopeDenied('authorization does not permit intrusive testing')
        if asset.environment not in INTRUSIVE_ENVIRONMENTS:
            raise ScopeDenied('intrusive testing is only permitted in staging or lab environments')
    if effective_tier == 'exploit':
        assert_exploit_authorized(asset, authorization, settings)

    if not _within_window(scope.window_start, scope.window_end, now):
        raise ScopeDenied('outside the permitted testing time window')

    # Target validity (web/repo get full validation inside validate_target; other kinds are normalized only).
    return policy.validate_target(asset.kind, asset.target, settings)


EXPLOIT_ENVIRONMENTS = {'staging', 'lab'}

def assert_exploit_authorized(asset, authorization, settings: Settings) -> None:
    """The exploit tier's own rules, shared by adapter runs and PoC runs."""
    if not getattr(authorization, 'allow_exploit', False):
        raise ScopeDenied('authorization does not permit exploit execution')
    permitted = exploit_environments(settings)
    if asset.environment in permitted:
        return
    document = str(getattr(authorization, 'scope_document_ref', '') or '').strip()
    if asset.environment == 'production' and document:
        return  # production is permitted with a signed rules-of-engagement reference
    raise ScopeDenied(
        f'exploit execution is not permitted in {asset.environment}; allowed environments: {sorted(permitted)}'
        + (' (production requires a scope document reference)' if asset.environment == 'production' else ''))


def exploit_environments(settings: Settings) -> set[str]:
    raw = str(getattr(settings, 'exploit_environments', 'staging,lab') or '')
    values = {v.strip().lower() for v in raw.split(',') if v.strip()}
    return values or set(EXPLOIT_ENVIRONMENTS)


def check_exploit(asset, scope, authorization, now: datetime, settings: Settings) -> str:
    """Gate for executing a model-authored PoC against one asset.

    Same envelope as check(), with the exploit tier's own rules: the scope must list 'exploit',
    the authorization must carry allow_exploit, and production additionally requires a signed
    scope document reference. Re-evaluated at execution time, never trusted from the queue.
    """
    now = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)

    if scope is None:
        raise ScopeDenied('no test scope is associated with this exploit run')
    if scope.revoked_at is not None:
        raise ScopeDenied('test scope has been revoked')
    if scope.expires_at is not None and _aware(scope.expires_at) <= now:
        raise ScopeDenied('test scope has expired')

    if 'exploit' not in set(loads(scope.allowed_tiers_json, [])):
        raise ScopeDenied('tier exploit is not allowed by the scope')
    if asset.id not in set(loads(scope.asset_ids_json, [])):
        raise ScopeDenied('asset is not listed in the test scope')
    scope_environments = set(loads(scope.environments_json, []))
    if scope_environments and asset.environment not in scope_environments:
        raise ScopeDenied(f'asset environment {asset.environment} is outside the scope')

    if authorization is None:
        raise ScopeDenied('no current authorization exists for this asset')
    if authorization.revoked_at is not None:
        raise ScopeDenied('asset authorization has been revoked')
    if authorization.expires_at is not None and _aware(authorization.expires_at) <= now:
        raise ScopeDenied('asset authorization has expired')
    assert_exploit_authorized(asset, authorization, settings)

    if not _within_window(scope.window_start, scope.window_end, now):
        raise ScopeDenied('outside the permitted testing time window')

    return policy.validate_target(asset.kind, asset.target, settings)
