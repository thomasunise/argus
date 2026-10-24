"""The action broker: the only component that changes the enterprise.

Lifecycle: request (validate -> policy -> dry run -> pending/auto_approved) -> approve x N ->
execute (queue job: kill switch -> policy -> dry run -> execute -> ActionRun with rollback
payload) -> rollback (queue job). Every transition is audited and published on the event bus.
Agents reach this module only through `request`; nothing here trusts the caller's claims about
approvals, and both queue handlers re-check authorization themselves.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.config import Settings, get_settings
from ..core.db import get_scoped, scoped, session_scope
from ..core.errors import Conflict, Forbidden, NotFound, PolicyDenied, ArgusError
from ..core.events import publish, publish_soon
from ..core.rbac import Principal, Role, has
from ..core.security import redact
from ..core.telemetry import ACTIONS
from ..models import ApiKey, Finding, Tenant, dumps, loads
from ..models.actions import EXECUTABLE_STATUSES, ActionApproval, ActionRequest, ActionRun
from . import catalog, policy
from .catalog import ActionError, ActionType, DryRunResult, ExecContext, ExecResult

log = logging.getLogger('argus.actions')

DRY_RUN_TIMEOUT = 60
EXECUTE_TIMEOUT = 600
JOB_LEASE = 900

_settings: Settings | None = None


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _cfg(settings: Settings | None = None) -> Settings:
    return settings or _settings or get_settings()


class InvalidParams(ArgusError):
    status = 422
    code = 'invalid_params'


# ---------------------------------------------------------------- helpers


def actor_id(principal: Principal) -> str:
    if principal.auth == 'api_key':
        return f'api_key:{principal.api_key_id}'
    if principal.auth == 'system' and not principal.user_id:
        return 'system'
    return principal.user_id or principal.email or 'unknown'


def identity_of(db: Session | None, actor: str) -> str:
    """Canonical human identity behind an actor id. An API key acts on behalf of the user who minted it, so a
    request made through a key and an approval made by that user (or another of their keys) are the SAME actor
    for separation-of-duty purposes. Unknown keys and 'system' stay as they are."""
    actor = actor or ''
    if actor.startswith('api_key:') and db is not None:
        key = db.get(ApiKey, actor[len('api_key:'):])
        if key is not None and key.created_by:
            return f'user:{key.created_by}'
        return actor
    if not actor or actor == 'system':
        return actor
    return f'user:{actor}'


def same_identity(db: Session | None, a: str, b: str) -> bool:
    return bool(a) and bool(b) and (policy.same_actor(a, b) or identity_of(db, a) == identity_of(db, b))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _redacted(value: Any, depth: int = 0) -> Any:
    if depth > 12:
        return '[truncated]'
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {str(k): _redacted(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redacted(v, depth + 1) for v in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact(str(value))


def _tenant(db: Session, tenant_id: str) -> Tenant | None:
    return db.get(Tenant, tenant_id)


def _tenant_settings(tenant: Tenant | None) -> dict:
    data = loads(tenant.settings_json, {}) if tenant else {}
    return data if isinstance(data, dict) else {}


async def _noop_heartbeat() -> None:
    return None


def build_context(settings: Settings, tenant: Tenant | None, req: ActionRequest, action: ActionType, *, db: Session | None = None,
                  heartbeat=None, actor: str = '', dry_run: bool = False) -> ExecContext:
    return ExecContext(tenant_id=req.tenant_id, settings=settings, request=req, logger=log, heartbeat=heartbeat or _noop_heartbeat,
                       platform=action.platform, tenant_settings=_tenant_settings(tenant), db=db, actor=actor, dry_run=dry_run)


async def safe_dry_run(action: ActionType, params: dict, ctx: ExecContext) -> DryRunResult:
    """Never raises: an executor that cannot plan returns ok=False with the reason."""
    try:
        result = await asyncio.wait_for(action.dry_run(params, ctx), timeout=DRY_RUN_TIMEOUT)
    except ActionError as exc:
        return DryRunResult(ok=False, summary=f'dry run failed: {exc.message}', details=_redacted(exc.details))
    except asyncio.TimeoutError:
        return DryRunResult(ok=False, summary=f'dry run timed out after {DRY_RUN_TIMEOUT}s')
    except Exception as exc:  # executors are third-party-shaped code; isolate their failures
        log.warning('dry run of %s raised %s', action.name, type(exc).__name__)
        return DryRunResult(ok=False, summary=f'dry run failed: {type(exc).__name__}: {redact(str(exc))[:300]}')
    if not isinstance(result, DryRunResult):
        return DryRunResult(ok=False, summary='dry run returned an unexpected value')
    return result


def _approvals(db: Session, req: ActionRequest) -> list[ActionApproval]:
    stmt = scoped(ActionApproval, req.tenant_id).where(ActionApproval.request_id == req.id).order_by(ActionApproval.created_at.asc())
    return list(db.execute(stmt).scalars().all())


def _runs(db: Session, req: ActionRequest) -> list[ActionRun]:
    stmt = scoped(ActionRun, req.tenant_id).where(ActionRun.request_id == req.id).order_by(ActionRun.created_at.asc())
    return list(db.execute(stmt).scalars().all())


def approvals_satisfied(req: ActionRequest, approvals: list[ActionApproval], db: Session | None = None) -> bool:
    if req.status == 'auto_approved':
        return True
    requester = identity_of(db, req.requested_by)
    approving = [a for a in approvals if a.decision == 'approve' and a.approver_id != req.requested_by
                 and identity_of(db, a.approver_id) != requester]
    distinct = {identity_of(db, a.approver_id) for a in approving}
    owner_ok = (not req.owner_approval_required) or any(a.can_approve_critical for a in approving)
    return len(distinct) >= req.required_approvals and owner_ok


def _expire_if_needed(db: Session, req: ActionRequest, principal: Principal | str) -> None:
    expires = _aware(req.expires_at)
    if req.status in {'pending', 'approved', 'auto_approved'} and expires and expires <= _now():
        req.status, req.decided_at = 'cancelled', _now()
        record_audit(db, principal, 'actions.expired', req.id, {'action_type': req.action_type}, tenant_id=req.tenant_id)
        db.commit()  # the Conflict below makes the request handler roll back; the expiry must survive it
        raise Conflict('action request has expired')


def _publish_sync(topic: str, payload: dict) -> None:
    publish_soon(topic, payload)


def _event(req: ActionRequest, **extra: Any) -> dict:
    data = {'tenant_id': req.tenant_id, 'request_id': req.id, 'action_type': req.action_type, 'risk': req.risk, 'status': req.status,
            'finding_id': req.finding_id, 'detection_id': req.detection_id, 'agent_run_id': req.agent_run_id}
    data.update(extra)
    return data


# ---------------------------------------------------------------- serializers


def approval_to_dict(a: ActionApproval) -> dict:
    return {'id': a.id, 'request_id': a.request_id, 'approver_id': a.approver_id, 'approver_role': a.approver_role,
            'can_approve_critical': bool(a.can_approve_critical), 'decision': a.decision, 'comment': a.comment, 'created_at': a.created_at}


def run_to_dict(r: ActionRun, *, include_rollback_payload: bool = False) -> dict:
    data = {'id': r.id, 'request_id': r.request_id, 'status': r.status, 'dry_run': bool(r.dry_run), 'result': loads(r.result_json, {}),
            'error': r.error, 'executed_by': r.executed_by, 'job_id': r.job_id, 'rollback_job_id': r.rollback_job_id,
            'has_rollback_payload': r.rollback_payload_json not in ('', '{}', 'null'), 'started_at': r.started_at,
            'finished_at': r.finished_at, 'rolled_back_at': r.rolled_back_at, 'rolled_back_by': r.rolled_back_by, 'created_at': r.created_at}
    if include_rollback_payload:
        data['rollback_payload'] = _redacted(loads(r.rollback_payload_json, {}))
    return data


def request_to_dict(r: ActionRequest, approvals: list[ActionApproval] | None = None, runs: list[ActionRun] | None = None) -> dict:
    data = {'id': r.id, 'action_type': r.action_type, 'params': loads(r.params_json, {}), 'reason': r.reason, 'risk': r.risk,
            'status': r.status, 'requested_by': r.requested_by, 'requested_by_role': r.requested_by_role, 'agent_run_id': r.agent_run_id,
            'agent_originated': bool(r.agent_run_id), 'finding_id': r.finding_id, 'detection_id': r.detection_id,
            'dry_run': loads(r.dry_run_json, {}), 'policy': loads(r.policy_json, {}), 'required_approvals': r.required_approvals,
            'owner_approval_required': bool(r.owner_approval_required), 'created_at': r.created_at, 'decided_at': r.decided_at,
            'expires_at': r.expires_at}
    if approvals is not None:
        data['approvals'] = [approval_to_dict(a) for a in approvals]
        data['approval_count'] = len({a.approver_id for a in approvals if a.decision == 'approve'})
    if runs is not None:
        data['runs'] = [run_to_dict(x) for x in runs]
    return data


def request_detail(db: Session, req: ActionRequest) -> dict:
    return request_to_dict(req, _approvals(db, req), _runs(db, req))


# ---------------------------------------------------------------- request


def _detection_in_tenant(db: Session, principal: Principal, detection_id: str) -> bool:
    try:
        from ..models.detections import Detection
    except ImportError:  # detections package absent: nothing to link to
        return False
    return get_scoped(db, Detection, principal, detection_id) is not None


async def request(db: Session, principal: Principal, action_type: str, params: dict, reason: str, finding_id: str | None = None,
                  detection_id: str | None = None, agent_run_id: str | None = None, *, settings: Settings | None = None) -> ActionRequest:
    """Create a pending (or auto-approved) ActionRequest. Nothing is executed here."""
    settings = _cfg(settings)
    action = catalog.get(action_type)
    if action is None:
        raise NotFound(f'unknown action type {action_type!r}')
    if not has(principal, 'actions:request'):
        raise Forbidden('Missing permission actions:request')
    params = action.normalize(params if isinstance(params, dict) else {})
    problems = action.validate(params)
    if problems:
        raise InvalidParams('invalid params: ' + '; '.join(problems[:8]))
    if finding_id and get_scoped(db, Finding, principal, finding_id) is None:
        raise NotFound('finding not found')
    if detection_id and not _detection_in_tenant(db, principal, detection_id):
        raise NotFound('detection not found')
    tenant = _tenant(db, principal.tenant_id)
    agent_originated = bool(agent_run_id)
    pre = policy.evaluate(db, tenant, settings, action, params, principal, agent_originated=agent_originated)
    if pre.denied:
        record_audit(db, principal, 'actions.denied', '', {'action_type': action.name, 'reason': pre.deny_reason, 'agent_run_id': agent_run_id})
        raise PolicyDenied(pre.deny_reason)

    req = ActionRequest(tenant_id=principal.tenant_id, action_type=action.name, params_json=dumps(params), reason=redact(reason or '')[:4000],
                        risk=action.risk, status='pending', requested_by=actor_id(principal), requested_by_role=str(principal.role),
                        agent_run_id=agent_run_id, finding_id=finding_id, detection_id=detection_id,
                        expires_at=_now() + timedelta(hours=policy.request_ttl_hours(tenant)))
    ctx = build_context(settings, tenant, req, action, db=db, actor=actor_id(principal), dry_run=True)
    dry = await safe_dry_run(action, params, ctx)
    decision = policy.evaluate(db, tenant, settings, action, params, principal, dry_run=dry, agent_originated=agent_originated)
    if decision.denied:
        raise PolicyDenied(decision.deny_reason)
    req.dry_run_json = dumps(dry.as_dict(), limit=16000)
    req.policy_json = dumps(decision.as_dict())
    req.required_approvals = decision.required_approvals
    req.owner_approval_required = decision.owner_required
    if decision.auto_approve:
        req.status, req.decided_at = 'auto_approved', _now()
    db.add(req)
    db.flush()
    record_audit(db, principal, 'actions.requested', req.id,
                 {'action_type': action.name, 'risk': action.risk, 'status': req.status, 'required_approvals': req.required_approvals,
                  'agent_run_id': agent_run_id, 'finding_id': finding_id, 'detection_id': detection_id, 'dry_run_ok': dry.ok,
                  'blast_radius': dry.blast_radius, 'params': _redacted(params)})
    await publish('action.requested', _event(req, requested_by=req.requested_by, required_approvals=req.required_approvals))
    return req


# ---------------------------------------------------------------- approve / cancel


def approve(db: Session, principal: Principal, request_id: str, decision: str, comment: str = '') -> ActionRequest:
    if decision not in {'approve', 'reject'}:
        raise InvalidParams('decision must be approve or reject')
    if not has(principal, 'actions:approve'):
        raise Forbidden('Missing permission actions:approve')
    req = get_scoped(db, ActionRequest, principal, request_id)
    if req is None:
        raise NotFound('action request not found')
    _expire_if_needed(db, req, principal)
    if req.status != 'pending':
        raise Conflict(f'request is {req.status}; only pending requests can be decided')
    me = actor_id(principal)
    if same_identity(db, me, req.requested_by):
        raise Forbidden('a requester cannot approve or reject their own request')
    existing = _approvals(db, req)
    if any(same_identity(db, a.approver_id, me) for a in existing):
        raise Conflict('you have already decided this request')
    approval = ActionApproval(tenant_id=req.tenant_id, request_id=req.id, approver_id=me, approver_role=str(principal.role),
                              can_approve_critical=policy.can_fill_owner_slot(principal), decision=decision, comment=redact(comment or '')[:2000])
    db.add(approval)
    db.flush()
    if decision == 'reject':
        req.status, req.decided_at = 'rejected', _now()
        record_audit(db, principal, 'actions.rejected', req.id, {'action_type': req.action_type, 'comment': approval.comment})
        _publish_sync('action.rejected', _event(req, approver=me))
        return req
    approvals = existing + [approval]
    if approvals_satisfied(req, approvals, db):
        req.status, req.decided_at = 'approved', _now()
        record_audit(db, principal, 'actions.approved', req.id,
                     {'action_type': req.action_type, 'approvers': sorted({a.approver_id for a in approvals if a.decision == 'approve'}),
                      'comment': approval.comment})
        _publish_sync('action.approved', _event(req, approver=me))
    else:
        remaining = req.required_approvals - len({a.approver_id for a in approvals if a.decision == 'approve'})
        owner_missing = req.owner_approval_required and not any(a.can_approve_critical for a in approvals)
        record_audit(db, principal, 'actions.approval_recorded', req.id,
                     {'action_type': req.action_type, 'remaining': max(0, remaining), 'owner_missing': owner_missing, 'comment': approval.comment})
    return req


def cancel(db: Session, principal: Principal, request_id: str, reason: str = '') -> ActionRequest:
    req = get_scoped(db, ActionRequest, principal, request_id)
    if req is None:
        raise NotFound('action request not found')
    me = actor_id(principal)
    if not (policy.same_actor(me, req.requested_by) or has(principal, 'actions:approve')):
        raise Forbidden('only the requester or an approver can cancel a request')
    if req.status not in {'pending', 'approved', 'auto_approved'}:
        raise Conflict(f'request is {req.status}; it cannot be cancelled')
    req.status, req.decided_at = 'cancelled', _now()
    record_audit(db, principal, 'actions.cancelled', req.id, {'action_type': req.action_type, 'reason': redact(reason or '')[:500]})
    _publish_sync('action.cancelled', _event(req, by=me))
    return req


# ---------------------------------------------------------------- kill switch


def kill_switch_state(db: Session, settings: Settings, tenant_id: str) -> dict:
    tenant = _tenant(db, tenant_id)
    detail = _tenant_settings(tenant).get('actions_kill_switch') or {}
    tenant_engaged = policy.tenant_kill_switch(tenant)
    return {'global': bool(settings.actions_kill_switch), 'tenant_engaged': tenant_engaged, 'actions_enabled': not tenant_engaged,
            'effective': bool(settings.actions_kill_switch) or tenant_engaged, 'detail': detail if isinstance(detail, dict) else {}}


def set_kill_switch(db: Session, principal: Principal, enabled: bool, reason: str = '', *, settings: Settings | None = None) -> dict:
    """enabled=True engages the tenant kill switch (actions_enabled=False); enabled=False releases it."""
    if not has(principal, 'actions:kill_switch') or principal.role not in {Role.admin, Role.owner} and principal.auth != 'system':
        raise Forbidden('Missing permission actions:kill_switch')
    tenant = _tenant(db, principal.tenant_id)
    if tenant is None:
        raise NotFound('tenant not found')
    data = _tenant_settings(tenant)
    data['actions_kill_switch'] = {'engaged': bool(enabled), 'by': actor_id(principal), 'at': _now().isoformat(), 'reason': redact(reason or '')[:500]}
    tenant.settings_json = dumps(data)
    tenant.actions_enabled = not enabled
    db.flush()
    record_audit(db, principal, 'actions.kill_switch', tenant.id, {'engaged': bool(enabled), 'reason': redact(reason or '')[:500]})
    _publish_sync('action.kill_switch', {'tenant_id': tenant.id, 'engaged': bool(enabled), 'by': actor_id(principal)})
    return kill_switch_state(db, _cfg(settings), tenant.id)


# ---------------------------------------------------------------- execute / rollback (enqueue side)


def _principal_payload(principal: Principal) -> dict:
    return {'actor': actor_id(principal), 'user_id': principal.user_id, 'email': principal.email, 'role': str(principal.role),
            'auth': principal.auth, 'api_key_id': principal.api_key_id}


def _principal_from_payload(tenant_id: str, payload: dict) -> Principal:
    try:
        role = Role(payload.get('role') or 'operator')
    except ValueError:
        role = Role.operator
    auth = payload.get('auth') or 'session'
    return Principal(tenant_id=tenant_id, role=role, auth=auth, user_id=payload.get('user_id'), email=payload.get('email') or '',
                     api_key_id=payload.get('api_key_id'))


async def execute(app, principal: Principal, request_id: str, *, db: Session | None = None) -> ActionRun:
    """Enqueue 'actions.execute' for an approved request. Returns the queued ActionRun."""
    if db is None:
        with session_scope(app.state.db_factory) as session:
            return await execute(app, principal, request_id, db=session)
    settings: Settings = app.state.settings
    if not has(principal, 'actions:execute'):
        raise Forbidden('Missing permission actions:execute')
    req = get_scoped(db, ActionRequest, principal, request_id)
    if req is None:
        raise NotFound('action request not found')
    _expire_if_needed(db, req, principal)
    if req.status not in EXECUTABLE_STATUSES:
        raise Conflict(f'request is {req.status}; only approved requests can be executed')
    action = catalog.get(req.action_type)
    if action is None:
        raise Conflict(f'action type {req.action_type} is no longer registered')
    tenant = _tenant(db, principal.tenant_id)
    if not approvals_satisfied(req, _approvals(db, req), db):
        raise PolicyDenied('request does not have the required approvals')
    params = loads(req.params_json, {})
    problems = action.validate(params if isinstance(params, dict) else {})
    if problems:
        raise PolicyDenied('stored params no longer satisfy the action schema: ' + '; '.join(problems[:5]))
    decision = policy.evaluate(db, tenant, settings, action, params, None, phase='execute')
    if decision.denied:
        record_audit(db, principal, 'actions.denied', req.id, {'action_type': req.action_type, 'reason': decision.deny_reason, 'phase': 'execute'})
        raise PolicyDenied(decision.deny_reason)
    previous_status = req.status
    run = ActionRun(tenant_id=req.tenant_id, request_id=req.id, status='queued', executed_by=actor_id(principal))
    req.status = 'executing'
    db.add(run)
    db.flush()
    record_audit(db, principal, 'actions.execute_requested', req.id, {'action_type': req.action_type, 'run_id': run.id})
    db.commit()  # the worker may claim the job before this request finishes; the rows must be visible first
    job = await app.state.queue.enqueue('actions.execute', {'request_id': req.id, 'run_id': run.id, 'previous_status': previous_status,
                                                            'principal': _principal_payload(principal)},
                                        tenant_id=req.tenant_id, lease_seconds=JOB_LEASE, idempotency_key=f'actions.execute:{run.id}', priority=2)
    run.job_id = job.id
    db.commit()
    return run


async def rollback(app, principal: Principal, run_id: str, *, db: Session | None = None) -> ActionRun:
    """Enqueue 'actions.rollback' for an executed run that has a rollback payload."""
    if db is None:
        with session_scope(app.state.db_factory) as session:
            return await rollback(app, principal, run_id, db=session)
    settings: Settings = app.state.settings
    if not has(principal, 'actions:rollback'):
        raise Forbidden('Missing permission actions:rollback')
    run = get_scoped(db, ActionRun, principal, run_id)
    if run is None:
        raise NotFound('action run not found')
    req = get_scoped(db, ActionRequest, principal, run.request_id)
    if req is None:
        raise NotFound('action request not found')
    if run.status != 'executed' or run.rolled_back_at is not None:
        raise Conflict(f'run is {run.status}; only executed runs can be rolled back')
    action = catalog.get(req.action_type)
    if action is None:
        raise Conflict(f'action type {req.action_type} is no longer registered')
    if not action.reversible:
        raise Conflict(f'{action.name} is not reversible')
    if run.rollback_payload_json in ('', '{}', 'null'):
        raise Conflict('run has no rollback payload')
    tenant = _tenant(db, principal.tenant_id)
    blocked = _kill_switch_reason(tenant, settings)
    if blocked:
        raise PolicyDenied(blocked)
    record_audit(db, principal, 'actions.rollback_requested', run.id, {'action_type': req.action_type, 'request_id': req.id})
    db.commit()
    job = await app.state.queue.enqueue('actions.rollback', {'run_id': run.id, 'request_id': req.id, 'principal': _principal_payload(principal)},
                                        tenant_id=req.tenant_id, lease_seconds=JOB_LEASE, idempotency_key=f'actions.rollback:{run.id}', priority=1)
    run.rollback_job_id = job.id
    db.commit()
    return run


def _kill_switch_reason(tenant: Tenant | None, settings: Settings) -> str:
    if settings.actions_kill_switch:
        return 'global kill switch is engaged (ACTIONS_KILL_SWITCH)'
    if policy.tenant_kill_switch(tenant):
        return 'actions are disabled for this tenant (kill switch engaged)'
    return ''


# ---------------------------------------------------------------- queue handlers


async def _load_pair(db: Session, tenant_id: str, request_id: str, run_id: str, attempts: int = 20) -> tuple[ActionRequest | None, ActionRun | None]:
    """The enqueueing request commits before enqueueing, but be tolerant of a slow commit."""
    for _ in range(attempts):
        req = get_scoped(db, ActionRequest, tenant_id, request_id)
        run = get_scoped(db, ActionRun, tenant_id, run_id)
        if req is not None and run is not None:
            return req, run
        db.expire_all()
        await asyncio.sleep(0.1)
    return None, None


def _finish(run: ActionRun, req: ActionRequest, *, run_status: str, request_status: str, error: str = '', result: dict | None = None) -> None:
    run.status, run.finished_at, run.error = run_status, _now(), redact(error or '')[:4000]
    if result is not None:
        run.result_json = dumps(_redacted(result), limit=32000)
    req.status = request_status


async def handle_execute(job, ctx) -> dict:
    payload = job.payload
    settings: Settings = ctx.settings
    principal = _principal_from_payload(job.tenant_id, payload.get('principal') or {})
    with session_scope(ctx.db_factory) as db:
        req, run = await _load_pair(db, job.tenant_id, payload['request_id'], payload['run_id'])
        if req is None or run is None:
            log.error('actions.execute: request %s / run %s not found for tenant %s', payload.get('request_id'), payload.get('run_id'), job.tenant_id)
            return {'ok': False, 'error': 'request or run not found'}
        if run.status != 'queued':
            return {'ok': True, 'skipped': True, 'status': run.status}  # idempotent re-delivery
        run.status, run.started_at, run.job_id = 'running', _now(), run.job_id or job.id
        action = catalog.get(req.action_type)
        tenant = _tenant(db, job.tenant_id)
        params = loads(req.params_json, {})
        previous = payload.get('previous_status') or 'approved'

        # 1. authorization is re-checked inside the handler: approvals, kill switch, policy.
        if action is None:
            _finish(run, req, run_status='failed', request_status='failed', error=f'action type {req.action_type} is not registered')
            return _audit_failure(db, principal, req, run)
        if req.status != 'executing':
            _finish(run, req, run_status='failed', request_status=req.status, error=f'request is {req.status}, not executing')
            return {'ok': False, 'error': run.error}
        if not approvals_satisfied(req, _approvals(db, req), db):
            _finish(run, req, run_status='failed', request_status=previous, error='approvals no longer satisfy policy')
            return _audit_failure(db, principal, req, run)
        # Params are validated against the schema again right before acting: what was approved is what runs.
        problems = action.validate(params if isinstance(params, dict) else {})
        if problems:
            _finish(run, req, run_status='failed', request_status='failed', error='params failed schema validation at execution: ' + '; '.join(problems[:5]))
            return _audit_failure(db, principal, req, run)
        decision = policy.evaluate(db, tenant, settings, action, params, None, phase='execute')
        if decision.denied:
            _finish(run, req, run_status='failed', request_status=previous, error=decision.deny_reason)
            record_audit(db, principal, 'actions.denied', req.id, {'action_type': req.action_type, 'reason': decision.deny_reason, 'phase': 'execute'})
            ACTIONS.labels(req.action_type, 'denied').inc()
            await publish('action.failed', _event(req, run_id=run.id, error=run.error, denied=True))
            return {'ok': False, 'error': run.error}

        await ctx.heartbeat()
        exec_ctx = build_context(settings, tenant, req, action, db=db, heartbeat=ctx.heartbeat, actor=actor_id(principal))

        # 2. dry run again right before acting: the world may have changed since the request.
        exec_ctx.dry_run = True
        dry = await safe_dry_run(action, params, exec_ctx)
        exec_ctx.dry_run = False
        if not dry.ok:
            _finish(run, req, run_status='failed', request_status='failed', error=f'pre-execution dry run failed: {dry.summary}', result={'dry_run': dry.as_dict()})
            return _audit_failure(db, principal, req, run)
        await ctx.heartbeat()

        # 3. execute.
        try:
            result = await asyncio.wait_for(action.execute(params, exec_ctx), timeout=EXECUTE_TIMEOUT)
        except ActionError as exc:
            _finish(run, req, run_status='failed', request_status='failed', error=exc.message, result={'dry_run': dry.as_dict(), 'details': exc.details})
            return _audit_failure(db, principal, req, run)
        except asyncio.TimeoutError:
            _finish(run, req, run_status='failed', request_status='failed', error=f'execution timed out after {EXECUTE_TIMEOUT}s', result={'dry_run': dry.as_dict()})
            return _audit_failure(db, principal, req, run)
        except Exception as exc:
            log.exception('action %s raised during execution', req.action_type)
            _finish(run, req, run_status='failed', request_status='failed', error=f'{type(exc).__name__}: {exc}', result={'dry_run': dry.as_dict()})
            return _audit_failure(db, principal, req, run)
        if not isinstance(result, ExecResult) or not result.ok:
            summary = getattr(result, 'summary', 'executor returned failure')
            _finish(run, req, run_status='failed', request_status='failed', error=summary,
                    result={'dry_run': dry.as_dict(), 'execution': result.as_dict() if isinstance(result, ExecResult) else {}})
            return _audit_failure(db, principal, req, run)
        # Stored intact (the column is encrypted at rest): rollback needs the real values (key ids, rule bodies, tokens
        # that match secret-looking patterns). It is redacted in run_to_dict when shown to a caller.
        run.rollback_payload_json = dumps(result.rollback_payload or {}, limit=64000) if action.reversible else '{}'
        _finish(run, req, run_status='executed', request_status='executed', result={'dry_run': dry.as_dict(), 'execution': result.as_dict()})
        record_audit(db, principal, 'actions.executed', req.id,
                     {'action_type': req.action_type, 'run_id': run.id, 'summary': result.summary[:500], 'blast_radius': dry.blast_radius,
                      'reversible': action.reversible})
        ACTIONS.labels(req.action_type, 'executed').inc()
        await publish('action.executed', _event(req, run_id=run.id, summary=redact(result.summary)[:500], reversible=action.reversible))
        return {'ok': True, 'run_id': run.id, 'summary': redact(result.summary)[:500]}


def _audit_failure(db: Session, principal: Principal, req: ActionRequest, run: ActionRun) -> dict:
    record_audit(db, principal, 'actions.failed', req.id, {'action_type': req.action_type, 'run_id': run.id, 'error': run.error[:500]})
    ACTIONS.labels(req.action_type, 'failed').inc()
    publish_soon('action.failed', _event(req, run_id=run.id, error=run.error[:500]))
    return {'ok': False, 'run_id': run.id, 'error': run.error}


async def handle_rollback(job, ctx) -> dict:
    payload = job.payload
    settings: Settings = ctx.settings
    principal = _principal_from_payload(job.tenant_id, payload.get('principal') or {})
    with session_scope(ctx.db_factory) as db:
        req, run = await _load_pair(db, job.tenant_id, payload['request_id'], payload['run_id'])
        if req is None or run is None:
            return {'ok': False, 'error': 'request or run not found'}
        if run.status != 'executed' or run.rolled_back_at is not None:
            return {'ok': True, 'skipped': True, 'status': run.status}
        action = catalog.get(req.action_type)
        tenant = _tenant(db, job.tenant_id)
        blocked = _kill_switch_reason(tenant, settings)
        if action is None or not action.reversible or blocked:
            error = blocked or f'{req.action_type} is not reversible'
            record_audit(db, principal, 'actions.rollback_failed', run.id, {'action_type': req.action_type, 'error': error})
            return {'ok': False, 'error': error}
        rollback_payload = loads(run.rollback_payload_json, {})
        await ctx.heartbeat()
        exec_ctx = build_context(settings, tenant, req, action, db=db, heartbeat=ctx.heartbeat, actor=actor_id(principal))
        try:
            result = await asyncio.wait_for(action.rollback(rollback_payload, exec_ctx), timeout=EXECUTE_TIMEOUT)
        except ActionError as exc:
            result = ExecResult(ok=False, summary=exc.message, details=exc.details)
        except asyncio.TimeoutError:
            result = ExecResult(ok=False, summary=f'rollback timed out after {EXECUTE_TIMEOUT}s')
        except Exception as exc:
            log.exception('action %s raised during rollback', req.action_type)
            result = ExecResult(ok=False, summary=f'{type(exc).__name__}: {exc}')
        existing = loads(run.result_json, {})
        existing['rollback'] = result.as_dict()
        run.result_json = dumps(_redacted(existing), limit=32000)
        if result.ok:
            run.status, run.rolled_back_at, run.rolled_back_by = 'rolled_back', _now(), actor_id(principal)
            req.status = 'rolled_back'
            record_audit(db, principal, 'actions.rolled_back', req.id, {'action_type': req.action_type, 'run_id': run.id, 'summary': result.summary[:500]})
            ACTIONS.labels(req.action_type, 'rolled_back').inc()
            await publish('action.rolled_back', _event(req, run_id=run.id, summary=redact(result.summary)[:500]))
            return {'ok': True, 'run_id': run.id}
        run.status, run.error = 'rollback_failed', redact(result.summary)[:4000]
        record_audit(db, principal, 'actions.rollback_failed', req.id, {'action_type': req.action_type, 'run_id': run.id, 'error': run.error[:500]})
        ACTIONS.labels(req.action_type, 'rollback_failed').inc()
        await publish('action.rollback_failed', _event(req, run_id=run.id, error=run.error[:500]))
        return {'ok': False, 'run_id': run.id, 'error': run.error}


# ---------------------------------------------------------------- queries used by the router


def list_requests(db: Session, principal: Principal, *, status: str | None = None, action_type: str | None = None,
                  finding_id: str | None = None, agent_only: bool = False):
    stmt = scoped(ActionRequest, principal)
    if status:
        stmt = stmt.where(ActionRequest.status == status)
    if action_type:
        stmt = stmt.where(ActionRequest.action_type == action_type)
    if finding_id:
        stmt = stmt.where(ActionRequest.finding_id == finding_id)
    if agent_only:
        stmt = stmt.where(ActionRequest.agent_run_id.is_not(None))
    return stmt.order_by(ActionRequest.created_at.desc())


def list_runs(db: Session, principal: Principal, *, status: str | None = None, request_id: str | None = None):
    stmt = scoped(ActionRun, principal)
    if status:
        stmt = stmt.where(ActionRun.status == status)
    if request_id:
        stmt = stmt.where(ActionRun.request_id == request_id)
    return stmt.order_by(ActionRun.created_at.desc())


def get_request(db: Session, principal: Principal, request_id: str) -> ActionRequest:
    req = get_scoped(db, ActionRequest, principal, request_id)
    if req is None:
        raise NotFound('action request not found')
    return req


def get_run(db: Session, principal: Principal, run_id: str) -> ActionRun:
    run = get_scoped(db, ActionRun, principal, run_id)
    if run is None:
        raise NotFound('action run not found')
    return run


def catalog_items(settings: Settings, tenant_settings: dict | None = None) -> list[dict]:
    return [a.as_dict(settings, tenant_settings) for a in catalog.all()]


__all__ = ['request', 'approve', 'cancel', 'execute', 'rollback', 'set_kill_switch', 'kill_switch_state', 'request_to_dict', 'run_to_dict',
           'approval_to_dict', 'request_detail', 'handle_execute', 'handle_rollback', 'configure', 'catalog_items', 'build_context', 'safe_dry_run']
