"""Autonomous response: playbooks that turn a detection into a governed action without a human.

Flow: 'detection.created' on the event bus -> 'autoresponse.evaluate' queue job -> for every
enabled playbook of the tenant that matches the detection, one AutoresponseExecution row with
the outcome:

  skipped    a guardrail stopped it (simulation, irreversible, risk, missing template value,
             invalid params, hourly cap, duplicate)
  shadow     mode=shadow: the dry run ran and the decision was recorded; nothing changed
  escalated  mode=enforce but the policy did not auto-approve (dry run failed, blast radius too
             wide...): an ordinary pending ActionRequest now waits for humans
  enforced   auto-approved through policy.evaluate(autonomous=...) and queued for execution
  denied     a hard policy denial (kill switch, deny-list, actions disabled)
  failed     unexpected error while evaluating

Enforced actions carry a rollback deadline: unless a human confirms "keep", sweep_rollbacks()
undoes them through the broker after `rollback_after_minutes`. Everything stays inside the
broker: approvals, kill switches, deny-lists, dry runs and the execute-time re-check apply as for
any other request. Agents never reach this module.

Off unless AUTORESPONSE_ENABLED=true and the tenant opted in (settings_json['autoresponse']).
"""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.config import Settings
from ..core.db import get_scoped, scoped, session_scope
from ..core.errors import ArgusError, PolicyDenied
from ..core.events import publish, subscribe
from ..core.findings import SEVERITIES
from ..core.rbac import Principal, Role
from ..core.security import redact
from ..models import Tenant, dumps, loads
from ..models.actions import ActionRun
from ..models.autoresponse import AutoresponseExecution, ResponsePlaybook
from . import broker, catalog
from .catalog import RISK_RANK

log = logging.getLogger('argus.actions.autoresponse')

JOB_KIND = 'autoresponse.evaluate'
SIMULATION_TAG = 'simulation'
_PLACEHOLDER = re.compile(r'\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}')
_MAX_TEMPLATE_DEPTH = 6


class MissingValue(Exception):
    """A template placeholder named a field the detection does not have."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def autoresponse_principal(tenant_id: str) -> Principal:
    """The identity autonomous requests are made under (a system principal; audit shows 'system')."""
    return Principal(tenant_id=tenant_id, role=Role.owner, auth='system', email='autoresponse')


# ---------------------------------------------------------------- tenant settings


def tenant_config(tenant: Tenant | None) -> dict:
    data = loads(tenant.settings_json, {}) if tenant is not None else {}
    config = data.get('autoresponse') if isinstance(data, dict) else None
    return config if isinstance(config, dict) else {}


def tenant_enabled(tenant: Tenant | None) -> bool:
    return bool(tenant is not None and tenant.is_active and tenant_config(tenant).get('enabled'))


def tenant_hourly_cap(tenant: Tenant | None, settings: Settings) -> int:
    global_cap = max(0, int(settings.autoresponse_max_per_hour))
    try:
        own = int(tenant_config(tenant).get('max_per_hour', global_cap))
    except (TypeError, ValueError):
        own = global_cap
    return max(0, min(global_cap, own))  # a tenant may lower the global cap, never raise it


def set_tenant_config(db: Session, principal: Principal, *, enabled: bool | None = None, max_per_hour: int | None = None) -> dict:
    tenant = db.get(Tenant, principal.tenant_id)
    data = loads(tenant.settings_json, {}) if tenant else {}
    data = data if isinstance(data, dict) else {}
    config = dict(data.get('autoresponse') or {})
    if enabled is not None:
        config['enabled'] = bool(enabled)
    if max_per_hour is not None:
        config['max_per_hour'] = max(0, int(max_per_hour))
    data['autoresponse'] = config
    tenant.settings_json = dumps(data)
    db.flush()
    record_audit(db, principal, 'autoresponse.settings', tenant.id, dict(config))
    return config


# ---------------------------------------------------------------- matching and templates


def detection_context(detection) -> dict:
    return {'id': detection.id, 'rule_id': detection.rule_id, 'title': detection.title, 'severity': detection.severity,
            'entity': detection.entity, 'entity_kind': detection.entity_kind, 'confidence': detection.confidence,
            'finding_id': detection.finding_id, 'evidence': loads(detection.evidence_json, {}), 'tags': loads(detection.tags_json, [])}


def is_simulation(context: dict) -> bool:
    tags = context.get('tags') or []
    evidence = context.get('evidence') if isinstance(context.get('evidence'), dict) else {}
    return SIMULATION_TAG in tags or evidence.get('simulation') is True or str(evidence.get('source') or '') == 'simulator'


def severity_at_least(severity: str, minimum: str) -> bool:
    if minimum not in SEVERITIES:
        return True
    if severity not in SEVERITIES:
        return False
    return SEVERITIES.index(severity) <= SEVERITIES.index(minimum)


def matches(playbook: ResponsePlaybook, context: dict) -> bool:
    rule_ids = loads(playbook.rule_ids_json, [])
    if rule_ids and context['rule_id'] not in rule_ids:
        return False
    if not severity_at_least(str(context['severity']), playbook.min_severity):
        return False
    if float(context.get('confidence') or 0.0) < float(playbook.min_confidence or 0.0):
        return False
    if playbook.entity_kind and playbook.entity_kind != context.get('entity_kind'):
        return False
    return True


def _lookup(context: dict, path: str) -> Any:
    value: Any = context
    for part in path.split('.'):
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            raise MissingValue(path)
    if value is None or value == '':
        raise MissingValue(path)
    if not isinstance(value, (str, int, float, bool)):
        raise MissingValue(f'{path} (not a scalar)')
    return value


def render(template: Any, context: dict, depth: int = 0) -> Any:
    """Substitute {{path}} placeholders from the detection context. No expressions, no eval: a string that
    is exactly one placeholder takes the value's type; otherwise values are interpolated as text."""
    if depth > _MAX_TEMPLATE_DEPTH:
        raise MissingValue('template nested too deeply')
    if isinstance(template, dict):
        return {str(k): render(v, context, depth + 1) for k, v in template.items()}
    if isinstance(template, list):
        return [render(v, context, depth + 1) for v in template]
    if not isinstance(template, str):
        return template
    whole = _PLACEHOLDER.fullmatch(template.strip())
    if whole:
        return _lookup(context, whole.group(1))
    return _PLACEHOLDER.sub(lambda m: str(_lookup(context, m.group(1))), template)


def placeholders(template: Any) -> list[str]:
    found: list[str] = []
    if isinstance(template, dict):
        for value in template.values():
            found += placeholders(value)
    elif isinstance(template, list):
        for value in template:
            found += placeholders(value)
    elif isinstance(template, str):
        found += _PLACEHOLDER.findall(template)
    return found


def check_playbook_action(action_type: str, allow_high_risk: bool) -> str:
    """'' when the action may be used by a playbook, else the reason."""
    action = catalog.get(action_type)
    if action is None:
        return f'unknown action type {action_type!r}'
    if not action.reversible:
        return f'{action_type} is not reversible; autonomous playbooks only use reversible actions'
    if action.risk == 'critical':
        return f'{action_type} is critical risk; critical actions are never autonomous'
    if action.risk == 'high' and not allow_high_risk:
        return f'{action_type} is high risk; set allow_high_risk to use it'
    return ''


# ---------------------------------------------------------------- evaluation


def _count_since(db: Session, tenant_id: str, since: datetime, *, outcomes: tuple[str, ...], playbook_id: str | None = None) -> int:
    stmt = select(func.count()).select_from(AutoresponseExecution).where(
        AutoresponseExecution.tenant_id == tenant_id, AutoresponseExecution.created_at >= since, AutoresponseExecution.outcome.in_(outcomes))
    if playbook_id:
        stmt = stmt.where(AutoresponseExecution.playbook_id == playbook_id)
    return int(db.scalar(stmt) or 0)


def _record(db: Session, execution: AutoresponseExecution, outcome: str, reason: str, **fields: Any) -> AutoresponseExecution:
    execution.outcome, execution.reason = outcome, redact(reason or '')[:2000]
    for key, value in fields.items():
        setattr(execution, key, value)
    return execution


async def evaluate_detection(app, db: Session, tenant_id: str, detection_id: str) -> list[AutoresponseExecution]:
    """Run every matching playbook of the tenant for one detection. Idempotent per (playbook, detection)."""
    from ..models.detections import Detection

    settings: Settings = app.state.settings
    if not settings.autoresponse_enabled:
        return []
    tenant = db.get(Tenant, tenant_id)
    if not tenant_enabled(tenant):
        return []
    detection = get_scoped(db, Detection, tenant_id, detection_id)
    if detection is None:
        return []
    context = detection_context(detection)
    playbooks = db.execute(scoped(ResponsePlaybook, tenant_id).where(ResponsePlaybook.enabled.is_(True))
                           .order_by(ResponsePlaybook.created_at.asc())).scalars().all()
    principal = autoresponse_principal(tenant_id)
    results: list[AutoresponseExecution] = []
    for playbook in playbooks:
        if not matches(playbook, context):
            continue
        existing = db.execute(scoped(AutoresponseExecution, tenant_id).where(AutoresponseExecution.playbook_id == playbook.id,
                                                                            AutoresponseExecution.detection_id == detection.id)).scalar_one_or_none()
        if existing is not None:
            continue  # a re-delivered job: decided already
        execution = AutoresponseExecution(tenant_id=tenant_id, playbook_id=playbook.id, playbook_name=playbook.name, detection_id=detection.id,
                                          rule_id=detection.rule_id, action_type=playbook.action_type, mode=playbook.mode)
        db.add(execution)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            continue
        try:
            await _decide(app, db, settings, tenant, playbook, context, execution, principal)
        except Exception as exc:  # one playbook must not stop the others
            log.exception('autoresponse playbook %s failed on detection %s', playbook.id, detection.id)
            _record(db, execution, 'failed', f'{type(exc).__name__}: {exc}')
        playbook.last_triggered_at = _now()
        record_audit(db, principal, 'autoresponse.decision', execution.id,
                     {'playbook_id': playbook.id, 'playbook': playbook.name, 'detection_id': detection.id, 'rule_id': detection.rule_id,
                      'action_type': playbook.action_type, 'mode': playbook.mode, 'outcome': execution.outcome, 'reason': execution.reason[:500],
                      'action_request_id': execution.action_request_id, 'action_run_id': execution.action_run_id})
        db.commit()
        results.append(execution)
    return results


async def _decide(app, db: Session, settings: Settings, tenant: Tenant, playbook: ResponsePlaybook, context: dict,
                  execution: AutoresponseExecution, principal: Principal) -> None:
    if is_simulation(context):
        _record(db, execution, 'skipped', 'detection comes from the attack simulator')
        return
    problem = check_playbook_action(playbook.action_type, playbook.allow_high_risk)
    if problem:
        _record(db, execution, 'skipped', problem)
        return
    action = catalog.get(playbook.action_type)
    try:
        params = render(loads(playbook.params_template_json, {}), context)
    except MissingValue as exc:
        _record(db, execution, 'skipped', f'detection has no value for template field {exc}')
        return
    params = action.normalize(params if isinstance(params, dict) else {})
    execution.params_json = dumps(params, limit=8000)
    invalid = action.validate(params)
    if invalid:
        _record(db, execution, 'skipped', 'rendered params are invalid: ' + '; '.join(invalid[:5]))
        return
    hour_ago = _now() - timedelta(hours=1)
    if _count_since(db, tenant.id, hour_ago, outcomes=('shadow', 'escalated', 'enforced'), playbook_id=playbook.id) >= max(0, playbook.max_per_hour):
        _record(db, execution, 'skipped', f'playbook hourly limit reached ({playbook.max_per_hour})')
        return
    autonomous = {'playbook': playbook.name, 'max_risk': 'high' if playbook.allow_high_risk else 'medium',
                  'max_entities': max(1, int(playbook.max_blast_radius or 1))}

    if playbook.mode != 'enforce':
        stand_in = SimpleNamespace(id='', tenant_id=tenant.id)
        ctx = broker.build_context(settings, tenant, stand_in, action, db=db, actor='system', dry_run=True)
        dry = await broker.safe_dry_run(action, params, ctx)
        from . import policy

        decision = policy.evaluate(db, tenant, settings, action, params, principal, dry_run=dry, autonomous=autonomous)
        verdict = 'would be denied: ' + decision.deny_reason if decision.denied else (
            'would execute autonomously' if decision.auto_approve else 'would escalate to human approval')
        _record(db, execution, 'shadow', f'shadow mode: {verdict}; {"; ".join(decision.reasons[-2:])}', dry_run_json=dumps(dry.as_dict(), limit=8000))
        return

    if _count_since(db, tenant.id, hour_ago, outcomes=('enforced',)) >= tenant_hourly_cap(tenant, settings):
        _record(db, execution, 'skipped', f'tenant hourly autonomous-action cap reached ({tenant_hourly_cap(tenant, settings)})')
        return
    reason = f'Autonomous response: playbook "{playbook.name}" on detection {context["id"]} ({context["rule_id"]}: {context["title"]})'
    try:
        req = await broker.request(db, principal, action.name, params, reason, finding_id=context.get('finding_id'), detection_id=context['id'],
                                   settings=settings, autonomous=autonomous)
    except PolicyDenied as exc:
        _record(db, execution, 'denied', exc.message if hasattr(exc, 'message') else str(exc))
        return
    except ArgusError as exc:
        _record(db, execution, 'failed', getattr(exc, 'message', '') or str(exc))
        return
    execution.action_request_id = req.id
    execution.dry_run_json = req.dry_run_json
    if req.status != 'auto_approved':
        reasons = loads(req.policy_json, {}).get('reasons', [])
        _record(db, execution, 'escalated', 'guardrails did not allow autonomous execution; waiting for human approval: ' + '; '.join(reasons[-2:]))
        return
    db.commit()
    run = await broker.execute(app, principal, req.id, db=db)
    minutes = max(0, int(playbook.rollback_after_minutes or 0))
    due = _now() + timedelta(minutes=minutes) if minutes else None
    _record(db, execution, 'enforced', f'executed autonomously; {"rolls back at " + due.isoformat() if due else "no automatic rollback"} unless kept',
            action_run_id=run.id, rollback_state='pending' if due else '', rollback_due_at=due)
    await publish('action.autonomous', {'tenant_id': tenant.id, 'request_id': req.id, 'run_id': run.id, 'action_type': action.name, 'risk': action.risk,
                                        'status': 'executing', 'severity': context['severity'], 'playbook': playbook.name, 'playbook_id': playbook.id,
                                        'detection_id': context['id'], 'execution_id': execution.id, 'reversible': True,
                                        'rollback_due_at': due.isoformat() if due else None,
                                        'title': f'Autonomous {action.name} by playbook "{playbook.name}"',
                                        'summary': redact(f'{context["title"]} -> {action.name}. Rolls back automatically '
                                                          f'{"at " + due.isoformat() if due else "never"} unless someone keeps it.')})


# ---------------------------------------------------------------- keep / rollback / sweep


def keep(db: Session, principal: Principal, execution: AutoresponseExecution) -> AutoresponseExecution:
    from ..core.errors import Conflict

    if execution.rollback_state != 'pending':
        raise Conflict(f'execution has no pending automatic rollback (state {execution.rollback_state or "none"})')
    execution.rollback_state, execution.kept_by, execution.kept_at = 'kept', broker.actor_id(principal), _now()
    record_audit(db, principal, 'autoresponse.kept', execution.id, {'action_run_id': execution.action_run_id, 'playbook': execution.playbook_name})
    return execution


async def rollback(app, db: Session, principal: Principal, execution: AutoresponseExecution) -> AutoresponseExecution:
    from ..core.errors import Conflict

    if not execution.action_run_id:
        raise Conflict('execution did not run an action')
    await broker.rollback(app, principal, execution.action_run_id, db=db)
    execution.rollback_state = 'requested'
    record_audit(db, principal, 'autoresponse.rollback_requested', execution.id, {'action_run_id': execution.action_run_id, 'manual': True})
    return execution


async def sweep_rollbacks(app, now: datetime | None = None) -> dict:
    """Roll back enforced actions whose deadline passed and that nobody kept; settle requested rollbacks."""
    now = now or _now()
    counts = {'requested': 0, 'done': 0, 'failed': 0, 'waiting': 0}
    with session_scope(app.state.db_factory) as db:
        rows = db.execute(select(AutoresponseExecution).where(AutoresponseExecution.rollback_state.in_(('pending', 'requested')))
                          .order_by(AutoresponseExecution.created_at.asc()).limit(200)).scalars().all()
        for execution in rows:
            run = get_scoped(db, ActionRun, execution.tenant_id, execution.action_run_id or '')
            if execution.rollback_state == 'requested':
                if run is not None and run.status == 'rolled_back':
                    execution.rollback_state, execution.rolled_back_at = 'done', _aware(run.rolled_back_at) or now
                    counts['done'] += 1
                elif run is None or run.status == 'rollback_failed':
                    execution.rollback_state = 'failed'
                    counts['failed'] += 1
                continue
            due = _aware(execution.rollback_due_at)
            if due is None or due > now:
                continue
            if run is None:
                execution.rollback_state = 'failed'
                counts['failed'] += 1
                continue
            if run.status in ('queued', 'running'):
                counts['waiting'] += 1
                continue
            if run.status != 'executed' or run.rolled_back_at is not None:
                execution.rollback_state = 'not_needed' if run.status != 'rolled_back' else 'done'
                continue
            principal = autoresponse_principal(execution.tenant_id)
            try:
                await broker.rollback(app, principal, run.id, db=db)
            except PolicyDenied as exc:  # kill switch engaged: retry on a later sweep
                log.warning('autoresponse rollback of run %s blocked: %s', run.id, exc)
                counts['waiting'] += 1
                continue
            except ArgusError as exc:
                execution.rollback_state = 'failed'
                execution.reason = redact(f'{execution.reason}; automatic rollback failed: {getattr(exc, "message", exc)}')[:2000]
                counts['failed'] += 1
                continue
            execution.rollback_state = 'requested'
            record_audit(db, principal, 'autoresponse.rollback_requested', execution.id,
                         {'action_run_id': run.id, 'manual': False, 'due_at': due.isoformat()}, tenant_id=execution.tenant_id)
            counts['requested'] += 1
            db.commit()
    return counts


# ---------------------------------------------------------------- serialization


def playbook_to_dict(p: ResponsePlaybook) -> dict:
    return {'id': p.id, 'name': p.name, 'description': p.description, 'enabled': bool(p.enabled), 'mode': p.mode,
            'rule_ids': loads(p.rule_ids_json, []), 'min_severity': p.min_severity, 'min_confidence': p.min_confidence,
            'entity_kind': p.entity_kind, 'action_type': p.action_type, 'params_template': loads(p.params_template_json, {}),
            'max_per_hour': p.max_per_hour, 'max_blast_radius': p.max_blast_radius, 'rollback_after_minutes': p.rollback_after_minutes,
            'allow_high_risk': bool(p.allow_high_risk), 'created_by': p.created_by, 'created_at': p.created_at, 'updated_at': p.updated_at,
            'last_triggered_at': p.last_triggered_at}


def execution_to_dict(e: AutoresponseExecution) -> dict:
    return {'id': e.id, 'playbook_id': e.playbook_id, 'playbook_name': e.playbook_name, 'detection_id': e.detection_id, 'rule_id': e.rule_id,
            'action_type': e.action_type, 'mode': e.mode, 'outcome': e.outcome, 'reason': e.reason, 'params': loads(e.params_json, {}),
            'dry_run': loads(e.dry_run_json, {}), 'action_request_id': e.action_request_id, 'action_run_id': e.action_run_id,
            'rollback_state': e.rollback_state, 'rollback_due_at': e.rollback_due_at, 'rolled_back_at': e.rolled_back_at,
            'kept_by': e.kept_by, 'kept_at': e.kept_at, 'created_at': e.created_at}


# ---------------------------------------------------------------- wiring


def install(app) -> None:
    queue = app.state.queue
    settings: Settings = app.state.settings

    async def on_detection(topic: str, payload: dict) -> None:
        if not settings.autoresponse_enabled:
            return
        tenant_id, detection_id = payload.get('tenant_id'), payload.get('detection_id')
        if not tenant_id or not detection_id:
            return
        try:
            await queue.enqueue(JOB_KIND, {'detection_id': str(detection_id)}, tenant_id=str(tenant_id), priority=1,
                                idempotency_key=f'{JOB_KIND}:{detection_id}')
        except Exception:  # the bus must never fail the producer
            log.exception('could not enqueue %s for detection %s', JOB_KIND, detection_id)

    subscribe('detection.created', on_detection)

    @queue.handler(JOB_KIND)
    async def _evaluate(job, ctx):
        detection_id = str(job.payload.get('detection_id') or '')
        with session_scope(ctx.db_factory) as db:
            tenant = db.get(Tenant, job.tenant_id)
            if tenant is None or not tenant.is_active:
                raise PermissionError('tenant is not active')
            results = await evaluate_detection(ctx.app, db, job.tenant_id, detection_id)  # loads the detection scoped to job.tenant_id
            return {'executions': [{'id': r.id, 'outcome': r.outcome} for r in results]}

    async def _start(app) -> None:
        if settings.app_env == 'test' or not settings.autoresponse_enabled:
            return
        from ..main import spawn

        spawn(app, _sweep_loop(app))

    app.state.startup_hooks.append(_start)


async def _sweep_loop(app) -> None:
    interval = max(15, int(app.state.settings.autoresponse_sweep_seconds or 60))
    while True:
        await asyncio.sleep(interval)
        try:
            await sweep_rollbacks(app)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception('autoresponse rollback sweep failed')
