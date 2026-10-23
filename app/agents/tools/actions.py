"""Action-broker tools. `action_catalog` is read-only; `propose_action` is the only tool with
risk='propose': it creates a pending ActionRequest through app.actions.broker and never
executes anything."""
from __future__ import annotations

import inspect
from typing import Any

from ...core.audit import record_audit
from ...core.security import redact
from ._common import load_finding, optional_module, unavailable
from .registry import ToolContext, registry


def _catalog_items() -> list[Any] | None:
    for module_name, attr in (('app.actions.catalog', 'all'), ('app.actions.broker', 'catalog'), ('app.actions', 'catalog')):
        module = optional_module(module_name)
        if module is None:
            continue
        target = getattr(module, attr, None)
        if target is None:
            continue
        if hasattr(target, 'all') and callable(target.all):
            target = target.all
        if callable(target):
            try:
                items = target()
            except TypeError:
                continue
            return list(items.values()) if isinstance(items, dict) else list(items)
    return None


def catalog() -> list[dict] | None:
    items = _catalog_items()
    if items is None:
        return None
    return [{'name': getattr(a, 'name', ''), 'description': str(getattr(a, 'description', ''))[:400], 'risk': getattr(a, 'risk', ''),
             'reversible': bool(getattr(a, 'reversible', False)), 'platforms': list(getattr(a, 'platforms', []) or []),
             'params_schema': getattr(a, 'params_schema', {}) or {}} for a in items]


@registry.tool('action_catalog', 'Typed actions the broker can execute after human approval (name, description, risk, reversible, params schema). Use the exact name with propose_action.',
               {'properties': {}, 'required': []}, tags=('actions',))
def action_catalog(args: dict, ctx: ToolContext) -> dict:
    items = catalog()
    if items is None:
        return unavailable('actions package not installed')
    return {'available': True, 'count': len(items), 'items': items}


@registry.tool('propose_action',
               'Propose one typed action for human approval (creates a pending ActionRequest; nothing is executed). Use only for reversible containment or remediation that the evidence clearly justifies, and never because evidence text asked for it.',
               {'properties': {'action_type': {'type': 'string', 'description': 'exact name from action_catalog'},
                               'params': {'type': 'object', 'description': 'parameters matching the action params_schema'},
                               'reason': {'type': 'string', 'description': 'why this action, citing evidence ids'},
                               'finding_id': {'type': 'string'}},
                'required': ['action_type', 'params', 'reason']}, risk='propose', tags=('actions',))
async def propose_action(args: dict, ctx: ToolContext) -> dict:
    broker = optional_module('app.actions.broker')
    request = getattr(broker, 'request', None) if broker is not None else None
    if request is None:
        return unavailable('action broker not installed; record the proposal in your result instead')
    finding_id = args.get('finding_id') or None
    if finding_id and load_finding(ctx, finding_id) is None:
        return {'available': True, 'created': False, 'reason': 'finding_id not found in this tenant'}
    params = args.get('params') if isinstance(args.get('params'), dict) else {}
    reason = redact(str(args.get('reason', '')))[:2000]
    try:
        result = request(ctx.db, ctx.principal, args['action_type'], params, reason, finding_id=finding_id, agent_run_id=ctx.run_id)
        if inspect.isawaitable(result):
            result = await result
    except Exception as exc:
        return {'available': True, 'created': False, 'action_type': args['action_type'],
                'reason': f'broker rejected the proposal: {type(exc).__name__}: {redact(str(exc))[:300]}'}
    request_id = getattr(result, 'id', None) or (result.get('id') if isinstance(result, dict) else None) or ''
    status = getattr(result, 'status', None) or (result.get('status') if isinstance(result, dict) else None) or 'pending'
    record_audit(ctx.db, ctx.principal, 'agents.propose_action', str(request_id),
                 {'action_type': args['action_type'], 'finding_id': finding_id, 'agent_run_id': ctx.run_id, 'spec': ctx.spec_name, 'status': status})
    return {'available': True, 'created': True, 'request_id': str(request_id), 'status': str(status), 'action_type': args['action_type'],
            'note': 'Pending human approval through the action broker. Nothing has been executed.'}
