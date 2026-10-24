"""Read-only views over the active-testing harness (app.testing)."""
from __future__ import annotations

from typing import Any

from ...core.db import get_scoped, scoped
from ._common import clamp_limit, optional_attr, optional_module, serialize, unavailable
from .registry import ToolContext, registry


def _models():
    return optional_attr('app.models.testing', 'TestRun'), optional_attr('app.models.testing', 'TestResult')


@registry.tool('list_test_runs', 'Recent active-test runs (adapter, status, started/finished, result counts), optionally for one asset.',
               {'properties': {'asset_id': {'type': 'string'}, 'limit': {'type': 'integer'}}, 'required': []}, tags=('testing',))
def list_test_runs(args: dict, ctx: ToolContext) -> dict:
    TestRun, _ = _models()
    if TestRun is None:
        return unavailable('testing package not installed')
    stmt = scoped(TestRun, ctx.principal)
    if args.get('asset_id') and hasattr(TestRun, 'asset_id'):
        stmt = stmt.where(TestRun.asset_id == args['asset_id'])
    for name in ('created_at', 'started_at', 'id'):
        column = getattr(TestRun, name, None)
        if column is not None:
            stmt = stmt.order_by(column.desc())
            break
    rows = ctx.db.execute(stmt.limit(clamp_limit(args.get('limit'), default=25, maximum=200))).scalars().all()
    return {'available': True, 'count': len(rows), 'items': [serialize(r) for r in rows]}


@registry.tool('test_results', 'Normalized results of one test run.',
               {'properties': {'run_id': {'type': 'string'}, 'limit': {'type': 'integer'}}, 'required': ['run_id']}, tags=('testing',))
def test_results(args: dict, ctx: ToolContext) -> dict:
    TestRun, TestResult = _models()
    if TestRun is None or TestResult is None:
        return unavailable('testing package not installed')
    run = get_scoped(ctx.db, TestRun, ctx.principal, args['run_id'])
    if run is None:
        return {'available': True, 'found': False, 'run_id': args['run_id']}
    stmt = scoped(TestResult, ctx.principal) if hasattr(TestResult, 'tenant_id') else None
    if stmt is None:
        from sqlalchemy import select

        stmt = select(TestResult)
    stmt = stmt.where(TestResult.run_id == run.id) if hasattr(TestResult, 'run_id') else stmt.where(TestResult.test_run_id == run.id)
    rows = ctx.db.execute(stmt.limit(clamp_limit(args.get('limit'), default=100, maximum=500))).scalars().all()
    return {'available': True, 'found': True, 'run': serialize(run), 'count': len(rows), 'items': [serialize(r) for r in rows]}


def adapter_catalog() -> list[dict] | None:
    for module_name in ('app.testing.harness', 'app.testing.adapters', 'app.testing'):
        module = optional_module(module_name)
        if module is None:
            continue
        for attr in ('registry', 'ADAPTERS', 'adapters', 'all_adapters'):
            candidate: Any = getattr(module, attr, None)
            if candidate is None:
                continue
            if callable(candidate) and not isinstance(candidate, type):
                try:
                    candidate = candidate()
                except TypeError:
                    continue
            if hasattr(candidate, 'all') and callable(candidate.all):
                candidate = candidate.all()
            items = list(candidate.values()) if isinstance(candidate, dict) else list(candidate) if isinstance(candidate, (list, tuple)) else None
            if items is None:
                continue
            out = []
            for a in items:
                available = getattr(a, 'available', None)
                try:
                    is_available = bool(available()) if callable(available) else bool(available) if available is not None else True
                except Exception:
                    is_available = False
                out.append({'name': getattr(a, 'name', ''), 'tier': getattr(a, 'tier', ''), 'target_kinds': list(getattr(a, 'target_kinds', []) or []),
                            'available': is_available, 'description': str(getattr(a, 'description', '') or getattr(a, '__doc__', '') or '')[:300].strip()})
            return out
    return None


@registry.tool('available_test_adapters', 'Test adapters Argus can run (name, tier passive/active/intrusive, target kinds, installed or not). Agents cannot run them.',
               {'properties': {}, 'required': []}, tags=('testing',))
def available_test_adapters(args: dict, ctx: ToolContext) -> dict:
    adapters = adapter_catalog()
    if adapters is None:
        return unavailable('testing harness not installed')
    return {'available': True, 'count': len(adapters), 'items': adapters}
