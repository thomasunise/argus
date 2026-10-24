"""Evals for specialist agents: suites, deterministic graders, runner and the `agents.eval`
queue handler. `register(app)` is idempotent; app.agents.setup should call it once, and the
evals router calls it lazily as a safety net."""
from __future__ import annotations

import logging

from .runner import eval_to_dict, list_suites, load_suite, run_case, run_suite  # noqa: F401

log = logging.getLogger('argus.agents.evals')

JOB_KIND = 'agents.eval'


def register(app) -> None:
    queue = app.state.queue
    if JOB_KIND in queue.kinds:
        return

    @queue.handler(JOB_KIND)
    async def run_eval(job, ctx):
        from ...core.rbac import Principal, Role

        payload = job.payload
        principal = Principal(tenant_id=job.tenant_id, role=Role(payload.get('role', 'analyst')), user_id=payload.get('user_id'),
                              email=payload.get('email', ''), auth='system' if payload.get('system') else payload.get('auth') or 'session',
                              api_key_id=payload.get('api_key_id'), scopes=frozenset(payload.get('scopes') or ()))
        if not principal.can('evals:run'):
            raise PermissionError('principal lacks evals:run')
        run = await run_suite(payload['suite'], principal=principal, db_factory=ctx.db_factory, settings=ctx.settings, app=ctx.app,
                              spec_name=payload.get('spec') or None, eval_id=payload.get('eval_id'), heartbeat=ctx.heartbeat,
                              case_ids=payload.get('case_ids') or None)
        return {'eval_id': run.id, 'status': run.status, 'total': run.total, 'passed': run.passed, 'failed': run.failed}


def is_registered(app) -> bool:
    return JOB_KIND in app.state.queue.kinds
