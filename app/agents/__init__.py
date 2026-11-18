"""Agent runtime package. setup(app) registers the queue handler that executes agent runs
and imports tools and specialists so their registries are populated."""
from __future__ import annotations

import importlib
import logging
import pkgutil

from .runtime import SPECS, AgentRuntime, AgentSpec, get_runtime, register_spec  # noqa: F401
from .tools.registry import registry  # noqa: F401

log = logging.getLogger('argus.agents')


OFFENSIVE_TOOLS = {'exploit', 'pentest_tool'}
OFFENSIVE_SPECIALISTS = {'redteam_plan', 'poc_author', 'offensive_pentest'}


def _import_all(package_name: str, *, skip: set[str] | None = None) -> None:
    try:
        package = importlib.import_module(package_name)
    except ModuleNotFoundError:
        return
    for module in pkgutil.iter_modules(package.__path__):
        if not module.name.startswith('_') and (not skip or module.name not in skip):
            try:
                importlib.import_module(f'{package_name}.{module.name}')
            except ModuleNotFoundError:
                continue


def setup(app) -> None:
    core_only = bool(getattr(app.state.settings, 'core_only_build', False))
    _import_all('app.agents.tools', skip=OFFENSIVE_TOOLS if core_only else None)
    _import_all('app.agents.specialists', skip=OFFENSIVE_SPECIALISTS if core_only else None)
    from .evals import register as register_evals

    register_evals(app)
    queue = app.state.queue

    @queue.handler('agents.run')
    async def run_agent(job, ctx):
        from ..core.rbac import Principal, Role

        payload = job.payload
        spec = SPECS[payload['spec']]
        principal = Principal(tenant_id=job.tenant_id, role=Role(payload.get('role', 'analyst')), user_id=payload.get('user_id'),
                              email=payload.get('email', ''), auth='system' if payload.get('system') else payload.get('auth') or 'session',
                              api_key_id=payload.get('api_key_id'), scopes=frozenset(payload.get('scopes') or ()))
        runtime = get_runtime(ctx.app) if ctx.app else AgentRuntime(ctx.settings)
        result = await runtime.run(spec, payload['task'], payload.get('inputs', {}), principal, ctx.db_factory,
                                   run_id=payload.get('run_id'), finding_id=payload.get('finding_id'),
                                   parent_run_id=payload.get('parent_run_id'), job_id=job.id, heartbeat=ctx.heartbeat)
        return {'run_id': result.run_id, 'status': result.status}
