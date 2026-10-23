"""Testing-harness package.

setup(app) imports the adapters so the registry is populated, registers the 'testing.run'
queue handler (its body is harness.execute_run), and, when autoscan is enabled, starts a
scheduler loop that enqueues due scheduled plans.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil

from .harness import ADAPTERS, HarnessContext, NormalizedFinding, TestAdapter, execute_run, run_tool  # noqa: F401
from . import scope  # noqa: F401

log = logging.getLogger('sentinel.testing')


def _import_adapters() -> None:
    try:
        package = importlib.import_module('app.testing.adapters')
    except ModuleNotFoundError:  # pragma: no cover
        return
    for module in pkgutil.iter_modules(package.__path__):
        if not module.name.startswith('_'):
            importlib.import_module(f'app.testing.adapters.{module.name}')


def setup(app) -> None:
    _import_adapters()
    queue = app.state.queue
    settings = app.state.settings

    @queue.handler('testing.run')
    async def _run(job, ctx):
        return await execute_run(job.payload['run_id'], ctx.db_factory, ctx.settings, ctx.app, heartbeat=ctx.heartbeat, job_tenant_id=job.tenant_id)

    if settings.autoscan_enabled:
        async def _start_scheduler(app) -> None:
            from .scheduler import scheduler_loop
            from ..main import spawn

            spawn(app, scheduler_loop(app))

        app.state.startup_hooks.append(_start_scheduler)
