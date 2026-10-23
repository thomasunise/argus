"""Action broker package.

setup(app) imports every executor module so the catalog is populated, stores the settings
for callers that only have a db session (the agents' propose_action tool), and registers the
'actions.execute' and 'actions.rollback' queue handlers.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil

from . import broker, catalog, credentials, policy  # noqa: F401
from .catalog import ActionError, ActionType, DryRunResult, ExecContext, ExecResult, register  # noqa: F401

log = logging.getLogger('sentinel.actions')


def load_executors() -> None:
    try:
        package = importlib.import_module('app.actions.executors')
    except ModuleNotFoundError:  # pragma: no cover - partial checkout
        return
    for module in pkgutil.iter_modules(package.__path__):
        if not module.name.startswith('_'):
            importlib.import_module(f'app.actions.executors.{module.name}')


def setup(app) -> None:
    load_executors()
    broker.configure(app.state.settings)
    queue = app.state.queue

    @queue.handler('actions.execute')
    async def _execute(job, ctx):
        return await broker.handle_execute(job, ctx)

    @queue.handler('actions.rollback')
    async def _rollback(job, ctx):
        return await broker.handle_rollback(job, ctx)

    log.info('action broker ready: %d action types', len(catalog.all()))
