"""Collectors: inventory the enterprise estate (cloud, identity, code, endpoints, Kubernetes,
network) into the evidence graph and emit security events.

Public interface for other packages:
  from app.collectors import registry, load_builtin, Collector, CollectorContext, CollectorResult, NodeDraft, EdgeDraft, EventDraft
  from app.collectors.runner import enqueue_run, is_due, scheduler_tick
setup(app) registers the `collectors.run` queue handler and the scheduler startup hook.
"""
from __future__ import annotations

import logging

from .base import Collector, CollectorContext, CollectorResult, EdgeDraft, EventDraft, NodeDraft, is_secret_ref, validate_config  # noqa: F401
from . import registry  # noqa: F401  (module: register/get/all/has delegate to the singleton)
from .registry import BUILTIN, Registry, load_builtin  # noqa: F401

log = logging.getLogger('sentinel.collectors')


def setup(app) -> None:
    load_builtin()
    from .runner import install

    install(app)
