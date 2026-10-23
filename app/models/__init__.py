"""Import every model module so Base.metadata is complete before create_all / Alembic.

Workstreams add their module name to MODULES. Missing modules are tolerated so partial
checkouts still start.
"""
from __future__ import annotations

import importlib

from .base import Base, TenantMixin, dumps, loads, uid, utcnow  # noqa: F401
from .identity import ApiKey, Membership, OidcIdentity, Tenant, User  # noqa: F401
from .inventory import Asset, AssetAuthorization  # noqa: F401
from .findings import Approval, Finding, Investigation, ScanRun, SecurityEvent  # noqa: F401
from .audit import AuditEntry  # noqa: F401
from .agents import AgentRun, AgentStep, EvalRun  # noqa: F401

MODULES = ['graph', 'detections', 'collectors', 'testing', 'actions', 'integrations']

for _name in MODULES:
    try:
        importlib.import_module(f'{__name__}.{_name}')
    except ModuleNotFoundError as exc:  # pragma: no cover - partial checkout
        if exc.name != f'{__name__}.{_name}':
            raise
