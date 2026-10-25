"""Import every model module so Base.metadata is complete before create_all / Alembic."""
from __future__ import annotations

from .base import Base, TenantMixin, dumps, loads, uid, utcnow  # noqa: F401
from .identity import ApiKey, Membership, OidcIdentity, Tenant, User  # noqa: F401
from .inventory import Asset, AssetAuthorization  # noqa: F401
from .findings import Approval, Finding, Investigation, ScanRun, SecurityEvent  # noqa: F401
from .audit import AuditEntry  # noqa: F401
from .agents import AgentRun, AgentStep, EvalRun  # noqa: F401

from . import actions, ai, autoresponse, collectors, detections, graph, integrations, ops, simulation, testing  # noqa: F401  (registers their tables)
