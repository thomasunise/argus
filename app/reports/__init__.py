"""Reports package: dashboard summary, posture score, compliance evidence mapping and trends.

Public interface:
  from app.reports import summary, posture, compliance, trends, FRAMEWORKS
  summary(db, tenant_id, settings) -> dict
  posture(db, tenant_id, settings) -> dict          # score 0..100 with weighted components
  compliance(db, tenant_id, framework, settings)   # per-control satisfied/partial/missing/manual + evidence
  trends(db, tenant_id, days) -> dict

Everything is computed from the tenant's own rows; other packages (graph, detections,
collectors, testing, actions) are imported lazily and reported as unavailable when absent.
"""
from __future__ import annotations

from .controls import FRAMEWORKS, compliance  # noqa: F401
from .posture import posture  # noqa: F401
from .summary import summary  # noqa: F401
from .trends import trends  # noqa: F401


def setup(app) -> None:  # nothing to register; present so the app factory treats the package uniformly
    return None
