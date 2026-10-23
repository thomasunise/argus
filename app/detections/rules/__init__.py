"""Detection rules. Each module registers one or more `DetectionRule` instances with
`app.detections.engine.registry` at import time; `registry.ensure_loaded()` imports them all."""
from __future__ import annotations


def load_all() -> None:
    from ..engine import registry

    registry.ensure_loaded()
