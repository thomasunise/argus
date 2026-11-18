"""Specialist agents. Each module calls register_spec at import; app.agents.setup imports them all."""
from __future__ import annotations

SPECIALISTS = ('triage', 'investigate', 'hunt', 'redteam_plan', 'remediate', 'posture_report', 'swarm_responder', 'poc_author', 'offensive_pentest')
OFFENSIVE_SPECIALISTS = {'redteam_plan', 'poc_author', 'offensive_pentest'}


def load_all(*, core_only: bool = False) -> None:
    """Import every specialist module so SPECS is populated (idempotent)."""
    import contextlib
    import importlib

    for name in SPECIALISTS:
        if core_only and name in OFFENSIVE_SPECIALISTS:
            continue
        with contextlib.suppress(ModuleNotFoundError):
            importlib.import_module(f'{__name__}.{name}')
