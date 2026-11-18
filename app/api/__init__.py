"""Router discovery. Every module in this package that defines `router` is mounted by the
app factory. A new package adds its own module here and nothing else needs to change."""
from __future__ import annotations

import importlib
import logging
import pkgutil

from fastapi import APIRouter

log = logging.getLogger('argus.api')
OFFENSIVE_ROUTERS = {'pentest', 'discovery', 'exploits', 'autopilot'}


def discover_routers(*, core_only: bool = False) -> list[APIRouter]:
    routers: list[APIRouter] = []
    for module_info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        if module_info.name.startswith('_') or module_info.name == 'deps':
            continue
        if core_only and module_info.name in OFFENSIVE_ROUTERS:
            continue
        try:
            module = importlib.import_module(f'{__name__}.{module_info.name}')
        except (ModuleNotFoundError, ImportError):
            continue
        router = getattr(module, 'router', None)
        if isinstance(router, APIRouter):
            routers.append(router)
        for extra in getattr(module, 'routers', []) or []:
            if isinstance(extra, APIRouter):
                routers.append(extra)
    return routers
