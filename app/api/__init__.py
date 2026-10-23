"""Router discovery. Every module in this package that defines `router` is mounted by the
app factory. A new package adds its own module here and nothing else needs to change."""
from __future__ import annotations

import importlib
import logging
import pkgutil

from fastapi import APIRouter

log = logging.getLogger('sentinel.api')


def discover_routers() -> list[APIRouter]:
    routers: list[APIRouter] = []
    for module_info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        if module_info.name.startswith('_') or module_info.name == 'deps':
            continue
        module = importlib.import_module(f'{__name__}.{module_info.name}')
        router = getattr(module, 'router', None)
        if isinstance(router, APIRouter):
            routers.append(router)
        for extra in getattr(module, 'routers', []) or []:
            if isinstance(extra, APIRouter):
                routers.append(extra)
    return routers
