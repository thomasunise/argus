"""Collector registry. `registry` is the singleton; the module-level `register`, `get`, `all`
and `has` delegate to it so `from app.collectors import registry` works whether the name
resolves to this module or to the instance."""
from __future__ import annotations

import importlib
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .base import Collector

log = logging.getLogger('sentinel.collectors')

KINDS = ('cloud', 'identity', 'code', 'endpoint', 'network', 'k8s')
BUILTIN = ('aws', 'azure', 'gcp', 'kubernetes', 'github', 'okta', 'entra', 'osquery', 'netflow')


class Registry:
    def __init__(self) -> None:
        self._items: dict[str, 'Collector'] = {}

    def register(self, collector: 'Collector') -> 'Collector':
        if not collector.name:
            raise ValueError('collector needs a name')
        if collector.kind not in KINDS:
            raise ValueError(f'collector {collector.name} has unknown kind {collector.kind!r}')
        self._items[collector.name] = collector
        return collector

    def unregister(self, name: str) -> None:
        self._items.pop(name, None)

    def get(self, name: str) -> 'Collector':
        try:
            return self._items[name]
        except KeyError:
            raise KeyError(f'unknown collector {name!r}') from None

    def all(self) -> list['Collector']:
        return [self._items[k] for k in sorted(self._items)]

    def names(self) -> list[str]:
        return sorted(self._items)

    def has(self, name: str) -> bool:
        return name in self._items

    def __contains__(self, name: str) -> bool:
        return name in self._items


registry = Registry()
_loaded = False


def load_builtin() -> Registry:
    global _loaded
    if not _loaded:
        for name in BUILTIN:
            importlib.import_module(f'{__package__}.{name}')
        _loaded = True
    return registry


def register(collector: 'Collector') -> 'Collector':
    return registry.register(collector)


def unregister(name: str) -> None:
    registry.unregister(name)


def get(name: str) -> 'Collector':
    return registry.get(name)


def all() -> list['Collector']:  # noqa: A001 - mirrors the Registry API
    return registry.all()


def names() -> list[str]:
    return registry.names()


def has(name: str) -> bool:
    return registry.has(name)
