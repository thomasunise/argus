"""Typed action catalog.

An ActionType describes one change the broker may make to the estate: its parameter schema,
risk tier, reversibility, and three coroutines (dry_run, execute, rollback). Executors are
thin, lazily-imported SDK/API calls; everything about governance lives in policy.py and
broker.py. Nothing in this module talks to the network.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from ..core.config import Settings
from ..core.security import redact, resolve_secret
from . import schema as schema_module

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.orm import Session

log = logging.getLogger('sentinel.actions')

RISKS = ('low', 'medium', 'high', 'critical')
RISK_RANK = {name: index for index, name in enumerate(RISKS)}


class ActionError(Exception):
    """Raised by executors for an expected failure (target missing, API refused). The message is
    shown to operators, so executors must keep secrets out of it."""

    def __init__(self, message: str, *, details: dict | None = None):
        super().__init__(redact(message))
        self.message = redact(message)
        self.details = details or {}


@dataclass
class DryRunResult:
    ok: bool
    summary: str
    blast_radius: dict = field(default_factory=dict)  # {'entities': int, 'kind': str, 'ids': [...], ...}
    warnings: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    @property
    def entities(self) -> int:
        try:
            return int(self.blast_radius.get('entities', 0))
        except (TypeError, ValueError):
            return 0

    def as_dict(self) -> dict:
        return {'ok': self.ok, 'summary': redact(self.summary), 'blast_radius': self.blast_radius,
                'warnings': [redact(w) for w in self.warnings], 'details': self.details}


@dataclass
class ExecResult:
    ok: bool
    summary: str
    rollback_payload: dict | None = None
    details: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {'ok': self.ok, 'summary': redact(self.summary), 'details': self.details}


@dataclass
class ExecContext:
    """What an executor gets. `request` is the ActionRequest row (or a stand-in in tests)."""

    tenant_id: str
    settings: Settings
    request: Any
    logger: logging.Logger
    heartbeat: Callable[[], Awaitable[None]]
    platform: str = ''
    tenant_settings: dict = field(default_factory=dict)
    db: 'Session | None' = None
    actor: str = ''
    dry_run: bool = False

    @property
    def request_id(self) -> str:
        return str(getattr(self.request, 'id', '') or '')

    def secret(self, ref: str) -> str:
        return resolve_secret(ref, self.settings)

    def credential(self, key: str, platform: str | None = None) -> str:
        from .credentials import resolve

        return resolve(platform or self.platform, key, self.settings, self.tenant_settings)

    def require_credential(self, key: str, platform: str | None = None) -> str:
        value = self.credential(key, platform)
        if not value:
            from .credentials import env_name

            raise ActionError(f'{platform or self.platform} credentials are not configured ({env_name(platform or self.platform, key)})')
        return value


class ActionType:
    """Base class. Subclasses set the class attributes and implement the coroutines."""

    name: str = ''
    description: str = ''
    params_schema: dict = {'type': 'object', 'properties': {}, 'required': [], 'additionalProperties': False}
    risk: str = 'medium'
    reversible: bool = False
    platforms: list[str] = []
    platform: str = ''  # credential namespace; defaults to the first platform
    category: str = 'remediation'  # remediation | containment | internal
    sdk: str = ''  # importable module name when an SDK is required (checked by available())

    def __init__(self) -> None:
        if not self.name:
            raise ValueError('ActionType needs a name')
        if self.risk not in RISKS:
            raise ValueError(f'{self.name}: risk must be one of {RISKS}')
        if not self.reversible and RISK_RANK[self.risk] < RISK_RANK['high']:
            raise ValueError(f'{self.name}: irreversible actions must be risk high or critical')
        schema = dict(self.params_schema or {})
        schema.setdefault('type', 'object')
        schema.setdefault('properties', {})
        schema.setdefault('required', [])
        schema['additionalProperties'] = False
        self.params_schema = schema
        if not self.platform:
            self.platform = self.platforms[0] if self.platforms else ''

    # -- what the broker calls

    def validate(self, params: dict) -> list[str]:
        if not isinstance(params, dict):
            return ['params must be an object']
        return schema_module.validate(self.params_schema, params)

    def normalize(self, params: dict) -> dict:
        return schema_module.apply_defaults(self.params_schema, params)

    def available(self, settings: Settings, tenant_settings: dict | None = None) -> bool:
        """True when the executor could run: SDK importable (when needed) and credentials present."""
        if self.sdk:
            import importlib.util

            if importlib.util.find_spec(self.sdk.split('.')[0]) is None:
                return False
        if not self.platform or self.platform == 'sentinel':
            return True
        from .credentials import configured

        return configured(self.platform, settings, tenant_settings or {})

    async def dry_run(self, params: dict, ctx: ExecContext) -> DryRunResult:  # pragma: no cover - interface
        raise NotImplementedError

    async def execute(self, params: dict, ctx: ExecContext) -> ExecResult:  # pragma: no cover - interface
        raise NotImplementedError

    async def rollback(self, payload: dict, ctx: ExecContext) -> ExecResult:
        if not self.reversible:
            return ExecResult(ok=False, summary=f'{self.name} is not reversible')
        raise NotImplementedError

    def as_dict(self, settings: Settings | None = None, tenant_settings: dict | None = None) -> dict:
        data = {'name': self.name, 'description': self.description, 'params_schema': self.params_schema, 'risk': self.risk,
                'reversible': self.reversible, 'platforms': list(self.platforms), 'category': self.category}
        if settings is not None:
            try:
                data['available'] = bool(self.available(settings, tenant_settings))
            except Exception:  # availability must never break the catalog listing
                data['available'] = False
        return data


# ---------------------------------------------------------------- registry

_REGISTRY: dict[str, ActionType] = {}


def register(action):
    """Register an ActionType instance or class. Usable as a class decorator: the class is
    instantiated once, stored, and the class itself is returned so it can still be subclassed."""
    instance = action() if isinstance(action, type) else action
    if instance.name in _REGISTRY and type(_REGISTRY[instance.name]) is not type(instance):
        log.warning('action type %s replaced', instance.name)
    _REGISTRY[instance.name] = instance
    return action


def unregister(name: str) -> None:
    _REGISTRY.pop(name, None)


def get(name: str) -> ActionType | None:
    return _REGISTRY.get(name)


def all() -> list[ActionType]:  # noqa: A001 - the name is part of the documented interface
    return sorted(_REGISTRY.values(), key=lambda a: a.name)


def names() -> list[str]:
    return sorted(_REGISTRY)


def entities(count: int, kind: str, ids: list[str] | None = None, **extra: Any) -> dict:
    """Blast-radius helper used by executors."""
    data: dict[str, Any] = {'entities': int(count), 'kind': kind, 'ids': [str(i) for i in (ids or [])][:50]}
    data.update(extra)
    return data
