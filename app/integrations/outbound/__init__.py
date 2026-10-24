"""Outbound channels. Each channel implements `async send(event, config, secrets) -> DeliveryResult`.

    from app.integrations.outbound import registry, OutboundEvent, DeliveryResult, Channel
    result = await registry.get('slack').send(event, config={'channel': '#sec'}, secrets={'webhook_url': '...'})
"""
from __future__ import annotations

import asyncio
import importlib
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable

import httpx

from ...core.config import get_settings
from ...core.findings import SEVERITIES

log = logging.getLogger('argus.integrations.outbound')

BUILTIN = ['webhook', 'slack', 'jira', 'servicenow', 'pagerduty', 'email']
DEFAULT_TIMEOUT = 15.0
RESPONSE_EXCERPT = 300


@dataclass
class OutboundEvent:
    topic: str
    tenant_id: str
    subject_kind: str = ''          # finding detection action test_run agent_run test
    subject_id: str = ''
    title: str = ''
    severity: str = 'low'
    status: str = ''
    summary: str = ''
    payload: dict = field(default_factory=dict)
    occurred_at: datetime | None = None
    url: str = ''
    delivery_id: str = ''
    tenant_name: str = ''

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data['occurred_at'] = self.occurred_at.isoformat() if self.occurred_at else None
        return data

    @property
    def severity_rank(self) -> int:
        return SEVERITIES.index(self.severity) if self.severity in SEVERITIES else len(SEVERITIES)

    @property
    def is_resolution(self) -> bool:
        return self.topic.endswith(('.resolved', '.closed', '.completed', '.rolled_back')) or self.status in {'resolved', 'false_positive', 'accepted', 'closed'}


@dataclass
class DeliveryResult:
    ok: bool
    status_code: int | None = None
    error: str = ''
    external_ref: str = ''
    retryable: bool = False
    skipped: bool = False
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class Channel:
    kind: str = ''
    description: str = ''
    config_schema: dict[str, Any] = {'type': 'object', 'properties': {}, 'additionalProperties': False}
    secret_fields: list[str] = []
    topics: list[str] = ['*']        # topic prefixes the channel can handle; others are skipped
    default_topics: list[str] = ['finding.created', 'detection.created']

    async def send(self, event: OutboundEvent, config: dict[str, Any], secrets: dict[str, str]) -> DeliveryResult:  # pragma: no cover - interface
        raise NotImplementedError

    def handles(self, topic: str) -> bool:
        return any(t == '*' or topic == t or (t.endswith('*') and topic.startswith(t[:-1])) for t in self.topics)

    def describe(self) -> dict[str, Any]:
        return {'kind': self.kind, 'description': self.description, 'config_schema': self.config_schema, 'secret_fields': list(self.secret_fields),
                'topics': list(self.topics), 'default_topics': list(self.default_topics)}


class Registry:
    def __init__(self) -> None:
        self._channels: dict[str, Channel] = {}
        self._loaded = False

    def register(self, channel: Channel) -> Channel:
        self._channels[channel.kind] = channel
        return channel

    def load_builtin(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        for module in BUILTIN:
            importlib.import_module(f'{__name__}.{module}')

    def has(self, kind: str) -> bool:
        self.load_builtin()
        return kind in self._channels

    def get(self, kind: str) -> Channel:
        self.load_builtin()
        return self._channels[kind]

    def all(self) -> list[Channel]:
        self.load_builtin()
        return [self._channels[k] for k in sorted(self._channels)]

    def kinds(self) -> list[str]:
        self.load_builtin()
        return sorted(self._channels)


registry = Registry()


# ---------------------------------------------------------------- shared HTTP helpers


def excerpt(response: httpx.Response) -> str:
    try:
        return response.text[:RESPONSE_EXCERPT]
    except Exception:  # pragma: no cover - defensive
        return ''


def is_transient(status_code: int | None) -> bool:
    return status_code is None or status_code == 429 or status_code >= 500


async def request_with_retry(fn: Callable[[httpx.AsyncClient], Awaitable[httpx.Response]], *, attempts: int = 1, backoff: float = 0.5,
                             timeout: float = DEFAULT_TIMEOUT) -> tuple[httpx.Response | None, str]:
    """Run `fn(client)` up to `attempts` times, backing off exponentially on transport errors, 429 and 5xx.
    Returns (last response or None, last error text)."""
    attempts = max(1, int(attempts))
    last_error = ''
    response: httpx.Response | None = None
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        for index in range(attempts):
            try:
                response = await fn(client)
                last_error = ''
                if not is_transient(response.status_code):
                    return response, ''
                last_error = f'HTTP {response.status_code}: {excerpt(response)}'
            except httpx.HTTPError as exc:
                response = None
                last_error = f'{type(exc).__name__}: {str(exc)[:200]}'
            if index < attempts - 1:
                await asyncio.sleep(backoff * (2 ** index))
    return response, last_error


def result_from_response(response: httpx.Response | None, error: str, *, ok_codes: tuple[int, ...] = (200, 201, 202, 204),
                         external_ref: str = '') -> DeliveryResult:
    if response is None:
        return DeliveryResult(ok=False, error=error or 'no response', retryable=True)
    ok = response.status_code in ok_codes
    return DeliveryResult(ok=ok, status_code=response.status_code, error='' if ok else (error or f'HTTP {response.status_code}: {excerpt(response)}'),
                          retryable=not ok and is_transient(response.status_code), external_ref=external_ref,
                          detail={'response': excerpt(response)} if not ok else {})


def egress_error(url: Any, *, allow_http: bool = False) -> str:
    """Send-time guard for a destination URL: '' when it may be contacted, else the reason. Never raises."""
    from ..egress import egress_ok

    try:
        settings = get_settings()
    except Exception:  # settings unavailable outside the app (pure unit tests): fall back to the syntactic default rules
        from ...core.config import Settings

        settings = Settings(session_secret='x' * 32, admin_password='x' * 14)
    return egress_ok(url, settings, allow_http=allow_http or bool(settings.allow_private_targets))


def severity_label(severity: str) -> str:
    return {'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low', 'informational': 'Info'}.get(severity, severity.title())


__all__ = ['registry', 'Registry', 'Channel', 'OutboundEvent', 'DeliveryResult', 'request_with_retry', 'result_from_response', 'severity_label',
           'excerpt', 'is_transient', 'egress_error', 'BUILTIN']
