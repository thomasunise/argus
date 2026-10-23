"""Helpers shared by executors: a bounded httpx call that turns failures into ActionError
with redacted detail, and a thread hop for blocking SDK clients."""
from __future__ import annotations

import asyncio
from typing import Any, Callable

import httpx

from ...core.security import redact
from ..catalog import ActionError

DEFAULT_TIMEOUT = 30.0
BODY_SNIPPET = 300


async def http(method: str, url: str, *, headers: dict | None = None, json: Any = None, data: Any = None, params: dict | None = None,
               timeout: float = DEFAULT_TIMEOUT, allow: tuple[int, ...] = (), label: str = '') -> httpx.Response:
    """One HTTP call. 2xx returns; any status in `allow` returns; everything else raises ActionError.
    Error messages never include request headers and the body snippet is redacted."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.request(method.upper(), url, headers=headers, json=json, data=data, params=params)
    except httpx.HTTPError as exc:
        raise ActionError(f'{label or "api"} {method.upper()} {_path(url)} failed: {type(exc).__name__}') from exc
    if 200 <= response.status_code < 300 or response.status_code in allow:
        return response
    snippet = redact(response.text[:BODY_SNIPPET]) if response.text else ''
    raise ActionError(f'{label or "api"} {method.upper()} {_path(url)} returned {response.status_code}: {snippet}',
                      details={'status': response.status_code})


def body(response: httpx.Response) -> Any:
    if not response.content:
        return {}
    try:
        return response.json()
    except ValueError:
        return {'raw': redact(response.text[:BODY_SNIPPET])}


def _path(url: str) -> str:
    try:
        parsed = httpx.URL(url)
        return f'{parsed.host}{parsed.path}'
    except Exception:  # noqa: BLE001 - only used for messages
        return url.split('?')[0]


async def run_blocking(fn: Callable, *args: Any, **kwargs: Any) -> Any:
    """Run a blocking SDK call off the event loop and normalize its errors."""
    try:
        return await asyncio.to_thread(fn, *args, **kwargs)
    except ActionError:
        raise
    except Exception as exc:  # SDK-specific error classes are not importable without the SDK
        raise ActionError(_describe(exc)) from exc


def error_code(exc: BaseException) -> str:
    """Best-effort error code from boto3 / kubernetes / google exceptions without importing them."""
    response = getattr(exc, 'response', None)
    if isinstance(response, dict):
        return str((response.get('Error') or {}).get('Code', ''))
    status = getattr(exc, 'status', None)
    if status is not None:
        return str(status)
    return type(exc).__name__


def _describe(exc: BaseException) -> str:
    code = error_code(exc)
    text = redact(str(exc))[:300]
    return f'{code}: {text}' if code and code not in text else text


def is_not_found(exc: BaseException) -> bool:
    code = error_code(exc)
    return code in {'404', 'NoSuchEntity', 'NoSuchBucket', 'NotFound', 'InvalidInstanceID.NotFound', 'InvalidGroup.NotFound',
                    'InvalidPermission.NotFound', 'NoSuchPublicAccessBlockConfiguration', 'ResourceNotFoundException'}


def one_of(params: dict, *keys: str) -> str:
    """Exactly one of the keys must be present and truthy; returns it."""
    present = [k for k in keys if params.get(k)]
    if len(present) != 1:
        raise ActionError(f'exactly one of {", ".join(keys)} is required')
    return present[0]
