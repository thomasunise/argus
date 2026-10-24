"""In-process event bus. Packages subscribe to topics such as 'finding.created',
'detection.created', 'action.executed'; outbound integrations fan these out."""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any, Awaitable, Callable

log = logging.getLogger('argus.events')

Subscriber = Callable[[str, dict[str, Any]], Awaitable[None]]

_subscribers: dict[str, list[Subscriber]] = defaultdict(list)


def subscribe(topic: str, fn: Subscriber) -> None:
    """topic may end with '*' to match a prefix, e.g. 'finding.*'."""
    _subscribers[topic].append(fn)


def clear() -> None:
    _subscribers.clear()


async def publish(topic: str, payload: dict[str, Any]) -> None:
    targets: list[Subscriber] = []
    for key, fns in _subscribers.items():
        if key == topic or (key.endswith('*') and topic.startswith(key[:-1])):
            targets.extend(fns)
    if not targets:
        return
    results = await asyncio.gather(*(fn(topic, payload) for fn in targets), return_exceptions=True)
    for result in results:
        if isinstance(result, Exception):
            log.exception('subscriber failed for %s', topic, exc_info=result)


def publish_soon(topic: str, payload: dict[str, Any]) -> None:
    """Fire and forget from sync code when an event loop is running."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(publish(topic, payload))
