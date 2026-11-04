"""In-process event bus. Packages subscribe to topics such as 'finding.created',
'detection.created', 'action.executed'; outbound integrations fan these out."""
from __future__ import annotations

import asyncio
import logging
from contextlib import contextmanager
from contextvars import ContextVar
from collections import defaultdict
from typing import Any, Awaitable, Callable

log = logging.getLogger('argus.events')

Subscriber = Callable[[str, dict[str, Any]], Awaitable[None]]

_subscribers: dict[str, list[Subscriber]] = defaultdict(list)
# App setup happens synchronously. Attribute its subscriptions to that specific
# application so shutdown cannot leave closures holding an old database engine.
_registration_owner: ContextVar[Any | None] = ContextVar('argus_event_registration_owner', default=None)


@contextmanager
def registration_scope(app):
    token = _registration_owner.set(app)
    try:
        yield
    finally:
        _registration_owner.reset(token)


def subscribe(topic: str, fn: Subscriber) -> None:
    """Register an event handler, retaining an app-scoped removal handle."""
    _subscribers[topic].append(fn)
    owner = _registration_owner.get()
    if owner is not None:
        owner.state.event_subscriptions.append((topic, fn))


def unsubscribe_app(app) -> None:
    """Remove only this application's callbacks; other running apps are unaffected."""
    subscriptions = getattr(app.state, 'event_subscriptions', ())
    for topic, callback in subscriptions:
        remaining = [fn for fn in _subscribers.get(topic, ()) if fn is not callback]
        if remaining:
            _subscribers[topic] = remaining
        else:
            _subscribers.pop(topic, None)
    app.state.event_subscriptions = []


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
