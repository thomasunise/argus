"""Standalone queue worker: `python -m app.worker`. Requires REDIS_URL. Runs the same
handlers as the API process so any job kind can execute here."""
from __future__ import annotations

import asyncio
import logging
import os
import signal

os.environ.setdefault('SENTINEL_LAZY_APP', '1')

from .core.config import get_settings  # noqa: E402
from .main import create_app  # noqa: E402

log = logging.getLogger('sentinel.worker')


async def main() -> None:
    settings = get_settings()
    if not settings.redis_url:
        raise SystemExit('REDIS_URL is required for a standalone worker')
    settings = settings.model_copy(update={'workers_inprocess': False})
    app = create_app(settings)
    queue = app.state.queue
    await queue.start(concurrency=settings.worker_concurrency)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # Windows
            signal.signal(sig, lambda *_: stop.set())
    log.info('worker started with %s handlers: %s', len(queue.kinds), ', '.join(queue.kinds))
    await stop.wait()
    await queue.stop()


if __name__ == '__main__':
    asyncio.run(main())
