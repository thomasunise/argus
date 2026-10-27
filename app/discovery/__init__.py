"""Discovery package. setup(app) registers the 'discovery.run' queue handler."""
from __future__ import annotations

from . import service  # noqa: F401


def setup(app) -> None:
    queue = app.state.queue

    @queue.handler('discovery.run')
    async def _run(job, ctx):
        return await service.execute_run(ctx.app, job.payload['run_id'])
