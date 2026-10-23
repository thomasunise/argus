"""Durable job queue with leases, retries, cancellation and heartbeat.

Two backends: in-memory (asyncio, single process) and Redis (multi-process workers via
`python -m app.worker`). Handlers are registered by kind and must be idempotent.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from .config import Settings

log = logging.getLogger('sentinel.queue')

Handler = Callable[['Job', 'JobContext'], Awaitable[Any]]


@dataclass
class Job:
    id: str
    kind: str
    payload: dict
    tenant_id: str
    status: str = 'queued'  # queued running completed failed cancelled
    attempts: int = 0
    max_attempts: int = 3
    lease_seconds: int = 600
    priority: int = 5  # 0 high .. 9 low
    idempotency_key: str | None = None
    error: str = ''
    result: Any = None
    created_at: float = field(default_factory=time.time)
    not_before: float = 0.0
    started_at: float | None = None
    finished_at: float | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data['result'] = None if self.result is None else json.loads(json.dumps(self.result, default=str))
        return data


class JobContext:
    def __init__(self, queue: 'JobQueue', job: Job):
        self.queue = queue
        self.job = job
        self.settings: Settings = queue.settings
        self.db_factory = queue.db_factory
        self.app = queue.app
        self._cancelled = False

    async def heartbeat(self) -> None:
        await self.queue._extend_lease(self.job)
        if await self.queue._is_cancelled(self.job.id):
            self._cancelled = True
            raise asyncio.CancelledError('job cancelled')

    @property
    def cancelled(self) -> bool:
        return self._cancelled


class JobQueue:
    def __init__(self, settings: Settings, db_factory=None, app=None):
        self.settings = settings
        self.db_factory = db_factory
        self.app = app
        self._handlers: dict[str, Handler] = {}
        self._backend: _MemoryBackend | _RedisBackend = _RedisBackend(settings.redis_url) if settings.redis_url else _MemoryBackend()
        self._workers: list[asyncio.Task] = []
        self._running = False
        # Workers run on a dedicated thread with their own event loop so a handler's blocking
        # database work never stalls the HTTP loop (and vice versa). Every backend call is
        # marshalled onto that loop with _call().
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._stopped = False

    async def _call(self, fn, *args, **kwargs):
        """Run an async backend operation on the worker loop from any thread or loop."""
        if self._loop is None or not self._loop.is_running():
            if self._stopped and isinstance(self._backend, _RedisBackend):
                # Never open a Redis connection on the caller's loop after shutdown: on Windows a stray
                # socket keeps the HTTP loop from closing, and on any OS the job would be lost.
                raise RuntimeError('job queue is stopped')
            return await fn(*args, **kwargs)
        future = asyncio.run_coroutine_threadsafe(fn(*args, **kwargs), self._loop)
        return await asyncio.wrap_future(future)

    # ---- registration
    def handler(self, kind: str):
        def decorator(fn: Handler) -> Handler:
            if kind in self._handlers and self._handlers[kind] is not fn:
                log.warning('queue handler for %s replaced', kind)
            self._handlers[kind] = fn
            return fn
        return decorator

    def register(self, kind: str, fn: Handler) -> None:
        self._handlers[kind] = fn

    @property
    def kinds(self) -> list[str]:
        return sorted(self._handlers)

    # ---- producer API
    async def enqueue(self, kind: str, payload: dict | None = None, *, tenant_id: str, lease_seconds: int = 600,
                      idempotency_key: str | None = None, delay_seconds: float = 0, priority: int = 5,
                      max_attempts: int | None = None) -> Job:
        if kind not in self._handlers:
            raise KeyError(f'no handler registered for job kind {kind!r}')
        if idempotency_key:
            existing = await self._call(self._backend.find_by_idempotency, idempotency_key)
            if existing and existing.status in {'queued', 'running'}:
                return existing
        from ..models import uid

        job = Job(id=uid(), kind=kind, payload=payload or {}, tenant_id=tenant_id, lease_seconds=lease_seconds,
                  priority=max(0, min(9, priority)), idempotency_key=idempotency_key,
                  max_attempts=max_attempts or self.settings.queue_max_attempts,
                  not_before=time.time() + delay_seconds if delay_seconds else 0.0)
        await self._call(self._backend.put, job)
        return job

    async def cancel(self, job_id: str) -> bool:
        return await self._call(self._backend.cancel, job_id)

    async def status(self, job_id: str) -> Job | None:
        return await self._call(self._backend.get, job_id)

    async def list(self, tenant_id: str | None = None, limit: int = 100, status: str | None = None) -> list[Job]:
        return await self._call(self._backend.list, tenant_id, limit, status)

    async def wait(self, job_id: str, timeout: float = 30) -> Job | None:
        """Test helper: poll until the job is terminal."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            job = await self._call(self._backend.get, job_id)
            if job and job.status in {'completed', 'failed', 'cancelled'}:
                return job
            await asyncio.sleep(0.05)
        return await self._call(self._backend.get, job_id)

    # ---- worker lifecycle
    async def start(self, concurrency: int | None = None) -> None:
        if self._running:
            return
        self._running = True
        n = concurrency or self.settings.worker_concurrency
        ready = threading.Event()
        failure: list[BaseException] = []

        def thread_main() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop

            async def bootstrap():
                try:
                    await self._backend.connect()
                    self._workers = [asyncio.create_task(self._worker_loop(i), name=f'sentinel-worker-{i}') for i in range(n)]
                    self._workers.append(asyncio.create_task(self._reaper_loop(), name='sentinel-reaper'))
                except BaseException as exc:  # surfaced to start()
                    failure.append(exc)
                finally:
                    ready.set()

            loop.create_task(bootstrap())
            try:
                loop.run_forever()
            finally:
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.close()

        self._thread = threading.Thread(target=thread_main, name='sentinel-queue', daemon=True)
        self._thread.start()
        await asyncio.to_thread(ready.wait, 30)
        if failure:
            self._running = False
            raise failure[0]

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self._stopped = True
        loop, thread = self._loop, self._thread

        async def shutdown():
            for task in self._workers:
                task.cancel()
            for task in self._workers:
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
            self._workers = []
            await self._backend.close()

        if loop is not None and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(shutdown(), loop)
            await asyncio.to_thread(future.result, 30)
            loop.call_soon_threadsafe(loop.stop)
        if thread is not None:
            await asyncio.to_thread(thread.join, 30)
        self._loop, self._thread = None, None

    async def drain(self, timeout: float = 30) -> None:
        """Test helper: wait until no queued or running jobs remain."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not await self._call(self._backend.has_pending):
                return
            await asyncio.sleep(0.05)

    async def _worker_loop(self, index: int) -> None:
        while self._running:
            try:
                job = await self._backend.claim(timeout=1.0)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception('worker %s claim failed', index)
                await asyncio.sleep(1)
                continue
            if job is None:
                continue
            await self._run_job(job)

    async def _run_job(self, job: Job) -> None:
        handler = self._handlers.get(job.kind)
        job.status, job.attempts, job.started_at = 'running', job.attempts + 1, time.time()
        await self._backend.update(job)
        ctx = JobContext(self, job)
        if handler is None:
            job.status, job.error, job.finished_at = 'failed', f'no handler for {job.kind}', time.time()
            await self._backend.update(job)
            return
        try:
            job.result = await asyncio.wait_for(handler(job, ctx), timeout=job.lease_seconds)
            job.status, job.finished_at = 'completed', time.time()
        except asyncio.CancelledError:
            if not self._running:
                job.status, job.error = 'queued', 'worker shutdown'  # will be re-claimed by the reaper
                await self._backend.requeue(job)
                raise
            job.status, job.error, job.finished_at = 'cancelled', 'cancelled', time.time()
        except asyncio.TimeoutError:
            job.error = f'lease of {job.lease_seconds}s exceeded'
            await self._fail_or_retry(job)
            return
        except Exception as exc:
            job.error = f'{type(exc).__name__}: {exc}'[:1000]
            log.exception('job %s (%s) failed', job.id, job.kind)
            await self._fail_or_retry(job)
            return
        await self._backend.update(job)

    async def _fail_or_retry(self, job: Job) -> None:
        if job.attempts < job.max_attempts:
            backoff = min(300, (2 ** job.attempts) + random.uniform(0, 1))
            job.status, job.not_before = 'queued', time.time() + backoff
            await self._backend.requeue(job)
        else:
            job.status, job.finished_at = 'failed', time.time()
            await self._backend.update(job)

    async def _reaper_loop(self) -> None:
        while self._running:
            try:
                await self._backend.reap(self.settings)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception('reaper failed')
            await asyncio.sleep(5)

    async def _extend_lease(self, job: Job) -> None:
        await self._call(self._backend.extend, job)

    async def _is_cancelled(self, job_id: str) -> bool:
        job = await self._call(self._backend.get, job_id)
        return bool(job and job.status == 'cancelled')


# ---------------------------------------------------------------- backends


class _MemoryBackend:
    def __init__(self):
        self.jobs: dict[str, Job] = {}
        self._queue: asyncio.PriorityQueue | None = None
        self._seq = 0

    async def connect(self):
        self._queue = asyncio.PriorityQueue()
        for job in self.jobs.values():
            if job.status == 'queued':
                await self._push(job)

    async def close(self):
        pass

    async def _push(self, job: Job):
        if self._queue is None:
            self._queue = asyncio.PriorityQueue()
        self._seq += 1
        await self._queue.put((job.priority, job.not_before, self._seq, job.id))

    async def put(self, job: Job):
        self.jobs[job.id] = job
        await self._push(job)

    async def update(self, job: Job):
        self.jobs[job.id] = job

    async def requeue(self, job: Job):
        self.jobs[job.id] = job
        await self._push(job)

    async def get(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    async def find_by_idempotency(self, key: str) -> Job | None:
        return next((j for j in self.jobs.values() if j.idempotency_key == key), None)

    async def cancel(self, job_id: str) -> bool:
        job = self.jobs.get(job_id)
        if not job or job.status in {'completed', 'failed'}:
            return False
        job.status, job.finished_at = 'cancelled', time.time()
        return True

    async def claim(self, timeout: float) -> Job | None:
        assert self._queue is not None
        try:
            priority, not_before, seq, job_id = await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        job = self.jobs.get(job_id)
        if job is None or job.status != 'queued':
            return None
        if job.not_before and job.not_before > time.time():
            await asyncio.sleep(min(1.0, job.not_before - time.time()))
            await self._push(job)
            return None
        return job

    async def extend(self, job: Job):
        job.started_at = time.time()

    async def reap(self, settings: Settings):
        # Memory jobs run inside this process; nothing can be orphaned across processes.
        cutoff = time.time() - 86400
        for job_id in [j.id for j in self.jobs.values() if j.finished_at and j.finished_at < cutoff]:
            self.jobs.pop(job_id, None)

    async def list(self, tenant_id, limit, status):
        items = [j for j in self.jobs.values() if (tenant_id is None or j.tenant_id == tenant_id) and (status is None or j.status == status)]
        items.sort(key=lambda j: j.created_at, reverse=True)
        return items[:limit]

    async def has_pending(self) -> bool:
        return any(j.status in {'queued', 'running'} for j in self.jobs.values())


class _RedisBackend:
    """Redis layout: hash sentinel:job:{id}; lists sentinel:q:{priority}; set sentinel:running;
    key sentinel:lease:{id} (EX); hash sentinel:idem."""

    def __init__(self, url: str):
        self.url = url
        self.redis = None

    async def connect(self):
        import redis.asyncio as redis  # lazy

        self.redis = redis.from_url(self.url, decode_responses=True)
        await self.redis.ping()

    async def close(self):
        if self.redis:
            try:
                await self.redis.aclose()
            finally:
                self.redis = None

    def _key(self, job_id: str) -> str:
        return f'sentinel:job:{job_id}'

    async def _save(self, job: Job):
        await self.redis.set(self._key(job.id), json.dumps(job.to_dict(), default=str), ex=7 * 86400)

    async def put(self, job: Job):
        if self.redis is None:
            await self.connect()
        await self._save(job)
        if job.idempotency_key:
            await self.redis.hset('sentinel:idem', job.idempotency_key, job.id)
        if job.not_before:
            await self.redis.zadd('sentinel:delayed', {job.id: job.not_before})
        else:
            await self.redis.rpush(f'sentinel:q:{job.priority}', job.id)

    async def update(self, job: Job):
        await self._save(job)
        if job.status in {'completed', 'failed', 'cancelled'}:
            await self.redis.srem('sentinel:running', job.id)
            await self.redis.delete(f'sentinel:lease:{job.id}')

    async def requeue(self, job: Job):
        await self._save(job)
        await self.redis.srem('sentinel:running', job.id)
        await self.redis.delete(f'sentinel:lease:{job.id}')
        if job.not_before and job.not_before > time.time():
            await self.redis.zadd('sentinel:delayed', {job.id: job.not_before})
        else:
            await self.redis.rpush(f'sentinel:q:{job.priority}', job.id)

    async def get(self, job_id: str) -> Job | None:
        if self.redis is None:
            await self.connect()
        raw = await self.redis.get(self._key(job_id))
        return Job(**json.loads(raw)) if raw else None

    async def find_by_idempotency(self, key: str) -> Job | None:
        if self.redis is None:
            await self.connect()
        job_id = await self.redis.hget('sentinel:idem', key)
        return await self.get(job_id) if job_id else None

    async def cancel(self, job_id: str) -> bool:
        job = await self.get(job_id)
        if not job or job.status in {'completed', 'failed'}:
            return False
        job.status, job.finished_at = 'cancelled', time.time()
        await self.update(job)
        return True

    async def claim(self, timeout: float) -> Job | None:
        keys = [f'sentinel:q:{p}' for p in range(10)]
        item = await self.redis.blpop(keys, timeout=max(1, int(timeout)))
        if not item:
            return None
        job = await self.get(item[1])
        if job is None or job.status != 'queued':
            return None
        await self.redis.sadd('sentinel:running', job.id)
        await self.redis.set(f'sentinel:lease:{job.id}', '1', ex=job.lease_seconds)
        return job

    async def extend(self, job: Job):
        await self.redis.expire(f'sentinel:lease:{job.id}', job.lease_seconds)

    async def reap(self, settings: Settings):
        now = time.time()
        # Promote delayed jobs whose time has come.
        ready = await self.redis.zrangebyscore('sentinel:delayed', 0, now)
        for job_id in ready:
            await self.redis.zrem('sentinel:delayed', job_id)
            job = await self.get(job_id)
            if job and job.status == 'queued':
                await self.redis.rpush(f'sentinel:q:{job.priority}', job_id)
        # Requeue running jobs whose lease expired (worker died).
        for job_id in await self.redis.smembers('sentinel:running'):
            if await self.redis.exists(f'sentinel:lease:{job_id}'):
                continue
            job = await self.get(job_id)
            if not job:
                await self.redis.srem('sentinel:running', job_id)
                continue
            if job.status == 'running':
                job.error = 'lease expired; worker lost'
                if job.attempts < job.max_attempts:
                    job.status = 'queued'
                    await self.requeue(job)
                else:
                    job.status, job.finished_at = 'failed', now
                    await self.update(job)

    async def list(self, tenant_id, limit, status):
        jobs: list[Job] = []
        async for key in self.redis.scan_iter('sentinel:job:*', count=500):
            raw = await self.redis.get(key)
            if not raw:
                continue
            job = Job(**json.loads(raw))
            if (tenant_id is None or job.tenant_id == tenant_id) and (status is None or job.status == status):
                jobs.append(job)
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]

    async def has_pending(self) -> bool:
        if await self.redis.scard('sentinel:running'):
            return True
        for p in range(10):
            if await self.redis.llen(f'sentinel:q:{p}'):
                return True
        return bool(await self.redis.zcard('sentinel:delayed'))


def iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None
