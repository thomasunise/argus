"""Argus application factory."""
from __future__ import annotations

import asyncio
import importlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from starlette.middleware.sessions import SessionMiddleware

from .api import discover_routers
from .api.deps import RateLimiter
from .core import audit as audit_module
from .core import crypto
from .core.bootstrap import bootstrap
from .core.config import Settings, assert_safe_config, get_settings
from .core.db import CommitBeforeResponseMiddleware, init_db, make_engine, make_session_factory, session_scope
from .core.errors import install_error_handlers
from .core.queue import JobQueue
from .core.telemetry import BodySizeLimitMiddleware, RequestContextMiddleware, configure_logging, configure_tracing, install_metrics_endpoint

log = logging.getLogger('argus')
STATIC_DIR = Path(__file__).parent / 'static'
VERSION = '1.0.0'

# Packages that may expose setup(app). Order matters: tools before specialists, catalogs before brokers.
PACKAGES = ['app.graph', 'app.detections', 'app.collectors', 'app.integrations', 'app.testing', 'app.actions', 'app.agents', 'app.reports']


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    assert_safe_config(settings)
    configure_logging(settings)
    audit_module.configure(settings)
    crypto.configure(settings.data_encryption_keys, settings.data_encryption_key)

    engine = make_engine(settings)
    factory = make_session_factory(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db(engine, settings)
        with session_scope(factory) as db:
            tenant = bootstrap(db, settings)
            app.state.default_tenant_id = tenant.id
        if settings.workers_inprocess:
            await app.state.queue.start()
        for hook in app.state.startup_hooks:
            await hook(app)
        log.info('Argus %s started (env=%s, provider=%s, queue=%s)', VERSION, settings.app_env, settings.ai_provider,
                 'redis' if settings.redis_url else 'memory')
        from .agents.providers import unpriced_model_warning

        if warning := unpriced_model_warning(settings):
            log.warning(warning)
        try:
            yield
        finally:
            for hook in app.state.shutdown_hooks:
                try:
                    await hook(app)
                except Exception:
                    log.exception('shutdown hook failed')
            for task in list(app.state.background_tasks):
                task.cancel()
            await asyncio.gather(*app.state.background_tasks, return_exceptions=True)
            if settings.workers_inprocess:
                await app.state.queue.stop()
            engine.dispose()

    app = FastAPI(title=settings.app_name, version=VERSION, lifespan=lifespan, docs_url='/api/docs', openapi_url='/api/openapi.json')
    app.state.settings = settings
    app.state.engine = engine
    app.state.db_factory = factory
    app.state.login_attempts = {}
    app.state.rate_limiter = RateLimiter()
    app.state.queue = JobQueue(settings, db_factory=factory, app=app)
    app.state.startup_hooks = []
    app.state.shutdown_hooks = []
    app.state.background_tasks = set()

    app.add_middleware(CommitBeforeResponseMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    app.add_middleware(RequestContextMiddleware, settings=settings)
    app.add_middleware(SessionMiddleware, secret_key=settings.session_secret, session_cookie='argus_session',
                       # lax, not strict: the OIDC callback is a cross-site top-level navigation that must carry the cookie
                       # holding the PKCE verifier. State-changing requests are protected by the X-CSRF-Token header.
                       same_site='lax', https_only=settings.cookie_secure, max_age=settings.session_max_age)
    install_error_handlers(app)
    install_metrics_endpoint(app, settings)
    configure_tracing(app, settings)

    for package in PACKAGES:
        try:
            module = importlib.import_module(package)
        except ModuleNotFoundError as exc:
            if exc.name == package:
                continue
            raise
        setup = getattr(module, 'setup', None)
        if setup:
            setup(app)

    for router in discover_routers():
        app.include_router(router)

    @app.get('/', include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / 'index.html')

    @app.get('/static/{file_path:path}', include_in_schema=False)
    def static(file_path: str):
        root = STATIC_DIR.resolve()
        path = (root / file_path).resolve()
        if root not in path.parents or not path.is_file() or path.suffix not in {'.js', '.css', '.svg', '.png', '.ico', '.woff2', '.map', '.json'}:
            raise HTTPException(404)
        return FileResponse(path)

    @app.get('/health', include_in_schema=False)
    def health():
        return {'status': 'healthy', 'version': VERSION}

    @app.get('/ready', include_in_schema=False)
    def ready():
        try:
            with engine.connect() as conn:
                conn.exec_driver_sql('SELECT 1')
        except Exception as exc:
            raise HTTPException(503, detail=f'database unavailable: {type(exc).__name__}')
        if settings.redis_url:
            try:
                import redis as _redis

                _redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2).ping()
            except Exception as exc:
                raise HTTPException(503, detail=f'redis unavailable: {type(exc).__name__}')
        return {'status': 'ready', 'queue': 'redis' if settings.redis_url else 'memory', 'provider': settings.ai_provider,
                'encryption': crypto.configured()}

    return app


def spawn(app: FastAPI, coro) -> asyncio.Task:
    """Track a background task so shutdown cancels it."""
    task = asyncio.create_task(coro)
    app.state.background_tasks.add(task)
    task.add_done_callback(app.state.background_tasks.discard)
    return task


app = create_app() if __name__ != '__main__' and __import__('os').getenv('ARGUS_LAZY_APP') != '1' else None
