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
from .core import crypto, events
from .core.bootstrap import bootstrap
from .core.config import Settings, assert_safe_config, get_settings
from .core.db import (
    CommitBeforeResponseMiddleware,
    assert_restricted_runtime_role,
    init_db,
    make_engine,
    make_session_factory,
    pool_stats,
    session_scope,
)
from .core.errors import install_error_handlers
from .core.login_limiter import LoginFailureLimiter
from .core.queue import JobQueue
from .core.sessions import ServerSessionStore
from .core.telemetry import (
    BodySizeLimitMiddleware,
    RequestContextMiddleware,
    configure_logging,
    configure_tracing,
    install_metrics_endpoint,
)

log = logging.getLogger('argus')
STATIC_DIR = Path(__file__).parent / 'static'
VERSION = '1.0.0'

# Packages that may expose setup(app). Order matters: tools before specialists, catalogs before brokers.
PACKAGES = ['app.graph', 'app.detections', 'app.collectors', 'app.integrations', 'app.testing', 'app.pentest', 'app.discovery', 'app.actions', 'app.exploit', 'app.agents', 'app.reports', 'app.intel', 'app.simulator', 'app.ai', 'app.ops']
OFFENSIVE_PACKAGES = {'app.pentest', 'app.discovery', 'app.exploit'}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    assert_safe_config(settings)
    configure_logging(settings)
    audit_module.configure(settings)
    crypto.configure(
        settings.data_encryption_keys,
        settings.data_encryption_key,
        refuse_plaintext=settings.is_production,
        kms_provider=settings.kms_provider,
        kms_key_id=settings.kms_key_id,
        vault_addr=settings.vault_addr,
        vault_token=settings.vault_token,
    )

    engine = make_engine(settings)
    if settings.is_production:
        assert_restricted_runtime_role(engine)  # also enforced by standalone workers (which do not run lifespan)
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
            events.unsubscribe_app(app)
            engine.dispose()

    app = FastAPI(
        title=settings.app_name,
        version=VERSION,
        lifespan=lifespan,
        docs_url=None if settings.is_production else '/api/docs',
        openapi_url=None if settings.is_production else '/api/openapi.json',
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.db_factory = factory
    app.state.login_limiter = LoginFailureLimiter(redis_url=settings.redis_url)
    app.state.rate_limiter = RateLimiter(redis_url=settings.redis_url)
    app.state.session_store = ServerSessionStore(redis_url=settings.redis_url, ttl_seconds=settings.session_absolute_max_age)
    app.state.queue = JobQueue(settings, db_factory=factory, app=app)
    app.state.startup_hooks = []
    app.state.shutdown_hooks = []
    app.state.background_tasks = set()
    app.state.event_subscriptions = []

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

    # Event-bus callbacks registered by packages must be removed at app shutdown.
    # Otherwise each TestClient lifetime leaves subscribers retaining old engines.
    with events.registration_scope(app):
        for package in PACKAGES:
            if settings.core_only_build and package in OFFENSIVE_PACKAGES:
                continue
            try:
                module = importlib.import_module(package)
            except ModuleNotFoundError as exc:
                if exc.name == package or (exc.name and exc.name.startswith(package + '.')):
                    continue
                raise
            setup = getattr(module, 'setup', None)
            if setup:
                setup(app)

    for router in discover_routers(core_only=settings.core_only_build):
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
        if app.state.settings.is_production:
            return {'status': 'healthy'}
        return {'status': 'healthy', 'version': VERSION, 'env': settings.app_env, 'pool': pool_stats(engine)}

    @app.get('/ready', include_in_schema=False)
    def ready():
        checks: dict[str, str] = {}
        try:
            with engine.connect() as conn:
                conn.exec_driver_sql('SELECT 1')
            checks['database'] = 'ok'
        except Exception as exc:
            raise HTTPException(503, detail=f'database unavailable: {type(exc).__name__}') from exc
        if settings.redis_url:
            try:
                import redis as _redis

                _redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2).ping()
                checks['redis'] = 'ok'
            except Exception as exc:
                raise HTTPException(503, detail=f'redis unavailable: {type(exc).__name__}') from exc
        return {'status': 'ready', 'queue': 'redis' if settings.redis_url else 'memory', 'provider': settings.ai_provider,
                'encryption': crypto.configured(), 'checks': checks, 'pool': pool_stats(engine)}

    return app


def spawn(app: FastAPI, coro) -> asyncio.Task:
    """Track a background task so shutdown cancels it."""
    task = asyncio.create_task(coro)
    app.state.background_tasks.add(task)
    task.add_done_callback(app.state.background_tasks.discard)
    return task


app = create_app() if __name__ != '__main__' and __import__('os').getenv('ARGUS_LAZY_APP') != '1' else None
