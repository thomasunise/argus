"""Structured logging, Prometheus metrics and optional OpenTelemetry tracing."""
from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Callable

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from .config import Settings

log = logging.getLogger('argus')


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {'ts': self.formatTime(record, '%Y-%m-%dT%H:%M:%S'), 'level': record.levelname, 'logger': record.name,
                   'msg': record.getMessage()}
        for key in ('request_id', 'tenant_id', 'job_id', 'run_id'):
            value = getattr(record, key, None)
            if value:
                payload[key] = value
        if record.exc_info:
            payload['exc'] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(settings: Settings) -> None:
    root = logging.getLogger()
    root.setLevel(settings.log_level.upper())
    for handler in list(root.handlers):
        root.removeHandler(handler)
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter() if settings.log_json else logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
    root.addHandler(handler)
    logging.getLogger('uvicorn.access').setLevel('WARNING')


# ---------------------------------------------------------------- metrics

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

    HTTP_REQUESTS = Counter('argus_http_requests_total', 'HTTP requests', ['method', 'route', 'status'])
    HTTP_LATENCY = Histogram('argus_http_request_seconds', 'HTTP latency', ['method', 'route'])
    JOBS = Counter('argus_jobs_total', 'Queue jobs', ['kind', 'status'])
    AGENT_TOKENS = Counter('argus_agent_tokens_total', 'Agent tokens', ['provider', 'direction'])
    AGENT_RUNS = Counter('argus_agent_runs_total', 'Agent runs', ['spec', 'status'])
    FINDINGS_OPEN = Gauge('argus_findings_open', 'Open findings', ['tenant', 'severity'])
    ACTIONS = Counter('argus_actions_total', 'Broker actions', ['action', 'status'])
    DETECTIONS = Counter('argus_detections_total', 'Detections', ['rule', 'severity'])
    METRICS_AVAILABLE = True
except ImportError:  # pragma: no cover
    METRICS_AVAILABLE = False


class _Noop:
    def labels(self, *a, **k):
        return self

    def inc(self, *a, **k):
        pass

    def observe(self, *a, **k):
        pass

    def set(self, *a, **k):
        pass


if not METRICS_AVAILABLE:  # pragma: no cover
    HTTP_REQUESTS = HTTP_LATENCY = JOBS = AGENT_TOKENS = AGENT_RUNS = FINDINGS_OPEN = ACTIONS = DETECTIONS = _Noop()


class BodySizeLimitMiddleware:
    """Pure ASGI middleware: rejects requests whose declared or streamed body exceeds the limit."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        declared = next((v for k, v in scope.get('headers', []) if k == b'content-length'), None)
        if declared is not None:
            try:
                if int(declared) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                pass
        seen = 0
        rejected = False

        async def limited_receive():
            nonlocal seen, rejected
            message = await receive()
            if message['type'] == 'http.request':
                seen += len(message.get('body', b''))
                if seen > self.max_bytes and not rejected:
                    rejected = True
                    raise _BodyTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await self._reject(send)

    @staticmethod
    async def _reject(send):
        body = b'{"detail":"Request body too large","code":"payload_too_large"}'
        await send({'type': 'http.response.start', 'status': 413,
                    'headers': [(b'content-type', b'application/json'), (b'content-length', str(len(body)).encode())]})
        await send({'type': 'http.response.body', 'body': body})


class _BodyTooLarge(Exception):
    pass


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Adds a request id, timing, security headers and metrics to each request."""

    def __init__(self, app, settings: Settings):
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get(self.settings.request_id_header) or uuid.uuid4().hex
        request.state.request_id = request_id
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            HTTP_REQUESTS.labels(request.method, _route(request), '500').inc()
            raise
        elapsed = time.perf_counter() - start
        route = _route(request)
        HTTP_REQUESTS.labels(request.method, route, str(response.status_code)).inc()
        HTTP_LATENCY.labels(request.method, route).observe(elapsed)
        response.headers[self.settings.request_id_header] = request_id
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'no-referrer')
        response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        response.headers.setdefault('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        if self.settings.cookie_secure:
            response.headers.setdefault('Strict-Transport-Security', 'max-age=63072000; includeSubDomains')
        return response


def _route(request: Request) -> str:
    route = request.scope.get('route')
    return getattr(route, 'path', request.url.path) if route else request.url.path


def install_metrics_endpoint(app: FastAPI, settings: Settings) -> None:
    if not (settings.metrics_enabled and METRICS_AVAILABLE):
        return

    @app.get('/metrics', include_in_schema=False)
    def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def configure_tracing(app: FastAPI, settings: Settings) -> None:
    if not settings.otel_exporter_otlp_endpoint:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:  # pragma: no cover
        log.warning('OTEL endpoint configured but opentelemetry packages are not installed')
        return
    provider = TracerProvider(resource=Resource.create({'service.name': settings.otel_service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint)))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)
