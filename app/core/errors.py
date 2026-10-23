from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


class SentinelError(Exception):
    status = 400
    code = 'error'

    def __init__(self, message: str = '', *, code: str | None = None, status: int | None = None):
        super().__init__(message or self.__class__.__name__)
        self.message = message or self.__class__.__name__
        if code:
            self.code = code
        if status:
            self.status = status


class NotFound(SentinelError):
    status = 404
    code = 'not_found'


class Conflict(SentinelError):
    status = 409
    code = 'conflict'


class PolicyDenied(SentinelError):
    status = 403
    code = 'policy_denied'


class ScopeDenied(PolicyDenied):
    code = 'scope_denied'


class Forbidden(SentinelError):
    status = 403
    code = 'forbidden'


class Unauthorized(SentinelError):
    status = 401
    code = 'unauthorized'


class RateLimited(SentinelError):
    status = 429
    code = 'rate_limited'


class Unavailable(SentinelError):
    status = 503
    code = 'unavailable'


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(SentinelError)
    async def _handle(request: Request, exc: SentinelError):
        return JSONResponse(status_code=exc.status, content={'detail': exc.message, 'code': exc.code})
