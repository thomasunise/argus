from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


class ArgusError(Exception):
    status = 400
    code = 'error'

    def __init__(self, message: str = '', *, code: str | None = None, status: int | None = None):
        super().__init__(message or self.__class__.__name__)
        self.message = message or self.__class__.__name__
        if code:
            self.code = code
        if status:
            self.status = status


class NotFound(ArgusError):
    status = 404
    code = 'not_found'


class Conflict(ArgusError):
    status = 409
    code = 'conflict'


class PolicyDenied(ArgusError):
    status = 403
    code = 'policy_denied'


class ScopeDenied(PolicyDenied):
    code = 'scope_denied'


class Forbidden(ArgusError):
    status = 403
    code = 'forbidden'


class Unauthorized(ArgusError):
    status = 401
    code = 'unauthorized'


class RateLimited(ArgusError):
    status = 429
    code = 'rate_limited'


class Unavailable(ArgusError):
    status = 503
    code = 'unavailable'


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ArgusError)
    async def _handle(request: Request, exc: ArgusError):
        return JSONResponse(status_code=exc.status, content={'detail': exc.message, 'code': exc.code})
