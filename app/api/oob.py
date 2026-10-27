"""Out-of-band callback listener.

Unauthenticated by design: the caller is whatever external system the payload made fetch this URL.
The token is the secret. Hits are recorded, never trusted for anything but "a callback arrived".
"""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select

from ..core.errors import NotFound
from ..models import utcnow
from ..models.oob import OobToken

router = APIRouter(prefix='/api/v1/oob', tags=['oob'])

_PIXEL = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'


def _record(app, token: str, request: Request) -> OobToken:
    with app.state.db_factory() as db:
        row = db.execute(select(OobToken).where(OobToken.token == token)).scalar_one_or_none()
        if row is None:
            raise NotFound('unknown out-of-band token')
        row.hit_count += 1
        if row.first_hit_at is None:
            row.first_hit_at = utcnow()
            row.source_ip = (request.client.host if request.client else '')[:64]
            row.user_agent = (request.headers.get('user-agent') or '')[:256]
        db.commit()
        return row


@router.get('/{token}')
def get_callback(token: str, request: Request):
    """Record the callback and answer with a 1x1 GIF, so an <img> or fetch() payload also renders."""
    _record(request.app, token, request)
    return Response(content=_PIXEL, media_type='image/gif', headers={'Cache-Control': 'no-store'})


@router.post('/{token}')
def post_callback(token: str, request: Request):
    """Same as GET, for payloads that POST or for generic webhook testing."""
    row = _record(request.app, token, request)
    return JSONResponse({'ok': True, 'hits': row.hit_count})
