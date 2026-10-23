"""Ingest endpoints. `POST /api/v1/ingest/{source}` is API-key authenticated (ingest scope or
operator+ key). `/{source}/verify` is authenticated by the source's webhook signature (GitHub
X-Hub-Signature-256, Okta shared header) against the secret of the inbound IntegrationConfig named
by `?integration=`; Okta's one-time verification challenge is answered on GET."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..core.errors import NotFound, SentinelError, Unauthorized
from ..core.rbac import Principal
from ..integrations.delivery import resolve_secrets
from ..integrations.inbound import ParseContext, registry
from ..integrations.ingest import MAX_BODY_BYTES, BatchTooLarge, InvalidPayload, ingest_async
from ..models import Asset, loads
from ..models.integrations import IntegrationConfig
from .deps import get_db, get_settings, require_scope

router = APIRouter(prefix='/api/v1/ingest', tags=['ingest'])


class VerificationNotSupported(SentinelError):
    status = 400
    code = 'verification_not_supported'


async def _read_body(request: Request) -> bytes:
    declared = request.headers.get('content-length', '')
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise BatchTooLarge(f'Body exceeds {MAX_BODY_BYTES // (1024 * 1024)} MB')
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise BatchTooLarge(f'Body exceeds {MAX_BODY_BYTES // (1024 * 1024)} MB')
    return body


def _parse_json(body: bytes):
    try:
        payload = json.loads(body or b'null')
    except ValueError as exc:
        raise InvalidPayload('Invalid JSON') from exc
    if not isinstance(payload, (dict, list)):
        raise InvalidPayload('Payload must be a JSON object or array')
    return payload


def _asset_id(request: Request, db: Session, tenant_id: str) -> str | None:
    asset_id = request.headers.get('x-asset-id') or None
    if asset_id:
        asset = db.get(Asset, asset_id)
        if asset is None or asset.tenant_id != tenant_id:
            raise NotFound('Asset not found')
    return asset_id


@router.post('/{source}')
async def ingest_source(source: str, request: Request, db: Session = Depends(get_db), principal: Principal = Depends(require_scope('ingest'))):
    if not registry.has(source):
        raise NotFound(f'Unknown ingest source {source!r}; see GET /api/v1/integrations/types')
    asset_id = _asset_id(request, db, principal.tenant_id)
    payload = _parse_json(await _read_body(request))
    result = await ingest_async(db, principal.tenant_id, source, payload, actor=principal, headers=dict(request.headers), asset_id=asset_id,
                                api_key_id=principal.api_key_id or '')
    return result.as_dict()


def _webhook_integration(db: Session, source: str, integration_id: str) -> tuple[IntegrationConfig, object]:
    if not registry.has(source):
        raise NotFound(f'Unknown ingest source {source!r}')
    parser = registry.get(source)
    if not parser.supports_verify:
        raise VerificationNotSupported(f'{parser.name} has no webhook signature scheme; use POST /api/v1/ingest/{parser.name} with an API key')
    row = db.get(IntegrationConfig, integration_id) if integration_id else None
    if row is None or not row.enabled or registry.resolve(row.kind) != parser.name:
        raise NotFound('Integration not found')
    return row, parser


@router.get('/{source}/verify')
def verify_challenge(source: str, request: Request, integration: str = '', db: Session = Depends(get_db)):
    """Okta sends a one-time GET with X-Okta-Verification-Challenge and expects it echoed back."""
    row, parser = _webhook_integration(db, source, integration)
    ctx = ParseContext(tenant_id=row.tenant_id, source=parser.name, headers=dict(request.headers))
    challenge = getattr(parser, 'challenge', None)
    answer = challenge(ctx) if challenge else None
    if not answer:
        raise VerificationNotSupported('No verification challenge header present')
    return answer


@router.post('/{source}/verify')
async def ingest_verified(source: str, request: Request, integration: str = '', db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    row, parser = _webhook_integration(db, source, integration)
    request.app.state.rate_limiter.check(f'ingest:webhook:{row.id}', settings.ingest_rate_limit_per_minute)
    body = await _read_body(request)
    config = loads(row.config_json, {})
    secrets = resolve_secrets(loads(row.secret_refs_json, {}), settings)
    secret = next((secrets[f] for f in parser.secret_fields if secrets.get(f)), '')
    ctx = ParseContext(tenant_id=row.tenant_id, source=parser.name, headers=dict(request.headers), extra=config)
    if not secret or not parser.verify(ctx, body, secret):
        raise Unauthorized('Invalid webhook signature')
    payload = _parse_json(body)
    result = await ingest_async(db, row.tenant_id, parser.name, payload, actor=f'webhook:{row.id}', headers=dict(request.headers), extra=config)
    return result.as_dict()
