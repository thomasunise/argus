"""Offline-signed rules of engagement for production exploit testing.

The signing key is held by the independent engagement approver, not by ARGUS API
operators. ARGUS needs only this shared verification key; use a dedicated secret
distinct from session, audit and data-encryption keys. Whoever holds this key CAN
authorize production testing, so use a restricted secret manager and rotate it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time

TOKEN_PREFIX = 'roe1'
SHA256 = re.compile(r'^[a-f0-9]{64}$')


def _key(value: str) -> bytes:
    raw = (value or '').encode('utf-8')
    if len(raw) < 32 or value.startswith('REPLACE_'):
        raise ValueError('EXPLOIT_ROE_SIGNING_KEY must contain at least 32 non-placeholder characters')
    return raw


def sign_roe(*, key: str, tenant_id: str, asset_id: str, target: str,
             document_sha256: str, expires_epoch: int) -> str:
    """Issuer-side operation. Never expose through the ARGUS HTTP API."""
    if not SHA256.fullmatch(document_sha256):
        raise ValueError('a SHA-256 hash of the approved rules-of-engagement file is required')
    if expires_epoch <= int(time.time()):
        raise ValueError('ROE expiry must be in the future')
    claims = {'a': asset_id, 'd': document_sha256, 'e': int(expires_epoch),
              't': tenant_id, 'u': hashlib.sha256(target.encode()).hexdigest()}
    payload = base64.urlsafe_b64encode(json.dumps(claims, sort_keys=True, separators=(',', ':')).encode()).rstrip(b'=').decode()
    mac = hmac.new(_key(key), f'{TOKEN_PREFIX}.{payload}'.encode(), hashlib.sha256).hexdigest()
    return f'{TOKEN_PREFIX}.{payload}.{mac}'


def verify_roe(token: str, asset, settings, *, now: float | None = None) -> bool:
    """Require a genuine unexpired issuer signature bound to this exact asset."""
    try:
        prefix, payload, signature = token.split('.')
        if prefix != TOKEN_PREFIX or len(token) > 512 or not SHA256.fullmatch(signature):
            return False
        key = _key(getattr(settings, 'exploit_roe_signing_key', ''))
        expected = hmac.new(key, f'{prefix}.{payload}'.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return False
        raw = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))
        if len(raw) > 1024:
            return False
        claims = json.loads(raw)
        if set(claims) != {'a', 'd', 'e', 't', 'u'} or not SHA256.fullmatch(str(claims['d'])):
            return False
        if type(claims['e']) is not int or claims['e'] <= (now if now is not None else time.time()):
            return False
        return (claims['a'] == asset.id and claims['t'] == asset.tenant_id
                and hmac.compare_digest(claims['u'], hashlib.sha256(asset.target.encode()).hexdigest()))
    except (ValueError, TypeError, KeyError, UnicodeError, json.JSONDecodeError, OverflowError):
        return False
