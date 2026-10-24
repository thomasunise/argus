"""Passwords, API keys, TOTP, OIDC helpers, secret resolution and redaction.

Only the standard library is used for hashing and TOTP so the trust surface stays small.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

import httpx

from .config import Settings

# ---------------------------------------------------------------- passwords (scrypt)

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 14, 8, 1
_SCRYPT_MAXMEM = 64 * 1024 * 1024


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32, maxmem=_SCRYPT_MAXMEM)
    return 'scrypt$%d$%d$%d$%s$%s' % (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, digest_b64 = stored.split('$')
        if algo != 'scrypt':
            return False
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(digest_b64)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected), maxmem=_SCRYPT_MAXMEM)
        return hmac.compare_digest(digest, expected)
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------- API keys

API_KEY_PREFIX = 'argus'


def generate_api_key() -> tuple[str, str, str]:
    """Returns (plaintext_key, prefix, sha256_hash). Only the hash is stored."""
    prefix = secrets.token_hex(4)
    body = secrets.token_urlsafe(32)
    key = f'{API_KEY_PREFIX}_{prefix}_{body}'
    return key, prefix, hash_api_key(key)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def parse_api_key(key: str) -> str | None:
    parts = key.split('_', 2)
    if len(parts) == 3 and parts[0] == API_KEY_PREFIX and len(parts[1]) == 8:
        return parts[1]
    return None


# ---------------------------------------------------------------- TOTP (RFC 6238)


def totp_generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')


def _totp_code(secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret + '=' * (-len(secret) % 8))
    msg = struct.pack('>Q', counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_match(secret: str, code: str, window: int = 1, period: int = 30) -> int | None:
    """The time-step counter the code is valid for (within the window), or None. Callers store the counter so the
    same code cannot be replayed."""
    if not secret or not code or not code.isdigit():
        return None
    now = int(time.time()) // period
    matched: int | None = None
    for offset in range(-window, window + 1):
        if hmac.compare_digest(_totp_code(secret, now + offset), code):
            matched = now + offset
    return matched


def totp_verify(secret: str, code: str, window: int = 1, period: int = 30) -> bool:
    return totp_match(secret, code, window=window, period=period) is not None


def totp_provisioning_uri(secret: str, email: str, issuer: str) -> str:
    return f'otpauth://totp/{issuer}:{email}?' + urlencode({'secret': secret, 'issuer': issuer, 'digits': 6, 'period': 30})


# ---------------------------------------------------------------- secret references as shown to clients

MASKED_LITERAL_REF = 'literal:[set]'


def mask_secret_refs(refs: dict | None) -> dict:
    """API view of stored secret references: env:/file:/secrets: refs are not secret; a literal: value is."""
    return {k: (MASKED_LITERAL_REF if isinstance(v, str) and v.startswith('literal:') else v) for k, v in (refs or {}).items()}


def merge_secret_refs(new: dict | None, existing: dict | None) -> dict:
    """A client that edits a config sends the masked view back; keep the stored literal for every masked field."""
    existing = existing or {}
    merged: dict = {}
    for key, value in (new or {}).items():
        if value == MASKED_LITERAL_REF:
            if key in existing:
                merged[key] = existing[key]
            continue
        merged[key] = value
    return merged


# ---------------------------------------------------------------- OIDC (authorization code + PKCE)


@dataclass
class OidcDiscovery:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str = ''


_discovery_cache: dict[str, OidcDiscovery] = {}


async def oidc_discover(issuer: str) -> OidcDiscovery:
    if issuer in _discovery_cache:
        return _discovery_cache[issuer]
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        response = await client.get(issuer.rstrip('/') + '/.well-known/openid-configuration')
        response.raise_for_status()
        data = response.json()
    doc = OidcDiscovery(issuer=data['issuer'], authorization_endpoint=data['authorization_endpoint'],
                        token_endpoint=data['token_endpoint'], jwks_uri=data['jwks_uri'],
                        userinfo_endpoint=data.get('userinfo_endpoint', ''))
    _discovery_cache[issuer] = doc
    return doc


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    return verifier, challenge


def oidc_authorize_url(doc: OidcDiscovery, settings: Settings, state: str, nonce: str, challenge: str) -> str:
    params = {
        'response_type': 'code', 'client_id': settings.oidc_client_id, 'scope': 'openid email profile',
        'redirect_uri': settings.base_url.rstrip('/') + '/api/v1/auth/oidc/callback', 'state': state,
        'nonce': nonce, 'code_challenge': challenge, 'code_challenge_method': 'S256',
    }
    return doc.authorization_endpoint + '?' + urlencode(params)


async def oidc_exchange_code(doc: OidcDiscovery, settings: Settings, code: str, verifier: str, nonce: str) -> dict:
    """Exchanges the code and verifies the ID token signature, issuer, audience and nonce."""
    import jwt  # PyJWT with cryptography

    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        response = await client.post(doc.token_endpoint, data={
            'grant_type': 'authorization_code', 'code': code, 'client_id': settings.oidc_client_id,
            'client_secret': settings.oidc_client_secret, 'code_verifier': verifier,
            'redirect_uri': settings.base_url.rstrip('/') + '/api/v1/auth/oidc/callback',
        })
        response.raise_for_status()
        tokens = response.json()
    id_token = tokens.get('id_token', '')
    jwk_client = jwt.PyJWKClient(doc.jwks_uri)
    signing_key = jwk_client.get_signing_key_from_jwt(id_token)
    claims = jwt.decode(id_token, signing_key.key, algorithms=['RS256', 'ES256'], audience=settings.oidc_client_id,
                        issuer=doc.issuer, options={'require': ['exp', 'iat', 'sub']})
    if claims.get('nonce') != nonce:
        raise ValueError('OIDC nonce mismatch')
    return claims


# ---------------------------------------------------------------- secrets


_SECRET_LOG = __import__('logging').getLogger('argus.secrets')


def secret_ref_allowed(ref: str, settings: Settings) -> tuple[bool, str]:
    """Policy for secret references. env: names must carry SECRET_ENV_PREFIX or be allowlisted
    (so an admin cannot point an integration at SESSION_SECRET or DATABASE_URL); file: paths must
    resolve under SECRETS_DIR; literal: requires ALLOW_LITERAL_SECRET_REFS."""
    if not ref:
        return True, ''
    kind, _, value = ref.partition(':')
    if kind == 'env':
        allow = {x.strip() for x in settings.secret_env_allowlist.split(',') if x.strip()}
        if '*' in allow or value in allow or (settings.secret_env_prefix and value.startswith(settings.secret_env_prefix)):
            return True, ''
        return False, f'env:{value} is not an allowed secret variable (use the {settings.secret_env_prefix} prefix or SECRET_ENV_ALLOWLIST)'
    if kind == 'file':
        try:
            base = Path(settings.secrets_dir).resolve()
            target = Path(value).resolve()
        except (OSError, RuntimeError):
            return False, 'invalid secret file path'
        if base == target or base in target.parents:
            return True, ''
        return False, f'file:{value} is outside SECRETS_DIR'
    if kind == 'literal':
        return (True, '') if settings.allow_literal_secret_refs else (False, 'literal: secret references are disabled on this deployment')
    if kind == 'secrets':
        return True, ''
    return False, 'unknown secret reference scheme'


def resolve_secret(ref: str, settings: Settings) -> str:
    """Resolve 'env:NAME', 'file:/path', 'secrets:KEY' or 'literal:value' subject to secret_ref_allowed(). Empty ref returns ''."""
    if not ref:
        return ''
    allowed, reason = secret_ref_allowed(ref, settings)
    if not allowed:
        _SECRET_LOG.warning('refused secret reference: %s', reason)
        return ''
    kind, _, value = ref.partition(':')
    if kind == 'env':
        return os.getenv(value, '')
    if kind == 'file':
        try:
            return Path(value).read_text(encoding='utf-8').strip()
        except OSError:
            return ''
    if kind == 'secrets' and settings.secrets_backend == 'file' and settings.secrets_file:
        try:
            data = json.loads(Path(settings.secrets_file).read_text(encoding='utf-8'))
            return str(data.get(value, ''))
        except (OSError, ValueError):
            return ''
    if kind == 'literal':
        return value
    return ''


# ---------------------------------------------------------------- redaction

_REDACT_PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'(?i)(bearer\s+)[a-z0-9\-_\.=]{16,}'),
    re.compile(r'(?i)(api[_-]?key|secret|password|passwd|token|authorization)(\s*[:=]\s*)(["\']?)[^\s"\',;]{6,}'),
    re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'),
    re.compile(r'sk-[A-Za-z0-9]{20,}'),
    re.compile(r'argus_[0-9a-f]{8}_[A-Za-z0-9\-_]{20,}'),
    re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}'),
    re.compile(r'xox[baprs]-[A-Za-z0-9\-]{10,}'),
]


def redact(text: str) -> str:
    if not text:
        return text
    out = text
    for pattern in _REDACT_PATTERNS:
        out = pattern.sub(lambda m: (m.group(1) + m.group(2) + m.group(3) if m.lastindex and m.lastindex >= 3 else (m.group(1) if m.lastindex else '')) + '[REDACTED]', out)
    return out


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
