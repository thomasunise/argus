"""Envelope encryption for sensitive columns (TOTP secrets, rollback payloads, secret references).

Format: `enc:v1:<kid>:<base64 nonce||ciphertext>` using AES-256-GCM. Keys come from
DATA_ENCRYPTION_KEYS ("kid=base64key,kid2=base64key2"; the first entry encrypts, every entry
decrypts) or the single DATA_ENCRYPTION_KEY (kid "k1"). Values that are not prefixed are returned
unchanged so existing rows keep working until re-saved; production requires a key.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import threading

PREFIX = 'enc:v1:'
PREFIX_V2 = 'enc:v2:'
_lock = threading.Lock()
_keys: dict[str, bytes] = {}
_current: str = ''
_refuse_plaintext: bool = False
_kms_provider: str = 'local'  # local, aws_kms, azure_keyvault, vault_transit
_kms_key_id: str = ''
_tenant_dek_cache: dict[tuple[str, str], bytes] = {}


def _derive(raw: str) -> bytes:
    """Accept a base64url 32-byte key or any passphrase (hashed to 32 bytes)."""
    try:
        decoded = base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4))
        if len(decoded) == 32:
            return decoded
    except (ValueError, TypeError):
        pass
    return hashlib.sha256(raw.encode()).digest()


def _tenant_key(master: bytes, tenant_id: str) -> bytes:
    """Derive or unwrap a per-tenant 256-bit data encryption key (DEK) from the root/KMS key."""
    if not tenant_id:
        return master
    import hmac

    cache_key = (hashlib.sha256(master).hexdigest()[:16], tenant_id)
    if cache_key not in _tenant_dek_cache:
        _tenant_dek_cache[cache_key] = hmac.new(master, f'argus-dek:v2:{tenant_id}'.encode(), hashlib.sha256).digest()
    return _tenant_dek_cache[cache_key]


def bind_aad(*, tenant_id: str = '', table: str = '', column: str = '', row_id: str = '') -> str:
    """Canonical AAD binding string for envelope encryption of a specific database cell."""
    return f'tenant={tenant_id}|table={table}|column={column}|row={row_id}'


def key_ring(keys_spec: str = '', single_key: str = '') -> tuple[dict[str, bytes], str]:
    """Parse DATA_ENCRYPTION_KEYS / DATA_ENCRYPTION_KEY into ({kid: key}, current kid)."""
    parsed: dict[str, bytes] = {}
    order: list[str] = []
    for item in (keys_spec or '').split(','):
        item = item.strip()
        if not item:
            continue
        kid, _, value = item.partition('=')
        if not value:
            kid, value = 'k1', kid
        parsed[kid.strip()] = _derive(value.strip())
        order.append(kid.strip())
    if single_key and 'k1' not in parsed:
        parsed['k1'] = _derive(single_key)
        order.append('k1')
    return parsed, (order[0] if order else '')


def configure(keys_spec: str = '', single_key: str = '', *, refuse_plaintext: bool = False,
              kms_provider: str = 'local', kms_key_id: str = '') -> None:
    global _keys, _current, _refuse_plaintext, _kms_provider, _kms_key_id
    with _lock:
        _keys, _current = key_ring(keys_spec, single_key)
        _refuse_plaintext = bool(refuse_plaintext)
        _kms_provider = kms_provider or 'local'
        _kms_key_id = kms_key_id or ''
        _tenant_dek_cache.clear()


def configured() -> bool:
    return bool(_current)


def current_key_id() -> str:
    return _current


def generate_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')


def encrypt(value: str | None, *, tenant_id: str = '', aad: str = '') -> str | None:
    if value is None or value == '' or not _current:
        return value
    if value.startswith((PREFIX, PREFIX_V2)):
        return value
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(12)
    if tenant_id or aad:
        dek = _tenant_key(_keys[_current], tenant_id)
        aad_b64 = base64.urlsafe_b64encode(aad.encode('utf-8')).decode().rstrip('=')
        aad_bytes = f'{_current}:{tenant_id}:{aad}'.encode()
        ciphertext = AESGCM(dek).encrypt(nonce, value.encode('utf-8'), aad_bytes)
        blob = base64.urlsafe_b64encode(nonce + ciphertext).decode()
        return f'{PREFIX_V2}{_current}:{tenant_id}:{aad_b64}:{blob}'
    ciphertext = AESGCM(_keys[_current]).encrypt(nonce, value.encode('utf-8'), _current.encode())
    return PREFIX + _current + ':' + base64.urlsafe_b64encode(nonce + ciphertext).decode()


def decrypt(value: str | None, *, tenant_id: str = '', aad: str = '', refuse_plaintext: bool | None = None) -> str | None:
    if value is None or value == '':
        return value
    strict = _refuse_plaintext if refuse_plaintext is None else refuse_plaintext
    if not value.startswith((PREFIX, PREFIX_V2)):
        if strict and value not in ('{}', '[]'):
            raise ValueError('unencrypted plaintext value is refused in production')
        return value
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if value.startswith(PREFIX_V2):
        try:
            rest = value[len(PREFIX_V2):]
            kid, stored_tenant, aad_b64, blob = rest.split(':', 3)
            if tenant_id and stored_tenant != tenant_id:
                raise ValueError('ciphertext tenant mismatch')
            stored_aad = base64.urlsafe_b64decode(aad_b64 + '=' * (-len(aad_b64) % 4)).decode('utf-8') if aad_b64 else ''
            if aad and stored_aad != aad:
                raise ValueError('ciphertext AAD context mismatch')
            dek = _tenant_key(_keys[kid], stored_tenant)
            raw = base64.urlsafe_b64decode(blob)
            aad_bytes = f'{kid}:{stored_tenant}:{stored_aad}'.encode()
            return AESGCM(dek).decrypt(raw[:12], raw[12:], aad_bytes).decode('utf-8')
        except (KeyError, ValueError, TypeError, InvalidTag) as exc:
            raise ValueError('cannot decrypt v2 value: unknown key id, context mismatch, or corrupt ciphertext') from exc
    try:
        _, _, rest = value.partition(PREFIX)
        kid, _, blob = rest.partition(':')
        key = _keys[kid]
        raw = base64.urlsafe_b64decode(blob)
        return AESGCM(key).decrypt(raw[:12], raw[12:], kid.encode()).decode('utf-8')
    except (KeyError, ValueError, TypeError, InvalidTag) as exc:
        raise ValueError('cannot decrypt value: unknown key id or corrupt ciphertext') from exc


def is_encrypted(value: str | None) -> bool:
    return value is not None and value.startswith((PREFIX, PREFIX_V2))


def needs_rotation(value: str | None) -> bool:
    """True when the value is encrypted under a key other than the current one."""
    if not value or not is_encrypted(value) or not _current:
        return False
    prefix = PREFIX_V2 if value.startswith(PREFIX_V2) else PREFIX
    kid = value[len(prefix):].split(':', 1)[0]
    return kid != _current


def rotate(value: str | None) -> str | None:
    """Re-encrypt under the current key (plaintext → encrypted, old key → current key)."""
    if value is None or value == '' or not _current:
        return value
    return encrypt(decrypt(value))


def env_configure() -> None:
    configure(os.getenv('DATA_ENCRYPTION_KEYS', ''), os.getenv('DATA_ENCRYPTION_KEY', ''))
