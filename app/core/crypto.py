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
_lock = threading.Lock()
_keys: dict[str, bytes] = {}
_current: str = ''


def _derive(raw: str) -> bytes:
    """Accept a base64url 32-byte key or any passphrase (hashed to 32 bytes)."""
    try:
        decoded = base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4))
        if len(decoded) == 32:
            return decoded
    except (ValueError, TypeError):
        pass
    return hashlib.sha256(raw.encode()).digest()


def configure(keys_spec: str = '', single_key: str = '') -> None:
    global _keys, _current
    with _lock:
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
        _keys = parsed
        _current = order[0] if order else ''


def configured() -> bool:
    return bool(_current)


def current_key_id() -> str:
    return _current


def generate_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')


def encrypt(value: str | None) -> str | None:
    if value is None or value == '' or not _current:
        return value
    if value.startswith(PREFIX):
        return value
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_keys[_current]).encrypt(nonce, value.encode('utf-8'), _current.encode())
    return PREFIX + _current + ':' + base64.urlsafe_b64encode(nonce + ciphertext).decode()


def decrypt(value: str | None) -> str | None:
    if value is None or not value.startswith(PREFIX):
        return value
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        _, _, rest = value.partition(PREFIX)
        kid, _, blob = rest.partition(':')
        key = _keys[kid]
        raw = base64.urlsafe_b64decode(blob)
        return AESGCM(key).decrypt(raw[:12], raw[12:], kid.encode()).decode('utf-8')
    except (KeyError, ValueError, TypeError, InvalidTag) as exc:
        raise ValueError('cannot decrypt value: unknown key id or corrupt ciphertext') from exc


def is_encrypted(value: str | None) -> bool:
    return bool(value) and value.startswith(PREFIX)


def needs_rotation(value: str | None) -> bool:
    """True when the value is encrypted under a key other than the current one."""
    if not is_encrypted(value) or not _current:
        return False
    kid = value[len(PREFIX):].split(':', 1)[0]
    return kid != _current


def rotate(value: str | None) -> str | None:
    """Re-encrypt under the current key (plaintext → encrypted, old key → current key)."""
    if value is None or value == '' or not _current:
        return value
    return encrypt(decrypt(value))


def env_configure() -> None:
    configure(os.getenv('DATA_ENCRYPTION_KEYS', ''), os.getenv('DATA_ENCRYPTION_KEY', ''))
