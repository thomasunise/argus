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
PREFIX_KMS = 'enc:kms:v2:'
_lock = threading.Lock()
_keys: dict[str, bytes] = {}
_current: str = ''
_refuse_plaintext: bool = False
_kms_provider: str = 'local'  # local, aws_kms, azure_keyvault, vault_transit
_kms_key_id: str = ''
_vault_addr: str = ''
_vault_token: str = ''
_tenant_dek_cache: dict[tuple[str, str], bytes] = {}
_kms_wrap_cache: dict[tuple[str, str, str], tuple[bytes, str]] = {}
_kms_unwrap_cache: dict[tuple[str, str, str], bytes] = {}


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


def _kms_wrap_dek(dek: bytes, tenant_id: str) -> str:
    ctx_tenant = tenant_id or 'global'
    if _kms_provider == 'aws_kms':
        import boto3

        resp = boto3.client('kms').encrypt(
            KeyId=_kms_key_id,
            Plaintext=dek,
            EncryptionContext={'tenant_id': ctx_tenant},
        )
        return base64.urlsafe_b64encode(resp['CiphertextBlob']).decode().rstrip('=')
    if _kms_provider == 'azure_keyvault':
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.keys.crypto import CryptographyClient, KeyWrapAlgorithm

        client = CryptographyClient(_kms_key_id, credential=DefaultAzureCredential())
        wrapped = client.wrap_key(KeyWrapAlgorithm.rsa_oaep_256, dek)
        return base64.urlsafe_b64encode(wrapped.encrypted_key).decode().rstrip('=')
    if _kms_provider == 'vault_transit':
        import httpx

        if not _vault_addr.startswith(('https://', 'http://')):
            raise ValueError('VAULT_ADDR must start with https:// or http://')
        url = f"{_vault_addr.rstrip('/')}/v1/transit/encrypt/{_kms_key_id}"
        payload = {
            'plaintext': base64.b64encode(dek).decode(),
            'context': base64.b64encode(ctx_tenant.encode()).decode(),
        }
        resp = httpx.post(url, json=payload, headers={'X-Vault-Token': _vault_token}, timeout=5.0)
        resp.raise_for_status()
        ct = str(resp.json()['data']['ciphertext'])
        return base64.urlsafe_b64encode(ct.encode()).decode().rstrip('=')
    raise ValueError(f'Unsupported KMS_PROVIDER {_kms_provider!r}')


def _kms_unwrap_dek(provider: str, wrapped_b64: str, tenant_id: str) -> bytes:
    cache_key = (provider, tenant_id, wrapped_b64)
    if cache_key in _kms_unwrap_cache:
        return _kms_unwrap_cache[cache_key]
    raw_wrapped = base64.urlsafe_b64decode(wrapped_b64 + '=' * (-len(wrapped_b64) % 4))
    ctx_tenant = tenant_id or 'global'
    if provider == 'aws_kms':
        import boto3

        resp = boto3.client('kms').decrypt(
            CiphertextBlob=raw_wrapped,
            EncryptionContext={'tenant_id': ctx_tenant},
        )
        dek = bytes(resp['Plaintext'])
    elif provider == 'azure_keyvault':
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.keys.crypto import CryptographyClient, KeyWrapAlgorithm

        client = CryptographyClient(_kms_key_id, credential=DefaultAzureCredential())
        dek = bytes(client.unwrap_key(KeyWrapAlgorithm.rsa_oaep_256, raw_wrapped).key)
    elif provider == 'vault_transit':
        import httpx

        if not _vault_addr.startswith(('https://', 'http://')):
            raise ValueError('VAULT_ADDR must start with https:// or http://')
        url = f"{_vault_addr.rstrip('/')}/v1/transit/decrypt/{_kms_key_id}"
        payload = {
            'ciphertext': raw_wrapped.decode('utf-8'),
            'context': base64.b64encode(ctx_tenant.encode()).decode(),
        }
        resp = httpx.post(url, json=payload, headers={'X-Vault-Token': _vault_token}, timeout=5.0)
        resp.raise_for_status()
        dek = base64.b64decode(resp.json()['data']['plaintext'])
    else:
        raise ValueError(f'Unsupported KMS provider {provider!r}')
    _kms_unwrap_cache[cache_key] = dek
    return dek


def _kms_get_or_create_dek(tenant_id: str) -> tuple[bytes, str]:
    cache_key = (_kms_provider, _kms_key_id, tenant_id)
    if cache_key not in _kms_wrap_cache:
        dek = secrets.token_bytes(32)
        wrapped = _kms_wrap_dek(dek, tenant_id)
        _kms_wrap_cache[cache_key] = (dek, wrapped)
        _kms_unwrap_cache[(_kms_provider, tenant_id, wrapped)] = dek
    return _kms_wrap_cache[cache_key]


def configure(keys_spec: str = '', single_key: str = '', *, refuse_plaintext: bool = False,
              kms_provider: str = 'local', kms_key_id: str = '',
              vault_addr: str = '', vault_token: str = '') -> None:
    global _keys, _current, _refuse_plaintext, _kms_provider, _kms_key_id, _vault_addr, _vault_token
    with _lock:
        _keys, _current = key_ring(keys_spec, single_key)
        _refuse_plaintext = bool(refuse_plaintext)
        _kms_provider = (kms_provider or 'local').strip().lower()
        _kms_key_id = kms_key_id or ''
        _vault_addr = vault_addr or ''
        _vault_token = vault_token or ''
        _tenant_dek_cache.clear()
        _kms_wrap_cache.clear()
        _kms_unwrap_cache.clear()


def configured() -> bool:
    return bool(_current or (_kms_provider != 'local' and _kms_key_id))


def current_key_id() -> str:
    return _current


def generate_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')


def encrypt(value: str | None, *, tenant_id: str = '', aad: str = '') -> str | None:
    if value is None or value == '' or not configured():
        return value
    if value.startswith((PREFIX, PREFIX_V2, PREFIX_KMS)):
        return value
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(12)
    if _kms_provider != 'local' and _kms_key_id:
        dek, wrapped_b64 = _kms_get_or_create_dek(tenant_id)
        aad_b64 = base64.urlsafe_b64encode(aad.encode('utf-8')).decode().rstrip('=')
        aad_bytes = f'kms:{_kms_provider}:{tenant_id}:{aad}'.encode()
        ciphertext = AESGCM(dek).encrypt(nonce, value.encode('utf-8'), aad_bytes)
        blob = base64.urlsafe_b64encode(nonce + ciphertext).decode()
        return f'{PREFIX_KMS}{_kms_provider}:{tenant_id}:{wrapped_b64}:{aad_b64}:{blob}'
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
    if not value.startswith((PREFIX, PREFIX_V2, PREFIX_KMS)):
        if strict and value not in ('{}', '[]'):
            raise ValueError('unencrypted plaintext value is refused in production')
        return value
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if value.startswith(PREFIX_KMS):
        try:
            rest = value[len(PREFIX_KMS):]
            provider, stored_tenant, wrapped_b64, aad_b64, blob = rest.split(':', 4)
            if tenant_id and stored_tenant != tenant_id:
                raise ValueError('ciphertext tenant mismatch')
            stored_aad = base64.urlsafe_b64decode(aad_b64 + '=' * (-len(aad_b64) % 4)).decode('utf-8') if aad_b64 else ''
            if aad and stored_aad != aad:
                raise ValueError('ciphertext AAD context mismatch')
            dek = _kms_unwrap_dek(provider, wrapped_b64, stored_tenant)
            raw = base64.urlsafe_b64decode(blob)
            aad_bytes = f'kms:{provider}:{stored_tenant}:{stored_aad}'.encode()
            return AESGCM(dek).decrypt(raw[:12], raw[12:], aad_bytes).decode('utf-8')
        except (KeyError, ValueError, TypeError, InvalidTag) as exc:
            raise ValueError('cannot decrypt kms v2 value: unwrap failed, context mismatch, or corrupt ciphertext') from exc
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
    return value is not None and value.startswith((PREFIX, PREFIX_V2, PREFIX_KMS))


def needs_rotation(value: str | None) -> bool:
    """True when the value is encrypted under a key other than the current one."""
    if not value or not is_encrypted(value) or not _current:
        return False
    if value.startswith(PREFIX_KMS):
        return False
    prefix = PREFIX_V2 if value.startswith(PREFIX_V2) else PREFIX
    kid = value[len(prefix):].split(':', 1)[0]
    return kid != _current


def rotate(value: str | None) -> str | None:
    """Re-encrypt under the current key (plaintext → encrypted, old key → current key)."""
    if value is None or value == '' or not configured():
        return value
    stored_tenant = ''
    stored_aad = ''
    if value.startswith(PREFIX_V2):
        _, stored_tenant, aad_b64, _ = value[len(PREFIX_V2):].split(':', 3)
        stored_aad = base64.urlsafe_b64decode(aad_b64 + '=' * (-len(aad_b64) % 4)).decode('utf-8') if aad_b64 else ''
    elif value.startswith(PREFIX_KMS):
        _, stored_tenant, _, aad_b64, _ = value[len(PREFIX_KMS):].split(':', 4)
        stored_aad = base64.urlsafe_b64decode(aad_b64 + '=' * (-len(aad_b64) % 4)).decode('utf-8') if aad_b64 else ''
    return encrypt(decrypt(value), tenant_id=stored_tenant, aad=stored_aad)


def env_configure() -> None:
    configure(os.getenv('DATA_ENCRYPTION_KEYS', ''), os.getenv('DATA_ENCRYPTION_KEY', ''))
