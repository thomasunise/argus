"""Cross-role authorization / IDOR verification adapter (intrusive, web): `idor_probe`.

Verifies Broken Object Level Authorization (BOLA / IDOR) using two configured asset
credential roles (e.g. `user_a` as resource owner and `user_b` as cross-tenant / cross-user
requester):
1. Requests the target endpoint with `owner_role` credentials and records the baseline 2xx response.
2. Requests the same endpoint unauthenticated to confirm the resource is protected (not public).
3. Requests the same endpoint with `attacker_role` credentials and verifies whether the server
   returns the owner's protected resource (2xx with matching object identity / content).
"""
from __future__ import annotations

from difflib import SequenceMatcher
import json

import httpx

from ...core.config import Settings
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register

DEFAULT_ENDPOINTS = ('/api/orders/1', '/api/users/1', '/api/profile')
MAX_ENDPOINTS = 10
SIMILARITY_THRESHOLD = 0.85


def _select_role_pair(role_headers: dict[str, dict[str, str]], plan_params: dict) -> tuple[str, str] | None:
    if not role_headers or len(role_headers) < 2:
        return None
    owner = str(plan_params.get('owner_role') or 'user_a')
    attacker = str(plan_params.get('attacker_role') or 'user_b')
    if owner in role_headers and attacker in role_headers and owner != attacker:
        return owner, attacker
    roles = list(role_headers.keys())
    return roles[0], roles[1]


def _resources_match(owner_body: str, attacker_body: str, *, owner_marker: str = '') -> tuple[bool, str]:
    if not owner_body.strip() or not attacker_body.strip():
        return False, ''
    if owner_marker and owner_marker in owner_body and owner_marker in attacker_body:
        return True, f'matched_owner_marker:{owner_marker[:40]}'
    try:
        o_json = json.loads(owner_body)
        a_json = json.loads(attacker_body)
        if isinstance(o_json, dict) and isinstance(a_json, dict) and o_json:
            for id_key in ('id', 'order_id', 'user_id', 'account_id', 'uuid', 'owner_id', 'email'):
                if id_key in o_json and o_json.get(id_key) is not None and o_json.get(id_key) == a_json.get(id_key):
                    if o_json == a_json:
                        return True, f'json_exact_match:{id_key}'
                    shared = sum(1 for k, v in o_json.items() if a_json.get(k) == v)
                    if shared >= max(1, len(o_json) // 2):
                        return True, f'json_id_match:{id_key}'
    except ValueError:
        pass
    ratio = SequenceMatcher(None, owner_body[:20_000], attacker_body[:20_000]).ratio()
    if ratio >= SIMILARITY_THRESHOLD:
        return True, f'body_similarity:{ratio:.2f}'
    return False, ''


class IdorProbeAdapter(TestAdapter):
    name = 'idor_probe'
    tier = 'intrusive'
    target_kinds = ('web',)
    description = 'Cross-role authorization check (compares owner_role vs attacker_role vs unauthenticated responses to confirm IDOR/BOLA).'

    def available(self, settings: Settings) -> bool:
        return True

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        if ctx.tier != 'intrusive':
            return []
        role_pair = _select_role_pair(ctx.role_headers or {}, plan_params)
        if role_pair is None:
            return []
        owner_role, attacker_role = role_pair
        owner_headers = ctx.role_headers[owner_role]
        attacker_headers = ctx.role_headers[attacker_role]

        target = (ctx.target or asset.target).rstrip('/')
        raw_endpoints = plan_params.get('endpoints') or list(DEFAULT_ENDPOINTS)
        endpoints = [str(e) for e in raw_endpoints if str(e).startswith('/')][:MAX_ENDPOINTS]
        owner_marker = str(plan_params.get('owner_marker') or '')

        findings: list[NormalizedFinding] = []
        async with httpx.AsyncClient(
            base_url=target, timeout=httpx.Timeout(10.0), follow_redirects=False,
            trust_env=False, verify=True, limits=httpx.Limits(max_connections=2),
        ) as client:
            for endpoint in endpoints:
                await ctx.rate_limiter.acquire()
                try:
                    owner_resp = await client.get(endpoint, headers=owner_headers)
                except httpx.HTTPError:
                    continue
                if not (200 <= owner_resp.status_code < 300) or not owner_resp.text.strip():
                    continue

                await ctx.rate_limiter.acquire()
                try:
                    unauth_resp = await client.get(endpoint)
                except httpx.HTTPError:
                    unauth_resp = None

                # Skip public endpoints where unauthenticated callers receive the exact same resource.
                if unauth_resp is not None and 200 <= unauth_resp.status_code < 300:
                    public_match, _ = _resources_match(owner_resp.text, unauth_resp.text, owner_marker=owner_marker)
                    if public_match:
                        continue

                await ctx.rate_limiter.acquire()
                try:
                    attacker_resp = await client.get(endpoint, headers=attacker_headers)
                except httpx.HTTPError:
                    continue
                if not (200 <= attacker_resp.status_code < 300):
                    continue

                matched, match_reason = _resources_match(owner_resp.text, attacker_resp.text, owner_marker=owner_marker)
                if not matched:
                    continue

                # Similar HTML templates are not proof that the same protected object
                # was returned. Likewise an unknown unauthenticated response is not
                # evidence that access controls were enforced.
                if match_reason.startswith('body_similarity:'):
                    continue
                unauth_status = unauth_resp.status_code if unauth_resp is not None else 0
                proven = unauth_status in (401, 403)
                findings.append(NormalizedFinding(
                    rule=f'{"idor-proof" if proven else "idor-suspected"}:{endpoint}',
                    title=f'{"Verified" if proven else "Possible"} cross-role authorization bypass (IDOR) on {endpoint}'[:240],
                    description=(
                        f'Protected endpoint {endpoint} returned {owner_role!r} resource data to {attacker_role!r} '
                        f'({attacker_resp.status_code}, {match_reason}) while unauthenticated access returned {unauth_status}.'
                    ),
                    remediation='Enforce object-level ownership checks against the authenticated principal on every resource read/write.',
                    severity='high' if proven else 'medium',
                    verified=proven,
                    evidence={
                        'endpoint': endpoint,
                        'owner_role': owner_role,
                        'attacker_role': attacker_role,
                        'owner_status': owner_resp.status_code,
                        'attacker_status': attacker_resp.status_code,
                        'unauth_status': unauth_status,
                        'match_reason': match_reason,
                        'proof_type': 'cross_role_differential',
                        'verified': proven,
                    },
                ))
        return findings


register(IdorProbeAdapter())
