"""Arjun-style HTTP parameter discovery adapter (active, web): `param_mine`.

Discovers hidden or unlinked query/body parameters by comparing chunked candidate requests against
a calibrated endpoint baseline (reflection, HTTP status shift, word/line count differential), or by
wrapping the `arjun` CLI when installed and requested. Discovered parameters carry `endpoint` and
`parameter` in evidence so the pentest orchestrator chains them directly into `payload_fuzz`.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import tempfile
from urllib.parse import urlsplit

import httpx

from ...core.config import Settings
from ...core.errors import Unavailable
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register, run_tool

CANDIDATE_PARAMS: tuple[str, ...] = (
    'id', 'user_id', 'account', 'account_id', 'role', 'admin', 'debug', 'test', 'q', 'search',
    'query', 's', 'keyword', 'filter', 'sort', 'order', 'by', 'page', 'limit', 'offset', 'count',
    'file', 'filename', 'path', 'filepath', 'template', 'view', 'include', 'doc', 'folder', 'dir',
    'redirect', 'redirect_uri', 'return', 'return_to', 'url', 'next', 'dest', 'destination',
    'callback', 'jsonp', 'token', 'access_token', 'api_key', 'key', 'secret', 'auth', 'format',
    'type', 'output', 'cmd', 'exec', 'command', 'ping', 'host', 'ip', 'domain', 'target', 'email',
    'user', 'username', 'name', 'lang', 'locale', 'code', 'state', 'Action', 'action', 'mode',
)
SENSITIVE_PARAMS = {
    'admin', 'debug', 'role', 'file', 'filename', 'path', 'filepath', 'template', 'include',
    'redirect', 'redirect_uri', 'url', 'next', 'cmd', 'exec', 'command', 'host', 'target', 'token',
    'api_key', 'key', 'secret',
}

MAX_ENDPOINTS = 5
MAX_PARAMS = 36
CHUNK_SIZE = 6


def _metrics(text: str) -> tuple[int, int, int]:
    body = text[:200_000]
    return len(body), len(body.split()), body.count('\n')


def parse_arjun_report(report: dict | str) -> list[NormalizedFinding]:
    """Parse Arjun `-oJ` JSON output (`{url: {"params": [...], "method": "GET"}}`)."""
    if isinstance(report, str):
        text = report.strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except ValueError:
            return []
    elif isinstance(report, dict):
        data = report
    else:
        return []

    findings: list[NormalizedFinding] = []
    seen: set[tuple[str, str]] = set()
    for url, meta in data.items():
        path = urlsplit(str(url)).path or '/'
        if not path.startswith('/'):
            path = '/' + path
        if isinstance(meta, dict):
            params = meta.get('params') or []
            method = str(meta.get('method') or 'GET').upper()
        elif isinstance(meta, list):
            params = meta
            method = 'GET'
        else:
            continue
        for p in params:
            param = str(p).strip()
            if not param or (path, param) in seen:
                continue
            seen.add((path, param))
            sensitive = param.lower() in SENSITIVE_PARAMS
            findings.append(NormalizedFinding(
                rule=f'param-mine:{path}:{param}',
                title=f'Discovered hidden parameter {param!r} on {path}',
                description=(
                    f'Parameter discovery identified accepted {method} parameter {param!r} on {path}. '
                    'Unlinked parameters often lack input validation or access controls.'
                ),
                remediation='Remove unused debug/internal parameters and enforce strict schema validation.',
                severity='medium' if sensitive else 'low',
                evidence={
                    'endpoint': path,
                    'parameter': param,
                    'method': method,
                    'reason': 'arjun',
                    'reflected': False,
                },
            ))
    return findings


async def mine_endpoint(client: httpx.AsyncClient, endpoint: str, candidates: list[str],
                        ctx: HarnessContext, *, chunk_size: int = CHUNK_SIZE) -> list[NormalizedFinding]:
    """Arjun-style chunked differential parameter discovery against one endpoint."""
    nonce = secrets.token_hex(3)
    await ctx.rate_limiter.acquire()
    try:
        r1 = await client.get(endpoint, params={f'_argus_b1_{nonce}': f'v1{nonce}'})
        await ctx.rate_limiter.acquire()
        r2 = await client.get(endpoint, params={f'_argus_b2_{nonce}': f'v2{nonce}'})
    except httpx.HTTPError:
        return []

    if r1.status_code >= 500 or r2.status_code >= 500:
        return []

    b1_len, b1_words, b1_lines = _metrics(r1.text)
    b2_len, b2_words, b2_lines = _metrics(r2.text)
    base_status = r1.status_code
    word_tol = max(3, abs(b1_words - b2_words) * 2)
    line_tol = max(2, abs(b1_lines - b2_lines) * 2)
    len_tol = max(24, abs(b1_len - b2_len) * 2)

    findings: list[NormalizedFinding] = []
    discovered: set[str] = set()

    def _record(param: str, reason: str, status: int, reflected: bool) -> None:
        if param in discovered:
            return
        discovered.add(param)
        sensitive = param.lower() in SENSITIVE_PARAMS or reflected
        findings.append(NormalizedFinding(
            rule=f'param-mine:{endpoint}:{param}',
            title=f'Discovered active parameter {param!r} on {endpoint} ({reason})',
            description=(
                f'GET {endpoint} changed behavior ({reason}) when supplied parameter {param!r}. '
                'This parameter is a candidate for targeted fuzzing and authorization checks.'
            ),
            remediation='Validate all accepted query parameters against an explicit schema and encode output.',
            severity='medium' if sensitive else 'low',
            evidence={
                'endpoint': endpoint,
                'parameter': param,
                'method': 'GET',
                'reason': reason,
                'status': status,
                'reflected': reflected,
            },
        ))

    for start in range(0, len(candidates), max(1, chunk_size)):
        chunk = [p for p in candidates[start:start + max(1, chunk_size)] if p not in discovered]
        if not chunk:
            continue
        markers = {p: f'arguspm{i}{nonce}' for i, p in enumerate(chunk)}
        await ctx.rate_limiter.acquire()
        try:
            resp = await client.get(endpoint, params=markers)
        except httpx.HTTPError:
            continue
        if resp.status_code >= 500:
            continue

        body_sample = resp.text[:200_000]
        reflected_in_chunk = False
        for p, marker in markers.items():
            if marker in body_sample:
                _record(p, 'reflected', resp.status_code, True)
                reflected_in_chunk = True

        c_len, c_words, c_lines = _metrics(resp.text)
        status_diff = resp.status_code != base_status
        body_diff = (
            abs(c_words - b1_words) > word_tol
            or abs(c_lines - b1_lines) > line_tol
            or abs(c_len - b1_len) > len_tol
        )
        if not (status_diff or body_diff or (reflected_in_chunk and len(chunk) > 1)):
            continue

        # Isolate which parameter(s) in the chunk caused the non-reflection differential.
        for p in chunk:
            if p in discovered:
                continue
            marker = f'argusiso{nonce}'
            await ctx.rate_limiter.acquire()
            try:
                single = await client.get(endpoint, params={p: marker})
            except httpx.HTTPError:
                continue
            if single.status_code >= 500:
                continue
            s_body = single.text[:200_000]
            if marker in s_body:
                _record(p, 'reflected', single.status_code, True)
                continue
            s_len, s_words, s_lines = _metrics(single.text)
            if single.status_code != base_status:
                _record(p, f'status_change:{base_status}->{single.status_code}', single.status_code, False)
            elif (
                abs(s_words - b1_words) > word_tol
                or abs(s_lines - b1_lines) > line_tol
                or abs(s_len - b1_len) > len_tol
            ):
                _record(p, 'response_differential', single.status_code, False)

    return findings


class ParamMineAdapter(TestAdapter):
    name = 'param_mine'
    tier = 'active'
    target_kinds = ('web',)
    description = 'Arjun-style HTTP parameter discovery via chunked response differentials and reflection analysis.'

    def available(self, settings: Settings) -> bool:
        return True

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        settings = ctx.settings
        target = (ctx.target or asset.target).rstrip('/')
        endpoints = [str(e) for e in (plan_params.get('endpoints') or ['/']) if str(e).startswith('/')][:MAX_ENDPOINTS]
        if not endpoints:
            endpoints = ['/']

        if plan_params.get('use_arjun_bin') and shutil.which(settings.arjun_bin):
            rps = max(1, int(scope.max_rps if scope else settings.test_rate_limit_rps))
            fd, report_path = tempfile.mkstemp(prefix='arjun-', suffix='.json')
            os.close(fd)
            try:
                url = target + endpoints[0]
                argv = [settings.arjun_bin, '-u', url, '-m', 'GET', '-oJ', report_path, '--rate-limit', str(rps), '-q']
                await ctx.rate_limiter.acquire()
                code, out, err = await run_tool(argv, timeout=settings.test_tool_timeout_seconds)
                raw = Path(report_path).read_text(encoding='utf-8', errors='replace') if os.path.exists(report_path) else out
                if not raw.strip() and code not in (0,):
                    raise Unavailable(f'arjun exited {code} with no output')
                return parse_arjun_report(raw)
            finally:
                try:
                    os.unlink(report_path)
                except OSError:
                    pass

        extra_params = [str(p).strip() for p in (plan_params.get('params') or []) if str(p).strip()]
        candidates = list(dict.fromkeys(extra_params + list(CANDIDATE_PARAMS)))[:MAX_PARAMS]
        chunk_size = int(plan_params.get('chunk_size') or CHUNK_SIZE)

        findings: list[NormalizedFinding] = []
        async with httpx.AsyncClient(
            base_url=target, timeout=httpx.Timeout(10.0), follow_redirects=False,
            trust_env=False, verify=True, limits=httpx.Limits(max_connections=2),
            headers=ctx.auth_headers or None,
        ) as client:
            for endpoint in endpoints:
                findings.extend(await mine_endpoint(client, endpoint, candidates, ctx, chunk_size=chunk_size))
        return findings


register(ParamMineAdapter())
