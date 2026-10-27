"""Proof-bounded SQL injection verification adapter (intrusive, web): `sqli_proof`.

Confirms SQL injection on candidate parameters without data dumps or destructive queries:
- When `sqlmap` is installed (or invoked via `run_tool`), executes strictly capped at
  `--batch --level=1 --risk=1 --banner --current-db --current-user --no-cast` (never `--dump`,
  `--os-shell` or `--sql-shell`).
- Otherwise runs a deterministic multi-pair boolean equivalence + banner proof (requiring two
  independent true predicates to match baseline and two independent false predicates to diverge
  consistently) so single-request dynamic page noise cannot false-positive.
Confirmed findings set `verified=True`, wiring directly into `Finding.validation_status='verified'`.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from urllib.parse import urlencode

import httpx

from ...core.config import Settings
from ...core.errors import ScopeDenied, Unavailable
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register, run_tool
from .sqli_blind import responses_differ

_PARAM_RE = re.compile(r'^[A-Za-z0-9_.\-\[\]]{1,64}$')
_SQLMAP_PARAM_RE = re.compile(r'Parameter:\s*([^\s(]+)\s*\(([^)]+)\)', re.IGNORECASE)
_SQLMAP_TYPE_RE = re.compile(r'Type:\s*([^\r\n]+)', re.IGNORECASE)
_SQLMAP_TITLE_RE = re.compile(r'Title:\s*([^\r\n]+)', re.IGNORECASE)
_SQLMAP_DBMS_RE = re.compile(r'back-end DBMS:\s*([^\r\n]+)', re.IGNORECASE)
_SQLMAP_BANNER_RE = re.compile(r"banner:\s*'([^'\r\n]{1,120})'", re.IGNORECASE)
_SQLMAP_DB_RE = re.compile(r"current database:\s*'([^'\r\n]{1,80})'", re.IGNORECASE)
_SQLMAP_USER_RE = re.compile(r"current user:\s*'([^'\r\n]{1,80})'", re.IGNORECASE)

BANNER_SIGNATURES: tuple[tuple[str, re.Pattern], ...] = (
    ('postgresql', re.compile(r'PostgreSQL\s+\d+\.\d+', re.IGNORECASE)),
    ('mysql', re.compile(r'(?:\d+\.\d+\.\d+-MariaDB|MySQL\s+\d+\.\d+)', re.IGNORECASE)),
    ('sqlite', re.compile(r'3\.\d+\.\d+\s+20\d\d-\d\d-\d\d', re.IGNORECASE)),
    ('mssql', re.compile(r'Microsoft SQL Server\s+20\d\d', re.IGNORECASE)),
)

TRUE_PAIRS = ("1' AND '1'='1", "1' AND '2'='2")
FALSE_PAIRS = ("1' AND '1'='2", "1' AND '2'='3")
MAX_ENDPOINTS = 5
MAX_PARAMS = 5


def safe_param_name(name: str) -> str:
    clean = (name or '').strip()
    if not _PARAM_RE.match(clean):
        raise ScopeDenied(f'unsafe parameter name for sqli_proof: {name!r}')
    return clean


def parse_sqlmap_output(stdout: str, *, endpoint: str = '/', fallback_param: str = 'id') -> list[NormalizedFinding]:
    """Parse bounded `sqlmap --batch --level=1 --risk=1 --banner` stdout into verified findings."""
    text = stdout or ''
    param_matches = list(_SQLMAP_PARAM_RE.finditer(text))
    if not param_matches and 'is vulnerable' not in text.lower() and 'injectable' not in text.lower():
        return []

    types = [m.group(1).strip()[:80] for m in _SQLMAP_TYPE_RE.finditer(text)][:4]
    titles = [m.group(1).strip()[:120] for m in _SQLMAP_TITLE_RE.finditer(text)][:4]
    dbms_m = _SQLMAP_DBMS_RE.search(text)
    banner_m = _SQLMAP_BANNER_RE.search(text)
    db_m = _SQLMAP_DB_RE.search(text)
    user_m = _SQLMAP_USER_RE.search(text)

    dbms = dbms_m.group(1).strip()[:80] if dbms_m else 'unknown'
    banner = banner_m.group(1).strip()[:120] if banner_m else ''
    current_db = db_m.group(1).strip()[:80] if db_m else ''
    current_user = user_m.group(1).strip()[:80] if user_m else ''

    params = [(m.group(1), m.group(2)) for m in param_matches] or [(fallback_param, 'GET')]
    findings: list[NormalizedFinding] = []
    seen: set[str] = set()
    for param, place in params:
        if param in seen:
            continue
        seen.add(param)
        findings.append(NormalizedFinding(
            rule=f'sqli-proof:{endpoint}:{param}',
            title=f'Verified SQL injection in {param!r} on {endpoint} ({dbms})'[:240],
            description=(
                f'Bounded SQLi proof confirmed parameter {param!r} ({place}) on {endpoint} is injectable '
                f'(DBMS: {dbms}' + (f', banner: {banner}' if banner else '') + '). No table data was dumped.'
            )[:2000],
            remediation='Replace string-concatenated SQL with parameterized queries / prepared statements.',
            severity='critical',
            verified=True,
            evidence={
                'endpoint': endpoint,
                'parameter': param,
                'place': place,
                'dbms': dbms,
                'banner': banner,
                'current_db': current_db,
                'current_user': current_user,
                'techniques': types,
                'titles': titles,
                'proof_type': 'sqlmap_banner',
                'verified': True,
            },
        ))
    return findings


async def verify_endpoint_param(client: httpx.AsyncClient, ctx: HarnessContext,
                                endpoint: str, param: str) -> NormalizedFinding | None:
    """Multi-pair boolean equivalence and banner proof (no data dumps)."""
    async def _req(val: str) -> tuple[int, str, float] | None:
        await ctx.rate_limiter.acquire()
        try:
            r = await client.get(endpoint, params={param: val})
        except httpx.HTTPError:
            return None
        if r.status_code >= 500:
            return None
        return r.status_code, r.text[:200_000], 0.0

    t1 = await _req(TRUE_PAIRS[0])
    f1 = await _req(FALSE_PAIRS[0])
    if not t1 or not f1 or not responses_differ(t1, f1):
        return None

    # Second independent boolean pair must confirm the exact same equivalence/divergence pattern.
    t2 = await _req(TRUE_PAIRS[1])
    f2 = await _req(FALSE_PAIRS[1])
    if not t2 or not f2:
        return None
    if responses_differ(t1, t2) or not responses_differ(t2, f2):
        return None

    banner = ''
    dbms = 'sql'
    for d_name, pattern in BANNER_SIGNATURES:
        m = pattern.search(t1[1])
        if m:
            dbms = d_name
            banner = m.group(0)[:120]
            break

    return NormalizedFinding(
        rule=f'sqli-proof:{endpoint}:{param}',
        title=f'Verified SQL injection in {param!r} on {endpoint}'[:240],
        description=(
            f'Two independent boolean SQL predicate pairs on {endpoint}?{param}=... consistently '
            'reproduced true/false response equivalence, proving the parameter is evaluated inside '
            'a SQL predicate without extracting table rows.'
        ),
        remediation='Use parameterized queries / bound parameters for all database access.',
        severity='critical',
        verified=True,
        evidence={
            'endpoint': endpoint,
            'parameter': param,
            'dbms': dbms,
            'banner': banner,
            'true_len': len(t1[1]),
            'false_len': len(f1[1]),
            'proof_type': 'boolean_equivalence_pair',
            'verified': True,
        },
    )


class SqliProofAdapter(TestAdapter):
    name = 'sqli_proof'
    tier = 'intrusive'
    target_kinds = ('web',)
    description = 'Proof-bounded SQLi verification (capped sqlmap level=1/risk=1 banner proof or dual boolean equivalence; never dumps data).'

    def available(self, settings: Settings) -> bool:
        return True

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        if ctx.tier != 'intrusive':
            return []
        settings = ctx.settings
        target = (ctx.target or asset.target).rstrip('/')
        endpoints = [str(e) for e in (plan_params.get('endpoints') or ['/']) if str(e).startswith('/')][:MAX_ENDPOINTS]
        params = [safe_param_name(str(p)) for p in (plan_params.get('params') or ['id', 'q'])][:MAX_PARAMS]

        use_sqlmap = bool(plan_params.get('use_sqlmap_bin')) or (
            not plan_params.get('use_native')
            and (shutil.which(settings.sqlmap_bin) or run_tool is not _DEFAULT_RUN_TOOL)
        )
        if use_sqlmap:
            findings: list[NormalizedFinding] = []
            for endpoint in endpoints:
                for param in params:
                    out_dir = tempfile.mkdtemp(prefix='sqlmap-')
                    try:
                        query = urlencode({param: '1'})
                        url = f'{target}{endpoint}?{query}'
                        argv = [
                            settings.sqlmap_bin,
                            '-u', url,
                            '-p', param,
                            '--batch',
                            '--level=1',
                            '--risk=1',
                            '--banner',
                            '--current-db',
                            '--current-user',
                            '--no-cast',
                            '--disable-coloring',
                            '--timeout=10',
                            '--retries=1',
                            f'--output-dir={out_dir}',
                        ]
                        await ctx.rate_limiter.acquire()
                        code, out, err = await run_tool(argv, timeout=settings.test_tool_timeout_seconds)
                        if not out.strip() and code not in (0,):
                            raise Unavailable(f'sqlmap exited {code} with no output')
                        findings.extend(parse_sqlmap_output(out, endpoint=endpoint, fallback_param=param))
                    finally:
                        shutil.rmtree(out_dir, ignore_errors=True)
            return findings

        findings = []
        async with httpx.AsyncClient(
            base_url=target, timeout=httpx.Timeout(10.0), follow_redirects=False,
            trust_env=False, verify=True, limits=httpx.Limits(max_connections=2),
            headers=ctx.auth_headers or None,
        ) as client:
            for endpoint in endpoints:
                for param in params:
                    nf = await verify_endpoint_param(client, ctx, endpoint, param)
                    if nf is not None:
                        findings.append(nf)
        return findings


_DEFAULT_RUN_TOOL = run_tool
register(SqliProofAdapter())
