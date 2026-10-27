"""Trufflehog secret discovery and live verification adapter (active, repo & web): `trufflehog_verify`.

Wraps `trufflehog filesystem <path> --json --no-update` for repositories and includes a native
candidate extractor + read-only provider verification probe (GitHub, Slack, Stripe, SendGrid)
for web bundles and zero-binary environments. Plaintext secrets are NEVER stored in findings
or evidence — only a 4-character prefix mask and a SHA-256 fingerprint.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil

import httpx

from ...core import policy
from ...core.config import Settings
from ...core.errors import Unavailable
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register, run_tool
from .js_analyze import script_urls

MAX_BUNDLES = 10
MAX_BYTES = 2 * 1024 * 1024

DETECTORS: list[tuple[str, re.Pattern]] = [
    ('GitHub', re.compile(r'\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,82})\b')),
    ('Slack', re.compile(r'\b(xox[bp]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,34})\b')),
    ('Stripe', re.compile(r'\b(sk_live_[0-9a-zA-Z]{24,99})\b')),
    ('SendGrid', re.compile(r'\b(SG\.[A-Za-z0-9_-]{20,24}\.[A-Za-z0-9_-]{38,46})\b')),
    ('AWS', re.compile(r'\b((?:AKIA|ASIA)[0-9A-Z]{16})\b')),
    ('GoogleAPI', re.compile(r'\b(AIza[0-9A-Za-z_-]{35})\b')),
]

PROVIDER_ENDPOINTS = {
    'GitHub': 'https://api.github.com/user',
    'Slack': 'https://slack.com/api/auth.test',
    'Stripe': 'https://api.stripe.com/v1/balance',
    'SendGrid': 'https://api.sendgrid.com/v3/scopes',
}


def mask_secret(raw: str) -> tuple[str, str]:
    """Return `(masked_sample, sha256_fingerprint_16)` without exposing the secret."""
    clean = (raw or '').strip()
    if not clean:
        return '****', ''
    fp = hashlib.sha256(clean.encode('utf-8')).hexdigest()[:16]
    prefix = clean[:4] if len(clean) >= 8 else clean[:2]
    return f'{prefix}****', fp


def _source_location(meta: dict) -> tuple[str, int | None]:
    data = (meta.get('Data') if isinstance(meta, dict) else None) or {}
    if not isinstance(data, dict):
        return 'unknown', None
    for key in ('Filesystem', 'Git', 'Web', 'Github'):
        sub = data.get(key)
        if isinstance(sub, dict):
            loc = str(sub.get('file') or sub.get('url') or sub.get('repository') or 'unknown')[:300]
            line = sub.get('line')
            return loc, int(line) if isinstance(line, int) else None
    return 'unknown', None


def parse_jsonl(text: str) -> list[NormalizedFinding]:
    """Parse Trufflehog `--json` JSONL lines into NormalizedFindings without ingesting raw secrets."""
    findings: list[NormalizedFinding] = []
    seen: set[tuple[str, str]] = set()
    for line in (text or '').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        detector = str(item.get('DetectorName') or item.get('SourceName') or 'Secret').strip()
        verified = bool(item.get('Verified'))
        raw_val = str(item.get('Raw') or item.get('Redacted') or '')
        loc, line_no = _source_location(item.get('SourceMetadata') or {})
        sample, fp = mask_secret(raw_val or f'{detector}:{loc}:{line_no}')
        if (detector, fp) in seen:
            continue
        seen.add((detector, fp))
        state_label = 'Verified live' if verified else 'Unverified candidate'
        findings.append(NormalizedFinding(
            rule=f'trufflehog:{detector.lower()}:{fp or loc}',
            title=f'{state_label} secret ({detector}) in {loc}'[:240],
            description=(
                f'Trufflehog detected a {detector} credential in {loc}'
                + (f' at line {line_no}' if line_no else '')
                + ('. Provider verification confirmed the credential is active.' if verified
                   else '. The credential was not verified active; review and rotate if valid.')
                + ' Plaintext secret was not stored.'
            ),
            remediation='Immediately revoke and rotate the credential in the provider console, audit access logs, and purge it from source/bundles.',
            severity='critical' if verified else 'high',
            evidence={
                'detector': detector,
                'verified': verified,
                'file': loc,
                'line': line_no,
                'sample': sample,
                'fingerprint': fp,
            },
        ))
    return findings


def extract_candidates(text: str, source: str) -> list[dict]:
    """Find candidate secrets in text. Returns dicts with `_raw` only in-memory for optional verification."""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for detector, pattern in DETECTORS:
        for match in pattern.finditer(text or ''):
            raw = match.group(1)
            sample, fp = mask_secret(raw)
            if (detector, fp) in seen:
                continue
            seen.add((detector, fp))
            line_no = (text[:match.start()].count('\n') + 1) if text else None
            out.append({
                'detector': detector,
                'source': source,
                'line': line_no,
                'sample': sample,
                'fingerprint': fp,
                '_raw': raw,
            })
    return out


async def verify_candidate(detector: str, token: str, client: httpx.AsyncClient) -> tuple[bool, str]:
    """Perform a safe, read-only identity check against the provider API to confirm whether `token` is live."""
    url = PROVIDER_ENDPOINTS.get(detector)
    if not url or not token:
        return False, 'unsupported_provider'
    try:
        if detector == 'GitHub':
            resp = await client.get(url, headers={'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json'})
            if resp.status_code == 200:
                login = str((resp.json() if resp.headers.get('content-type', '').startswith('application/json') else {}).get('login') or 'authenticated')
                return True, f'github_user:{login[:40]}'
            return False, f'http_{resp.status_code}'
        if detector == 'Slack':
            resp = await client.post(url, headers={'Authorization': f'Bearer {token}'})
            if resp.status_code == 200:
                body = resp.json() if resp.headers.get('content-type', '').startswith('application/json') else {}
                if body.get('ok') is True:
                    team = str(body.get('team') or 'workspace')[:40]
                    return True, f'slack_team:{team}'
            return False, 'slack_rejected'
        if detector == 'Stripe':
            resp = await client.get(url, headers={'Authorization': f'Bearer {token}'})
            if resp.status_code == 200:
                return True, 'stripe_live_balance'
            return False, f'http_{resp.status_code}'
        if detector == 'SendGrid':
            resp = await client.get(url, headers={'Authorization': f'Bearer {token}'})
            if resp.status_code == 200:
                return True, 'sendgrid_scopes_ok'
            return False, f'http_{resp.status_code}'
    except (httpx.HTTPError, ValueError):
        return False, 'network_error'
    return False, 'unverified'


async def _candidates_to_findings(candidates: list[dict], *, verify_live: bool, ctx: HarnessContext) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    if not candidates:
        return findings

    async with httpx.AsyncClient(timeout=httpx.Timeout(8.0), follow_redirects=False, trust_env=False, verify=True) as client:
        for cand in candidates[:100]:
            detector = cand['detector']
            raw = cand.pop('_raw', '')
            verified = False
            verification_detail = 'verification_disabled'
            if verify_live and detector in PROVIDER_ENDPOINTS:
                await ctx.rate_limiter.acquire()
                verified, verification_detail = await verify_candidate(detector, raw, client)
            del raw  # ensure raw secret reference is dropped immediately
            loc = cand['source']
            line_no = cand['line']
            fp = cand['fingerprint']
            sample = cand['sample']
            state_label = 'Verified live' if verified else 'Unverified candidate'
            findings.append(NormalizedFinding(
                rule=f'trufflehog:{detector.lower()}:{fp}',
                title=f'{state_label} secret ({detector}) in {loc}'[:240],
                description=(
                    f'Detected a {detector} credential in {loc}'
                    + (f' at line {line_no}' if line_no else '')
                    + (f' ({verification_detail}).' if verified else '. Plaintext secret was not stored.')
                ),
                remediation='Immediately revoke and rotate the credential in the provider console, audit access logs, and purge it from source/bundles.',
                severity='critical' if verified else 'high',
                evidence={
                    'detector': detector,
                    'verified': verified,
                    'verification_detail': verification_detail,
                    'file': loc,
                    'line': line_no,
                    'sample': sample,
                    'fingerprint': fp,
                },
            ))
    return findings


class TrufflehogVerifyAdapter(TestAdapter):
    name = 'trufflehog_verify'
    tier = 'active'
    target_kinds = ('repo', 'web')
    description = 'Trufflehog secret scanning and live provider API verification (never stores plaintext secrets).'

    def available(self, settings: Settings) -> bool:
        return True

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        settings = ctx.settings
        verify_live = bool(plan_params.get('verify', getattr(settings, 'trufflehog_verify_live', False)))

        if asset.kind == 'repo':
            repo_path = policy.validate_repo_target(asset.target, settings)
            if not plan_params.get('use_native') and (shutil.which(settings.trufflehog_bin) or run_tool is not _DEFAULT_RUN_TOOL):
                argv = [settings.trufflehog_bin, 'filesystem', str(repo_path), '--json', '--no-update']
                if not verify_live:
                    argv.append('--no-verification')
                elif plan_params.get('only_verified'):
                    argv.append('--only-verified')
                await ctx.rate_limiter.acquire()
                code, out, err = await run_tool(argv, timeout=settings.test_tool_timeout_seconds)
                if not out.strip() and code not in (0, 183):
                    raise Unavailable(f'trufflehog exited {code} with no output')
                return parse_jsonl(out)

            candidates: list[dict] = []
            for fpath in list(repo_path.rglob('*'))[:200]:
                if not fpath.is_file():
                    continue
                rel = str(fpath.relative_to(repo_path)).replace('\\', '/')
                try:
                    text = fpath.read_text(encoding='utf-8', errors='replace')[:MAX_BYTES]
                except OSError:
                    continue
                candidates.extend(extract_candidates(text, rel))
            return await _candidates_to_findings(candidates, verify_live=verify_live, ctx=ctx)

        target = ctx.target or asset.target
        page_url = target.rstrip('/') + '/'
        sources: list[tuple[str, str]] = []
        async with httpx.AsyncClient(
            base_url=target, timeout=httpx.Timeout(15.0), follow_redirects=False,
            trust_env=False, verify=True, headers=ctx.auth_headers or None,
        ) as client:
            await ctx.rate_limiter.acquire()
            try:
                page = await client.get('/')
            except httpx.HTTPError:
                return []
            sources.append(('inline', page.text[:MAX_BYTES]))
            for url in script_urls(page.text, page_url)[:MAX_BUNDLES]:
                await ctx.rate_limiter.acquire()
                try:
                    resp = await client.get(url)
                except httpx.HTTPError:
                    continue
                if resp.status_code < 400:
                    sources.append((url, resp.text[:MAX_BYTES]))

        candidates = []
        for src, text in sources:
            candidates.extend(extract_candidates(text, src))
        return await _candidates_to_findings(candidates, verify_live=verify_live, ctx=ctx)


_DEFAULT_RUN_TOOL = run_tool
register(TrufflehogVerifyAdapter())
