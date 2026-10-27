"""Retire.js vulnerable JavaScript library scanner (passive, web & repo): `retire_js`.

Evaluates loaded web scripts, inline bundles, repository JS files and `package.json` dependencies
against the Retire.js CVE repository (`app/testing/data/retirejs_db.json`, updated via
`scripts/update_retirejs_db.py`), and optionally wraps the `retire` CLI when installed.
"""
from __future__ import annotations

from functools import lru_cache
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import urlsplit

import httpx

from ...core import policy
from ...core.config import Settings
from ...core.errors import Unavailable
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register, run_tool
from .js_analyze import script_urls

DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / 'data' / 'retirejs_db.json'
VERSION_TOKEN = '§§version§§'
VERSION_REGEX = r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?'
MAX_BUNDLES = 15
MAX_BYTES = 2 * 1024 * 1024
MAX_REPO_FILES = 200
_SEV_MAP = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low', 'info': 'informational'}
_SEV_RANK = {'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def parse_version(text: str) -> tuple[tuple[int, ...], str] | None:
    """Parse '1.13.0-2' or '^3.4.1' into ((1, 13, 0), '2') for semantic comparison."""
    cleaned = re.sub(r'^[~^>=<v\s]+', '', (text or '').strip())
    match = re.match(r'^(\d+(?:\.\d+){1,3})(?:-([0-9A-Za-z.]+))?', cleaned)
    if not match:
        return None
    try:
        nums = tuple(int(p) for p in match.group(1).split('.'))
    except ValueError:
        return None
    while len(nums) < 3:
        nums = (*nums, 0)
    return nums[:3], (match.group(2) or '')


def version_in_range(version: str, *, below: str, at_or_above: str = '') -> bool:
    """True when `version` is strictly `< below` and (when given) `>= at_or_above`."""
    v = parse_version(version)
    hi = parse_version(below)
    if v is None or hi is None:
        return False
    v_nums, v_pre = v
    hi_nums, hi_pre = hi
    if v_nums > hi_nums:
        return False
    if v_nums == hi_nums:
        # e.g. below="1.13.0-2": 1.13.0 (no pre) or 1.13.0-1 is below 1.13.0-2
        if not hi_pre:
            return False
        if v_pre and v_pre >= hi_pre:
            return False
        if not v_pre:
            pass
    if at_or_above:
        lo = parse_version(at_or_above)
        if lo is not None and v_nums < lo[0]:
            return False
    return True


def _compile_extractor(pattern: str) -> re.Pattern | None:
    if VERSION_TOKEN in pattern:
        # If the pattern already wraps §§version§§ in a capturing group, replace the token directly;
        # otherwise wrap it in a named/indexed group.
        if f'({VERSION_TOKEN})' in pattern:
            regex_str = pattern.replace(VERSION_TOKEN, VERSION_REGEX)
        else:
            regex_str = pattern.replace(VERSION_TOKEN, f'({VERSION_REGEX})')
    else:
        regex_str = pattern
    try:
        return re.compile(regex_str, re.IGNORECASE)
    except re.error:
        return None


@lru_cache(maxsize=4)
def load_db(db_path: str = '') -> dict[str, dict]:
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    raw = json.loads(path.read_text(encoding='utf-8'))
    compiled: dict[str, dict] = {}
    for name, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        ext = entry.get('extractors') or {}
        vulns = entry.get('vulnerabilities') or []
        if not isinstance(ext, dict) or not isinstance(vulns, list):
            continue
        c_ext: dict[str, list[re.Pattern]] = {}
        for kind in ('uri', 'filename', 'filecontent'):
            pats = [ _compile_extractor(str(p)) for p in (ext.get(kind) or []) if isinstance(p, str) ]
            valid = [p for p in pats if p is not None]
            if valid:
                c_ext[kind] = valid
        if c_ext and vulns:
            compiled[name] = {'extractors': c_ext, 'vulnerabilities': vulns}
    return compiled


def detect_libraries(content: str, *, uri: str = '', filename: str = '', db: dict[str, dict] | None = None) -> list[tuple[str, str]]:
    """Return deduplicated `(library_name, version)` pairs matched via uri, filename or filecontent."""
    catalog = db if db is not None else load_db()
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    fname = filename or (urlsplit(uri).path.rsplit('/', 1)[-1] if uri else '')

    for lib, spec in catalog.items():
        ext = spec['extractors']
        matched_version = ''
        for kind, target_text in (('uri', uri), ('filename', fname), ('filecontent', content)):
            if not target_text:
                continue
            for regex in ext.get(kind, ()):
                m = regex.search(target_text)
                if m and m.groups():
                    parts = [g for g in m.groups() if g]
                    ver = '.'.join(parts) if len(parts) > 1 and all(p.isdigit() for p in parts[:1]) else (parts[0] if parts else '')
                    if parse_version(ver) is not None:
                        matched_version = ver
                        break
            if matched_version:
                break
        if matched_version and (lib, matched_version) not in seen:
            seen.add((lib, matched_version))
            found.append((lib, matched_version))
    return found


def evaluate_library(lib: str, version: str, *, source: str, db: dict[str, dict] | None = None) -> NormalizedFinding | None:
    """Evaluate `(lib, version)` against the Retire.js database and return a consolidated finding."""
    catalog = db if db is not None else load_db()
    spec = catalog.get(lib)
    if not spec:
        return None

    matched_vulns: list[dict] = []
    for v in spec.get('vulnerabilities', ()):
        below = str(v.get('below') or '')
        at_or_above = str(v.get('atOrAbove') or '')
        if below and version_in_range(version, below=below, at_or_above=at_or_above):
            matched_vulns.append(v)

    if not matched_vulns:
        return None

    cves: list[str] = []
    summaries: list[str] = []
    fixed_versions: list[str] = []
    highest_sev = 'low'

    for v in matched_vulns:
        sev = _SEV_MAP.get(str(v.get('severity') or 'medium').lower(), 'medium')
        if _SEV_RANK.get(sev, 2) > _SEV_RANK.get(highest_sev, 1):
            highest_sev = sev
        below = str(v.get('below') or '')
        if below and below not in fixed_versions:
            fixed_versions.append(below)
        ident = v.get('identifiers') or {}
        for cve in ident.get('CVE') or []:
            if isinstance(cve, str) and cve not in cves:
                cves.append(cve)
        summary = str(ident.get('summary') or '').strip()
        if summary and summary not in summaries:
            summaries.append(summary)

    fix_target = max(fixed_versions, key=lambda x: parse_version(x) or ((0, 0, 0), '')) if fixed_versions else 'latest'
    summary_text = '; '.join(summaries[:3]) or f'{lib} {version} is below fixed version {fix_target}'
    cve_suffix = f' ({", ".join(cves[:4])})' if cves else ''

    return NormalizedFinding(
        rule=f'retire-js:{lib}:{version}',
        title=f'Vulnerable JavaScript library: {lib} {version}{cve_suffix}'[:240],
        description=f'Retire.js matched {lib} {version} in {source}: {summary_text}.'[:2000],
        remediation=f'Upgrade {lib} to {fix_target} or later.',
        severity=highest_sev,
        cve_ids=cves,
        evidence={
            'library': lib,
            'version': version,
            'source': source,
            'fixed_below': fix_target,
            'cves': cves,
            'summary': summary_text[:500],
        },
    )


def parse_cli_report(report: dict | list | str) -> list[NormalizedFinding]:
    """Parse output from `retire --outputformat json`."""
    if isinstance(report, str):
        text = report.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except ValueError:
            return []
    else:
        parsed = report

    entries = parsed.get('data') if isinstance(parsed, dict) else (parsed if isinstance(parsed, list) else [])
    if not isinstance(entries, list):
        return []

    findings: list[NormalizedFinding] = []
    seen: set[tuple[str, str]] = set()
    for item in entries:
        if not isinstance(item, dict):
            continue
        file_src = str(item.get('file') or 'bundle')[:240]
        for res in item.get('results') or []:
            if not isinstance(res, dict):
                continue
            lib = str(res.get('component') or '').strip()
            ver = str(res.get('version') or '').strip()
            vulns = res.get('vulnerabilities') or []
            if not lib or not ver or not vulns or (lib, ver) in seen:
                continue
            seen.add((lib, ver))
            cves: list[str] = []
            summaries: list[str] = []
            highest_sev = 'low'
            for v in vulns:
                if not isinstance(v, dict):
                    continue
                sev = _SEV_MAP.get(str(v.get('severity') or 'medium').lower(), 'medium')
                if _SEV_RANK.get(sev, 2) > _SEV_RANK.get(highest_sev, 1):
                    highest_sev = sev
                ident = v.get('identifiers') or {}
                for c in ident.get('CVE') or []:
                    if isinstance(c, str) and c not in cves:
                        cves.append(c)
                s_txt = str(ident.get('summary') or '').strip()
                if s_txt and s_txt not in summaries:
                    summaries.append(s_txt)
            summary_text = '; '.join(summaries[:3]) or f'{lib} {ver} has known vulnerabilities'
            findings.append(NormalizedFinding(
                rule=f'retire-js:{lib}:{ver}',
                title=f'Vulnerable JavaScript library: {lib} {ver}'[:240],
                description=f'Retire.js matched {lib} {ver} in {file_src}: {summary_text}.'[:2000],
                remediation=f'Upgrade {lib} to a patched release.',
                severity=highest_sev,
                cve_ids=cves,
                evidence={'library': lib, 'version': ver, 'source': file_src, 'cves': cves, 'summary': summary_text[:500]},
            ))
    return findings


def scan_sources(sources: list[tuple[str, str]], *, db: dict[str, dict] | None = None) -> list[NormalizedFinding]:
    """Scan `(source_uri_or_path, text)` pairs against the Retire.js database."""
    catalog = db if db is not None else load_db()
    findings: list[NormalizedFinding] = []
    seen: set[tuple[str, str]] = set()
    for source, text in sources:
        uri = source if source != 'inline' else ''
        for lib, ver in detect_libraries(text, uri=uri, filename=source, db=catalog):
            if (lib, ver) in seen:
                continue
            seen.add((lib, ver))
            nf = evaluate_library(lib, ver, source=source, db=catalog)
            if nf is not None:
                findings.append(nf)
    return findings


def _scan_package_json(pkg_text: str, source: str, db: dict[str, dict]) -> list[NormalizedFinding]:
    try:
        data = json.loads(pkg_text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    deps: dict = {}
    for section in ('dependencies', 'devDependencies'):
        sec = data.get(section)
        if isinstance(sec, dict):
            deps.update(sec)
    findings: list[NormalizedFinding] = []
    for name, raw_ver in deps.items():
        lib = str(name).lower()
        ver_str = str(raw_ver or '').strip().lstrip('^~>=< ')
        if parse_version(ver_str) is None:
            continue
        nf = evaluate_library(lib, ver_str, source=source, db=db)
        if nf is not None:
            findings.append(nf)
    return findings


class RetireJsAdapter(TestAdapter):
    name = 'retire_js'
    tier = 'passive'
    target_kinds = ('web', 'repo')
    description = 'Retire.js JavaScript library vulnerability scanner backed by the Retire.js CVE database.'

    def available(self, settings: Settings) -> bool:
        db_file = Path(settings.retirejs_db_path) if getattr(settings, 'retirejs_db_path', '') else DEFAULT_DB_PATH
        return db_file.is_file() or bool(shutil.which(settings.retirejs_bin))

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        settings = ctx.settings
        db_path = str(getattr(settings, 'retirejs_db_path', '') or '')
        catalog = load_db(db_path)

        if asset.kind == 'repo':
            repo_path = policy.validate_repo_target(asset.target, settings)
            if plan_params.get('use_retire_bin') and shutil.which(settings.retirejs_bin):
                fd, report_path = tempfile.mkstemp(prefix='retire-', suffix='.json')
                os.close(fd)
                try:
                    argv = [settings.retirejs_bin, '--path', str(repo_path), '--outputformat', 'json',
                            '--outputpath', report_path, '--exitwith', '0']
                    await ctx.rate_limiter.acquire()
                    code, out, err = await run_tool(argv, timeout=settings.test_tool_timeout_seconds)
                    raw = Path(report_path).read_text(encoding='utf-8', errors='replace') if os.path.exists(report_path) else out
                    if not raw.strip() and code not in (0,):
                        raise Unavailable(f'retire exited {code} with no output')
                    return parse_cli_report(raw)
                finally:
                    try:
                        os.unlink(report_path)
                    except OSError:
                        pass

            sources: list[tuple[str, str]] = []
            pkg_findings: list[NormalizedFinding] = []
            count = 0
            for fpath in repo_path.rglob('*'):
                if count >= MAX_REPO_FILES:
                    break
                if not fpath.is_file():
                    continue
                rel = str(fpath.relative_to(repo_path)).replace('\\', '/')
                if fpath.name == 'package.json':
                    count += 1
                    try:
                        pkg_findings.extend(_scan_package_json(fpath.read_text(encoding='utf-8', errors='replace')[:MAX_BYTES], rel, catalog))
                    except OSError:
                        pass
                elif fpath.suffix.lower() in ('.js', '.mjs', '.html', '.htm'):
                    count += 1
                    try:
                        sources.append((rel, fpath.read_text(encoding='utf-8', errors='replace')[:MAX_BYTES]))
                    except OSError:
                        pass
            combined = pkg_findings + scan_sources(sources, db=catalog)
            deduped: list[NormalizedFinding] = []
            seen_rules: set[str] = set()
            for nf in combined:
                if nf.rule not in seen_rules:
                    seen_rules.add(nf.rule)
                    deduped.append(nf)
            return deduped

        target = ctx.target or asset.target
        page_url = target.rstrip('/') + '/'
        sources = []
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
                    response = await client.get(url)
                except httpx.HTTPError:
                    continue
                if response.status_code < 400:
                    sources.append((url, response.text[:MAX_BYTES]))
        return scan_sources(sources, db=catalog)


register(RetireJsAdapter())
