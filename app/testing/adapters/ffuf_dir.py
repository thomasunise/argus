"""Ffuf directory and endpoint discovery adapter (active, web):
`ffuf -u <target>/FUZZ -w <wordlist> -mc 200,204,301,302,307,401,403 -ac -rate <rps> -timeout 10 -of json -o <report> -s`.

Provides real wordlist-driven fuzzing, optional bounded recursion, and response clustering
(by status + word/line count) so soft-404 catch-all pages are filtered out automatically.
"""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import urlsplit

from ...core.config import Settings
from ...core.errors import ScopeDenied, Unavailable
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register, run_tool

DEFAULT_WORDLIST: tuple[str, ...] = (
    'admin', 'admin/login', 'administrator', 'api', 'api/v1', 'api/v2', 'api/v3', 'api/docs',
    'api/health', 'api/status', 'api/users', 'api/config', 'api/debug', 'api/graphql', 'api/swagger.json',
    'actuator', 'actuator/env', 'actuator/health', 'actuator/heapdump', 'actuator/mappings', 'actuator/metrics',
    'actuator/beans', 'actuator/configprops', 'actuator/threaddump', 'auth', 'auth/login', 'auth/token',
    'backup', 'backup.zip', 'backup.tar.gz', 'backup.sql', 'backups', 'beta', 'Bucket', 'cache',
    ' callback', 'cfg', 'cgi-bin', ' checkout', 'composer.json', 'composer.lock', 'conf', 'config',
    'config.json', 'config.yml', 'config.yaml', 'config.php', 'config.bak', 'console', 'credentials',
    'cron', 'dashboard', 'data', 'database.sql', 'db', 'db.sql', 'db_backup.sql', 'debug', 'debug/pprof',
    ' debug/vars', 'default', 'demo', 'deploy', 'dev', 'diagnostics', 'dist', 'docker-compose.yml',
    'docker-compose.yaml', 'Dockerfile', 'docs', 'download', 'dump.sql', 'env', '.env', '.env.local',
    '.env.production', '.env.development', '.env.bak', '.env.example', 'error', 'export', 'feed',
    'files', 'gitignore', '.gitignore', '.git/HEAD', '.git/config', '.git/index', '.git/logs/HEAD',
    '.gitlab-ci.yml', 'graphql', 'graphiql', 'health', 'healthz', 'readyz', 'livez', 'helm',
    'htaccess', '.htaccess', '.htpasswd', 'id_rsa', 'id_rsa.pub', 'import', 'info', ' info.php',
    'internal', 'invoice', 'jenkins', 'jobs', 'jwks.json', '.well-known/jwks.json',
    '.well-known/openid-configuration', '.well-known/security.txt', 'kibana', 'kube', 'LICENSE',
    'local', 'log', 'logs', 'logs/error.log', 'logs/access.log', 'login', 'logout', 'mail',
    'manage', 'management', 'manifest.json', 'metrics', 'migrations', 'monitor', 'monitoring',
    'new', 'next', 'node_modules', 'oauth', 'oauth/token', 'old', 'openapi.json', 'openapi.yaml',
    'ops', 'orders', 'package.json', 'package-lock.json', 'panel', 'passwd', 'phpinfo.php',
    'phpmyadmin', 'playground', 'portal', 'private', 'Portal', 'profile', 'prometheus', 'proxy',
    'public', 'queue', 'README.md', 'redoc', 'register', 'release', 'report', 'reports', 'reset',
    'rest', 'robots.txt', 'root', 'routes', 'rpc', 'schema.sql', 'scripts', 'search', 'secret',
    'secrets', 'secure', 'security', 'server-info', 'server-status', 'service', 'services',
    'session', 'settings', 'setup', 'shell', 'signin', 'signup', 'sitemap.xml', 'soap', 'source',
    'sql', 'ssh', 'sso', 'staff', 'stage', 'staging', 'static', 'stats', 'status', 'storage',
    'swagger', 'swagger/index.html', 'swagger-ui.html', 'swagger.json', 'swagger.yaml', 'system',
    'System', 'tar', 'temp', 'template', 'templates', 'test', 'testing', 'tmp', 'token', 'tokens',
    'tools', 'trace', 'tsconfig.json', 'upload', 'uploads', 'user', 'users', 'v1', 'v2', 'v3',
    'vendor', 'version', 'webhooks', 'web.config', 'webpack.config.js', 'wp-admin', 'wp-config.php',
    'wp-json', 'wp-login.php', 'xmlrpc.php', 'yarn.lock', '.svn/entries', '.DS_Store',
)

SENSITIVE_MARKERS = (
    '.env', '.git', '.svn', '.htpasswd', 'id_rsa', 'db.sql', 'database.sql', 'dump.sql', 'backup',
    'config', 'dockerfile', 'docker-compose', 'package.json', 'composer.', 'actuator', 'heapdump',
    'threaddump', 'pprof', 'server-status', 'console', 'phpmyadmin', 'web.config', 'wp-config',
    'credentials', 'secret', 'phpinfo',
)

CLUSTER_THRESHOLD = 5
MAX_WORDLIST_LINES = 5000
MAX_RECURSION_DEPTH = 2


def resolve_wordlist(name: object, settings: Settings) -> list[str]:
    """Load wordlist entries from SCAN_ROOT or settings.ffuf_wordlist; fallback to DEFAULT_WORDLIST."""
    candidate_path: Path | None = None
    if name:
        raw_name = str(name).strip()
        if '..' in raw_name or raw_name.startswith(('/', '\\', '-')):
            raise ScopeDenied('ffuf wordlist must be a relative path inside SCAN_ROOT')
        root = Path(settings.scan_root).resolve()
        resolved = (root / raw_name).resolve()
        if root not in resolved.parents or not resolved.is_file():
            raise ScopeDenied('ffuf wordlist not found inside SCAN_ROOT')
        candidate_path = resolved
    elif getattr(settings, 'ffuf_wordlist', ''):
        cfg = Path(settings.ffuf_wordlist)
        if cfg.is_file():
            candidate_path = cfg

    if candidate_path is not None:
        try:
            lines = candidate_path.read_text(encoding='utf-8', errors='replace').splitlines()
        except OSError as exc:
            raise Unavailable('could not read ffuf wordlist') from exc
        entries = [ln.strip().lstrip('/') for ln in lines if ln.strip() and not ln.strip().startswith('#')]
        if entries:
            return list(dict.fromkeys(entries))[:MAX_WORDLIST_LINES]

    return [w.strip().lstrip('/') for w in DEFAULT_WORDLIST if w.strip()]


def _normalize_path(item: dict) -> str:
    inp = item.get('input')
    fuzz = ''
    if isinstance(inp, dict):
        fuzz = str(inp.get('FUZZ') or '').strip()
    url = str(item.get('url') or '')
    if url and '://' in url:
        parsed_path = urlsplit(url).path
        if parsed_path:
            return parsed_path if parsed_path.startswith('/') else '/' + parsed_path
    clean = fuzz.lstrip('/')
    return '/' + clean if clean else '/'


def parse_report(report: dict | str, *, cluster_threshold: int = CLUSTER_THRESHOLD) -> list[NormalizedFinding]:
    """Parse ffuf JSON output and drop soft-404 response clusters sharing identical (status, words, lines)."""
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

    results = data.get('results')
    if not isinstance(results, list) or not results:
        return []

    # Build response clusters by (status, words, lines); if words/lines are missing, fall back to length.
    def _sig(item: dict) -> tuple[int, int, int]:
        status = int(item.get('status') or 0)
        words = int(item.get('words') or 0)
        lines = int(item.get('lines') or 0)
        length = int(item.get('length') or 0)
        return (status, words if (words or lines) else length, lines)

    counts = Counter(_sig(r) for r in results if isinstance(r, dict))
    findings: list[NormalizedFinding] = []
    seen_paths: set[str] = set()

    for item in results[:1000]:
        if not isinstance(item, dict):
            continue
        sig = _sig(item)
        status = sig[0]
        if status == 404 or status >= 500 or status <= 0:
            continue
        if cluster_threshold > 0 and counts[sig] >= cluster_threshold:
            continue

        path = _normalize_path(item)
        if path in seen_paths:
            continue
        seen_paths.add(path)

        length = int(item.get('length') or 0)
        words = int(item.get('words') or 0)
        lines = int(item.get('lines') or 0)
        content_type = str(item.get('content-type') or item.get('content_type') or '')[:120]
        redirect = str(item.get('redirectlocation') or '')[:240]
        sensitive = any(marker in path.lower() for marker in SENSITIVE_MARKERS)

        evidence = {
            'endpoint': path,
            'path': path,
            'status': status,
            'length': length,
            'words': words,
            'lines': lines,
            'content_type': content_type,
            'redirect_location': redirect,
        }

        if 200 <= status < 300:
            findings.append(NormalizedFinding(
                rule=f'ffuf:exposed:{path[:80]}',
                title=f'Discovered reachable endpoint {path}',
                description=(
                    f'Ffuf discovered {path} (HTTP {status}, {length} bytes, {words} words) '
                    'outside the baseline response cluster.'
                ),
                remediation='Confirm this endpoint is intended to be publicly reachable; remove backups, debug routes and VCS metadata.',
                severity='high' if sensitive else 'medium',
                evidence=evidence,
            ))
        elif status in (401, 403):
            findings.append(NormalizedFinding(
                rule=f'ffuf:protected:{path[:80]}',
                title=f'Discovered protected endpoint {path} (HTTP {status})',
                description=f'Ffuf discovered {path} returning HTTP {status}. Verify access controls and rate limiting.',
                remediation='Remove unused administrative or internal routes, or ensure strong authentication and authorization.',
                severity='medium' if sensitive else 'low',
                evidence=evidence,
            ))
        elif status in (301, 302, 307, 308) and sensitive:
            findings.append(NormalizedFinding(
                rule=f'ffuf:redirect:{path[:80]}',
                title=f'Redirecting sensitive path {path} (HTTP {status})',
                description=f'GET {path} redirected ({status}) to {redirect or "another location"}.',
                remediation='Ensure sensitive paths do not leak content before redirecting and are not exposed.',
                severity='low',
                evidence=evidence,
            ))
    return findings


class FfufDirAdapter(TestAdapter):
    name = 'ffuf_dir'
    tier = 'active'
    target_kinds = ('web',)
    description = 'Ffuf directory and endpoint discovery with auto-calibration, response clustering and optional recursion.'

    def available(self, settings: Settings) -> bool:
        import shutil

        return bool(shutil.which(settings.ffuf_bin))

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        settings = ctx.settings
        target = (ctx.target or asset.target).rstrip('/')
        rps = max(1, int(scope.max_rps if scope else settings.test_rate_limit_rps))
        entries = resolve_wordlist(plan_params.get('wordlist'), settings)
        extra_paths = [str(p).strip().lstrip('/') for p in (plan_params.get('paths') or []) if str(p).strip()]
        words = list(dict.fromkeys(extra_paths + entries))[:MAX_WORDLIST_LINES]

        w_fd, wordlist_path = tempfile.mkstemp(prefix='ffuf-words-', suffix='.txt')
        os.close(w_fd)
        r_fd, report_path = tempfile.mkstemp(prefix='ffuf-report-', suffix='.json')
        os.close(r_fd)
        try:
            Path(wordlist_path).write_text('\n'.join(words) + '\n', encoding='utf-8')
            argv = [
                settings.ffuf_bin,
                '-u', f'{target}/FUZZ',
                '-w', wordlist_path,
                '-mc', '200,204,301,302,307,401,403',
                '-ac',
                '-rate', str(rps),
                '-timeout', '10',
                '-of', 'json',
                '-o', report_path,
                '-s',
            ]
            recursion_depth = int(plan_params.get('recursion_depth') or 0)
            if recursion_depth > 0:
                depth = min(MAX_RECURSION_DEPTH, recursion_depth)
                argv += ['-recursion', '-recursion-depth', str(depth)]
            for hdr_name, hdr_val in (ctx.auth_headers or {}).items():
                if '\n' not in str(hdr_name) and '\n' not in str(hdr_val):
                    argv += ['-H', f'{hdr_name}: {hdr_val}']

            await ctx.rate_limiter.acquire()
            code, out, err = await run_tool(argv, timeout=settings.test_tool_timeout_seconds)
            raw = ''
            try:
                if os.path.exists(report_path):
                    raw = Path(report_path).read_text(encoding='utf-8', errors='replace')
            except OSError:
                raw = ''
            if not raw.strip():
                raw = out
            if not raw.strip() and code not in (0,):
                raise Unavailable(f'ffuf exited {code} with no output')
            return parse_report(raw)
        finally:
            for p in (wordlist_path, report_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass


register(FfufDirAdapter())
