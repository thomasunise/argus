"""Day-1 smoke test for a running Argus instance.

Logs in as a human user, creates a throwaway asset, ingests one synthetic event through the
real ingest path (API key with the `ingest` scope), confirms the event is queryable, runs the
detection engine as a queue job and waits for it to complete (which also proves a worker is
consuming the queue), verifies the tenant's audit hash chain, then cleans up after itself.
Every step prints PASS or FAIL; the process exits 1 on the first failure and 0 when all pass.

Standard library only, so it runs from the image (`docker compose exec api python scripts/smoke_test.py`),
from CI, or from an operator laptop.

    python scripts/smoke_test.py --url https://argus.example.com --email admin@argus.local
    ARGUS_PASSWORD=... ARGUS_TOTP_SECRET=... python scripts/smoke_test.py --tenant default

Environment (flags override):
    ARGUS_URL           base URL (default http://127.0.0.1:8080)
    ARGUS_EMAIL         login email (default admin@argus.local)
    ARGUS_PASSWORD      login password (required; prompted on a TTY when missing)
    ARGUS_TENANT        tenant slug (optional; defaults to the user's first membership)
    ARGUS_TOTP_SECRET   base32 TOTP secret of the user; a code is computed per login (optional)
    ARGUS_TOTP          a current 6-digit code instead of the secret (optional)
    ARGUS_INGEST_KEY    an existing ingest API key; when absent a temporary key is minted and revoked
    ARGUS_INSECURE      "1" disables TLS certificate verification (lab only)

Nothing here scans, calls a model, or executes an action. The asset, event and detections it
creates are labelled SMOKE and the asset is deleted at the end (events are kept as evidence,
exactly as a real ingest would; use --keep to leave the asset too).
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import http.cookiejar
import json
import os
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

DEFAULT_URL = 'http://127.0.0.1:8080'
DEFAULT_EMAIL = 'admin@argus.local'
JOB_TIMEOUT_SECONDS = 180
REQUEST_TIMEOUT_SECONDS = 30


class SmokeFailure(Exception):
    pass


def _out(line: str) -> None:
    sys.stdout.write(line + '\n')
    sys.stdout.flush()


def totp_code(secret: str, period: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret.strip().replace(' ', '').upper() + '=' * (-len(secret) % 8))
    counter = int(time.time()) // period
    digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


class Client:
    def __init__(self, base_url: str, insecure: bool = False) -> None:
        self.base_url = base_url.rstrip('/')
        self.jar = http.cookiejar.CookieJar()
        handlers: list[Any] = [urllib.request.HTTPCookieProcessor(self.jar)]
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.opener = urllib.request.build_opener(*handlers)
        self.csrf = ''
        self.request_ids: list[str] = []

    def call(self, method: str, path: str, body: Any = None, *, headers: dict[str, str] | None = None,
             expect: tuple[int, ...] = (200,), raw: bytes | None = None) -> tuple[int, Any]:
        url = self.base_url + path
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header('Accept', 'application/json')
        req.add_header('User-Agent', 'argus-smoke-test/1.0')
        if data is not None:
            req.add_header('Content-Type', 'application/json')
        if self.csrf and method not in {'GET', 'HEAD', 'OPTIONS'}:
            req.add_header('X-CSRF-Token', self.csrf)
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with self.opener.open(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                status, text = resp.status, resp.read().decode('utf-8', 'replace')
                rid = resp.headers.get('X-Request-ID')
        except urllib.error.HTTPError as exc:
            status, text = exc.code, exc.read().decode('utf-8', 'replace')
            rid = exc.headers.get('X-Request-ID') if exc.headers else None
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            raise SmokeFailure(f'{method} {path}: connection failed: {exc}') from exc
        if rid:
            self.request_ids.append(rid)
        try:
            payload = json.loads(text) if text else None
        except ValueError:
            payload = text
        if status not in expect:
            detail = payload if isinstance(payload, (dict, list)) else str(payload)[:300]
            raise SmokeFailure(f'{method} {path} -> HTTP {status} (expected {expect}); request_id={rid}; body={json.dumps(detail)[:600]}')
        return status, payload


class Smoke:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.client = Client(args.url, insecure=args.insecure)
        self.run_id = uuid.uuid4().hex[:10]
        self.asset_id: str | None = None
        self.key_id: str | None = None
        self.ingest_key: str = args.ingest_key or ''
        self.event_id: str | None = None
        self.job_id: str | None = None
        self.results: list[tuple[str, bool, str]] = []
        self.failed = False

    # ------------------------------------------------------------ framework

    def step(self, name: str, fn) -> None:
        if self.failed and name not in {'cleanup'}:
            self.results.append((name, False, 'skipped (earlier failure)'))
            _out(f'SKIP  {name}: earlier failure')
            return
        started = time.monotonic()
        try:
            detail = fn() or ''
        except SmokeFailure as exc:
            self.failed = True
            self.results.append((name, False, str(exc)))
            _out(f'FAIL  {name}: {exc}')
            return
        except Exception as exc:  # unexpected: still a failure, with the type for triage
            self.failed = True
            self.results.append((name, False, f'{type(exc).__name__}: {exc}'))
            _out(f'FAIL  {name}: {type(exc).__name__}: {exc}')
            return
        ms = int((time.monotonic() - started) * 1000)
        self.results.append((name, True, detail))
        _out(f'PASS  {name} ({ms} ms){": " + detail if detail else ""}')

    # ------------------------------------------------------------ steps

    def check_health(self) -> str:
        _, health = self.client.call('GET', '/health')
        if not isinstance(health, dict) or health.get('status') != 'healthy':
            raise SmokeFailure(f'/health returned {health!r}')
        _, ready = self.client.call('GET', '/ready')
        if not isinstance(ready, dict) or ready.get('status') != 'ready':
            raise SmokeFailure(f'/ready returned {ready!r}')
        return f'version={health.get("version")} queue={ready.get("queue")} provider={ready.get("provider")}'

    def login(self) -> str:
        body = {'email': self.args.email, 'password': self.args.password, 'tenant': self.args.tenant or ''}
        totp = self.args.totp or (totp_code(self.args.totp_secret) if self.args.totp_secret else '')
        if totp:
            body['totp'] = totp
        _, payload = self.client.call('POST', '/api/v1/auth/login', body, expect=(200,))
        if payload.get('mfa_required'):
            raise SmokeFailure('login succeeded but TOTP_REQUIRED=true and the user has not enrolled TOTP; enrol first '
                               '(POST /api/v1/auth/totp/enroll then /totp/verify) or pass --totp-secret')
        self.client.csrf = payload.get('csrf') or ''
        if not self.client.csrf:
            raise SmokeFailure(f'login response carried no CSRF token: {payload}')
        _, session = self.client.call('GET', '/api/v1/auth/session')
        if not session.get('authenticated'):
            raise SmokeFailure('session cookie was not accepted by GET /api/v1/auth/session')
        role = session.get('role')
        if role not in {'operator', 'admin', 'owner'}:
            raise SmokeFailure(f'user role is {role!r}; the smoke test needs operator or higher (assets:write, detections:run)')
        tenant = session.get('tenant') or {}
        return f'user={session["user"]["email"]} role={role} tenant={tenant.get("slug")} mfa={payload.get("mfa")}'

    def create_asset(self) -> str:
        body = {'name': f'SMOKE - smoke test host {self.run_id}', 'kind': 'host', 'target': f'smoke-{self.run_id}.argus.invalid',
                'environment': 'lab', 'criticality': 'low', 'owner': 'smoke-test', 'tags': ['smoke', 'synthetic']}
        _, asset = self.client.call('POST', '/api/v1/assets', body, expect=(201,))
        self.asset_id = asset.get('id')
        if not self.asset_id:
            raise SmokeFailure(f'asset response had no id: {asset}')
        _, fetched = self.client.call('GET', f'/api/v1/assets/{self.asset_id}')
        if fetched.get('target') != body['target']:
            raise SmokeFailure(f'asset read-back mismatch: {fetched}')
        return f'asset_id={self.asset_id}'

    def ensure_ingest_key(self) -> str:
        if self.ingest_key:
            return 'using provided ARGUS_INGEST_KEY'
        body = {'name': f'smoke-test-{self.run_id}', 'role': 'viewer', 'scopes': ['ingest']}
        _, key = self.client.call('POST', '/api/v1/auth/api-keys', body, expect=(201,))
        self.key_id, self.ingest_key = key.get('id'), key.get('key', '')
        if not self.ingest_key:
            raise SmokeFailure(f'api key response carried no plaintext key: {key}')
        return f'minted temporary key prefix={key.get("prefix")} (revoked at the end)'

    def ingest_event(self) -> str:
        external_id = f'smoke-{self.run_id}'
        now = datetime.now(timezone.utc).isoformat()
        event = {'id': external_id, 'title': f'[SMOKE] synthetic event {self.run_id}', 'severity': 'low', 'category': 'smoke',
                 'actor': 'smoke-test@argus.local', 'entity': f'host:smoke-{self.run_id}', 'action': 'smoke.test',
                 'occurred_at': now, 'source': 'smoke-test', 'ip': '203.0.113.7', 'metadata': {'smoke': True, 'run': self.run_id}}
        headers = {'X-API-Key': self.ingest_key}
        if self.asset_id:
            headers['X-Asset-Id'] = self.asset_id
        _, result = self.client.call('POST', '/api/v1/ingest/generic', [event], headers=headers, expect=(200,))
        if result.get('accepted', 0) < 1 or not result.get('event_ids'):
            raise SmokeFailure(f'ingest did not accept the event: {result}')
        self.event_id = result['event_ids'][0]
        return f'accepted={result["accepted"]} duplicates={result.get("duplicates")} event_id={self.event_id}'

    def confirm_event(self) -> str:
        _, event = self.client.call('GET', f'/api/v1/events/{self.event_id}')
        if event.get('action') != 'smoke.test' or event.get('asset_id') != self.asset_id:
            raise SmokeFailure(f'event read-back mismatch: {event}')
        _, page = self.client.call('GET', '/api/v1/events?' + urllib.parse.urlencode({'search': f'smoke-{self.run_id}', 'limit': 5}))
        if not any(item.get('id') == self.event_id for item in page.get('items', [])):
            raise SmokeFailure('event is not returned by the list endpoint search')
        return f'source={event.get("source")} received_at={event.get("received_at")}'

    def run_detections(self) -> str:
        _, job = self.client.call('POST', '/api/v1/detections/run', {'since_minutes': 60}, expect=(202,))
        self.job_id = job.get('job_id')
        if not self.job_id:
            raise SmokeFailure(f'no job id returned: {job}')
        deadline = time.monotonic() + self.args.job_timeout
        last: dict = {}
        while time.monotonic() < deadline:
            _, last = self.client.call('GET', f'/api/v1/ops/jobs/{self.job_id}')
            status = last.get('status')
            if status == 'completed':
                result = last.get('result') or {}
                return (f'job={self.job_id} rules_run={result.get("rules_run")} events_scanned={result.get("events_scanned")} '
                        f'detections_created={result.get("detections_created")} errors={len(result.get("errors") or [])}')
            if status in {'failed', 'cancelled'}:
                raise SmokeFailure(f'detection job {status}: {last.get("error")}')
            time.sleep(2)
        raise SmokeFailure(f'detection job {self.job_id} still {last.get("status")!r} after {self.args.job_timeout}s: '
                           'no worker is consuming the queue (check `docker compose logs worker` / the worker deployment)')

    def detection_stats(self) -> str:
        _, stats = self.client.call('GET', '/api/v1/detections/stats')
        last_run = stats.get('last_run') or {}
        if not last_run:
            raise SmokeFailure('detections/stats reports no run after the job completed')
        return f'rules_registered={stats.get("rules_registered")} last_run.trigger={last_run.get("trigger")} open_by_severity={stats.get("open_by_severity")}'

    def verify_audit(self) -> str:
        _, result = self.client.call('GET', '/api/v1/audit/verify')
        if result.get('valid') is not True:
            raise SmokeFailure(f'audit chain is NOT valid: {result}')
        if int(result.get('checked') or 0) < 1:
            raise SmokeFailure(f'audit chain verified zero entries: {result}')
        _, page = self.client.call('GET', '/api/v1/audit?' + urllib.parse.urlencode({'subject': self.asset_id or '', 'limit': 5}))
        if not any(item.get('action') == 'assets.created' for item in page.get('items', [])):
            raise SmokeFailure('audit log has no assets.created entry for the smoke asset')
        return f'valid=true checked={result.get("checked")} signed={result.get("signed")}'

    def cleanup(self) -> str:
        notes = []
        if self.key_id:
            self.client.call('DELETE', f'/api/v1/auth/api-keys/{self.key_id}')
            notes.append('temporary ingest key revoked')
            _, _ = self.client.call('GET', '/api/v1/auth/session', headers={'X-API-Key': self.ingest_key}, expect=(401,))
            notes.append('revoked key rejected (401)')
        if self.asset_id and not self.args.keep:
            self.client.call('DELETE', f'/api/v1/assets/{self.asset_id}')
            notes.append('smoke asset deleted (event kept as evidence)')
        elif self.asset_id:
            notes.append(f'asset kept: {self.asset_id}')
        self.client.call('POST', '/api/v1/auth/logout')
        notes.append('logged out')
        return '; '.join(notes)

    # ------------------------------------------------------------ run

    def run(self) -> int:
        _out(f'Argus smoke test {self.run_id} against {self.client.base_url} as {self.args.email}')
        self.step('health and readiness', self.check_health)
        self.step('login', self.login)
        self.step('create asset', self.create_asset)
        self.step('ingest key', self.ensure_ingest_key)
        self.step('ingest event', self.ingest_event)
        self.step('event visible', self.confirm_event)
        self.step('run detections (queue + worker)', self.run_detections)
        self.step('detection stats', self.detection_stats)
        self.step('audit chain verify', self.verify_audit)
        if self.client.csrf:
            self.step('cleanup', self.cleanup)
        passed = sum(1 for _, ok, _ in self.results if ok)
        total = len(self.results)
        verdict = 'FAILED' if self.failed else 'OK'
        _out(f'\n{verdict}: {passed}/{total} steps passed; request ids: {", ".join(self.client.request_ids[-3:]) or "n/a"}')
        return 1 if self.failed else 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Argus day-1 smoke test (login, asset, ingest, detections, audit chain).')
    parser.add_argument('--url', default=os.getenv('ARGUS_URL', DEFAULT_URL))
    parser.add_argument('--email', default=os.getenv('ARGUS_EMAIL', DEFAULT_EMAIL))
    parser.add_argument('--password', default=os.getenv('ARGUS_PASSWORD', ''))
    parser.add_argument('--tenant', default=os.getenv('ARGUS_TENANT', ''), help='tenant slug')
    parser.add_argument('--totp', default=os.getenv('ARGUS_TOTP', ''), help='current 6-digit TOTP code')
    parser.add_argument('--totp-secret', default=os.getenv('ARGUS_TOTP_SECRET', ''), help='base32 TOTP secret (code computed locally)')
    parser.add_argument('--ingest-key', default=os.getenv('ARGUS_INGEST_KEY', ''), help='existing ingest API key (else a temporary one is minted)')
    parser.add_argument('--job-timeout', type=int, default=int(os.getenv('ARGUS_SMOKE_JOB_TIMEOUT', JOB_TIMEOUT_SECONDS)))
    parser.add_argument('--keep', action='store_true', help='leave the smoke asset in place')
    parser.add_argument('--insecure', action='store_true', default=os.getenv('ARGUS_INSECURE') == '1', help='skip TLS verification (lab only)')
    args = parser.parse_args(argv)
    if not args.password:
        if sys.stdin.isatty():
            args.password = getpass.getpass(f'Password for {args.email}: ')
        else:
            parser.error('set ARGUS_PASSWORD or pass --password')
    return args


def main(argv: list[str]) -> int:
    try:
        return Smoke(parse_args(argv)).run()
    except KeyboardInterrupt:
        _out('interrupted')
        return 130


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
