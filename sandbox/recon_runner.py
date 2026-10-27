#!/usr/bin/env python3
"""Bounded web discovery for one asset origin.

Produces facts, not findings: endpoints found by crawling the entry page, robots.txt and a small
fixed path list, plus technology hints from response headers. It never brute-forces directories
with a wordlist, never sends payloads and never leaves the origin.

Emits `ARGUS_DISCOVERY {json}` per fact and an `ARGUS_ENGINE {json}` trailer.
"""
from __future__ import annotations

import json
import os
import re
import sys
from urllib.parse import urljoin, urlsplit

import httpx

DISCOVERY_MARKER = 'ARGUS_DISCOVERY '
TRAILER = 'ARGUS_ENGINE '
MAX_BODY = 512 * 1024

COMMON_PATHS = ('/', '/robots.txt', '/sitemap.xml', '/.well-known/security.txt', '/login', '/admin',
                '/api', '/api/v1', '/graphql', '/health', '/metrics', '/openapi.json', '/swagger.json')

_LINK = re.compile(r'''(?:href|src|action|data-url)\s*=\s*["']([^"'#]{1,300})["']''', re.IGNORECASE)
_JS_PATH = re.compile(r'''["'](/[A-Za-z0-9_\-./]{2,120})["']''')
_TECH_HEADERS = ('server', 'x-powered-by', 'x-aspnet-version', 'x-generator', 'via')


def extract_paths(html: str, base_path: str = '/', origin_host: str = '') -> list[str]:
    """Every same-origin path referenced by a document; other origins are skipped, not rewritten."""
    found: list[str] = []
    for match in _LINK.finditer(html or ''):
        raw = match.group(1).strip()
        if raw.startswith(('mailto:', 'tel:', 'javascript:')):
            continue
        absolute = urlsplit(raw)
        if absolute.hostname and origin_host and absolute.hostname != origin_host:
            continue
        path = urlsplit(urljoin(base_path, raw)).path or '/'
        if path not in found:
            found.append(path)
    for match in _JS_PATH.finditer(html or ''):
        path = match.group(1)
        if path not in found:
            found.append(path)
    return found[:200]


def technologies(headers: dict[str, str]) -> list[str]:
    out: list[str] = []
    for name in _TECH_HEADERS:
        value = headers.get(name, '')
        if value and len(value) <= 120:
            out.append(f'{name}: {value}')
    return out


def _emit(kind: str, value: str, source: str) -> None:
    print(DISCOVERY_MARKER + json.dumps({'kind': kind, 'value': value[:500], 'source': source}, separators=(',', ':')))


def main(argv: list[str]) -> int:
    target, max_endpoints = '', 100
    for index, value in enumerate(argv):
        if value == '--target' and index + 1 < len(argv):
            target = argv[index + 1]
        elif value == '--max-endpoints' and index + 1 < len(argv):
            try:
                max_endpoints = max(1, min(500, int(argv[index + 1])))
            except ValueError:
                max_endpoints = 100
    if not target:
        print('missing --target', file=sys.stderr)
        print(TRAILER + json.dumps({'exit_code': 2, 'discoveries': 0}))
        return 2

    discovered: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    def add(kind: str, value: str, source: str) -> None:
        key = f'{kind}:{value}'
        if key in seen or len(discovered) >= max_endpoints:
            return
        seen.add(key)
        discovered.append((kind, value, source))
        _emit(kind, value, source)

    base = urlsplit(target)
    origin = f'{base.scheme}://{base.netloc}'
    with httpx.Client(base_url=origin, timeout=httpx.Timeout(10.0), follow_redirects=False,
                      trust_env=False, verify=True, headers={'User-Agent': 'argus-discovery/1.0'}) as client:
        for path in COMMON_PATHS:
            try:
                response = client.get(path)
            except httpx.HTTPError:
                continue
            if response.status_code >= 500:
                continue
            if response.status_code < 400:
                if path != '/':
                    add('endpoint', path, 'probe')
                for tech in technologies(dict(response.headers)):
                    add('technology', tech, 'headers')
                content_type = response.headers.get('content-type', '')
                if 'html' in content_type or path == '/':
                    body = response.text[:MAX_BODY]
                    for found in extract_paths(body, path, base.hostname or ''):
                        add('endpoint', found, 'crawl')
            elif response.status_code in (401, 403):
                add('endpoint', path, 'probe-protected')

    print(TRAILER + json.dumps({'exit_code': 0, 'discoveries': len(discovered)}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
