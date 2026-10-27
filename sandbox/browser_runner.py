#!/usr/bin/env python3
"""Rendered-page discovery with passive request capture.

This is the browser half of discovery: it loads the asset in headless Chromium, lets the page make
its own requests, and records every same-origin request the page issued (the passive equivalent of
an interception proxy). Requests to other origins are aborted, so a third-party script cannot pull
the engine off the asset.

Playwright is imported lazily so the module can be unit-tested without a browser installed.
"""
from __future__ import annotations

import json
import os
import re
import sys
from urllib.parse import urlsplit, urljoin

MARKER = 'ARGUS_DISCOVERY '
TRAILER = 'ARGUS_ENGINE '
REQUEST_MARKER = 'ARGUS_REQUEST '
MAX_PAGES_HARD = 25
_LINK = re.compile(r'''(?:href|src|action)\s*=\s*["']([^"'#]{1,300})["']''', re.IGNORECASE)


def same_origin(url: str, origin: str) -> bool:
    if not url or not origin:
        return False
    parts = urlsplit(url)
    if not parts.hostname:
        return True  # relative
    return f'{parts.scheme}://{parts.netloc}' == origin.rstrip('/')


def normalize_path(url: str, origin: str) -> str:
    parts = urlsplit(url if '://' in url else urljoin(origin + '/', url))
    path = parts.path or '/'
    return path if len(path) <= 500 else path[:500]


def extract_links(html: str, base_url: str) -> list[str]:
    out: list[str] = []
    for match in _LINK.finditer(html or ''):
        raw = match.group(1).strip()
        if raw.startswith(('mailto:', 'tel:', 'javascript:', 'data:')):
            continue
        candidate = urljoin(base_url, raw)
        if same_origin(candidate, base_url):
            path = normalize_path(candidate, base_url)
            if path not in out:
                out.append(path)
    return out[:200]


def _emit(kind: str, value: str, source: str) -> None:
    print(MARKER + json.dumps({'kind': kind, 'value': value[:500], 'source': source}, separators=(',', ':')))


def main(argv: list[str]) -> int:
    target, max_pages = '', 10
    for index, value in enumerate(argv):
        if value == '--target' and index + 1 < len(argv):
            target = argv[index + 1]
        elif value == '--max-pages' and index + 1 < len(argv):
            try:
                max_pages = max(1, min(MAX_PAGES_HARD, int(argv[index + 1])))
            except ValueError:
                max_pages = 10
    if not target:
        print('missing --target', file=sys.stderr)
        print(TRAILER + json.dumps({'exit_code': 2, 'discoveries': 0}))
        return 2

    origin = f'{urlsplit(target).scheme}://{urlsplit(target).netloc}'
    captured: list[str] = []
    seen_requests: set[tuple[str, str]] = set()
    links: list[str] = []
    visited: list[str] = []
    blocked = 0

    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    with sync_playwright() as play:
        browser = play.chromium.launch(args=['--no-sandbox', '--disable-dev-shm-usage'])
        context = browser.new_context(ignore_https_errors=False, user_agent='argus-discovery/1.0',
                                      service_workers='block')
        page = context.new_page()

        def route_handler(route):
            nonlocal blocked
            if same_origin(route.request.url, origin):
                route.continue_()
            else:
                blocked += 1
                route.abort()

        page.route('**/*', route_handler)

        def on_request(request):
            if same_origin(request.url, origin):
                path = normalize_path(request.url, origin)
                if path not in captured and len(captured) < 300:
                    captured.append(path)

        page.on('request', on_request)

        def on_response(response):
            try:
                if not same_origin(response.url, origin) or len(seen_requests) >= 300:
                    return
                key = (response.request.method.upper(), normalize_path(response.url, origin))
                if key in seen_requests:
                    return
                seen_requests.add(key)
                headers = response.request.headers
                print(REQUEST_MARKER + json.dumps({
                    'method': key[0], 'path': key[1], 'status': response.status,
                    'content_type': (response.headers.get('content-type') or '')[:120],
                    'has_auth': bool(headers.get('authorization') or headers.get('cookie')),
                }, separators=(',', ':')))
            except Exception:  # noqa: BLE001 - a capture failure must not stop the crawl
                return

        page.on('response', on_response)
        queue = [target]
        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            try:
                page.goto(url, wait_until='networkidle', timeout=20_000)
                visited.append(url)
            except PlaywrightError:
                continue
            try:
                html = page.content()[:500_000]
            except PlaywrightError:
                continue
            for path in extract_links(html, origin):
                if path not in links:
                    links.append(path)
            for path in links[::-1][:20]:
                candidate = origin + path
                if candidate not in visited and candidate not in queue:
                    queue.append(candidate)
        context.close()
        browser.close()

    emitted = 0
    for path in captured:
        _emit('endpoint', path, 'browser-request')
        emitted += 1
    for path in links:
        if path not in captured:
            _emit('endpoint', path, 'browser-dom')
            emitted += 1
    _emit('technology', f'headless-chromium: {len(visited)} page(s)', 'browser')
    print(TRAILER + json.dumps({'exit_code': 0, 'discoveries': emitted, 'blocked_third_party': blocked}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
