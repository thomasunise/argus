"""HTML injection context adapter (intrusive, web): `browser_xss`.

Replaces raw substring reflection checks with HTML DOM parser sink confirmation:
- Sends a benign custom-element canary (`"><argus-xss data-canary="{nonce}">`) to candidate
  endpoints/parameters.
- Parses the response HTML document with `HTMLParser` to detect whether the canary broke out
  of its surrounding attribute/text context to create an injected DOM element or landed inside a
  `<script>` block.
- Reflections trapped inside HTML comments, `<textarea>`, `<title>`, `<style>`, `<noscript>`, or
  properly quoted non-event attributes are rejected. Parser evidence is NOT proof of script
  execution and must never automatically mark a finding as verified.
"""
from __future__ import annotations

from html.parser import HTMLParser
import secrets

import httpx

from ...core.config import Settings
from ..harness import HarnessContext, NormalizedFinding, TestAdapter, register

NON_EXECUTABLE_CONTAINERS = frozenset({'textarea', 'title', 'style', 'noscript', 'template', 'xmp'})
MAX_ENDPOINTS = 5
MAX_PARAMS = 5


class _DomSinkParser(HTMLParser):
    def __init__(self, nonce: str) -> None:
        super().__init__(convert_charrefs=False)
        self.nonce = nonce.lower()
        self.stack: list[str] = []
        self.sink: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_l = tag.lower()
        in_inert = any(t in NON_EXECUTABLE_CONTAINERS for t in self.stack)
        if not in_inert and self.sink is None:
            if tag_l == 'argus-xss':
                attr_map = {k.lower(): (v or '').lower() for k, v in attrs if k}
                if not self.nonce or attr_map.get('data-canary') == self.nonce or self.nonce in str(attr_map):
                    self.sink = {
                        'sink_type': 'dom_element_injection',
                        'tag': 'argus-xss',
                        'parent_tag': self.stack[-1] if self.stack else 'document',
                    }
            else:
                for attr_name, attr_val in attrs:
                    name_l = (attr_name or '').lower()
                    val_l = (attr_val or '').lower()
                    if name_l == 'data-canary' and self.nonce in val_l:
                        self.sink = {
                            'sink_type': 'attribute_breakout',
                            'tag': tag_l,
                            'attribute': name_l,
                        }
                        break
                    if name_l.startswith('on') and self.nonce in val_l:
                        self.sink = {
                            'sink_type': 'event_handler_injection',
                            'tag': tag_l,
                            'attribute': name_l,
                        }
                        break
        self.stack.append(tag_l)

    def handle_endtag(self, tag: str) -> None:
        tag_l = tag.lower()
        if tag_l in self.stack:
            idx = len(self.stack) - 1 - self.stack[::-1].index(tag_l)
            del self.stack[idx:]

    def handle_data(self, data: str) -> None:
        if self.sink is not None:
            return
        if self.stack and self.stack[-1] == 'script':
            if self.nonce and self.nonce in data.lower():
                self.sink = {
                    'sink_type': 'script_context_reflection',
                    'tag': 'script',
                }


def confirm_dom_sink(html: str, nonce: str) -> dict | None:
    """Return DOM sink metadata if `nonce` created an executable DOM element/attribute/script sink."""
    if not html or not nonce or nonce.lower() not in html.lower():
        return None
    parser = _DomSinkParser(nonce)
    try:
        parser.feed(html[:300_000])
        parser.close()
    except Exception:  # noqa: BLE001
        return None
    return parser.sink


class BrowserXssAdapter(TestAdapter):
    name = 'browser_xss'
    tier = 'intrusive'
    target_kinds = ('web',)
    description = 'Identifies suspicious HTML injection contexts; browser execution verification is not performed.'

    def available(self, settings: Settings) -> bool:
        return True

    async def run(self, plan_params: dict, asset, scope, ctx: HarnessContext) -> list[NormalizedFinding]:
        if ctx.tier != 'intrusive':
            return []
        target = (ctx.target or asset.target).rstrip('/')
        endpoints = [str(e) for e in (plan_params.get('endpoints') or ['/']) if str(e).startswith('/')][:MAX_ENDPOINTS]
        params = [str(p) for p in (plan_params.get('params') or ['q', 'search', 'id'])][:MAX_PARAMS]
        nonce = str(plan_params.get('nonce') or f'argus{secrets.token_hex(4)}')
        canary = f'"><argus-xss data-canary="{nonce}">'

        findings: list[NormalizedFinding] = []
        async with httpx.AsyncClient(
            base_url=target, timeout=httpx.Timeout(10.0), follow_redirects=False,
            trust_env=False, verify=True, limits=httpx.Limits(max_connections=2),
            headers=ctx.auth_headers or None,
        ) as client:
            for endpoint in endpoints:
                for param in params:
                    await ctx.rate_limiter.acquire()
                    try:
                        resp = await client.get(endpoint, params={param: canary})
                    except httpx.HTTPError:
                        continue
                    ctype = (resp.headers.get('content-type') or '').lower()
                    if ctype and 'html' not in ctype and 'xml' not in ctype:
                        continue
                    sink = confirm_dom_sink(resp.text, nonce)
                    if sink is None:
                        continue
                    findings.append(NormalizedFinding(
                        rule=f'xss-injection:{endpoint}:{param}',
                        title=f'HTML injection sink ({sink["sink_type"]}) in {param!r} on {endpoint}'[:240],
                        description=(
                            f'Canary input in parameter {param!r} on {endpoint} broke out of its surrounding HTML '
                            f'context and produced a parsed HTML sink ({sink["sink_type"]} on <{sink.get("tag", "unknown")}>). '
                            'JavaScript execution was not verified.'
                        ),
                        remediation='Apply context-aware HTML/attribute encoding and enforce a strict Content-Security-Policy.',
                        severity='high',
                        verified=False,
                        evidence={
                            'endpoint': endpoint,
                            'parameter': param,
                            'canary_nonce': nonce,
                            'sink': sink,
                            'status': resp.status_code,
                            'proof_type': 'html_sink_parser',
                            'verified': False,
                            'validation_level': 'injection_context',
                        },
                    ))
        return findings


register(BrowserXssAdapter())
