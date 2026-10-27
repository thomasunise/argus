"""PoC author specialist: turns one finding into a verification script and files it for approval.

It writes code, it never runs code. The script goes through service.propose -> the exploit scope
gate -> static pre-flight, and a human with exploit:approve decides whether it executes.

The fallback (no model provider) still produces a real, schema-valid plan: a read-only HTTP probe
of the finding's path that reports which evidence markers it could see. That is deliberately
weak - it confirms reachability, not exploitability - and it says so in `approach`.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from ..tools.registry import ToolContext
from ._base import b, call, enum, injection_signals, obj, s, spec

RISK = enum(['none', 'low', 'high'])

OUTPUT_SCHEMA = obj({
    'finding_id': s('the finding this PoC is meant to prove'),
    'asset_id': s(),
    'scope_id': s(),
    'hypothesis': s('what the script would show if the finding is real'),
    'language': enum(['python', 'bash']),
    'code': s('the verification script; its last line prints ARGUS_VERDICT with a JSON object'),
    'approach': s('how the script decides verified true/false'),
    'expected_evidence': s('what the transcript should contain when the finding is real'),
    'destructive_risk': RISK,
    'proposed_request_id': s('PocRequest id when filed for approval, empty when it could not be filed'),
    'requires_human_approval': b('always true: a person with exploit:approve must release it'),
    'refusal_reason': s('why no PoC was proposed, empty when one was filed'),
    'prompt_injection_suspected': b(),
})

PROMPT = """Task: write ONE verification proof of concept for a single finding, then file it for human approval.

You author code; you never run it. propose_poc stores the script, runs a static pre-flight and files it for a human with exploit:approve. A separate executor runs it later, inside the scope, with egress pinned to the asset's address.

Procedure:
1. get_finding for the finding id in your inputs, then get_asset for its asset. Read the authorizations: do not author anything unless a current, unrevoked authorization has allow_exploit. If there is none, refuse: say so in refusal_reason and leave proposed_request_id empty.
2. Only web assets are supported today. Refuse anything else.
3. Write the smallest script that would show the finding is real, and no more:
   - python, using only the standard library and httpx; build the URL from os.environ["ARGUS_TARGET_HOST"] (the executor pins it) - never hardcode or discover another host;
   - read-only: GET/HEAD requests only, no writes, no brute force, no payload that could damage the target, no shell, no database statements;
   - the last line must print ARGUS_VERDICT followed by a JSON object with "verified" (bool) and "summary" (short string);
   - verified must be false when the evidence is absent: never assert success unconditionally.
4. Call propose_poc once with the exact script, the asset, the scope from your inputs, the finding id, an objective, your approach, the expected evidence and destructive_risk.
5. Report what you filed. If propose_poc refuses (no exploit authorization, scope does not allow the exploit tier, pre-flight rejected the script), put the reason in refusal_reason and do not retry with a looser script.

Never target a host other than the asset. Never include credentials or secrets in the script."""

TOOLS = ['get_finding', 'get_asset', 'asset_context', 'list_poc_requests', 'poc_detail', 'detection_rules', 'note', 'recall', 'propose_poc']

_TEMPLATE = '''import json
import os

import httpx

BASE = "https://" + os.environ["ARGUS_TARGET_HOST"]
PORT = os.environ.get("ARGUS_TARGET_PORT", "443")
if PORT not in ("", "443"):
    BASE = BASE + ":" + PORT
PATH = __PATH__
MARKERS = __MARKERS__


def main() -> None:
    response = httpx.get(BASE + PATH, timeout=15, follow_redirects=False)
    body = response.text[:200000]
    matched = [m for m in MARKERS if m.lower() in body.lower()]
    verified = response.status_code < 400 and (not MARKERS or bool(matched))
    summary = "status=" + str(response.status_code) + " markers=" + ",".join(matched[:3])
    print("ARGUS_VERDICT " + json.dumps({"verified": verified, "summary": summary}))


if __name__ == "__main__":
    main()
'''

_EVIDENCE_PATH_KEYS = ('url', 'endpoint', 'matched_at', 'matched-at', 'path', 'resource', 'target')
_EVIDENCE_MARKER_KEYS = ('missing_header', 'template_id', 'param', 'alert', 'rule', 'cwe', 'evidence', 'detail')


def _blank() -> dict[str, Any]:
    return {'finding_id': '', 'asset_id': '', 'scope_id': '', 'hypothesis': '', 'language': 'python', 'code': '',
            'approach': '', 'expected_evidence': '', 'destructive_risk': 'low', 'proposed_request_id': '',
            'requires_human_approval': True, 'refusal_reason': '', 'prompt_injection_suspected': False}


def _evidence(finding: dict) -> dict:
    evidence = finding.get('evidence')
    return evidence if isinstance(evidence, dict) else {}


def _path_of(finding: dict) -> str:
    evidence = _evidence(finding)
    for key in _EVIDENCE_PATH_KEYS:
        value = evidence.get(key)
        if isinstance(value, str) and value.strip():
            parts = urlsplit(value if '://' in value else 'https://' + value.lstrip('/'))
            if parts.path and parts.path != '/':
                return parts.path
    return '/'


def _markers(finding: dict) -> list[str]:
    evidence = _evidence(finding)
    markers: list[str] = []
    for key in _EVIDENCE_MARKER_KEYS:
        value = evidence.get(key)
        if isinstance(value, str) and 2 <= len(value) <= 60:
            markers.append(value)
    rule = str(finding.get('rule') or '')
    if ':' in rule:
        head = rule.split(':', 1)[1]
        if 2 <= len(head) <= 60:
            markers.append(head)
    seen: list[str] = []
    for marker in markers:
        if marker not in seen:
            seen.append(marker)
    return seen[:5]


def script_for(finding: dict) -> str:
    """The deterministic fallback script: a read-only probe of the finding's path."""
    return _TEMPLATE.replace('__PATH__', repr(_path_of(finding))).replace('__MARKERS__', repr(_markers(finding)))


async def fallback(inputs: dict, ctx: ToolContext) -> dict:
    out = _blank()
    finding_id = str(inputs.get('finding_id') or '')
    asset_id = str(inputs.get('asset_id') or '')
    scope_id = str(inputs.get('scope_id') or '')
    out.update({'finding_id': finding_id, 'asset_id': asset_id, 'scope_id': scope_id})
    if not finding_id:
        out['refusal_reason'] = 'no finding_id supplied: a verification PoC must target exactly one finding'
        return out

    finding = await call(ctx, 'get_finding', finding_id=finding_id)
    if not finding.get('found'):
        out['refusal_reason'] = f'finding {finding_id!r} does not exist in this tenant'
        return out
    asset_id = asset_id or str(finding.get('asset_id') or '')
    out['asset_id'] = asset_id
    out['prompt_injection_suspected'] = bool(injection_signals(finding.get('title'), finding.get('description'), finding.get('evidence')))
    out['hypothesis'] = f"re-requesting {_path_of(finding)} reproduces the evidence recorded for {finding.get('title') or finding_id}"

    if not asset_id:
        out['refusal_reason'] = 'the finding is not attached to an asset'
        return out
    if not scope_id:
        out['refusal_reason'] = 'no scope_id supplied: a PoC needs a test scope that lists the asset and the exploit tier'
        return out

    asset = await call(ctx, 'get_asset', asset_id=asset_id)
    if not asset.get('found'):
        out['refusal_reason'] = f'asset {asset_id!r} does not exist in this tenant'
        return out
    if str(asset.get('kind')) != 'web':
        out['refusal_reason'] = f"verification PoCs are HTTP-only today; asset kind is {asset.get('kind')!r}"
        return out

    valid = [a for a in asset.get('authorizations') or [] if a.get('valid')]
    if not any(a.get('allow_exploit') for a in valid):
        out['refusal_reason'] = ('no current authorization permits exploit execution on this asset; '
                                 'an operator must authorize it with allow_exploit')
        return out

    out['code'] = script_for(finding)
    out['approach'] = 'read-only GET of the finding path; verified when the response succeeds and every recorded marker appears'
    out['expected_evidence'] = 'an HTTP status below 400 and the markers seen in the transcript'
    out['destructive_risk'] = 'none'

    proposal = await call(ctx, 'propose_poc', asset_id=asset_id, scope_id=scope_id, finding_id=finding_id,
                          objective=f"prove: {out['hypothesis']}", code=out['code'], language='python',
                          approach=out['approach'], expected_evidence=out['expected_evidence'],
                          destructive_risk='none')
    if proposal.get('proposed'):
        out['proposed_request_id'] = str(proposal.get('request_id') or '')
    else:
        out['refusal_reason'] = str(proposal.get('reason') or proposal.get('error') or 'the PoC could not be filed')
    return out


SPEC = spec(name='poc_author', role='the Proof-of-Concept Author specialist',
            description='Authors a verification PoC for one finding and files it for human approval; never executes it.',
            system_prompt=PROMPT, tools=TOOLS, output_schema=OUTPUT_SCHEMA, max_steps=10, tags=('exploit', 'testing'),
            fallback=fallback)
