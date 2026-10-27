#!/usr/bin/env python3
"""Runs Strix inside the engine container and normalizes its report.

Strix writes a run directory; the exact file layout is Strix's to change, so this wrapper is the
only place that knows it. It emits one `ARGUS_FINDINGS {json}` line per finding and an
`ARGUS_ENGINE {json}` trailer, which is what app/testing/adapters/strix.py parses.

The executor's pod is the sandbox. Strix's own nested Docker sandbox is not available inside it;
if your engine image needs extra flags, set ARGUS_STRIX_EXTRA_ARGS.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

FINDINGS_MARKER = 'ARGUS_FINDINGS '
TRAILER = 'ARGUS_ENGINE '
STRIX_BIN = os.environ.get('STRIX_BIN', 'strix')
WORKSPACE = os.environ.get('ARGUS_WORKSPACE', '/workspace')


def _args(argv: list[str]) -> tuple[str, str, str]:
    target, budget, run_id = '', '', ''
    for index, value in enumerate(argv):
        if value == '--target' and index + 1 < len(argv):
            target = argv[index + 1]
        elif value == '--budget' and index + 1 < len(argv):
            budget = argv[index + 1]
        elif value == '--run-id' and index + 1 < len(argv):
            run_id = argv[index + 1]
    return target, budget, run_id


def _candidates() -> list[Path]:
    roots = [Path(WORKSPACE) / 'strix_runs', Path(WORKSPACE)]
    out: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for pattern in ('**/*.json', '*.json'):
            out.extend(path for path in root.glob(pattern) if path.is_file())
    return sorted(set(out), key=lambda p: p.stat().st_mtime, reverse=True)


def _items_from(payload) -> list[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ('findings', 'vulnerabilities', 'results', 'issues'):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    if payload.get('title') or payload.get('name'):
        return [payload]
    return []


def _normalize(item: dict) -> dict:
    out = {
        'title': str(item.get('title') or item.get('name') or ''),
        'severity': str(item.get('severity') or item.get('risk') or 'medium').lower(),
        'description': str(item.get('description') or item.get('details') or '')[:8000],
        'remediation': str(item.get('remediation') or item.get('fix') or '')[:4000],
        'rule': str(item.get('rule') or item.get('id') or item.get('category') or item.get('vulnerability_type') or ''),
        'url': str(item.get('url') or item.get('endpoint') or ''),
    }
    poc = item.get('poc') or item.get('proof_of_concept') or item.get('exploit')
    if poc:
        out['poc'] = str(poc)[:8000]
    evidence = item.get('evidence')
    if isinstance(evidence, dict):
        out['evidence'] = {k: (str(v)[:1000] if isinstance(v, (str, int, float)) else v) for k, v in evidence.items()}
    cvss = item.get('cvss')
    if isinstance(cvss, (int, float)):
        out['cvss'] = float(cvss)
    cves = item.get('cve_ids') or item.get('cves')
    if isinstance(cves, list):
        out['cve_ids'] = [str(c) for c in cves if str(c).lower().startswith('cve-')][:10]
    return out


def main(argv: list[str]) -> int:
    target, budget, run_id = _args(argv)
    if not target:
        print('missing --target', file=sys.stderr)
        print(TRAILER + json.dumps({'exit_code': 2, 'findings': 0, 'run_id': run_id}))
        return 2

    command = [STRIX_BIN, '-n', '--target', target]
    if budget:
        command += ['--max-budget', budget]
    extra = os.environ.get('ARGUS_STRIX_EXTRA_ARGS', '').strip()
    if extra:
        command += extra.split()
    env = {**os.environ, 'HOME': WORKSPACE}

    try:
        completed = subprocess.run(command, cwd=WORKSPACE, env=env, capture_output=True, text=True, timeout=int(os.environ.get('ARGUS_WALL_SECONDS', '3600')) - 30)
        exit_code = completed.returncode
        if completed.stdout:
            print(completed.stdout[-20000:])
        if completed.stderr:
            print(completed.stderr[-20000:], file=sys.stderr)
    except subprocess.TimeoutExpired:
        exit_code = 124
        print('strix hit the wall clock', file=sys.stderr)
    except OSError as exc:
        print(f'could not start {STRIX_BIN}: {type(exc).__name__}', file=sys.stderr)
        print(TRAILER + json.dumps({'exit_code': 126, 'findings': 0, 'run_id': run_id}))
        return 126

    emitted = 0
    for path in _candidates()[:20]:
        try:
            payload = json.loads(path.read_text(encoding='utf-8', errors='replace'))
        except (ValueError, OSError):
            continue
        items = [_normalize(item) for item in _items_from(payload)]
        for item in items:
            if not item.get('title'):
                continue
            print(FINDINGS_MARKER + json.dumps(item, separators=(',', ':')))
            emitted += 1
        if items:
            break  # newest run report wins; older reports are history, not this run
    print(TRAILER + json.dumps({'exit_code': exit_code, 'findings': emitted, 'run_id': run_id}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
