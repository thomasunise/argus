"""Fetch, validate and normalize the Retire.js CVE repository into app/testing/data/retirejs_db.json.

Usage:
    python scripts/update_retirejs_db.py [--source URL_OR_PATH] [--output PATH] [--verify-only]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import urllib.request

UPSTREAM_URL = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json'
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / 'app' / 'testing' / 'data' / 'retirejs_db.json'
SKIP_KEYS = {'$schema', 'dont check', 'retire-example'}


def normalize_repository(raw: dict) -> dict:
    """Keep valid library entries with extractors and vulnerabilities."""
    if not isinstance(raw, dict):
        raise ValueError('Retire.js repository root must be a JSON object')
    cleaned: dict[str, dict] = {}
    for name, entry in raw.items():
        if name in SKIP_KEYS or not isinstance(entry, dict):
            continue
        extractors = entry.get('extractors')
        vulns = entry.get('vulnerabilities')
        if not isinstance(extractors, dict) or not isinstance(vulns, list) or not vulns:
            continue
        norm_extractors: dict[str, list[str]] = {}
        for kind in ('uri', 'filename', 'filecontent'):
            pats = extractors.get(kind)
            if isinstance(pats, list):
                valid_pats = [str(p) for p in pats if isinstance(p, str) and p.strip()]
                if valid_pats:
                    norm_extractors[kind] = valid_pats
        if not norm_extractors:
            continue
        norm_vulns: list[dict] = []
        for v in vulns:
            if not isinstance(v, dict) or not v.get('below'):
                continue
            ident = v.get('identifiers') if isinstance(v.get('identifiers'), dict) else {}
            cves = [str(c) for c in (ident.get('CVE') or []) if isinstance(c, str) and c.startswith('CVE-')]
            summary = str(ident.get('summary') or ident.get('issue') or '')[:500]
            item: dict = {
                'below': str(v['below']),
                'severity': str(v.get('severity') or 'medium').lower(),
                'identifiers': {'CVE': cves, 'summary': summary},
            }
            if v.get('atOrAbove'):
                item['atOrAbove'] = str(v['atOrAbove'])
            if isinstance(v.get('info'), list):
                item['info'] = [str(u) for u in v['info'][:3] if isinstance(u, str)]
            norm_vulns.append(item)
        if norm_vulns:
            cleaned[str(name)] = {'extractors': norm_extractors, 'vulnerabilities': norm_vulns}
    if not cleaned:
        raise ValueError('No valid library definitions found in Retire.js repository')
    return cleaned


def load_source(source: str) -> dict:
    if source.startswith(('http://', 'https://')):
        req = urllib.request.Request(source, headers={'User-Agent': 'Argus-RetireJS-Updater/1.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return json.loads(resp.read().decode('utf-8'))
    return json.loads(Path(source).read_text(encoding='utf-8'))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Update bundled Retire.js CVE repository.')
    parser.add_argument('--source', default=UPSTREAM_URL, help='Upstream URL or local JSON path.')
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT), help='Destination JSON path.')
    parser.add_argument('--verify-only', action='store_true', help='Validate the existing database without writing.')
    args = parser.parse_args(argv)

    target_src = str(args.output) if args.verify_only and args.source == UPSTREAM_URL else str(args.source)
    raw = load_source(target_src)
    cleaned = normalize_repository(raw)
    if args.verify_only:
        print(f'Verified {len(cleaned)} libraries in {target_src}')
        return 0
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix('.json.tmp')
    tmp_path.write_text(json.dumps(cleaned, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    tmp_path.replace(out_path)
    print(f'Wrote {len(cleaned)} libraries to {out_path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
