"""Bounded, read-only load smoke test for Argus readiness.

This is not a capacity benchmark. It issues only GET /ready, caps the request
volume and concurrency, and exits nonzero when the response target is missed.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import statistics
import time
from urllib.request import urlopen


def probe(url: str) -> tuple[float, bool]:
    start = time.perf_counter()
    try:
        with urlopen(url + '/ready', timeout=8) as r:
            success = r.status == 200 and b'"ready"' in r.read(16_384)
    except Exception:
        success = False
    return round((time.perf_counter() - start) * 1000, 2), success


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8080')
    parser.add_argument('--requests', type=int, default=50)
    parser.add_argument('--concurrency', type=int, default=4)
    parser.add_argument('--max-p95-ms', type=float, default=3000)
    parser.add_argument('--max-failure-rate', type=float, default=0.01)
    args = parser.parse_args()
    if not 1 <= args.requests <= 1000 or not 1 <= args.concurrency <= 20:
        parser.error('requests must be 1..1000 and concurrency 1..20')
    url = args.url.rstrip('/')
    if not url.startswith(('http://127.0.0.1:', 'http://localhost:', 'https://')):
        parser.error('target must be local HTTP or explicit HTTPS')
    begin = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        results = list(pool.map(lambda _: probe(url), range(args.requests)))
    values = sorted(x[0] for x in results)
    p95 = values[min(len(values) - 1, math.ceil(0.95 * len(values)) - 1)]
    failures = sum(not success for _, success in results)
    report = {
        'endpoint': '/ready', 'requests': args.requests, 'concurrency': args.concurrency,
        'failures': failures, 'failure_rate': round(failures / len(results), 4),
        'p50_ms': statistics.median(values), 'p95_ms': p95, 'max_ms': max(values),
        'total_elapsed_seconds': round(time.perf_counter() - begin, 3),
    }
    print(json.dumps(report, indent=2))
    return int(report['failure_rate'] > args.max_failure_rate or p95 > args.max_p95_ms)


if __name__ == '__main__':
    raise SystemExit(main())
