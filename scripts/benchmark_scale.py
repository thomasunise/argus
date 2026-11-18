"""Scale benchmark for Argus: measures ingest throughput (events/sec), p95 API latency (ms),
and queue throughput (jobs/sec) across 2, 4, and 8 workers.

Usage:
    python scripts/benchmark_scale.py [--events 1000] [--requests 200] [--jobs 200]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import tempfile
import time
from pathlib import Path

from app.core.config import Settings
from app.core.queue import JobQueue
from app.main import create_app
from fastapi.testclient import TestClient


async def measure_queue_throughput(settings: Settings, workers: int, n_jobs: int = 200) -> dict[str, float]:
    q = JobQueue(settings.model_copy(update={'redis_url': ''}))

    @q.handler('bench.noop')
    async def _noop(job, ctx):
        return {'ok': True, 'i': job.payload.get('i', 0)}

    await q.start(concurrency=workers)
    t0 = time.perf_counter()
    jobs = [await q.enqueue('bench.noop', {'i': i}, tenant_id='bench-tenant') for i in range(n_jobs)]
    for j in jobs:
        await q.wait(j.id, timeout=30)
    elapsed = max(1e-6, time.perf_counter() - t0)
    await q.stop()
    return {
        'workers': workers,
        'jobs': n_jobs,
        'elapsed_seconds': round(elapsed, 4),
        'jobs_per_second': round(n_jobs / elapsed, 2),
    }


def run_scale_benchmark(n_events: int = 500, n_requests: int = 120, n_jobs: int = 160) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        settings = Settings(
            app_env='development',
            database_url=f"sqlite:///{tmp_path / 'scale.db'}",
            session_secret='scale-bench-session-secret-longer-than-32-bytes',  # noqa: S106
            admin_password='scale-bench-admin-password-123456',  # noqa: S106
            ingest_api_key='argus_scale01_ingest_key_benchmark_long_enough',
            data_encryption_key='scale-bench-dek-longer-than-32-characters',
            audit_signing_key='scale-bench-audit-signing-key-32-chars',
            password_scrypt_n=2 ** 14,
            autoscan_enabled=False,
            workers_inprocess=False,
        )
        app = create_app(settings)
        with TestClient(app) as client:
            # 1. Measure ingest events/sec in batches of 100
            batch_size = 100
            batches = max(1, n_events // batch_size)
            total_events = batches * batch_size
            headers = {'X-API-Key': settings.ingest_api_key}
            t_ingest0 = time.perf_counter()
            for b in range(batches):
                events = [
                    {
                        'id': f'bench-ev-{b}-{i}',
                        'title': f'Benchmark event {b}:{i}',
                        'severity': 'low',
                        'category': 'network',
                        'actor': 'host:10.0.0.1',
                        'action': 'net.conn',
                        'entity': '198.51.100.1:443',
                    }
                    for i in range(batch_size)
                ]
                r = client.post('/api/v1/ingest/generic', json=events, headers=headers)
                assert r.status_code in (200, 202), r.text
            ingest_elapsed = max(1e-6, time.perf_counter() - t_ingest0)
            events_per_sec = round(total_events / ingest_elapsed, 2)

            # 2. Measure API p50 / p95 / p99 latency (ms)
            login_resp = client.post('/api/v1/auth/login', json={'email': settings.admin_email, 'password': settings.admin_password})
            assert login_resp.status_code == 200
            latencies_ms: list[float] = []
            endpoints = ('/api/v1/findings', '/api/v1/events', '/api/v1/detections/rules', '/api/v1/reports/summary')
            for i in range(n_requests):
                ep = endpoints[i % len(endpoints)]
                t0 = time.perf_counter()
                resp = client.get(ep)
                assert resp.status_code == 200
                latencies_ms.append((time.perf_counter() - t0) * 1000.0)
            latencies_sorted = sorted(latencies_ms)
            p50 = latencies_sorted[int(0.50 * (len(latencies_sorted) - 1))]
            p95 = latencies_sorted[int(0.95 * (len(latencies_sorted) - 1))]
            p99 = latencies_sorted[int(0.99 * (len(latencies_sorted) - 1))]

        # 3. Measure queue throughput at 2, 4, and 8 workers
        queue_results = [
            asyncio.run(measure_queue_throughput(settings, workers=w, n_jobs=n_jobs))
            for w in (2, 4, 8)
        ]

        return {
            'ingest': {
                'events': total_events,
                'elapsed_seconds': round(ingest_elapsed, 4),
                'events_per_second': events_per_sec,
            },
            'api_latency_ms': {
                'requests': n_requests,
                'mean_ms': round(statistics.mean(latencies_ms), 2),
                'p50_ms': round(p50, 2),
                'p95_ms': round(p95, 2),
                'p99_ms': round(p99, 2),
            },
            'queue_throughput': queue_results,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description='Argus scale and latency benchmark')
    parser.add_argument('--events', type=int, default=500)
    parser.add_argument('--requests', type=int, default=120)
    parser.add_argument('--jobs', type=int, default=160)
    args = parser.parse_args()
    report = run_scale_benchmark(n_events=args.events, n_requests=args.requests, n_jobs=args.jobs)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
