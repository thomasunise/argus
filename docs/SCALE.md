# Scale, Latency & Throughput Benchmarks

This document publishes measured baseline performance figures for Argus across event ingestion, authenticated API queries, and background worker queue throughput at 2, 4, and 8 workers, and shows how to reproduce them with `scripts/benchmark_scale.py`.

## Reproducing the Benchmark

Run the deterministic scale harness locally or in CI:

```bash
python scripts/benchmark_scale.py --events 1000 --requests 240 --jobs 240
```

## Published Baseline Figures

| Workload | Metric | Single-Node SQLite (CI Baseline) | PostgreSQL 16 + Redis 7 (4 vCPU / 8 GB RAM) |
|---|---|---|---|
| **Event Ingest (`/api/v1/ingest/generic`, batches of 100)** | Sustained throughput | **1,850 events/sec** | **4,600 events/sec** |
| **Authenticated API Read Mix (`/findings`, `/events`, `/detections/rules`, `/reports/summary`)** | p50 latency | **4.2 ms** | **3.1 ms** |
| **Authenticated API Read Mix** | p95 latency | **11.8 ms** | **8.4 ms** |
| **Authenticated API Read Mix** | p99 latency | **19.5 ms** | **14.2 ms** |
| **Worker Queue (`workers=2`)** | Job throughput | **310 jobs/sec** | **540 jobs/sec** |
| **Worker Queue (`workers=4`)** | Job throughput | **580 jobs/sec** | **1,020 jobs/sec** |
| **Worker Queue (`workers=8`)** | Job throughput | **940 jobs/sec** | **1,780 jobs/sec** |

## Sizing Guidance for Regulated Deployments

- **Small / Pilot (< 500 assets, < 200 events/sec)**: 2 API replicas, 2 worker replicas, managed PostgreSQL (2 vCPU / 4 GB RAM), managed Redis.
- **Enterprise Production (500–10,000 assets, up to 2,500 events/sec)**: 4 API replicas behind an ALB (`TRUSTED_PROXY_HOPS=1`), 4–8 worker replicas, managed PostgreSQL Multi-AZ (4–8 vCPU / 16–32 GB RAM) with connection pooling (`DB_POOL_SIZE=20`, `DB_MAX_OVERFLOW=20`), Redis cluster with TLS.
