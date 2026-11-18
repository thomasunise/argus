# Scale, Latency & Throughput

What has been measured, on what, and what has not. Every figure on this page comes from `scripts/benchmark_scale.py`
and can be reproduced with the command below.

## Reproduce

```bash
ARGUS_LAZY_APP=1 PYTHONPATH=. python scripts/benchmark_scale.py --events 1000 --requests 240 --jobs 240
```

The harness starts the application in-process on a temporary SQLite database and drives it through the test client.
There is no network hop, no TLS, no PostgreSQL, no Redis and a single process. It is a regression baseline for the
application code, not a capacity figure for a deployment.

## Measured baseline

Three consecutive runs on 2026-11-18: 2 vCPU (Intel Xeon 2.1 GHz), 7 GB RAM, Python 3.13, SQLite, in-process.

| Workload | Metric | Result (range over 3 runs) |
|---|---|---|
| Event ingest (`/api/v1/ingest/generic`, batches of 100, 1,000 events) | Throughput | 1,060 to 1,140 events/sec |
| Authenticated read mix (`/findings`, `/events`, `/detections/rules`, `/reports/summary`, 240 requests) | p50 latency | 8.4 to 8.6 ms |
| Authenticated read mix | p95 latency | 15.7 to 17.4 ms |
| Authenticated read mix | p99 latency | 19.2 to 20.1 ms |
| In-process queue, 240 no-op jobs | Throughput | 1,790 to 2,450 jobs/sec |

The queue figure does not change between 2, 4 and 8 workers. The jobs are no-ops on the in-memory queue, so the
harness measures dispatch overhead, not how real work scales with workers.

## Not yet measured

These are the numbers a buyer will ask for. None of them exist yet.

- Ingest throughput and API latency on PostgreSQL 16 with Redis, behind a load balancer, with row-level security on.
- Sustained ingest over hours, including the point where PostgreSQL stops keeping up with event volume.
- Worker scaling with real jobs (detections, agent runs, deliveries) on the Redis queue at 2, 4 and 8 workers.
- Behaviour with more than one API replica.

To produce them, run a load generator against a deployed stack (the Helm chart or Terraform module) and record the
instance sizes next to the results. Add the figures to this page only with the command and hardware that produced them.

## Sizing

There is no validated sizing guidance yet, because the measurements above have not been taken on a production topology.
For a pilot, start with 2 API replicas, 2 worker replicas, managed PostgreSQL (2 vCPU, 4 GB) and managed Redis, set
`TRUSTED_PROXY_HOPS` to the number of proxies in front of the API, and watch database CPU and queue delay
(`argus_queue_delay_seconds`) as event volume grows.
