# ARGUS release validation gates

## Automated checks

- PostgreSQL and SQLite suites (3.11/3.12), browser E2E, dependency and code security scans, Docker and Compose smoke.
- PostgreSQL schema drift: `python scripts/migrate.py --check` after migrations.
- Synthetic detection smoke: `python scripts/benchmark_detections.py --min-scenarios 5 --min-precision 1 --min-recall 1 --max-false-positive-rate 0`.
- Read-only bounded HTTP readiness load smoke: `python scripts/load_smoke.py --url https://your-staging-host --requests 100 --concurrency 8`.

Passing these checks **does not** mean ARGUS is production-certified. They establish reproducibility and basic regression checks.

## Independent detection quality

For production suitability, obtain a separately labeled dataset (at least 100 attack and benign scenarios, multiple providers/attack techniques and realistic negative controls) and run:

```
python scripts/benchmark_detections.py --dataset ./independent-cases.json --min-scenarios 100 --min-recall 0.9 --min-precision 0.9 --max-false-positive-rate 0.1 --report independent-results.json
```

The scorer uses a disposable database; it does not connect to the customer's database. Document who labeled the cases, exact expected detections and provenance. Report misses, class balance, false positives, full scenario outputs and CI commit SHA. Do not treat the synthetic benchmark's 100% scores as independent results.

## Independent security validation

The following checks **require a deployed staging estate and human/external access** and cannot be proven solely by source code:

1. Independent penetration test with an agreed scope and final retest.
2. Restricted-role PostgreSQL RLS validation on a real deployment and tenant break-out tests.
3. Kubernetes NetworkPolicy and CNI egress-denial verification, including DNS rebinding and cloud metadata paths.
4. Action execution, rollback and account revocation under multi-replica concurrency.
5. Provider integration validation against real sandbox accounts.
6. Restore from encrypted backup after a destructive staging failure; verify hash chains and all tenant row counts.
7. Capacity test at the actual intended event ingestion rate and number of tenants (including soak tests and failure injection).
8. Confirmation that no enabled scanner can access destinations outside the signed scope.

Maintain a dated evidence bundle of findings, tests, retests, migration results and sign-offs. Do not claim SOC 2 compliance, zero vulnerabilities, full isolation or enterprise readiness from passing unit tests alone.
