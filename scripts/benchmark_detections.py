"""Evaluate versioned labeled detection scenarios in a disposable SQLite database.

Usage:
    python scripts/benchmark_detections.py --min-scenarios 5
    python scripts/benchmark_detections.py --dataset ./data/independent.json --min-scenarios 100 --report metrics.json

Never runs against a customer or production database. A synthetic score is not
an independently established detection accuracy claim.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from app.models import Base, Tenant  # noqa: E402
from app.detections.benchmark import BenchmarkScenario, default_scenarios, run_benchmark  # noqa: E402


def load_scenarios(path: Path) -> list[BenchmarkScenario]:
    payload = json.loads(path.read_text(encoding='utf-8'))
    items = payload.get('scenarios') if isinstance(payload, dict) else payload
    if not isinstance(items, list) or not items or len(items) > 2000:
        raise ValueError('dataset must contain between 1 and 2000 scenarios')
    result = []
    for index, record in enumerate(items):
        if not isinstance(record, dict) or not isinstance(record.get('events'), list):
            raise ValueError(f'scenario {index}: expected object with events list')
        if len(record['events']) > 200:
            raise ValueError(f'scenario {index}: at most 200 events per scenario')
        events = []
        for event in record['events']:
            if not isinstance(event, dict) or not all(k in event for k in ('source', 'external_id', 'actor', 'action', 'entity')):
                raise ValueError(f'scenario {index}: event missing source/external_id/actor/action/entity')
            e = dict(event)
            when = e.get('occurred_at')
            if isinstance(when, str):
                e['occurred_at'] = datetime.fromisoformat(when.replace('Z', '+00:00')).astimezone(timezone.utc)
            # Prefix the source id with the scenario so one case cannot borrow
            # another case's detection via a deduplicated normalized event.
            e['external_id'] = f"{record.get('id', index)}:{e['external_id']}"
            events.append(e)
        expected = record.get('expected_rule')
        if expected is not None and (not isinstance(expected, str) or not expected):
            raise ValueError(f'scenario {index}: expected_rule must be a rule id or null')
        result.append(BenchmarkScenario(
            id=str(record['id']), category=str(record['category']),
            technique=str(record['technique']), expected_rule=expected, events=events))
    if len({s.id for s in result}) != len(result):
        raise ValueError('scenario ids must be unique')
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', type=Path, help='JSON array or {"scenarios": [...]} of labeled scenarios')
    parser.add_argument('--report', type=Path, help='write structured JSON metrics')
    parser.add_argument('--min-scenarios', type=int, default=100)
    parser.add_argument('--min-recall', type=float, default=0.0)
    parser.add_argument('--min-precision', type=float, default=0.0)
    parser.add_argument('--max-false-positive-rate', type=float, default=1.0)
    args = parser.parse_args()

    scenarios = load_scenarios(args.dataset) if args.dataset else default_scenarios()
    # Always create an independent ephemeral database. Never accept DATABASE_URL.
    engine = create_engine('sqlite+pysqlite:///:memory:')
    try:
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            tenant = Tenant(id='benchmark-isolated', slug='benchmark-isolated', name='Detection benchmark')
            db.add(tenant)
            db.commit()
            result = run_benchmark(db, tenant.id, scenarios)
            db.rollback()
    finally:
        engine.dispose()
    result['dataset'] = str(args.dataset) if args.dataset else 'built-in synthetic smoke suite'
    result['qualified_for_release'] = bool(args.dataset and result['scenarios_total'] >= args.min_scenarios)
    result['limitations'] = 'Synthetic regression data cannot establish real-world detection accuracy or time-to-detect.'
    rendered = json.dumps(result, indent=2, default=str)
    if args.report:
        args.report.write_text(rendered + '\n', encoding='utf-8')
    print(rendered)
    fails = []
    if len(scenarios) < args.min_scenarios:
        fails.append(f'only {len(scenarios)} scenarios (requires {args.min_scenarios})')
    if result['recall'] < args.min_recall:
        fails.append('recall below threshold')
    if result['precision'] < args.min_precision:
        fails.append('precision below threshold')
    if result['false_positive_rate'] > args.max_false_positive_rate:
        fails.append('false-positive rate exceeds threshold')
    if fails:
        print('Benchmark gate failed: ' + '; '.join(fails), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
