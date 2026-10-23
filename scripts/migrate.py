"""Apply the database schema for Sentinel.

Order of preference:
  1. Alembic, when `alembic.ini` and `alembic/env.py` exist (the normal path; see docs/MIGRATIONS.md).
  2. `Base.metadata.create_all` on the configured DATABASE_URL, for a checkout without an
     Alembic environment. This never drops or alters columns.

Run from the repository root (the container entrypoint does this when RUN_MIGRATIONS=true):
    python scripts/migrate.py                 # alembic upgrade head
    python scripts/migrate.py --check         # exit 1 when models changed without a migration
    python scripts/migrate.py --current       # show the database revision
    python scripts/migrate.py --sql           # print the upgrade SQL instead of executing it
    python scripts/migrate.py --stamp head    # mark an existing create_all database as migrated
The database URL comes from ALEMBIC_DATABASE_URL, then DATABASE_URL, then .env (alembic/env.py).
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault('SENTINEL_LAZY_APP', '1')

log = logging.getLogger('sentinel.migrate')


def _alembic_available() -> bool:
    return (ROOT / 'alembic.ini').is_file() and (ROOT / 'alembic' / 'env.py').is_file()


def _alembic(*args: str) -> int:
    argv = [sys.executable, '-m', 'alembic', '-c', str(ROOT / 'alembic.ini'), *args]
    log.info('alembic %s', ' '.join(args))
    return subprocess.run(argv, cwd=ROOT, check=False, timeout=900).returncode


def _create_all() -> int:
    from app.core.config import get_settings
    from app.core.db import make_engine
    from app.models import Base

    settings = get_settings()
    engine = make_engine(settings)
    Base.metadata.create_all(engine)
    engine.dispose()
    log.info('schema ensured with create_all on %s', settings.database_url.split('@')[-1])
    return 0


def main(argv: list[str]) -> int:
    logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'), format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    if not _alembic_available():
        if argv:
            log.warning('no Alembic environment present; options %s ignored', ' '.join(argv))
            return 0 if argv == ['--check'] else 2
        return _create_all()
    if '--check' in argv:
        return _alembic('check')
    if '--current' in argv:
        return _alembic('current', '--verbose')
    if '--sql' in argv:
        return _alembic('upgrade', 'head', '--sql')
    if '--stamp' in argv:
        index = argv.index('--stamp')
        revision = argv[index + 1] if len(argv) > index + 1 and not argv[index + 1].startswith('--') else 'head'
        return _alembic('stamp', revision)
    return _alembic('upgrade', 'head')


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
