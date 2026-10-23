"""Alembic environment. Resolves the database URL from DATABASE_URL / .env through the app's
Settings and targets `Base.metadata` with every model module imported."""
from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault('SENTINEL_LAZY_APP', '1')

import app.models  # noqa: E402,F401  (imports every model module so metadata is complete)
from app.models import Base  # noqa: E402

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    url = os.getenv('ALEMBIC_DATABASE_URL') or os.getenv('DATABASE_URL')
    if url:
        return url
    from app.core.config import Settings

    return Settings().database_url


def _is_sqlite(url: str) -> bool:
    return url.startswith('sqlite')


def run_migrations_offline() -> None:
    url = get_url()
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True, dialect_opts={'paramstyle': 'named'},
                      render_as_batch=_is_sqlite(url), compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = get_url()
    section = config.get_section(config.config_ini_section, {})
    section['sqlalchemy.url'] = url
    connectable = engine_from_config(section, prefix='sqlalchemy.', poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=_is_sqlite(url), compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
