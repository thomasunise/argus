"""Backups and retention from the command line. Reads the same settings as the app (environment / .env).

    python -m app.ops backup create                 back up now (also copies to S3 / Azure and prunes)
    python -m app.ops backup list                   backups in every store
    python -m app.ops backup verify NAME|PATH       authenticate and count a backup without restoring it
    python -m app.ops backup restore NAME|PATH [--target-url URL] [--key KEY] [--no-upgrade]
                                                    restore into an EMPTY database (default: DATABASE_URL)
    python -m app.ops backup prune                  apply BACKUP_KEEP to every store
    python -m app.ops retention preview [--tenant SLUG]
    python -m app.ops retention run [--tenant SLUG]  (every active tenant when --tenant is omitted)

Inside the container: `docker compose exec worker python -m app.ops backup list`.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

os.environ.setdefault('ARGUS_LAZY_APP', '1')


def _context():
    from ..core import audit, crypto
    from ..core.config import get_settings
    from ..core.db import make_engine, make_session_factory

    settings = get_settings()
    audit.configure(settings)
    crypto.configure(settings.data_encryption_keys, settings.data_encryption_key)
    engine = make_engine(settings)
    return settings, engine, make_session_factory(engine)


def _locate(settings, ref: str) -> Path:
    """A path on disk, or the name of a backup in one of the stores (fetched into BACKUP_DIR)."""
    path = Path(ref)
    if path.is_file():
        return path
    from .stores import build_stores

    for store in build_stores(settings):
        if ref in store.names():
            return store.fetch(ref, Path(settings.backup_dir))
    raise SystemExit(f'no backup file or stored backup named {ref!r}; see `python -m app.ops backup list`')


def _print(data) -> None:
    print(json.dumps(data, indent=2, default=str, sort_keys=True))


def _tenants(db, slug: str | None):
    from sqlalchemy import select

    from ..models import Tenant

    query = select(Tenant).where(Tenant.is_active.is_(True))
    if slug:
        query = select(Tenant).where(Tenant.slug == slug)
    tenants = list(db.execute(query).scalars())
    if slug and not tenants:
        raise SystemExit(f'no tenant with slug {slug!r}')
    return tenants


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='python -m app.ops', description='Argus backups and data retention')
    groups = parser.add_subparsers(dest='group', required=True)

    backup = groups.add_parser('backup').add_subparsers(dest='command', required=True)
    backup.add_parser('create')
    backup.add_parser('list')
    backup.add_parser('prune')
    verify = backup.add_parser('verify')
    verify.add_argument('ref')
    verify.add_argument('--key', default='', help='BACKUP_ENCRYPTION_KEY or data key, when the environment does not have it')
    restore = backup.add_parser('restore')
    restore.add_argument('ref')
    restore.add_argument('--target-url', default='', help='database to restore into (must be empty); default DATABASE_URL')
    restore.add_argument('--key', default='')
    restore.add_argument('--no-upgrade', action='store_true', help='leave the schema at the backup revision')

    ret = groups.add_parser('retention').add_subparsers(dest='command', required=True)
    for name in ('preview', 'run'):
        sub = ret.add_parser(name)
        sub.add_argument('--tenant', default=None, help='tenant slug (default: every active tenant)')

    args = parser.parse_args(argv)
    settings, engine, factory = _context()
    from . import backup as backup_mod
    from . import retention, run_backup, run_retention
    from .stores import build_stores

    try:
        if args.group == 'backup':
            if args.command == 'create':
                _print(run_backup(factory, engine, settings, trigger='cli', requested_by='cli'))
            elif args.command == 'list':
                _print({store.name: sorted(store.names(), reverse=True) for store in build_stores(settings)})
            elif args.command == 'prune':
                _print({store.name: store.prune(settings.backup_keep) for store in build_stores(settings)})
            elif args.command == 'verify':
                _print(backup_mod.verify_file(_locate(settings, args.ref), settings, args.key))
            elif args.command == 'restore':
                target = args.target_url or settings.database_url
                engine.dispose()
                result = backup_mod.restore(_locate(settings, args.ref), target, settings, key_override=args.key, upgrade=not args.no_upgrade)
                _print(result)
                return 0 if result['checks']['ok'] else 1
        else:
            from ..core.db import session_scope

            with session_scope(factory) as db:
                tenants = [(t.id, t.slug) for t in _tenants(db, args.tenant)]
            out = {}
            for tenant_id, slug in tenants:
                if args.command == 'preview':
                    with session_scope(factory) as db:
                        from ..models import Tenant

                        out[slug] = retention.preview(db, settings, db.get(Tenant, tenant_id))
                else:
                    out[slug] = run_retention(factory, settings, tenant_id, record_empty=True)
            _print(out)
    except backup_mod.BackupError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    finally:
        engine.dispose()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
