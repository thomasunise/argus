"""Regression: a request thread and a job worker auditing at the same time on SQLite must not deadlock.

The worker already holds the SQLite write lock (it wrote detections) when it calls record_audit. If the request
thread took the in-process audit lock first and then waited for the write lock, each waited on the other until the
busy timeout ran out and the request failed with "database is locked".
"""
from __future__ import annotations

import threading
import time

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.core.audit import record_audit, verify_chain
from app.models import Base

TENANT = 'tenant-lock-order'


def test_concurrent_audit_writers_do_not_deadlock(tmp_path):
    engine = create_engine(f'sqlite:///{tmp_path}/lock.db', connect_args={'check_same_thread': False, 'timeout': 3})

    @event.listens_for(engine, 'connect')
    def _wal(dbapi_connection, _):
        dbapi_connection.execute('PRAGMA journal_mode=WAL')

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    worker, request = factory(), factory()
    errors: list[BaseException] = []
    try:
        # The worker writes first and keeps its transaction open, like a detections run does.
        record_audit(worker, 'system', 'worker.first', tenant_id=TENANT)

        def request_thread():
            try:
                record_audit(request, 'admin@test.local', 'request.write', tenant_id=TENANT)
                request.commit()
            except BaseException as exc:  # surfaced below
                request.rollback()
                errors.append(exc)

        thread = threading.Thread(target=request_thread)
        thread.start()
        time.sleep(0.3)  # let the request thread start waiting for the write lock

        started = time.monotonic()
        record_audit(worker, 'system', 'worker.second', tenant_id=TENANT)
        worker.commit()
        assert time.monotonic() - started < 1.5, 'worker waited on the request thread'

        thread.join(10)
        assert not thread.is_alive()
        assert errors == []
        chain = verify_chain(worker, TENANT)
        assert chain['valid'] is True and chain['checked'] == 3, chain
    finally:
        worker.close()
        request.close()
        engine.dispose()
