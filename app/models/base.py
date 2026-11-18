from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    return datetime.now(UTC)


def uid() -> str:
    return str(uuid4())


def dumps(value: Any, limit: int | None = None) -> str:
    text = json.dumps(value if value is not None else {}, default=str, sort_keys=True, separators=(',', ':'))
    if limit and len(text) > limit:
        text = json.dumps({'truncated': True, 'preview': text[: max(0, limit - 64)]})
    return text


def loads(text: str | None, default: Any = None) -> Any:
    if not text:
        return {} if default is None else default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return {} if default is None else default


class UTCDateTime(TypeDecorator):
    """Timezone-aware UTC datetimes on every driver. SQLite drops the offset on the way in, so
    values are re-attached as UTC on the way out; Postgres timestamptz round-trips natively."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class EncryptedText(TypeDecorator):
    """Text column encrypted at rest with core.crypto (AES-256-GCM envelope). Transparent to the ORM:
    plaintext in, plaintext out. Without a configured key values are stored as-is (development)."""

    impl = Text
    cache_ok = True

    def __init__(self, *, table: str = '', column: str = '', tenant_bound: bool = True) -> None:
        super().__init__()
        self.table = table
        self.column = column
        # Columns on tenant-scoped tables are sealed under the writing tenant's key. Account-level columns
        # (users.*) belong to no single tenant and pass tenant_bound=False.
        self.tenant_bound = tenant_bound

    def _aad(self) -> str:
        if not self.table and not self.column:
            return ''
        from ..core import crypto

        return crypto.bind_aad(table=self.table, column=self.column)

    def process_bind_param(self, value, dialect):
        from ..core import crypto

        tenant_id = crypto.flush_tenant.get() if self.tenant_bound else ''
        return crypto.encrypt(value, tenant_id=tenant_id, aad=self._aad())

    def process_result_value(self, value, dialect):
        from ..core import crypto

        aad = self._aad()
        if aad and isinstance(value, str) and value.startswith(crypto.PREFIX):
            return crypto.decrypt(value)
        return crypto.decrypt(value, aad=aad)


class Base(DeclarativeBase):
    pass


class TenantMixin:
    """Every domain table is tenant scoped. Queries must go through core.db.scoped()."""

    tenant_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
