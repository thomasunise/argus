from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


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
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class Base(DeclarativeBase):
    pass


class TenantMixin:
    """Every domain table is tenant scoped. Queries must go through core.db.scoped()."""

    tenant_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
