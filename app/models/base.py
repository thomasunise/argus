from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


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


class Base(DeclarativeBase):
    pass


class TenantMixin:
    """Every domain table is tenant scoped. Queries must go through core.db.scoped()."""

    tenant_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
