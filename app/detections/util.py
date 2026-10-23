"""Small, dependency-free helpers shared by the detection engine and rules: time normalization,
metadata access, sliding windows, statistics and evidence bounding."""
from __future__ import annotations

import math
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator, Sequence

from ..core.security import redact
from ..models import SecurityEvent, loads

MAX_EVIDENCE_IDS = 25
MAX_EVIDENCE_SAMPLES = 10


def aware(value: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes for timezone-aware columns; treat naive as UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def event_time(event: SecurityEvent) -> datetime:
    return aware(event.occurred_at) or aware(event.received_at) or datetime.now(timezone.utc)


def epoch(value: datetime) -> float:
    return aware(value).timestamp()  # type: ignore[union-attr]


def window_bucket(when: datetime, window_minutes: int) -> str:
    """Bucket label for fingerprinting: the window-aligned floor of `when` as an integer index."""
    seconds = max(60, int(window_minutes) * 60)
    return str(int(epoch(when) // seconds))


def bucket_start(when: datetime, window_minutes: int) -> datetime:
    seconds = max(60, int(window_minutes) * 60)
    return datetime.fromtimestamp((epoch(when) // seconds) * seconds, tz=timezone.utc)


_META_CACHE_ATTR = '_sentinel_meta_cache'


def meta(event: SecurityEvent) -> dict:
    """Parsed metadata, cached on the ORM instance for the lifetime of a rule evaluation."""
    cached = getattr(event, _META_CACHE_ATTR, None)
    if cached is None:
        parsed = loads(event.metadata_json)
        cached = parsed if isinstance(parsed, dict) else {}
        try:
            setattr(event, _META_CACHE_ATTR, cached)
        except AttributeError:  # pragma: no cover - defensive
            pass
    return cached


def first_present(data: dict, *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in data and data[key] not in (None, ''):
            return data[key]
    return default


def deep_find_truthy(data: Any, keys: set[str], *, max_depth: int = 6, max_nodes: int = 500) -> list[str]:
    """Return the names of `keys` found anywhere in a nested dict/list with a truthy value. Bounded."""
    found: list[str] = []
    budget = [max_nodes]

    def walk(node: Any, depth: int) -> None:
        if budget[0] <= 0 or depth > max_depth:
            return
        budget[0] -= 1
        if isinstance(node, dict):
            for key, value in node.items():
                if key in keys and _truthy(value):
                    found.append(key)
                walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node[:50]:
                walk(item, depth + 1)

    walk(data, 0)
    return sorted(set(found))


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {'true', 'yes', '1', 'on'}
    if isinstance(value, (int, float)):
        return value != 0
    return False


def entity_class(event: SecurityEvent) -> str:
    """Coarse entity class: explicit metadata, then the `kind:` prefix of entity, then category."""
    data = meta(event)
    explicit = first_present(data, 'entity_kind', 'resource_type', 'asset_kind', 'kind')
    if isinstance(explicit, str) and explicit:
        return explicit[:40]
    entity = event.entity or ''
    if ':' in entity:
        head = entity.split(':', 1)[0]
        if head and len(head) <= 40 and ' ' not in head:
            return head
    return event.category or 'unknown'


def service_of(event: SecurityEvent) -> str:
    """Service namespace of an action: `s3.get_object` -> s3, `iam:CreateUser` -> iam, else metadata/source."""
    data = meta(event)
    explicit = first_present(data, 'service', 'event_source', 'eventSource')
    if isinstance(explicit, str) and explicit:
        return explicit.split('.')[0][:40].lower()
    action = event.action or ''
    for sep in ('.', ':', '/'):
        if sep in action:
            return action.split(sep, 1)[0][:40].lower()
    return (event.source or 'unknown')[:40].lower()


def source_ip(event: SecurityEvent) -> str:
    data = meta(event)
    value = first_present(data, 'src_ip', 'source_ip', 'sourceIPAddress', 'client_ip', 'ip', 'remote_addr', default='')
    return str(value)[:64]


def user_agent(event: SecurityEvent) -> str:
    data = meta(event)
    value = first_present(data, 'user_agent', 'userAgent', 'ua', default='')
    if not value and isinstance(data.get('headers'), dict):
        headers = {str(k).lower(): v for k, v in data['headers'].items()}
        value = headers.get('user-agent', '')
    return str(value)[:300]


def geo_of(event: SecurityEvent) -> tuple[float | None, float | None, str]:
    """(lat, lon, country) from common metadata layouts. Missing values are None/''."""
    data = meta(event)
    geo = data.get('geo') if isinstance(data.get('geo'), dict) else data
    lat = first_present(geo, 'lat', 'latitude')
    lon = first_present(geo, 'lon', 'lng', 'long', 'longitude')
    country = first_present(geo, 'country', 'country_code', 'countryCode', default='') or first_present(data, 'src_country', 'geo_country', default='')
    try:
        lat_f = float(lat) if lat is not None else None
        lon_f = float(lon) if lon is not None else None
    except (TypeError, ValueError):
        lat_f = lon_f = None
    return lat_f, lon_f, str(country)[:8].upper()


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def sliding(times: Sequence[float], window_seconds: float) -> Iterator[tuple[int, int]]:
    """Yield (start, end) index pairs so that times[start:end] all fall within window_seconds of times[start].
    `times` must be sorted ascending. Two-pointer, O(n)."""
    end = 0
    n = len(times)
    for start in range(n):
        if end < start:
            end = start
        while end < n and times[end] - times[start] <= window_seconds:
            end += 1
        yield start, end


def gaps_ms(times: Sequence[float]) -> list[float]:
    return [(b - a) * 1000.0 for a, b in zip(times, times[1:])]


def median(values: Iterable[float]) -> float:
    data = list(values)
    return statistics.median(data) if data else 0.0


def scale_confidence(value: float, threshold: float, *, base: float = 0.6, cap: float = 0.97) -> float:
    """base at the threshold, rising to cap when value is 3x the threshold."""
    if threshold <= 0:
        return cap
    ratio = max(0.0, value / threshold - 1.0) / 2.0
    return round(min(cap, base + (cap - base) * min(1.0, ratio)), 3)


def event_ids(events: Iterable[SecurityEvent], cap: int = MAX_EVIDENCE_IDS) -> list[str]:
    out: list[str] = []
    for event in events:
        out.append(event.id)
        if len(out) >= cap:
            break
    return out


def sample(values: Iterable[str], cap: int = MAX_EVIDENCE_SAMPLES) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.append(redact(str(value))[:200])
            if len(seen) >= cap:
                break
    return seen


def iso(value: datetime | None) -> str | None:
    return aware(value).isoformat() if value else None  # type: ignore[union-attr]


def span(events: Sequence[SecurityEvent]) -> tuple[datetime, datetime]:
    first, last = event_time(events[0]), event_time(events[-1])
    return (first, last) if first <= last else (last, first)


def minutes(n: float) -> timedelta:
    return timedelta(minutes=float(n))
