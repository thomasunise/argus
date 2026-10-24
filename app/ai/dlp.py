"""Data-loss checks for AI gateway requests.

`scan(texts)` returns {type: count}; nothing else about a match is kept. `redact_value(value,
types)` replaces matches of the given types in every free-text string of a JSON request body.
Secret patterns follow core.security.redact; anything that redact() would mask but no typed
pattern names is counted as 'secret_other'.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, Callable, Iterable

from ..core.security import redact

SECRET_TYPES = ('aws_access_key', 'private_key', 'api_key', 'jwt', 'credential_assignment', 'secret_other')
PII_TYPES = ('credit_card', 'us_ssn', 'email', 'iban')
ALL_TYPES = SECRET_TYPES + PII_TYPES
DEFAULT_ENFORCED = ('aws_access_key', 'private_key', 'api_key', 'jwt', 'credential_assignment', 'secret_other', 'credit_card', 'us_ssn')

# JSON keys whose values are protocol structure, not user content.
STRUCTURAL_KEYS = {'model', 'role', 'type', 'id', 'tool_call_id', 'tool_use_id', 'stop', 'stop_sequences', 'tool_choice', 'response_format',
                   'encoding_format', 'media_type', 'detail', 'finish_reason', 'stream', 'user', 'service_tier', 'reasoning_effort',
                   'data', 'image_url', 'signature', 'cache_control'}
MAX_SCAN_CHARS = 1_000_000


def _luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _card_ok(match: re.Match) -> bool:
    digits = re.sub(r'\D', '', match.group(0))
    return 13 <= len(digits) <= 19 and _luhn(digits) and len(set(digits)) > 1


def _ssn_ok(match: re.Match) -> bool:
    area, group, serial = match.group(1), match.group(2), match.group(3)
    return area not in {'000', '666'} and not area.startswith('9') and group != '00' and serial != '0000'


PATTERNS: list[tuple[str, re.Pattern, Callable[[re.Match], bool] | None]] = [
    ('private_key', re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'), None),
    ('aws_access_key', re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), None),
    ('api_key', re.compile(r'\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9\-]{10,}'
                           r'|argus_[0-9a-f]{8}_[A-Za-z0-9\-_]{20,}|AIza[0-9A-Za-z\-_]{35}|glpat-[A-Za-z0-9\-_]{20,}|hf_[A-Za-z0-9]{30,})'), None),
    ('jwt', re.compile(r'\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}'), None),
    ('credential_assignment', re.compile(r'(?i)\b(?:api[_-]?key|secret|password|passwd|token|client[_-]?secret)\s*[:=]\s*["\']?[^\s"\',;]{6,}'), None),
    ('credit_card', re.compile(r'(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])'), _card_ok),
    ('us_ssn', re.compile(r'(?<!\d)(\d{3})-(\d{2})-(\d{4})(?!\d)'), _ssn_ok),
    ('email', re.compile(r'(?i)\b[a-z0-9._%+\-]{1,64}@[a-z0-9.\-]{1,253}\.[a-z]{2,24}\b'), None),
    ('iban', re.compile(r'\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b'), None),
]


def texts(value: Any, *, skip_roles: tuple[str, ...] = (), depth: int = 0) -> Iterable[str]:
    """Free-text strings in a JSON request body. `skip_roles` drops whole messages by role (used for
    prompt-injection checks, where operator-authored system prompts are trusted)."""
    if depth > 12:
        return
    if isinstance(value, str):
        if not value.startswith('data:'):
            yield value
    elif isinstance(value, dict):
        if skip_roles and value.get('role') in skip_roles:
            return
        for key, item in value.items():
            if key in STRUCTURAL_KEYS:
                continue
            if skip_roles and key == 'system':
                continue
            yield from texts(item, skip_roles=skip_roles, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from texts(item, skip_roles=skip_roles, depth=depth + 1)


def scan(strings: Iterable[str]) -> dict[str, int]:
    hits: Counter = Counter()
    budget = MAX_SCAN_CHARS
    for text in strings:
        if budget <= 0:
            break
        text = text[:budget]
        budget -= len(text)
        typed = 0
        for name, pattern, check in PATTERNS:
            for match in pattern.finditer(text):
                if check is None or check(match):
                    hits[name] += 1
                    if name in SECRET_TYPES:
                        typed += 1
        if not typed and redact(text) != text:
            hits['secret_other'] += 1
    return dict(hits)


def redact_text(text: str, types: Iterable[str]) -> str:
    wanted = set(types)
    out = text
    for name, pattern, check in PATTERNS:
        if name not in wanted:
            continue
        out = pattern.sub(lambda m, n=name, c=check: f'[REDACTED:{n}]' if c is None or c(m) else m.group(0), out)
    if 'secret_other' in wanted:
        out = redact(out)
    return out


def redact_value(value: Any, types: Iterable[str], depth: int = 0) -> Any:
    types = tuple(types)
    if depth > 12:
        return value
    if isinstance(value, str):
        return value if value.startswith('data:') else redact_text(value, types)
    if isinstance(value, dict):
        return {k: (v if k in STRUCTURAL_KEYS else redact_value(v, types, depth + 1)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v, types, depth + 1) for v in value]
    return value
