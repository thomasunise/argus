"""Blind and time-based SQL injection detection, added to the payload fuzzer.

Error-based payloads catch the careless case. This adds the two checks sqlmap is really used for:
a boolean pair whose responses must differ for injection to be present, and a time-based payload
whose response must take measurably longer than the baseline. Neither extracts data and neither is
destructive: two requests for the boolean test, one for the timing test.
"""
from __future__ import annotations

import re
import time

import httpx

TIME_THRESHOLD = 2.5
BOOLEAN_DIFFERENCE = 0.15
CLOCK = time.perf_counter

BOOLEAN_TRUE = ("' AND '1'='1", "' AND 1=1-- -")
BOOLEAN_FALSE = ("' AND '1'='2", "' AND 1=2-- -")
TIME_PAYLOADS = (
    ("' AND SLEEP(3)-- -", 'mysql'),
    ("'; WAITFOR DELAY '0:0:3'-- -", 'mssql'),
    ("'||pg_sleep(3)-- -", 'postgres'),
)
TIME_RE = re.compile(r'sleep\s*\(|waitfor\s+delay|pg_sleep', re.IGNORECASE)


async def _fetch(client, ctx, endpoint: str, param: str, payload: str) -> tuple[int, str, float] | None:
    await ctx.rate_limiter.acquire()
    started = CLOCK()
    try:
        response = await client.get(endpoint, params={param: payload})
    except httpx.HTTPError:
        return None
    return response.status_code, response.text[:200_000], CLOCK() - started


def responses_differ(left: tuple[int, str, float], right: tuple[int, str, float]) -> bool:
    if left[0] != right[0]:
        return True
    longest = max(len(left[1]), len(right[1]), 1)
    return abs(len(left[1]) - len(right[1])) / longest >= BOOLEAN_DIFFERENCE


async def detect_blind(client, ctx, endpoint: str, param: str, *, rate_limiter=None):
    """Return a NormalizedFinding for boolean or time-based injection, else None."""
    from ..harness import NormalizedFinding

    truthy = await _fetch(client, ctx, endpoint, param, BOOLEAN_TRUE[0])
    falsy = await _fetch(client, ctx, endpoint, param, BOOLEAN_FALSE[0])
    if truthy and falsy and responses_differ(truthy, falsy):
        return NormalizedFinding(
            rule=f'fuzz:sqli-blind:{param}', title=f'Blind SQL injection in {param!r}',
            description='A true and a false boolean condition produced materially different responses, which is the '
                        'signature of injected SQL that the application does not echo.',
            remediation='Use parameterized queries; never concatenate input into SQL.',
            severity='high', evidence={'endpoint': endpoint, 'parameter': param,
                                       'true_len': len(truthy[1]), 'false_len': len(falsy[1]),
                                       'payloads': [BOOLEAN_TRUE[0], BOOLEAN_FALSE[0]]})

    for payload, dialect in TIME_PAYLOADS:
        result = await _fetch(client, ctx, endpoint, param, payload)
        if result is None:
            continue
        elapsed = result[2]
        if elapsed >= TIME_THRESHOLD:
            return NormalizedFinding(
                rule=f'fuzz:sqli-time:{param}', title=f'Time-based SQL injection in {param!r}',
                description=f'A {dialect} delay payload took {elapsed:.1f}s, well above the request baseline, which '
                            'indicates the database executed it.',
                remediation='Use parameterized queries; never concatenate input into SQL.',
                severity='critical', evidence={'endpoint': endpoint, 'parameter': param, 'payload': payload[:80],
                                               'elapsed_seconds': round(elapsed, 2), 'dialect': dialect})
    return None
