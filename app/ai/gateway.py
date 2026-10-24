"""AI gateway: a governed proxy in front of model providers.

Callers authenticate with an Argus API key (`Authorization: Bearer` or `x-api-key`, so the
OpenAI and Anthropic SDKs work with base_url pointed at Argus). Argus applies the tenant policy
(providers, models, DLP, prompt-injection, size, rate, monthly budget), forwards the request with
the organization's provider key, and records metadata only: never prompts, completions or keys.
"""
from __future__ import annotations

import fnmatch
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.config import Settings, parse_model_prices
from ..core.security import resolve_secret
from ..models import Tenant, dumps, loads, utcnow
from ..models.ai import AIGatewayRequest
from . import dlp

log = logging.getLogger('argus.ai.gateway')

PROVIDERS = ('openai', 'anthropic')
DLP_MODES = ('block', 'redact', 'log')
ENDPOINTS = {
    ('openai', 'chat.completions'): '/v1/chat/completions',
    ('openai', 'embeddings'): '/v1/embeddings',
    ('openai', 'models'): '/v1/models',
    ('anthropic', 'messages'): '/v1/messages',
    ('anthropic', 'models'): '/v1/models',
}
FORWARD_HEADERS = {'openai': ('openai-beta',), 'anthropic': ('anthropic-version', 'anthropic-beta')}
DEFAULT_ANTHROPIC_VERSION = '2023-06-01'
_REF_PREFIXES = ('env:', 'file:', 'secrets:', 'literal:')


# ---------------------------------------------------------------- policy


@dataclass
class GatewayPolicy:
    enabled: bool = True
    allowed_providers: list[str] = field(default_factory=list)  # empty = every configured provider
    allowed_models: list[str] = field(default_factory=list)  # fnmatch globs; empty = any model
    dlp_mode: str = 'block'
    dlp_types: list[str] = field(default_factory=lambda: list(dlp.DEFAULT_ENFORCED))
    block_prompt_injection: bool = False
    max_request_bytes: int | None = None
    requests_per_minute: int | None = None
    monthly_budget_usd: float | None = None

    def as_dict(self) -> dict:
        return {'enabled': self.enabled, 'allowed_providers': list(self.allowed_providers), 'allowed_models': list(self.allowed_models),
                'dlp_mode': self.dlp_mode, 'dlp_types': list(self.dlp_types), 'block_prompt_injection': self.block_prompt_injection,
                'max_request_bytes': self.max_request_bytes, 'requests_per_minute': self.requests_per_minute,
                'monthly_budget_usd': self.monthly_budget_usd}


POLICY_FIELDS = set(GatewayPolicy().as_dict())


def validate_policy(raw: dict) -> GatewayPolicy:
    """Strict validation of a policy document. Raises ValueError with a readable message."""
    if not isinstance(raw, dict):
        raise ValueError('policy must be an object')
    unknown = sorted(set(raw) - POLICY_FIELDS)
    if unknown:
        raise ValueError(f'unknown policy fields {unknown}')
    policy = GatewayPolicy()
    if 'enabled' in raw:
        if not isinstance(raw['enabled'], bool):
            raise ValueError('enabled must be a boolean')
        policy.enabled = raw['enabled']
    if 'allowed_providers' in raw:
        values = raw['allowed_providers'] or []
        if not isinstance(values, list) or any(v not in PROVIDERS for v in values):
            raise ValueError(f'allowed_providers must be a list drawn from {list(PROVIDERS)}')
        policy.allowed_providers = list(dict.fromkeys(values))
    if 'allowed_models' in raw:
        values = raw['allowed_models'] or []
        if not isinstance(values, list) or len(values) > 100 or not all(isinstance(v, str) and 0 < len(v) <= 120 for v in values):
            raise ValueError('allowed_models must be a list of up to 100 model names or globs')
        policy.allowed_models = values
    if 'dlp_mode' in raw:
        if raw['dlp_mode'] not in DLP_MODES:
            raise ValueError(f'dlp_mode must be one of {list(DLP_MODES)}')
        policy.dlp_mode = raw['dlp_mode']
    if 'dlp_types' in raw:
        values = raw['dlp_types'] or []
        if not isinstance(values, list) or any(v not in dlp.ALL_TYPES for v in values):
            raise ValueError(f'dlp_types must be drawn from {list(dlp.ALL_TYPES)}')
        policy.dlp_types = list(dict.fromkeys(values))
    if 'block_prompt_injection' in raw:
        if not isinstance(raw['block_prompt_injection'], bool):
            raise ValueError('block_prompt_injection must be a boolean')
        policy.block_prompt_injection = raw['block_prompt_injection']
    for name, low, high in (('max_request_bytes', 1024, 16 * 1024 * 1024), ('requests_per_minute', 1, 100_000)):
        if raw.get(name) is not None:
            value = raw[name]
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError(f'{name} must be an integer between {low} and {high}')
            setattr(policy, name, value)
    if raw.get('monthly_budget_usd') is not None:
        value = raw['monthly_budget_usd']
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= float(value) <= 10_000_000:
            raise ValueError('monthly_budget_usd must be a number between 0 and 10000000')
        policy.monthly_budget_usd = float(value)
    return policy


def tenant_policy(tenant: Tenant | None) -> GatewayPolicy:
    data = loads(tenant.settings_json, {}) if tenant else {}
    raw = data.get('ai_gateway') if isinstance(data, dict) else None
    if not isinstance(raw, dict):
        return GatewayPolicy()
    try:
        return validate_policy(raw)
    except ValueError:
        log.warning('tenant %s has an invalid ai_gateway policy; using defaults', tenant.id if tenant else '?')
        return GatewayPolicy()


def store_policy(tenant: Tenant, policy: GatewayPolicy) -> None:
    data = loads(tenant.settings_json, {})
    data = data if isinstance(data, dict) else {}
    data['ai_gateway'] = policy.as_dict()
    tenant.settings_json = dumps(data)


def model_allowed(policy: GatewayPolicy, model: str) -> bool:
    if not policy.allowed_models:
        return True
    return any(fnmatch.fnmatchcase(model, pattern) for pattern in policy.allowed_models)


# ---------------------------------------------------------------- providers and pricing


def provider_key(settings: Settings, provider: str) -> str:
    raw = str(getattr(settings, f'ai_gateway_{provider}_api_key', '') or '')
    if raw.startswith(_REF_PREFIXES):
        return resolve_secret(raw, settings)
    return raw


def provider_base(settings: Settings, provider: str) -> str:
    return str(getattr(settings, f'ai_gateway_{provider}_base_url', '') or '').rstrip('/')


def configured_providers(settings: Settings) -> list[str]:
    return [p for p in PROVIDERS if provider_key(settings, p)]


def prices(settings: Settings) -> dict[str, tuple[float, float]]:
    from ..agents.providers import PRICES

    table = dict(PRICES)
    try:
        table.update(parse_model_prices(settings.agent_model_prices))
        table.update(parse_model_prices(settings.ai_gateway_model_prices))
    except ValueError:
        pass
    return table


def price_for(table: dict[str, tuple[float, float]], model: str) -> tuple[float, float] | None:
    if model in table:
        return table[model]
    # Dated snapshots ('claude-sonnet-5-5-20261001', 'gpt-4.1-2025-04-14') fall back to the longest known prefix.
    best = max((k for k in table if model.startswith(k + '-')), key=len, default=None)
    return table[best] if best else None


def cost(settings: Settings, model: str, input_tokens: int, output_tokens: int) -> float:
    price = price_for(prices(settings), model)
    if not price:
        return 0.0
    return round((input_tokens * price[0] + output_tokens * price[1]) / 1_000_000, 6)


def month_spend(db: Session, tenant_id: str, now: datetime | None = None) -> float:
    now = now or utcnow()
    start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    total = db.scalar(select(func.coalesce(func.sum(AIGatewayRequest.cost_usd), 0.0))
                      .where(AIGatewayRequest.tenant_id == tenant_id, AIGatewayRequest.created_at >= start))
    return float(total or 0.0)


# ---------------------------------------------------------------- usage parsing


def usage_from_body(provider: str, body: Any) -> tuple[int, int]:
    usage = body.get('usage') if isinstance(body, dict) else None
    if not isinstance(usage, dict):
        return 0, 0
    if provider == 'anthropic':
        inp = int(usage.get('input_tokens') or 0) + int(usage.get('cache_creation_input_tokens') or 0) + int(usage.get('cache_read_input_tokens') or 0)
        return inp, int(usage.get('output_tokens') or 0)
    return int(usage.get('prompt_tokens') or usage.get('input_tokens') or 0), int(usage.get('completion_tokens') or usage.get('output_tokens') or 0)


class SSEUsage:
    """Incremental parser for usage figures in a server-sent-event stream. Keeps only a partial line."""

    def __init__(self, provider: str):
        self.provider = provider
        self.input_tokens = 0
        self.output_tokens = 0
        self._buffer = b''

    def feed(self, chunk: bytes) -> None:
        self._buffer += chunk
        if len(self._buffer) > 1_000_000:  # a single line this long is not an SSE usage record
            self._buffer = self._buffer[-1000:]
        *lines, self._buffer = self._buffer.split(b'\n')
        for line in lines:
            self._line(line.strip())

    def close(self) -> None:
        if self._buffer:
            self._line(self._buffer.strip())
            self._buffer = b''

    def _line(self, line: bytes) -> None:
        if not line.startswith(b'data:'):
            return
        data = line[5:].strip()
        if not data or data == b'[DONE]' or b'usage' not in data:
            return
        try:
            event = json.loads(data)
        except ValueError:
            return
        if not isinstance(event, dict):
            return
        if self.provider == 'anthropic':
            message = event.get('message') if isinstance(event.get('message'), dict) else {}
            inp, out = usage_from_body('anthropic', message)
            if inp:
                self.input_tokens = inp
            if out:
                self.output_tokens = max(self.output_tokens, out)
            inp2, out2 = usage_from_body('anthropic', event)
            if inp2:
                self.input_tokens = max(self.input_tokens, inp2)
            if out2:
                self.output_tokens = max(self.output_tokens, out2)
        else:
            inp, out = usage_from_body('openai', event)
            if inp or out:
                self.input_tokens, self.output_tokens = inp, out


# ---------------------------------------------------------------- inspection


@dataclass
class Inspection:
    body: dict
    model: str
    stream: bool
    dlp_hits: dict[str, int]
    dlp_action: str  # '' | logged | redacted | blocked
    prompt_injection: bool
    injection_signals: list[str]
    block_reason: str = ''


def inspect(provider: str, endpoint: str, body: dict, policy: GatewayPolicy) -> Inspection:
    model = str(body.get('model') or '')[:120]
    stream = bool(body.get('stream')) and endpoint != 'embeddings'
    hits = dlp.scan(dlp.texts(body))
    enforced = {k: v for k, v in hits.items() if k in set(policy.dlp_types)}
    action = 'logged' if hits else ''
    result_body = body
    reason = ''
    if enforced and policy.dlp_mode == 'block':
        action, reason = 'blocked', 'sensitive data in request: ' + ', '.join(sorted(enforced))
    elif enforced and policy.dlp_mode == 'redact':
        action = 'redacted'
        result_body = dlp.redact_value(body, policy.dlp_types)
    from ..agents.specialists._base import injection_signals

    signals = injection_signals(*list(dlp.texts(body, skip_roles=('system', 'developer', 'assistant')))[:200])
    if signals and policy.block_prompt_injection and not reason:
        reason = 'prompt injection suspected: ' + '; '.join(signals[:3])
    if stream and provider == 'openai' and endpoint == 'chat.completions' and not reason:
        options = result_body.get('stream_options') if isinstance(result_body.get('stream_options'), dict) else {}
        if 'include_usage' not in options:
            result_body = {**result_body, 'stream_options': {**options, 'include_usage': True}}  # needed for metering
    return Inspection(body=result_body, model=model, stream=stream, dlp_hits=hits, dlp_action=action, prompt_injection=bool(signals),
                      injection_signals=signals, block_reason=reason)


def request_to_dict(row: AIGatewayRequest) -> dict:
    return {'id': row.id, 'api_key_id': row.api_key_id, 'user_id': row.user_id, 'actor': row.actor, 'provider': row.provider,
            'endpoint': row.endpoint, 'model': row.model, 'stream': bool(row.stream), 'status': row.status, 'block_reason': row.block_reason,
            'dlp_hits': loads(row.dlp_hits_json, {}), 'dlp_action': row.dlp_action, 'prompt_injection': bool(row.prompt_injection),
            'input_tokens': row.input_tokens, 'output_tokens': row.output_tokens, 'cost_usd': row.cost_usd, 'latency_ms': row.latency_ms,
            'upstream_status': row.upstream_status, 'request_bytes': row.request_bytes, 'created_at': row.created_at}


def error_body(provider: str, status: int, message: str, kind: str = 'argus_policy') -> dict:
    """Error payloads shaped like each provider's, so SDKs surface the message."""
    if provider == 'anthropic':
        return {'type': 'error', 'error': {'type': kind, 'message': message}}
    return {'error': {'message': message, 'type': kind, 'code': status}}
