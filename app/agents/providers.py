"""Model providers behind one interface.

Neutral message format used by the runtime:
  {'role': 'user', 'content': str}
  {'role': 'assistant', 'content': str, 'tool_calls': [{'id','name','args'}], 'raw': provider blocks or None}
  {'role': 'tool', 'results': [{'id','name','content','is_error'}]}
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..core.config import Settings

log = logging.getLogger('sentinel.agents.providers')

# USD per million tokens, used for budget ceilings. Update when pricing changes.
PRICES: dict[str, tuple[float, float]] = {
    'claude-opus-5-5': (4.0, 20.0), 'claude-opus-5': (5.0, 25.0), 'claude-sonnet-5-5': (2.0, 10.0),
    'claude-sonnet-5': (2.0, 10.0), 'claude-haiku-5-5': (0.10, 0.50), 'claude-fable-5-1': (10.0, 50.0),
    'claude-opus-4-8': (5.0, 25.0), 'claude-opus-4-7': (5.0, 25.0), 'claude-sonnet-4-6': (3.0, 15.0),
}


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0


@dataclass
class ModelTurn:
    text: str
    tool_calls: list[ToolCall]
    stop_reason: str  # end_turn, tool_use, max_tokens, refusal, error
    usage: Usage = field(default_factory=Usage)
    raw: Any = None
    model: str = ''
    refusal_category: str = ''


class Provider:
    name = 'base'
    model = ''

    async def complete(self, system: str, messages: list[dict], tools: list[dict], max_tokens: int = 16000) -> ModelTurn:  # pragma: no cover
        raise NotImplementedError

    def cost(self, usage: Usage) -> float:
        inp, out = PRICES.get(self.model, (0.0, 0.0))
        return (usage.input_tokens * inp + usage.output_tokens * out) / 1_000_000


class NullProvider(Provider):
    """Used when AI_PROVIDER=none. Agents fall back to rule-based output."""

    name = 'none'

    async def complete(self, system, messages, tools, max_tokens=16000) -> ModelTurn:
        return ModelTurn(text='', tool_calls=[], stop_reason='error', model='none')


# ---------------------------------------------------------------- Anthropic


class AnthropicProvider(Provider):
    name = 'anthropic'

    def __init__(self, settings: Settings):
        import anthropic

        self.model = settings.anthropic_model
        self.effort = settings.anthropic_effort
        self.client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key or None, max_retries=3, timeout=600)
        self._anthropic = anthropic

    @staticmethod
    def _convert(messages: list[dict]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            if m['role'] == 'user':
                out.append({'role': 'user', 'content': m['content']})
            elif m['role'] == 'assistant':
                if m.get('raw') is not None:
                    out.append({'role': 'assistant', 'content': m['raw']})
                else:
                    blocks: list[dict] = []
                    if m.get('content'):
                        blocks.append({'type': 'text', 'text': m['content']})
                    for call in m.get('tool_calls', []):
                        blocks.append({'type': 'tool_use', 'id': call['id'], 'name': call['name'], 'input': call['args']})
                    out.append({'role': 'assistant', 'content': blocks or [{'type': 'text', 'text': '(no output)'}]})
            elif m['role'] == 'tool':
                out.append({'role': 'user', 'content': [
                    {'type': 'tool_result', 'tool_use_id': r['id'], 'content': r['content'], 'is_error': bool(r.get('is_error'))}
                    for r in m['results']]})
        return out

    async def complete(self, system, messages, tools, max_tokens=16000) -> ModelTurn:
        tool_defs = [{'name': t['name'], 'description': t['description'], 'input_schema': t['input_schema'], 'strict': strict_compatible(t['input_schema'])} for t in tools]
        params: dict[str, Any] = dict(
            model=self.model, max_tokens=max_tokens,
            system=[{'type': 'text', 'text': system, 'cache_control': {'type': 'ephemeral'}}],
            messages=self._convert(messages), output_config={'effort': self.effort},
        )
        if tool_defs:
            params['tools'] = tool_defs
        try:
            try:
                response = await self.client.beta.messages.create(betas=['server-side-fallback-2026-07-01'], fallbacks='default', **params)
            except TypeError:
                # Older SDK without the fallbacks parameter.
                response = await self.client.messages.create(**params)
        except self._anthropic.RateLimitError as exc:
            return ModelTurn(text='', tool_calls=[], stop_reason='error', model=self.model, raw=str(exc))
        except self._anthropic.APIStatusError as exc:
            log.warning('anthropic error %s: %s', exc.status_code, exc.message)
            return ModelTurn(text='', tool_calls=[], stop_reason='error', model=self.model, raw=exc.message)
        except self._anthropic.APIConnectionError as exc:
            return ModelTurn(text='', tool_calls=[], stop_reason='error', model=self.model, raw=str(exc))
        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in response.content:
            if block.type == 'text':
                text_parts.append(block.text)
            elif block.type == 'tool_use':
                args = block.input if isinstance(block.input, dict) else json.loads(block.input or '{}')
                calls.append(ToolCall(id=block.id, name=block.name, args=args))
        usage = Usage(input_tokens=getattr(response.usage, 'input_tokens', 0) or 0, output_tokens=getattr(response.usage, 'output_tokens', 0) or 0,
                      cache_read_tokens=getattr(response.usage, 'cache_read_input_tokens', 0) or 0)
        stop = response.stop_reason or 'end_turn'
        category = ''
        if stop == 'refusal' and getattr(response, 'stop_details', None):
            category = getattr(response.stop_details, 'category', '') or ''
        if stop == 'pause_turn':
            stop = 'tool_use' if calls else 'end_turn'
        # Pass the content blocks back unchanged on the next turn (thinking blocks included).
        raw = [b.model_dump(exclude_none=True) if hasattr(b, 'model_dump') else b for b in response.content]
        return ModelTurn(text=''.join(text_parts), tool_calls=calls, stop_reason=stop, usage=usage, raw=raw,
                         model=getattr(response, 'model', self.model) or self.model, refusal_category=category)


# ---------------------------------------------------------------- OpenAI


class OpenAIProvider(Provider):
    name = 'openai'

    def __init__(self, settings: Settings):
        from openai import AsyncOpenAI

        self.model = settings.openai_model
        self.client = AsyncOpenAI(api_key=settings.openai_api_key, max_retries=3, timeout=600)

    @staticmethod
    def _convert(system: str, messages: list[dict]) -> list[dict]:
        out: list[dict] = [{'role': 'system', 'content': system}]
        for m in messages:
            if m['role'] == 'user':
                out.append({'role': 'user', 'content': m['content']})
            elif m['role'] == 'assistant':
                item: dict = {'role': 'assistant', 'content': m.get('content') or None}
                if m.get('tool_calls'):
                    item['tool_calls'] = [{'id': c['id'], 'type': 'function', 'function': {'name': c['name'], 'arguments': json.dumps(c['args'])}}
                                          for c in m['tool_calls']]
                out.append(item)
            elif m['role'] == 'tool':
                for r in m['results']:
                    out.append({'role': 'tool', 'tool_call_id': r['id'], 'content': r['content']})
        return out

    async def complete(self, system, messages, tools, max_tokens=16000) -> ModelTurn:
        tool_defs = [{'type': 'function', 'function': {'name': t['name'], 'description': t['description'], 'parameters': t['input_schema'], 'strict': strict_compatible(t['input_schema'])}} for t in tools]
        kwargs: dict[str, Any] = dict(model=self.model, messages=self._convert(system, messages), max_completion_tokens=max_tokens)
        if tool_defs:
            kwargs['tools'] = tool_defs
        try:
            response = await self.client.chat.completions.create(**kwargs)
        except Exception as exc:  # the OpenAI SDK raises its own hierarchy; all map to a failed turn
            log.warning('openai error: %s', exc)
            return ModelTurn(text='', tool_calls=[], stop_reason='error', model=self.model, raw=str(exc))
        choice = response.choices[0]
        calls = [ToolCall(id=c.id, name=c.function.name, args=_safe_json(c.function.arguments)) for c in (choice.message.tool_calls or [])]
        usage = Usage(input_tokens=getattr(response.usage, 'prompt_tokens', 0) or 0, output_tokens=getattr(response.usage, 'completion_tokens', 0) or 0)
        finish = choice.finish_reason or 'stop'
        stop = 'tool_use' if calls else ('max_tokens' if finish == 'length' else 'refusal' if finish == 'content_filter' else 'end_turn')
        return ModelTurn(text=choice.message.content or '', tool_calls=calls, stop_reason=stop, usage=usage, model=self.model)


# ---------------------------------------------------------------- Ollama


class OllamaProvider(Provider):
    name = 'ollama'

    def __init__(self, settings: Settings):
        self.model = settings.ollama_model
        self.url = settings.ollama_url.rstrip('/')

    async def complete(self, system, messages, tools, max_tokens=16000) -> ModelTurn:
        payload = {
            'model': self.model, 'stream': False, 'options': {'temperature': 0, 'num_predict': min(max_tokens, 8000)},
            'messages': OpenAIProvider._convert(system, messages),
        }
        if tools:
            payload['tools'] = [{'type': 'function', 'function': {'name': t['name'], 'description': t['description'], 'parameters': t['input_schema']}} for t in tools]
        try:
            async with httpx.AsyncClient(timeout=300, trust_env=False, follow_redirects=False) as client:
                response = await client.post(f'{self.url}/api/chat', json=payload)
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            return ModelTurn(text='', tool_calls=[], stop_reason='error', model=self.model, raw=str(exc))
        message = data.get('message', {})
        calls = []
        for i, c in enumerate(message.get('tool_calls') or []):
            fn = c.get('function', {})
            args = fn.get('arguments', {})
            calls.append(ToolCall(id=c.get('id') or f'call_{i}', name=fn.get('name', ''), args=args if isinstance(args, dict) else _safe_json(args)))
        usage = Usage(input_tokens=data.get('prompt_eval_count', 0) or 0, output_tokens=data.get('eval_count', 0) or 0)
        return ModelTurn(text=message.get('content', '') or '', tool_calls=calls, stop_reason='tool_use' if calls else 'end_turn', usage=usage, model=self.model)


def strict_compatible(schema: dict) -> bool:
    """Strict tool mode requires every object level to set additionalProperties: false and list required keys.
    Free-form objects (e.g. action params) are legal tool inputs but must not be sent as strict."""
    if not isinstance(schema, dict):
        return True
    if schema.get('type') == 'object' or 'properties' in schema:
        if schema.get('additionalProperties', True) is not False:
            return False
        props = schema.get('properties', {})
        if set(schema.get('required', [])) != set(props):
            return False
        return all(strict_compatible(v) for v in props.values())
    if schema.get('type') == 'array':
        return strict_compatible(schema.get('items', {}))
    for key in ('anyOf', 'oneOf', 'allOf'):
        if key in schema and not all(strict_compatible(s) for s in schema[key]):
            return False
    return True


def _safe_json(text: str) -> dict:
    try:
        value = json.loads(text or '{}')
        return value if isinstance(value, dict) else {}
    except ValueError:
        return {}


def get_provider(settings: Settings, override: str | None = None) -> Provider:
    name = (override or settings.ai_provider or 'none').lower()
    if name == 'anthropic':
        return AnthropicProvider(settings)
    if name == 'openai':
        return OpenAIProvider(settings)
    if name == 'ollama':
        return OllamaProvider(settings)
    return NullProvider()


def provider_available(settings: Settings) -> bool:
    if settings.ai_provider == 'anthropic':
        return bool(settings.anthropic_api_key or os.getenv('ANTHROPIC_AUTH_TOKEN') or os.getenv('ANTHROPIC_PROFILE'))
    if settings.ai_provider == 'openai':
        return bool(settings.openai_api_key)
    return settings.ai_provider == 'ollama'
