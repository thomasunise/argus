"""Tool registry for the agent runtime.

Tools are read-only views over Sentinel data, except tools with risk='propose' which may
create pending ActionRequest rows. No tool may execute anything against the estate.
"""
from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from sqlalchemy.orm import Session

from ...core.config import Settings
from ...core.rbac import Principal

ToolHandler = Callable[[dict, 'ToolContext'], Any | Awaitable[Any]]


@dataclass
class ToolContext:
    db: Session
    principal: Principal
    settings: Settings
    run_id: str
    spec_name: str
    app: Any = None
    scratch: dict = field(default_factory=dict)


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict
    handler: ToolHandler
    risk: str = 'read'  # read | propose
    tags: tuple[str, ...] = ()

    def __post_init__(self):
        schema = dict(self.input_schema or {})
        schema.setdefault('type', 'object')
        schema.setdefault('properties', {})
        schema.setdefault('additionalProperties', False)
        schema.setdefault('required', [k for k in schema['properties'] if k not in schema.get('optional', [])] if 'required' not in schema else schema['required'])
        schema.pop('optional', None)
        self.input_schema = schema
        if self.risk not in {'read', 'propose'}:
            raise ValueError('tool risk must be read or propose')

    def validate(self, args: dict) -> list[str]:
        problems: list[str] = []
        props = self.input_schema.get('properties', {})
        for key in self.input_schema.get('required', []):
            if key not in args:
                problems.append(f'missing required argument {key!r}')
        if not self.input_schema.get('additionalProperties', False):
            for key in args:
                if key not in props:
                    problems.append(f'unknown argument {key!r}')
        for key, value in args.items():
            expected = props.get(key, {}).get('type')
            if expected and not _type_ok(value, expected):
                problems.append(f'argument {key!r} should be {expected}')
        return problems

    async def invoke(self, args: dict, ctx: ToolContext) -> Any:
        result = self.handler(args, ctx)
        if inspect.isawaitable(result):
            result = await result
        return result


def _type_ok(value: Any, expected: str | list[str]) -> bool:
    types = expected if isinstance(expected, list) else [expected]
    mapping = {'string': str, 'integer': int, 'number': (int, float), 'boolean': bool, 'array': list, 'object': dict, 'null': type(None)}
    for t in types:
        py = mapping.get(t)
        if py is None:
            return True
        if t == 'integer' and isinstance(value, bool):
            continue
        if isinstance(value, py):
            return True
    return False


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> Tool:
        self._tools[tool.name] = tool
        return tool

    def tool(self, name: str, description: str, input_schema: dict | None = None, risk: str = 'read', tags: tuple[str, ...] = ()):
        def decorator(fn: ToolHandler) -> Tool:
            return self.register(Tool(name=name, description=description, input_schema=input_schema or {}, handler=fn, risk=risk, tags=tags))
        return decorator

    def get(self, name: str) -> Tool:
        return self._tools[name]

    def resolve(self, names: list[str]) -> list[Tool]:
        missing = [n for n in names if n not in self._tools]
        if missing:
            raise KeyError(f'unknown tools: {missing}')
        return [self._tools[n] for n in names]

    def all(self) -> list[Tool]:
        return sorted(self._tools.values(), key=lambda t: t.name)

    def names(self) -> list[str]:
        return sorted(self._tools)


registry = ToolRegistry()
