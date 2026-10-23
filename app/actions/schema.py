"""Small JSON-schema validator for action parameters.

Action params schemas are deliberately simple (flat objects, additionalProperties false), so
a dependency-free subset of draft-07 is enough: type, properties, required,
additionalProperties, enum, const, string/number/array bounds, pattern, items, anyOf/oneOf.
"""
from __future__ import annotations

import re
from typing import Any

_TYPES = {'string': str, 'integer': int, 'number': (int, float), 'boolean': bool, 'array': list, 'object': dict, 'null': type(None)}


def _is_type(value: Any, expected: str) -> bool:
    py = _TYPES.get(expected)
    if py is None:
        return True
    if expected in {'integer', 'number'} and isinstance(value, bool):
        return False
    return isinstance(value, py)


def validate(schema: dict, value: Any, path: str = '$') -> list[str]:
    """Returns a list of human-readable problems; empty means valid."""
    problems: list[str] = []
    if not isinstance(schema, dict):
        return problems
    expected = schema.get('type')
    if expected is not None:
        types = expected if isinstance(expected, list) else [expected]
        if not any(_is_type(value, t) for t in types):
            problems.append(f'{path} should be {" or ".join(types)}')
            return problems
    if 'const' in schema and value != schema['const']:
        problems.append(f'{path} must equal {schema["const"]!r}')
    if 'enum' in schema and value not in schema['enum']:
        problems.append(f'{path} must be one of {schema["enum"]}')
    if isinstance(value, str):
        if 'minLength' in schema and len(value) < schema['minLength']:
            problems.append(f'{path} is shorter than {schema["minLength"]} characters')
        if 'maxLength' in schema and len(value) > schema['maxLength']:
            problems.append(f'{path} is longer than {schema["maxLength"]} characters')
        if 'pattern' in schema and not re.search(schema['pattern'], value):
            problems.append(f'{path} does not match {schema["pattern"]}')
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if 'minimum' in schema and value < schema['minimum']:
            problems.append(f'{path} is below {schema["minimum"]}')
        if 'maximum' in schema and value > schema['maximum']:
            problems.append(f'{path} is above {schema["maximum"]}')
        if 'exclusiveMinimum' in schema and value <= schema['exclusiveMinimum']:
            problems.append(f'{path} must be greater than {schema["exclusiveMinimum"]}')
    if isinstance(value, list):
        if 'minItems' in schema and len(value) < schema['minItems']:
            problems.append(f'{path} needs at least {schema["minItems"]} items')
        if 'maxItems' in schema and len(value) > schema['maxItems']:
            problems.append(f'{path} allows at most {schema["maxItems"]} items')
        if schema.get('uniqueItems') and len({repr(v) for v in value}) != len(value):
            problems.append(f'{path} items must be unique')
        if 'items' in schema:
            for index, item in enumerate(value):
                problems.extend(validate(schema['items'], item, f'{path}[{index}]'))
    if isinstance(value, dict):
        props = schema.get('properties', {})
        for key in schema.get('required', []):
            if key not in value:
                problems.append(f'{path}.{key} is required')
        extra = schema.get('additionalProperties', True)
        for key, item in value.items():
            if key in props:
                problems.extend(validate(props[key], item, f'{path}.{key}'))
            elif extra is False:
                problems.append(f'{path}.{key} is not an allowed property')
            elif isinstance(extra, dict):
                problems.extend(validate(extra, item, f'{path}.{key}'))
    for keyword in ('anyOf', 'oneOf'):
        options = schema.get(keyword)
        if options:
            matches = [opt for opt in options if not validate(opt, value, path)]
            if not matches or (keyword == 'oneOf' and len(matches) != 1):
                problems.append(f'{path} does not satisfy {keyword}')
    return problems


def apply_defaults(schema: dict, value: dict) -> dict:
    """Returns a copy of value with top-level property defaults filled in."""
    out = dict(value)
    for key, prop in (schema.get('properties') or {}).items():
        if key not in out and isinstance(prop, dict) and 'default' in prop:
            out[key] = prop['default']
    return out
