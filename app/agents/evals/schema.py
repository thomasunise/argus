"""Small, dependency-free JSON-schema validator for the subset specialists use:
type, enum, properties/required/additionalProperties, items, minimum/maximum, minItems/maxItems."""
from __future__ import annotations

from typing import Any

_TYPES = {'string': (str,), 'integer': (int,), 'number': (int, float), 'boolean': (bool,), 'array': (list,), 'object': (dict,), 'null': (type(None),)}


def _type_ok(value: Any, expected: str) -> bool:
    if expected in ('integer', 'number') and isinstance(value, bool):
        return False
    kinds = _TYPES.get(expected)
    return True if kinds is None else isinstance(value, kinds)


def validate(schema: dict, value: Any, path: str = '$') -> list[str]:
    """Returns a list of problems; empty means valid."""
    problems: list[str] = []
    expected = schema.get('type')
    if expected:
        types = expected if isinstance(expected, list) else [expected]
        if not any(_type_ok(value, t) for t in types):
            return [f'{path}: expected {"|".join(types)}, got {type(value).__name__}']
    if 'enum' in schema and value not in schema['enum']:
        problems.append(f'{path}: {value!r} not in {schema["enum"]}')
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if 'minimum' in schema and value < schema['minimum']:
            problems.append(f'{path}: {value} < minimum {schema["minimum"]}')
        if 'maximum' in schema and value > schema['maximum']:
            problems.append(f'{path}: {value} > maximum {schema["maximum"]}')
    if isinstance(value, dict) and (schema.get('type') == 'object' or 'properties' in schema or (isinstance(expected, list) and 'object' in expected)):
        props = schema.get('properties', {})
        for key in schema.get('required', []):
            if key not in value:
                problems.append(f'{path}: missing required {key!r}')
        if schema.get('additionalProperties') is False:
            for key in value:
                if key not in props:
                    problems.append(f'{path}: unexpected property {key!r}')
        for key, sub in props.items():
            if key in value:
                problems.extend(validate(sub, value[key], f'{path}.{key}'))
    if isinstance(value, list):
        if 'minItems' in schema and len(value) < schema['minItems']:
            problems.append(f'{path}: fewer than {schema["minItems"]} items')
        if 'maxItems' in schema and len(value) > schema['maxItems']:
            problems.append(f'{path}: more than {schema["maxItems"]} items')
        items = schema.get('items')
        if isinstance(items, dict):
            for index, item in enumerate(value):
                problems.extend(validate(items, item, f'{path}[{index}]'))
    return problems


def minimal_instance(schema: dict) -> Any:
    """Smallest value that satisfies a strict schema (used by the scripted eval harness)."""
    if 'enum' in schema:
        return schema['enum'][0]
    expected = schema.get('type', 'object')
    kind = expected[0] if isinstance(expected, list) else expected
    if kind == 'object':
        return {key: minimal_instance(sub) for key, sub in schema.get('properties', {}).items() if key in schema.get('required', schema.get('properties', {}))}
    if kind == 'array':
        return []
    if kind == 'string':
        return ''
    if kind == 'integer':
        return int(schema.get('minimum', 0))
    if kind == 'number':
        return float(schema.get('minimum', 0))
    if kind == 'boolean':
        return False
    return None
