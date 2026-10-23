"""Config validation for integrations: a small JSON-schema subset, secret-reference checks and
topic / severity validation. Kept inside this package so it does not depend on other workstreams."""
from __future__ import annotations

import re
from typing import Any

from ..core.findings import SEVERITIES
from ..core.security import redact

SECRET_REF_PREFIXES = ('env:', 'file:', 'secrets:', 'literal:')
TOPIC_PATTERN = re.compile(r'^[a-z_]+(\.[a-z_*]+)?$|^\*$')
KNOWN_TOPIC_PREFIXES = ('finding.', 'detection.', 'action.', 'testing.', 'agent.')  # the families the delivery subscriber forwards


def is_secret_ref(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(SECRET_REF_PREFIXES) and len(value) > value.index(':') + 1


def validate_schema(schema: dict[str, Any], config: Any, path: str = '') -> list[str]:
    """Supports type, properties, required, additionalProperties, enum, items, minItems, minimum,
    maximum, maxLength, pattern, format (uri, email). Returns human-readable errors."""
    errors: list[str] = []
    expected = schema.get('type')
    label = path or 'config'
    if expected == 'object':
        if not isinstance(config, dict):
            return [f'{label} must be an object']
        properties: dict[str, Any] = schema.get('properties', {}) or {}
        if schema.get('additionalProperties') is False:
            errors += [f'unknown key {label}.{key}' for key in config if key not in properties]
        elif isinstance(schema.get('additionalProperties'), dict):
            for key, value in config.items():
                if key not in properties:
                    errors += validate_schema(schema['additionalProperties'], value, f'{label}.{key}')
        for key in schema.get('required', []) or []:
            if key not in config or config[key] in ('', None, []):
                errors.append(f'{label}.{key} is required')
        for key, sub in properties.items():
            if key in config and config[key] is not None:
                errors += validate_schema(sub, config[key], f'{label}.{key}')
        return errors
    if expected == 'array':
        if not isinstance(config, list):
            return [f'{label} must be an array']
        if 'minItems' in schema and len(config) < int(schema['minItems']):
            errors.append(f'{label} needs at least {schema["minItems"]} item(s)')
        if 'items' in schema:
            for index, item in enumerate(config):
                errors += validate_schema(schema['items'], item, f'{label}[{index}]')
        return errors
    if expected == 'string':
        if not isinstance(config, str):
            return [f'{label} must be a string']
        if 'maxLength' in schema and len(config) > int(schema['maxLength']):
            errors.append(f'{label} is longer than {schema["maxLength"]} characters')
        if 'enum' in schema and config not in schema['enum']:
            errors.append(f'{label} must be one of {", ".join(map(str, schema["enum"]))}')
        if 'pattern' in schema and not re.search(schema['pattern'], config):
            errors.append(f'{label} does not match {schema["pattern"]}')
        if schema.get('format') == 'uri' and not re.match(r'^[a-z][a-z0-9+.-]*://\S+$', config, re.I):
            errors.append(f'{label} must be a URL')
        if schema.get('format') == 'email' and not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', config):
            errors.append(f'{label} must be an email address')
        return errors
    if expected in {'integer', 'number'}:
        if isinstance(config, bool) or not isinstance(config, (int, float)) or (expected == 'integer' and not float(config).is_integer()):
            return [f'{label} must be a {expected}']
        if 'minimum' in schema and config < schema['minimum']:
            errors.append(f'{label} must be >= {schema["minimum"]}')
        if 'maximum' in schema and config > schema['maximum']:
            errors.append(f'{label} must be <= {schema["maximum"]}')
        return errors
    if expected == 'boolean' and not isinstance(config, bool):
        return [f'{label} must be true or false']
    return errors


def validate_secret_refs(secret_refs: dict[str, Any], allowed: list[str]) -> list[str]:
    errors: list[str] = []
    for key, ref in (secret_refs or {}).items():
        if key not in allowed:
            errors.append(f'unknown secret field {key}; allowed: {", ".join(allowed) or "none"}')
        elif not is_secret_ref(ref):
            errors.append(f'secret_refs.{key} must be a reference (env:NAME, file:/path, secrets:KEY); a literal value needs the literal: prefix')
    return errors


def validate_no_inline_secrets(config: dict[str, Any], secret_fields: list[str]) -> list[str]:
    errors: list[str] = []
    for key, value in (config or {}).items():
        if key in secret_fields:
            errors.append(f'{key} is a secret and must be supplied in secret_refs, never inline')
        elif isinstance(value, str) and redact(value) != value:
            errors.append(f'config value {key} looks like a credential; move it to secret_refs')
    return errors


def validate_topics(topics: list[Any]) -> list[str]:
    errors: list[str] = []
    for topic in topics or []:
        if not isinstance(topic, str) or not TOPIC_PATTERN.match(topic):
            errors.append(f'invalid topic {topic!r}; use forms like finding.created, finding.*, action.*')
        elif topic != '*' and not topic.startswith(KNOWN_TOPIC_PREFIXES):
            errors.append(f'unknown topic family {topic!r}; known: {", ".join(p + "*" for p in KNOWN_TOPIC_PREFIXES)}')
    return errors


def validate_severity(value: Any) -> list[str]:
    return [] if value in SEVERITIES else [f'min_severity must be one of {", ".join(SEVERITIES)}']


def topic_matches(patterns: list[str], topic: str) -> bool:
    for pattern in patterns or []:
        if pattern == '*' or pattern == topic or (pattern.endswith('*') and topic.startswith(pattern[:-1])):
            return True
    return False


def severity_at_least(severity: str, minimum: str) -> bool:
    if severity not in SEVERITIES:
        return True  # events without a severity are not filtered
    if minimum not in SEVERITIES:
        return True
    return SEVERITIES.index(severity) <= SEVERITIES.index(minimum)
