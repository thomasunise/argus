"""Inbound parsers. Each parser normalizes one source's payloads into `EventDraft`s (and, for
vulnerability-report sources, `FindingDraft`s).

    from app.integrations.inbound import registry, Parser, ParseContext, FindingDraft
    parser = registry.get('aws_cloudtrail')
    drafts = parser.parse(payload, ParseContext(tenant_id=..., source='aws_cloudtrail'))
"""
from __future__ import annotations

import importlib

from ._common import FindingDraft, ParseContext, Parser, clean_metadata, parse_time, snake  # noqa: F401

BUILTIN = ['wazuh', 'falco', 'trivy', 'aws_guardduty', 'aws_cloudtrail', 'azure_defender', 'gcp_scc', 'crowdstrike', 'sentinelone',
           'okta_logs', 'k8s_audit', 'github_webhook', 'generic', 'network']


class Registry:
    def __init__(self) -> None:
        self._parsers: dict[str, Parser] = {}
        self._aliases: dict[str, str] = {}
        self._loaded = False

    def register(self, parser: Parser) -> Parser:
        self._parsers[parser.name] = parser
        for alias in parser.aliases:
            self._aliases[alias] = parser.name
        return parser

    def load_builtin(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        for module in BUILTIN:
            importlib.import_module(f'{__name__}.{module}')

    def resolve(self, name: str) -> str | None:
        self.load_builtin()
        key = (name or '').strip().lower().replace('-', '_')
        if key in self._parsers:
            return key
        return self._aliases.get(key)

    def has(self, name: str) -> bool:
        return self.resolve(name) is not None

    def get(self, name: str) -> Parser:
        key = self.resolve(name)
        if key is None:
            raise KeyError(name)
        return self._parsers[key]

    def all(self) -> list[Parser]:
        self.load_builtin()
        return [self._parsers[k] for k in sorted(self._parsers)]

    def names(self) -> list[str]:
        self.load_builtin()
        return sorted(self._parsers)


registry = Registry()

__all__ = ['registry', 'Registry', 'Parser', 'ParseContext', 'FindingDraft', 'clean_metadata', 'parse_time', 'snake', 'BUILTIN']
