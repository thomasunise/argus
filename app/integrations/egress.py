"""Shared allow/deny check for user-supplied outbound URLs (webhooks, ticketing systems, chat
hooks, SIEM indexers, fleet servers).

Operators configure these destinations through the API, so a compromised or careless admin
account must not be able to point Sentinel at the cloud metadata service, loopback, link-local
or RFC 1918 space. The check is applied when a configuration is saved (with DNS resolution)
and again, syntactically, right before every send. DNS rebinding between the two is a known
residual that network egress policy must cover (see docs/THREAT-MODEL.md).
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Any, Iterable
from urllib.parse import urlsplit

from ..core.config import Settings
from ..core.errors import SentinelError
from ..core.policy import allowed_ip


class EgressDenied(SentinelError):
    status = 400
    code = 'egress_denied'


# Hostnames that are never a legitimate destination for tenant data. Reserved TLDs never resolve
# publicly (RFC 2606 / RFC 6761); the metadata names resolve to link-local addresses inside clouds.
BLOCKED_HOSTS = {'localhost', 'localhost.localdomain', 'metadata', 'metadata.google.internal', 'instance-data', 'metadata.azure.com',
                 'kubernetes.default', 'kubernetes.default.svc', 'kubernetes.default.svc.cluster.local', 'ip6-localhost', 'ip6-loopback'}
# Private DNS suffixes such as .internal or .local are legitimate for self-hosted fleets and SIEMs; only names that
# are loopback by definition are blocked by suffix. Everything else is judged by the address it resolves to.
BLOCKED_SUFFIXES = ('.localhost', '.svc.cluster.local')
RESERVED_TLDS = ('.test', '.example', '.invalid')
RESERVED_DOMAINS = ('example.com', 'example.net', 'example.org')
URL_CONFIG_KEYS = ('url', 'base_url', 'instance_url', 'indexer_url', 'fleet_url', 'api_url', 'endpoint', 'server_url', 'graph_url', 'login_url')


def _unresolvable_by_design(hostname: str) -> bool:
    return hostname.endswith(RESERVED_TLDS) or hostname in RESERVED_DOMAINS or hostname.endswith(tuple('.' + d for d in RESERVED_DOMAINS))


def validate_outbound_url(url: Any, settings: Settings, *, resolve: bool = True, allow_http: bool = False, label: str = 'url') -> str:
    """Return the URL when it may be contacted; raise EgressDenied otherwise.

    Rules: http(s) only (https unless allow_http); no embedded credentials; no loopback, link-local,
    multicast, unspecified or private hosts (private ranges only when ALLOW_PRIVATE_TARGETS lists them);
    no cloud metadata or cluster-internal names. With resolve=True every address the hostname
    resolves to must pass as well; names that cannot be resolved are left to the connection to fail.
    """
    if not isinstance(url, str) or not url.strip():
        raise EgressDenied(f'{label} is required')
    text = url.strip()
    try:
        parts = urlsplit(text)
    except ValueError as exc:
        raise EgressDenied(f'{label} is not a valid URL') from exc
    scheme = (parts.scheme or '').lower()
    if scheme not in {'http', 'https'} or (scheme == 'http' and not allow_http):
        raise EgressDenied(f'{label} must use https://')
    if parts.username or parts.password:
        raise EgressDenied(f'{label} must not embed credentials')
    hostname = (parts.hostname or '').strip().strip('.').lower()
    if not hostname:
        raise EgressDenied(f'{label} has no host')
    if hostname in BLOCKED_HOSTS or hostname.endswith(BLOCKED_SUFFIXES):
        raise EgressDenied(f'{label} points at a local or cluster-internal host')
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if not allowed_ip(str(literal), settings):
            raise EgressDenied(f'{label} points at a private, loopback or link-local address')
        return text
    if resolve and not _unresolvable_by_design(hostname):
        try:
            results = socket.getaddrinfo(hostname, parts.port or (443 if scheme == 'https' else 80), type=socket.SOCK_STREAM)
        except (socket.gaierror, OSError, UnicodeError):
            results = []
        addresses = {entry[4][0] for entry in results}
        if addresses and any(not allowed_ip(ip, settings) for ip in addresses):
            raise EgressDenied(f'{label} resolves to a private, loopback or link-local address')
    return text


def check_url_config(config: dict[str, Any], settings: Settings, *, keys: Iterable[str] = URL_CONFIG_KEYS, resolve: bool = True,
                     allow_http: bool = False) -> list[str]:
    """Validate every URL-bearing key present in an integration/collector config. Returns error strings."""
    errors: list[str] = []
    for key in keys:
        value = (config or {}).get(key)
        if value in (None, ''):
            continue
        try:
            validate_outbound_url(value, settings, resolve=resolve, allow_http=allow_http, label=key)
        except EgressDenied as exc:
            errors.append(exc.message)
    return errors


def egress_ok(url: Any, settings: Settings, *, allow_http: bool = False) -> str:
    """Send-time guard: '' when the URL may be contacted, otherwise the reason it may not."""
    try:
        validate_outbound_url(url, settings, resolve=False, allow_http=allow_http)
    except EgressDenied as exc:
        return exc.message
    return ''


__all__ = ['EgressDenied', 'validate_outbound_url', 'check_url_config', 'egress_ok', 'URL_CONFIG_KEYS']
