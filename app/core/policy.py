"""Target validation. A model cannot override these checks. DNS validation is defense in
depth; production deployments MUST additionally enforce egress filtering against DNS rebinding."""
from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlsplit

from .config import Settings
from .errors import PolicyDenied


def allowed_ip(ip: str, settings: Settings) -> bool:
    addr = ipaddress.ip_address(ip)
    if addr.is_global:
        return True
    if settings.allow_private_targets:
        for cidr in settings.private_target_cidrs.split(','):
            if cidr.strip() and addr in ipaddress.ip_network(cidr.strip(), strict=False):
                return not (addr.is_multicast or addr.is_unspecified or addr.is_loopback or addr.is_link_local)
    return False


def validate_web_target(target: str, settings: Settings, *, resolve: bool = True) -> str:
    value = urlsplit(target)
    if value.scheme != 'https' or not value.hostname or value.username or value.password:
        raise PolicyDenied('Only HTTPS targets with no embedded credentials are permitted')
    if value.query or value.fragment or (value.path not in {'', '/'}):
        raise PolicyDenied('Only HTTPS origin URLs are permitted (no paths, queries, or fragments)')
    if value.port not in {None, 443, 8443}:
        raise PolicyDenied('Port must be 443 or 8443')
    hostname = value.hostname.lower().strip('.')
    if hostname in {'localhost', 'localhost.localdomain'} or hostname.endswith('.localhost'):
        raise PolicyDenied('Localhost is not a valid scan target')
    if resolve:
        try:
            results = socket.getaddrinfo(hostname, value.port or 443, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise PolicyDenied('Could not resolve target hostname') from exc
        ips = {entry[4][0] for entry in results}
        if not ips or any(not allowed_ip(ip, settings) for ip in ips):
            raise PolicyDenied('Target resolves outside permitted IP ranges')
    return f'https://{hostname}' + (':8443' if value.port == 8443 else '')


def validate_repo_target(target: str, settings: Settings) -> Path:
    root = settings.scan_root.resolve()
    path = (root / target).resolve()
    if not target or Path(target).is_absolute() or path == root or root not in path.parents:
        raise PolicyDenied('Repository path must be a subdirectory of SCAN_ROOT')
    if not path.is_dir():
        raise PolicyDenied('Repository directory does not exist on this server')
    return path


def validate_target(kind: str, target: str, settings: Settings, *, resolve: bool = True) -> str:
    """Normalizes targets for all asset kinds. Non-scannable kinds are inventory only."""
    if kind == 'web':
        return validate_web_target(target, settings, resolve=resolve)
    if kind == 'repo':
        return str(validate_repo_target(target, settings).relative_to(settings.scan_root.resolve())).replace('\\', '/')
    if not target or len(target) > 512:
        raise PolicyDenied('Target is required')
    return target.strip()
