"""Platform credentials for executors.

Integrations (per-tenant IntegrationConfig with secret refs) is another workstream, so the
broker resolves credentials from two places:

1. Tenant override: `Tenant.settings_json['action_credentials'][platform][key]` holding a
   secret *reference* ('env:NAME', 'file:/path', 'secrets:NAME'). Literal values are ignored.
2. Process environment: ACTIONS_<PLATFORM>_<KEY>. The value may itself be a reference
   (resolved through core.security.resolve_secret) or the literal value.

Nothing here is ever logged or stored.
"""
from __future__ import annotations

import os

from ..core.config import Settings
from ..core.security import resolve_secret

# platform -> key -> environment variable
ENV: dict[str, dict[str, str]] = {
    'aws': {'role_arn': 'ACTIONS_AWS_ROLE_ARN', 'external_id': 'ACTIONS_AWS_EXTERNAL_ID', 'region': 'ACTIONS_AWS_REGION',
            'access_key_id': 'ACTIONS_AWS_ACCESS_KEY_ID', 'secret_access_key': 'ACTIONS_AWS_SECRET_ACCESS_KEY',
            'session_token': 'ACTIONS_AWS_SESSION_TOKEN'},
    'azure': {'tenant_id': 'ACTIONS_AZURE_TENANT_ID', 'client_id': 'ACTIONS_AZURE_CLIENT_ID', 'client_secret': 'ACTIONS_AZURE_CLIENT_SECRET',
              'subscription_id': 'ACTIONS_AZURE_SUBSCRIPTION_ID'},
    'entra': {'tenant_id': 'ACTIONS_ENTRA_TENANT_ID', 'client_id': 'ACTIONS_ENTRA_CLIENT_ID', 'client_secret': 'ACTIONS_ENTRA_CLIENT_SECRET'},
    'gcp': {'access_token': 'ACTIONS_GCP_ACCESS_TOKEN', 'credentials_file': 'ACTIONS_GCP_CREDENTIALS_FILE', 'project': 'ACTIONS_GCP_PROJECT'},
    'kubernetes': {'kubeconfig': 'ACTIONS_K8S_KUBECONFIG', 'context': 'ACTIONS_K8S_CONTEXT'},
    'okta': {'org_url': 'ACTIONS_OKTA_ORG_URL', 'token': 'ACTIONS_OKTA_TOKEN'},
    'github': {'token': 'ACTIONS_GITHUB_TOKEN', 'api_url': 'ACTIONS_GITHUB_API_URL'},
    'cloudflare': {'token': 'ACTIONS_CLOUDFLARE_TOKEN'},
}

# Keys that must be present for the platform to count as configured (any one group suffices).
REQUIRED: dict[str, list[list[str]]] = {
    'aws': [['role_arn'], ['access_key_id', 'secret_access_key']],
    'azure': [['tenant_id', 'client_id', 'client_secret']],
    'entra': [['tenant_id', 'client_id', 'client_secret']],
    'gcp': [['access_token'], ['credentials_file']],
    'kubernetes': [['kubeconfig']],
    'okta': [['org_url', 'token']],
    'github': [['token']],
    'cloudflare': [['token']],
}

FALLBACK = {'entra': 'azure'}  # Entra actions may reuse the Azure app registration

_REF_PREFIXES = ('env:', 'file:', 'secrets:')


def env_name(platform: str, key: str) -> str:
    return ENV.get(platform, {}).get(key, f'ACTIONS_{platform.upper()}_{key.upper()}')


def _from_env(platform: str, key: str, settings: Settings) -> str:
    raw = os.getenv(env_name(platform, key), '')
    if not raw:
        return ''
    if raw.startswith(_REF_PREFIXES):
        return resolve_secret(raw, settings)
    return raw


def _from_tenant(platform: str, key: str, settings: Settings, tenant_settings: dict | None) -> str:
    overrides = (tenant_settings or {}).get('action_credentials') or {}
    ref = (overrides.get(platform) or {}).get(key, '') if isinstance(overrides, dict) else ''
    if not isinstance(ref, str) or not ref.startswith(_REF_PREFIXES):
        return ''  # refs only; a literal secret in tenant settings is ignored on purpose
    return resolve_secret(ref, settings)


def resolve(platform: str, key: str, settings: Settings, tenant_settings: dict | None = None) -> str:
    """Tenant override (secret ref) first, then ACTIONS_* environment, then the fallback platform."""
    value = _from_tenant(platform, key, settings, tenant_settings) or _from_env(platform, key, settings)
    if not value and platform in FALLBACK:
        value = resolve(FALLBACK[platform], key, settings, tenant_settings)
    return value


def credentials(platform: str, settings: Settings, tenant_settings: dict | None = None) -> dict[str, str]:
    keys = set(ENV.get(platform, {})) | set(ENV.get(FALLBACK.get(platform, ''), {}))
    return {key: resolve(platform, key, settings, tenant_settings) for key in sorted(keys)}


def configured(platform: str, settings: Settings, tenant_settings: dict | None = None) -> bool:
    groups = REQUIRED.get(platform)
    if not groups:
        return False
    return any(all(resolve(platform, key, settings, tenant_settings) for key in group) for group in groups)


def platforms() -> list[str]:
    return sorted(ENV)
