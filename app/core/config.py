from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AI_PROVIDERS = {'none', 'anthropic', 'openai', 'ollama'}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore', case_sensitive=False)

    # --- app ---
    app_env: str = 'development'  # development, staging, production
    app_name: str = 'Argus'
    base_url: str = 'http://127.0.0.1:8080'
    session_secret: str = ''
    session_max_age: int = 3600  # idle timeout (the cookie is refreshed on every response)
    session_absolute_max_age: int = 43200  # hard lifetime from login, regardless of activity
    cookie_secure: bool = False
    db_auto_create: bool = True
    request_id_header: str = 'X-Request-ID'

    # --- database / queue ---
    database_url: str = 'sqlite:///./data/argus.db'
    redis_url: str = ''
    workers_inprocess: bool = True
    worker_concurrency: int = 4
    queue_max_attempts: int = 3

    # --- auth ---
    admin_email: str = 'admin@argus.local'
    admin_password: str = ''
    admin_password_reset: bool = False  # true: re-apply ADMIN_PASSWORD to the bootstrap owner at startup (recovery)
    default_tenant_slug: str = 'default'
    default_tenant_name: str = 'Default'
    ingest_api_key: str = ''  # bootstrap ingest key for the default tenant
    totp_required: bool = False
    oidc_issuer: str = ''
    oidc_client_id: str = ''
    oidc_client_secret: str = ''
    oidc_default_role: str = 'viewer'
    oidc_allowed_domains: str = ''  # comma separated email domains
    oidc_auto_provision: bool = True
    oidc_trust_email: bool = False  # link an existing local account to an SSO identity even when the IdP does not assert email_verified
    login_max_attempts: int = 8
    login_window_seconds: int = 300

    # --- audit ---
    audit_jsonl_path: str = ''
    audit_signing_key: str = ''
    audit_signing_keys: str = ''  # 'kid=key,kid2=key2'; first signs, all verify
    audit_s3_bucket: str = ''
    audit_s3_prefix: str = 'argus-audit/'
    audit_azure_container: str = ''
    audit_azure_connection_string: str = ''

    # --- telemetry ---
    log_json: bool = False
    log_level: str = 'INFO'
    metrics_enabled: bool = True
    otel_exporter_otlp_endpoint: str = ''
    otel_service_name: str = 'argus'

    # --- AI / agents ---
    ai_provider: str = 'none'
    anthropic_api_key: str = ''
    anthropic_model: str = 'claude-opus-5-5'
    anthropic_effort: str = 'high'
    openai_api_key: str = ''
    openai_model: str = 'gpt-4.1'
    ollama_url: str = 'http://127.0.0.1:11434'
    ollama_model: str = 'gpt-oss:20b'
    agent_max_steps: int = 12
    agent_max_tokens: int = 150_000
    agent_max_seconds: int = 300
    agent_tool_result_limit: int = 6000
    agent_cost_ceiling_usd: float = 5.0
    # USD per million tokens for models missing from the built-in table: 'model=input:output,...'.
    agent_model_prices: str = ''

    # --- testing harness ---
    scan_root: Path = Path('./targets')
    enable_trivy: bool = False
    trivy_bin: str = 'trivy'
    nuclei_bin: str = 'nuclei'
    nuclei_templates: str = ''
    semgrep_bin: str = 'semgrep'
    gitleaks_bin: str = 'gitleaks'
    prowler_bin: str = 'prowler'
    zap_url: str = ''
    zap_api_key: str = ''
    caldera_url: str = ''
    caldera_api_key: str = ''
    test_rate_limit_rps: float = 5.0
    test_tool_timeout_seconds: int = 900
    allow_private_targets: bool = False
    private_target_cidrs: str = ''
    autoscan_enabled: bool = False
    autoscan_minutes: int = 360

    # --- actions ---
    actions_kill_switch: bool = False
    actions_auto_approve_low: bool = False
    actions_require_two_for_high: bool = True
    actions_maintenance_window: str = ''  # e.g. "02:00-04:00" UTC

    # --- threat intel enrichment (CISA KEV / FIRST EPSS) ---
    intel_enrichment_enabled: bool = True
    intel_offline: bool = False  # never fetch; use files placed in INTEL_CACHE_DIR
    intel_cache_dir: Path = Path('./data/intel')
    intel_kev_refresh_hours: int = 12
    intel_epss_ttl_hours: int = 24
    intel_kev_min_severity: str = 'high'  # KEV-listed findings are raised to at least this; '' disables
    intel_epss_escalate_threshold: float = 0.0  # e.g. 0.5 raises findings with EPSS >= 0.5 to high; 0 disables

    # --- secrets backend / encryption at rest ---
    secrets_backend: str = 'env'  # env, file
    secrets_file: str = ''
    data_encryption_key: str = ''
    secret_env_prefix: str = 'ARGUS_SECRET_'  # env: refs must start with this prefix or be allowlisted
    secret_env_allowlist: str = ''  # comma separated env names; '*' allows any (development only)
    secrets_dir: Path = Path('/run/secrets')  # file: refs must resolve under this directory
    max_request_body_bytes: int = 8 * 1024 * 1024
    data_encryption_keys: str = ''  # 'kid=base64key,kid2=base64key2'; first encrypts, all decrypt
    allow_literal_secret_refs: bool = True  # forced False in production

    # --- legacy integrations ---
    wazuh_indexer_url: str = ''
    wazuh_indexer_user: str = ''
    wazuh_indexer_password: str = ''
    wazuh_ca_bundle: str = ''

    # --- limits ---
    ingest_rate_limit_per_minute: int = 1200
    api_rate_limit_per_minute: int = 600

    @field_validator('ai_provider')
    @classmethod
    def _provider(cls, value: str) -> str:
        value = (value or 'none').lower()
        if value not in AI_PROVIDERS:
            raise ValueError(f'AI_PROVIDER must be one of {sorted(AI_PROVIDERS)}')
        return value

    @field_validator('scan_root', mode='before')
    @classmethod
    def _scan_root(cls, value):
        return Path(value or './targets').resolve()

    @field_validator('autoscan_minutes')
    @classmethod
    def _autoscan(cls, value: int) -> int:
        return max(15, int(value))

    @property
    def is_production(self) -> bool:
        return self.app_env == 'production'

    @property
    def sqlite(self) -> bool:
        return self.database_url.startswith('sqlite')


def parse_model_prices(raw: str) -> dict[str, tuple[float, float]]:
    """Parse AGENT_MODEL_PRICES ('gpt-4.1=2:8,my-model=0.5:1.5', USD per million input:output tokens)."""
    prices: dict[str, tuple[float, float]] = {}
    for item in (raw or '').split(','):
        item = item.strip()
        if not item:
            continue
        name, _, rest = item.partition('=')
        inp, sep, out = rest.partition(':')
        try:
            if not name.strip() or not sep:
                raise ValueError
            pair = (float(inp), float(out))
        except ValueError:
            raise ValueError(f'AGENT_MODEL_PRICES entry {item!r} must look like model=input:output') from None
        if pair[0] < 0 or pair[1] < 0:
            raise ValueError(f'AGENT_MODEL_PRICES entry {item!r} has a negative price')
        prices[name.strip()] = pair
    return prices


def assert_safe_config(settings: Settings) -> None:
    try:
        parse_model_prices(settings.agent_model_prices)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from None
    if len(settings.session_secret) < 32 or settings.session_secret.startswith('REPLACE_'):
        raise RuntimeError('Set SESSION_SECRET to at least 32 random characters in .env')
    if len(settings.admin_password) < 14 or settings.admin_password.startswith('REPLACE_'):
        raise RuntimeError('Set a strong ADMIN_PASSWORD (at least 14 characters) in .env')
    if settings.ingest_api_key and (len(settings.ingest_api_key) < 24 or settings.ingest_api_key.startswith('REPLACE_')):
        raise RuntimeError('INGEST_API_KEY must be at least 24 random characters')
    if settings.ingest_api_key:
        from .security import parse_api_key  # local import: security depends on this module

        if not parse_api_key(settings.ingest_api_key):
            raise RuntimeError('INGEST_API_KEY must have the argus_<prefix>_<secret> form; generate one with scripts/generate_secrets.py')
    if settings.oidc_default_role not in {'viewer', 'analyst', 'operator', 'admin', 'owner'}:
        raise RuntimeError(f'OIDC_DEFAULT_ROLE {settings.oidc_default_role!r} is not a role')
    if settings.is_production:
        if settings.sqlite:
            raise RuntimeError('Production requires PostgreSQL (DATABASE_URL=postgresql+psycopg://...)')
        if not settings.cookie_secure:
            raise RuntimeError('Production requires COOKIE_SECURE=true behind HTTPS')
        if not settings.redis_url:
            raise RuntimeError('Production requires REDIS_URL for durable job processing')
        if not settings.base_url.startswith('https://'):
            raise RuntimeError('Production requires BASE_URL to be an https:// URL')
        if not (settings.data_encryption_key or settings.data_encryption_keys):
            raise RuntimeError('Production requires DATA_ENCRYPTION_KEY (or DATA_ENCRYPTION_KEYS) for encryption at rest')
        if not (settings.audit_signing_key or settings.audit_signing_keys):
            raise RuntimeError('Production requires AUDIT_SIGNING_KEY (or AUDIT_SIGNING_KEYS)')
        if not (settings.audit_jsonl_path or settings.audit_s3_bucket or settings.audit_azure_container):
            raise RuntimeError('Production requires an external audit sink (AUDIT_JSONL_PATH, AUDIT_S3_BUCKET or AUDIT_AZURE_CONTAINER)')
        if not settings.totp_required and not settings.oidc_issuer:
            raise RuntimeError('Production requires TOTP_REQUIRED=true or OIDC single sign-on')
        if settings.secret_env_allowlist.strip() == '*':
            raise RuntimeError('SECRET_ENV_ALLOWLIST=* is not permitted in production; list the exact variable names')
        if settings.allow_private_targets and not settings.private_target_cidrs:
            raise RuntimeError('ALLOW_PRIVATE_TARGETS requires an explicit PRIVATE_TARGET_CIDRS allowlist')
        settings_dict = settings.__dict__
        settings_dict['allow_literal_secret_refs'] = False
    if settings.ai_provider == 'anthropic' and not settings.anthropic_api_key:
        # The SDK can also resolve credentials from ANTHROPIC_AUTH_TOKEN or an `ant auth login` profile.
        import os
        if not (os.getenv('ANTHROPIC_AUTH_TOKEN') or os.getenv('ANTHROPIC_PROFILE')):
            raise RuntimeError('AI_PROVIDER=anthropic requires ANTHROPIC_API_KEY (or an Anthropic auth profile)')
    if settings.ai_provider == 'openai' and not settings.openai_api_key:
        raise RuntimeError('AI_PROVIDER=openai requires OPENAI_API_KEY')


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
