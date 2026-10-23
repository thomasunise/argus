from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def truthy(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {'true', '1', 'yes', 'on'}


@dataclass(frozen=True)
class Settings:
    admin_password: str
    session_secret: str
    ingest_api_key: str
    database_url: str
    cookie_secure: bool
    autoscan_enabled: bool
    autoscan_minutes: int
    allow_private_targets: bool
    private_target_cidrs: str
    scan_root: Path
    enable_trivy: bool
    ai_provider: str
    ollama_url: str
    ollama_model: str
    openai_api_key: str
    openai_model: str
    anthropic_api_key: str
    anthropic_model: str
    wazuh_indexer_url: str
    wazuh_indexer_user: str
    wazuh_indexer_password: str
    wazuh_ca_bundle: str


def get_settings() -> Settings:
    return Settings(
        admin_password=os.getenv('ADMIN_PASSWORD', ''),
        session_secret=os.getenv('SESSION_SECRET', ''),
        ingest_api_key=os.getenv('INGEST_API_KEY', ''),
        database_url=os.getenv('DATABASE_URL', 'sqlite:///./data/sentinel.db'),
        cookie_secure=truthy('COOKIE_SECURE'),
        autoscan_enabled=truthy('AUTOSCAN_ENABLED'),
        autoscan_minutes=max(15, int(os.getenv('AUTOSCAN_MINUTES', '360'))),
        allow_private_targets=truthy('ALLOW_PRIVATE_TARGETS'),
        private_target_cidrs=os.getenv('PRIVATE_TARGET_CIDRS', ''),
        scan_root=Path(os.getenv('SCAN_ROOT', './targets')).resolve(),
        enable_trivy=truthy('ENABLE_TRIVY'),
        ai_provider=os.getenv('AI_PROVIDER', 'none').lower(),
        ollama_url=os.getenv('OLLAMA_URL', 'http://127.0.0.1:11434').rstrip('/'),
        ollama_model=os.getenv('OLLAMA_MODEL', 'gpt-oss:20b'),
        openai_api_key=os.getenv('OPENAI_API_KEY', ''),
        openai_model=os.getenv('OPENAI_MODEL', 'gpt-4.1'),
        anthropic_api_key=os.getenv('ANTHROPIC_API_KEY', ''),
        anthropic_model=os.getenv('ANTHROPIC_MODEL', 'claude-sonnet-4-5'),
        wazuh_indexer_url=os.getenv('WAZUH_INDEXER_URL', '').rstrip('/'),
        wazuh_indexer_user=os.getenv('WAZUH_INDEXER_USER', ''),
        wazuh_indexer_password=os.getenv('WAZUH_INDEXER_PASSWORD', ''),
        wazuh_ca_bundle=os.getenv('WAZUH_CA_BUNDLE', ''),
    )


def assert_safe_config(settings: Settings) -> None:
    if len(settings.admin_password) < 14 or settings.admin_password.startswith('REPLACE_'):
        raise RuntimeError('Set a strong ADMIN_PASSWORD (at least 14 characters) in .env')
    if len(settings.session_secret) < 32 or settings.session_secret.startswith('REPLACE_'):
        raise RuntimeError('Set SESSION_SECRET to at least 32 random characters in .env')
    if len(settings.ingest_api_key) < 24 or settings.ingest_api_key.startswith('REPLACE_'):
        raise RuntimeError('Set INGEST_API_KEY to at least 24 random characters in .env')
    if settings.ai_provider not in {'none', 'ollama', 'openai', 'anthropic'}:
        raise RuntimeError('AI_PROVIDER must be none, ollama, openai, or anthropic')
