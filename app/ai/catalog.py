"""Catalog of known AI services used by shadow-AI discovery.

Three kinds of signature:
- domains: hostnames seen in network, DNS, proxy or endpoint telemetry (suffix match);
- cloud API signatures: managed model APIs called through a cloud provider's control plane
  (AWS Bedrock, Azure OpenAI / Cognitive Services, Google Vertex AI and Gemini API);
- app names: OAuth/SaaS application names seen in Okta and Entra consent or grant events.

Nothing here talks to the network. The lists are deliberately conservative: a match must name
a hostname or application that exists only to serve an AI product.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AIServiceDef:
    key: str
    provider: str
    name: str
    category: str  # api | assistant | code | meeting | platform | cloud
    domains: tuple[str, ...] = ()
    app_names: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {'key': self.key, 'provider': self.provider, 'name': self.name, 'category': self.category,
                'domains': list(self.domains), 'app_names': list(self.app_names)}


SERVICES: tuple[AIServiceDef, ...] = (
    AIServiceDef('openai.api', 'OpenAI', 'OpenAI API', 'api', ('api.openai.com',)),
    AIServiceDef('openai.chatgpt', 'OpenAI', 'ChatGPT', 'assistant', ('chatgpt.com', 'chat.openai.com', 'chatgpt.livekit.cloud'), ('ChatGPT', 'OpenAI')),
    AIServiceDef('anthropic.api', 'Anthropic', 'Anthropic API', 'api', ('api.anthropic.com',)),
    AIServiceDef('anthropic.claude', 'Anthropic', 'Claude', 'assistant', ('claude.ai',), ('Claude', 'Anthropic')),
    AIServiceDef('google.gemini_api', 'Google', 'Gemini API', 'api', ('generativelanguage.googleapis.com',)),
    AIServiceDef('google.gemini', 'Google', 'Gemini', 'assistant', ('gemini.google.com', 'bard.google.com', 'aistudio.google.com', 'notebooklm.google.com'),
                 ('Gemini', 'NotebookLM')),
    AIServiceDef('microsoft.copilot', 'Microsoft', 'Microsoft Copilot', 'assistant',
                 ('copilot.microsoft.com', 'sydney.bing.com', 'copilot.cloud.microsoft', 'substrate.office.com'), ('Microsoft Copilot', 'Copilot Studio')),
    AIServiceDef('github.copilot', 'GitHub', 'GitHub Copilot', 'code',
                 ('copilot-proxy.githubusercontent.com', 'api.githubcopilot.com', 'origin-tracker.githubusercontent.com', 'copilot-telemetry.githubusercontent.com'),
                 ('GitHub Copilot',)),
    AIServiceDef('mistral.api', 'Mistral AI', 'Mistral API / Le Chat', 'api', ('api.mistral.ai', 'chat.mistral.ai', 'codestral.mistral.ai'), ('Le Chat',)),
    AIServiceDef('cohere.api', 'Cohere', 'Cohere API', 'api', ('api.cohere.com', 'api.cohere.ai', 'dashboard.cohere.com')),
    AIServiceDef('groq.api', 'Groq', 'Groq API', 'api', ('api.groq.com', 'console.groq.com')),
    AIServiceDef('openrouter.api', 'OpenRouter', 'OpenRouter', 'api', ('openrouter.ai',)),
    AIServiceDef('together.api', 'Together AI', 'Together API', 'api', ('api.together.xyz', 'api.together.ai')),
    AIServiceDef('deepseek.api', 'DeepSeek', 'DeepSeek', 'api', ('api.deepseek.com', 'chat.deepseek.com')),
    AIServiceDef('perplexity', 'Perplexity', 'Perplexity', 'assistant', ('api.perplexity.ai', 'perplexity.ai'), ('Perplexity',)),
    AIServiceDef('xai.grok', 'xAI', 'Grok / xAI API', 'api', ('api.x.ai', 'grok.com', 'console.x.ai'), ('Grok',)),
    AIServiceDef('huggingface', 'Hugging Face', 'Hugging Face', 'platform', ('huggingface.co', 'api-inference.huggingface.co', 'hf.space')),
    AIServiceDef('replicate', 'Replicate', 'Replicate', 'platform', ('replicate.com', 'api.replicate.com', 'replicate.delivery')),
    AIServiceDef('fireworks.api', 'Fireworks AI', 'Fireworks API', 'api', ('api.fireworks.ai',)),
    AIServiceDef('cursor', 'Anysphere', 'Cursor', 'code', ('api2.cursor.sh', 'api.cursor.sh', 'cursor.com'), ('Cursor',)),
    AIServiceDef('codeium', 'Codeium', 'Windsurf / Codeium', 'code', ('server.codeium.com', 'windsurf.com', 'codeium.com'), ('Windsurf', 'Codeium')),
    AIServiceDef('tabnine', 'Tabnine', 'Tabnine', 'code', ('api.tabnine.com',), ('Tabnine',)),
    AIServiceDef('otter', 'Otter.ai', 'Otter.ai', 'meeting', ('otter.ai',), ('Otter.ai', 'Otter')),
    AIServiceDef('fireflies', 'Fireflies.ai', 'Fireflies.ai', 'meeting', ('fireflies.ai', 'app.fireflies.ai'), ('Fireflies.ai', 'Fireflies')),
    AIServiceDef('readai', 'Read AI', 'Read AI', 'meeting', ('read.ai',), ('Read AI', 'Read.ai')),
    AIServiceDef('jasper', 'Jasper', 'Jasper', 'assistant', ('jasper.ai', 'app.jasper.ai'), ('Jasper',)),
    AIServiceDef('character', 'Character.AI', 'Character.AI', 'assistant', ('character.ai', 'beta.character.ai')),
    AIServiceDef('poe', 'Quora', 'Poe', 'assistant', ('poe.com',)),
    AIServiceDef('elevenlabs', 'ElevenLabs', 'ElevenLabs', 'api', ('api.elevenlabs.io', 'elevenlabs.io')),
    AIServiceDef('midjourney', 'Midjourney', 'Midjourney', 'assistant', ('midjourney.com',)),
    # Cloud-hosted model APIs (matched by API signature as well as hostname).
    AIServiceDef('aws.bedrock', 'Amazon Web Services', 'Amazon Bedrock', 'cloud', ('bedrock-runtime.amazonaws.com', 'bedrock.amazonaws.com')),
    AIServiceDef('azure.openai', 'Microsoft', 'Azure OpenAI / AI Foundry', 'cloud', ('openai.azure.com', 'cognitiveservices.azure.com', 'services.ai.azure.com')),
    AIServiceDef('gcp.vertex', 'Google Cloud', 'Vertex AI', 'cloud', ('aiplatform.googleapis.com',)),
    AIServiceDef('argus.gateway', 'Argus', 'Argus AI gateway', 'api'),
)

BY_KEY = {s.key: s for s in SERVICES}

# Longest domain first so 'api.openai.com' wins over a shorter overlapping suffix.
_DOMAIN_INDEX: list[tuple[str, AIServiceDef]] = sorted(((d, s) for s in SERVICES for d in s.domains), key=lambda x: -len(x[0]))
_APP_INDEX: list[tuple[re.Pattern, AIServiceDef]] = [
    (re.compile(rf'(?<![A-Za-z0-9]){re.escape(name)}(?![A-Za-z0-9])', re.IGNORECASE), s)
    for s in SERVICES for name in sorted(s.app_names, key=len, reverse=True)
]

_HOST_RE = re.compile(r'(?i)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}')


@dataclass
class CloudSignature:
    service_key: str
    sources: tuple[str, ...]  # event.source prefixes ('' = any)
    action_prefixes: tuple[str, ...] = ()
    strings: tuple[str, ...] = ()  # lower-case substrings of event_source / service / resource provider
    note: str = ''
    extra: dict = field(default_factory=dict)


CLOUD_SIGNATURES: tuple[CloudSignature, ...] = (
    CloudSignature('aws.bedrock', ('aws_cloudtrail', 'cloudtrail', 'aws'), ('bedrock.', 'bedrock_runtime.', 'bedrock-runtime.'),
                   ('bedrock.amazonaws.com', 'bedrock-runtime.amazonaws.com'), 'Bedrock API call in CloudTrail'),
    CloudSignature('azure.openai', ('azure', 'azure_activity', 'azure_defender', 'entra', 'generic'),
                   ('microsoft.cognitiveservices', 'cognitiveservices.'), ('microsoft.cognitiveservices', 'openai.azure.com'),
                   'Azure Cognitive Services / OpenAI operation'),
    CloudSignature('gcp.vertex', ('gcp', 'gcp_audit', 'gcp_scc', 'generic'), ('aiplatform.', 'google.cloud.aiplatform.'),
                   ('aiplatform.googleapis.com',), 'Vertex AI call in Cloud Audit Logs'),
    CloudSignature('google.gemini_api', ('gcp', 'gcp_audit', 'generic'), ('generativelanguage.',), ('generativelanguage.googleapis.com',),
                   'Gemini API call'),
)

# Event actions / titles that indicate an OAuth consent or SaaS app assignment.
OAUTH_HINTS = ('consent', 'oauth', 'grant', 'app.', 'application', 'app_role', 'service_principal', 'add_app', 'app_user', 'app_access',
               'appassignment', 'add app role', 'add service principal')
IDENTITY_SOURCES = ('okta', 'okta_logs', 'entra', 'azure_ad', 'google_workspace', 'generic')


def match_domain(host: str) -> tuple[AIServiceDef, str] | None:
    host = (host or '').strip().lower().rstrip('.')
    if not host:
        return None
    for domain, service in _DOMAIN_INDEX:
        if host == domain or host.endswith('.' + domain):
            return service, domain
    return None


def hosts_in(text: str) -> list[str]:
    """Hostname-like tokens in free text (URLs, SNI, DNS queries, 'host:port')."""
    if not text or len(text) > 4000:
        text = (text or '')[:4000]
    return [m.group(0).lower() for m in _HOST_RE.finditer(text)]


def match_app_name(text: str) -> tuple[AIServiceDef, str] | None:
    if not text:
        return None
    for pattern, service in _APP_INDEX:
        found = pattern.search(text[:2000])
        if found:
            return service, found.group(0)
    return None


def catalog() -> list[dict]:
    return [s.as_dict() for s in SERVICES if s.key != 'argus.gateway']
