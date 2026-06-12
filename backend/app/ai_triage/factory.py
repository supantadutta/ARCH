"""Provider factory — selects an AI triage provider from settings.

Defaults to the offline, deterministic mock provider so the platform is always
runnable and safe with no external dependencies.
"""

from __future__ import annotations

from app.ai_triage.base import AITriageProvider
from app.ai_triage.local_provider import LocalLLMTriageProvider
from app.ai_triage.mock_provider import MockTriageProvider
from app.ai_triage.openai_provider import OpenAITriageProvider
from app.config import settings

_PROVIDERS: dict[str, type[AITriageProvider]] = {
    "mock": MockTriageProvider,
    "openai": OpenAITriageProvider,
    "local": LocalLLMTriageProvider,
}


def available_providers() -> list[str]:
    """Return the list of registered provider names."""
    return list(_PROVIDERS)


def get_provider(name: str | None = None) -> AITriageProvider:
    """Instantiate the configured provider (or the named one).

    Falls back to the mock provider for an unknown name.
    """
    key = (name or settings.ai_provider or "mock").lower()
    cls = _PROVIDERS.get(key, MockTriageProvider)
    return cls()
