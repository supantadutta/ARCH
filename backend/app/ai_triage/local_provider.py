"""Local LLM AI triage provider (placeholder).

A thin placeholder for running triage against a *self-hosted* model exposed via
an OpenAI-compatible API (e.g. Ollama, vLLM, LM Studio, llama.cpp server). It
reuses the OpenAI-compatible transport but points at a local endpoint and does
not require an API key.

This is intentionally a placeholder: it is wired up and usable if a local
endpoint is available, but the platform defaults to the offline mock provider so
nothing external is required. The same strict grounding guard applies, so a
local model can never introduce invented evidence either.
"""

from __future__ import annotations

from app.ai_triage.openai_provider import AITriageError, OpenAITriageProvider
from app.ai_triage.base import FindingContext
from app.config import settings
from app.schemas.schemas import TriageResult


class LocalLLMTriageProvider(OpenAITriageProvider):
    name = "local"

    def __init__(self, base_url: str | None = None, model: str | None = None):
        # Local endpoints typically need no key; send a placeholder token so the
        # shared transport's Authorization header is well-formed.
        super().__init__(
            base_url=base_url or settings.ai_local_base_url,
            api_key="local-no-auth",
            model=model or settings.ai_local_model,
        )

    def triage(self, context: FindingContext) -> TriageResult:
        try:
            return super().triage(context)
        except AITriageError as exc:
            # Surface a clear, actionable message rather than a raw stack trace —
            # the local model server is likely not running.
            raise AITriageError(
                "Local LLM provider is a placeholder and requires a running "
                f"OpenAI-compatible endpoint at {self.base_url}. ({exc})"
            ) from exc
