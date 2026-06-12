"""OpenAI-compatible AI triage provider.

Works against any endpoint that implements the OpenAI ``/chat/completions`` API
(OpenAI, Azure OpenAI gateways, OpenRouter, LiteLLM, vLLM, etc.). It sends the
finding data with the strict system prompt and parses the model's JSON reply
into a :class:`TriageResult`.

Safety: the response is always passed through :func:`enforce_grounding`, so even
if the model ignores the prompt and invents evidence, that evidence is stripped
and the finding is forced into manual review. No exploitation content is ever
requested — the prompt asks for remediation guidance only.
"""

from __future__ import annotations

import json

import httpx

from app.ai_triage.base import (
    TRIAGE_SYSTEM_PROMPT,
    AITriageProvider,
    FindingContext,
    enforce_grounding,
)
from app.config import settings
from app.schemas.schemas import Confidence, Severity, TriageResult

_VALID_SEVERITY = {s.value for s in Severity}
_VALID_CONFIDENCE = {c.value for c in Confidence}


class AITriageError(RuntimeError):
    """Raised when an external AI provider cannot produce a usable result."""


class OpenAITriageProvider(AITriageProvider):
    name = "openai"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
    ):
        self.base_url = (base_url or settings.ai_openai_base_url).rstrip("/")
        self.api_key = api_key if api_key is not None else settings.ai_openai_api_key
        self.model = model or settings.ai_openai_model

    # -- public API --------------------------------------------------------
    def triage(self, context: FindingContext) -> TriageResult:
        if not self.api_key:
            raise AITriageError(
                "OpenAI-compatible provider selected but AI_OPENAI_API_KEY is not set."
            )
        payload = self._build_payload(context)
        data = self._call(payload)
        result = self._parse(data, context)
        return enforce_grounding(result, context)

    # -- helpers -----------------------------------------------------------
    def _finding_as_json(self, ctx: FindingContext) -> str:
        """Serialize ONLY the finding's existing data for the model to reason over."""
        return json.dumps(
            {
                "title": ctx.title,
                "description": ctx.description,
                "severity": ctx.severity,
                "confidence": ctx.confidence,
                "category": ctx.category,
                "cwe": ctx.cwe,
                "owasp": ctx.owasp,
                "evidence_summary": ctx.evidence_summary,
                "raw_output": (ctx.raw_output or "")[:4000],
                "scanner_name": ctx.scanner_name,
                "asset": ctx.asset_value,
            },
            indent=2,
        )

    def _build_payload(self, ctx: FindingContext) -> dict:
        return {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        "Triage this finding. Use only its data; do not invent "
                        "anything. Finding JSON:\n" + self._finding_as_json(ctx)
                    ),
                },
            ],
        }

    def _call(self, payload: dict) -> dict:
        url = f"{self.base_url}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        try:
            resp = httpx.post(
                url, headers=headers, json=payload, timeout=settings.ai_request_timeout
            )
            resp.raise_for_status()
            body = resp.json()
            content = body["choices"][0]["message"]["content"]
            return json.loads(content)
        except (httpx.HTTPError, KeyError, IndexError, json.JSONDecodeError) as exc:
            raise AITriageError(f"AI provider call failed: {exc}") from exc

    def _parse(self, data: dict, ctx: FindingContext) -> TriageResult:
        """Map the model's JSON into a TriageResult, normalizing enums safely."""
        severity = str(data.get("severity", ctx.severity)).lower()
        if severity not in _VALID_SEVERITY:
            severity = ctx.severity if ctx.severity in _VALID_SEVERITY else "info"
        confidence = str(data.get("confidence", ctx.confidence)).lower()
        if confidence not in _VALID_CONFIDENCE:
            confidence = "low"

        evidence_used = data.get("evidence_used") or []
        if not isinstance(evidence_used, list):
            evidence_used = [str(evidence_used)]
        evidence_used = [str(e) for e in evidence_used]

        impact = str(data.get("impact") or "Impact not assessed.")
        remediation = str(data.get("remediation") or ctx.remediation or "Investigate and remediate.")
        report_draft = str(data.get("report_draft") or "")
        title = str(data.get("title") or ctx.title)

        return TriageResult(
            title=title,
            severity=severity,  # type: ignore[arg-type]
            confidence=confidence,  # type: ignore[arg-type]
            category=str(data.get("category") or ctx.category or "misconfiguration"),
            cwe=str(data.get("cwe") or ctx.cwe or "CWE-Unknown"),
            owasp=str(data.get("owasp") or ctx.owasp or ""),
            business_impact=impact,
            remediation=remediation,
            evidence_used=evidence_used,
            report_draft=report_draft,
            manual_review_required=bool(data.get("manual_review_required", True)),
            ai_summary=f"AI triage via {self.name}:{self.model}. {impact}",
        )
