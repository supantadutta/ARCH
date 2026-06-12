"""Abstraction layer for AI triage providers.

A provider receives a *read-only snapshot* of an existing finding and returns a
structured triage assessment. The contract is deliberately strict:

**The provider must never invent evidence, URLs, payloads, users, credentials,
or impact.** It may only reason over the data present in the supplied
:class:`FindingContext`. The mock provider demonstrates this by
echoing/condensing existing fields rather than fabricating details. LLM-backed
providers are additionally constrained by :func:`enforce_grounding`, which
rejects any "evidence used" the model returns that is not actually present on
the finding.

Implement :class:`AITriageProvider` to add a new backend; the factory in
:mod:`app.ai_triage.factory` selects one based on settings.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass

from app.schemas.schemas import TriageResult


@dataclass
class FindingContext:
    """Read-only snapshot of a finding handed to a triage provider."""

    title: str
    description: str | None
    severity: str
    confidence: str
    category: str | None
    cwe: str | None
    owasp: str | None
    evidence_summary: str | None
    raw_output: str | None
    scanner_name: str | None
    asset_value: str | None
    remediation: str | None = None


# The system prompt shared by every LLM-backed provider. It encodes the
# authorized-only, evidence-grounded contract in natural language; the
# programmatic guard (:func:`enforce_grounding`) enforces it regardless of
# whether the model complies.
TRIAGE_SYSTEM_PROMPT = (
    "You are a careful security triage assistant for an AUTHORIZED-ONLY "
    "vulnerability management platform. You will be given the data of a single "
    "existing finding produced by an automated scanner.\n\n"
    "STRICT RULES — you MUST follow all of them:\n"
    "1. Use ONLY the information provided in the finding. Do NOT invent, "
    "assume, or fabricate evidence, URLs, endpoints, payloads, exploit steps, "
    "usernames, credentials, secrets, or business impact that is not present "
    "in the input.\n"
    "2. Do NOT provide exploitation instructions, attack payloads, or steps to "
    "bypass security controls. Remediation guidance only.\n"
    "3. 'evidence_used' MUST be a list of short verbatim snippets taken from "
    "the provided finding data (evidence summary, raw output, or asset). If "
    "there is no concrete evidence, return an empty list and set "
    "manual_review_required to true.\n"
    "4. If you are unsure, or severity is high/critical, set "
    "manual_review_required to true. Never auto-confirm a finding.\n"
    "5. Respond with a SINGLE JSON object and nothing else, using exactly "
    "these keys: title, severity, confidence, category, cwe, owasp, impact, "
    "remediation, evidence_used, report_draft, manual_review_required.\n"
    "   - severity in [info, low, medium, high, critical]\n"
    "   - confidence in [low, medium, high]\n"
    "   - evidence_used is a JSON array of strings\n"
    "   - manual_review_required is a boolean"
)


def collect_source_evidence(ctx: FindingContext) -> list[str]:
    """Return the concrete evidence strings actually present on the finding.

    This is the *only* permissible source of ``evidence_used``. Anything a
    provider claims as evidence is validated against this set.
    """
    items: list[str] = []
    if ctx.evidence_summary:
        items.append(ctx.evidence_summary.strip())
    if ctx.raw_output:
        # Raw output can be large; keep a bounded snapshot for grounding.
        items.append(ctx.raw_output.strip()[:2000])
    return [i for i in items if i]


def grounding_corpus(ctx: FindingContext) -> str:
    """Concatenated lower-cased text of everything the finding actually contains."""
    parts = [
        ctx.title,
        ctx.description or "",
        ctx.evidence_summary or "",
        ctx.raw_output or "",
        ctx.asset_value or "",
        ctx.category or "",
        ctx.cwe or "",
        ctx.owasp or "",
    ]
    return "\n".join(parts).lower()


def enforce_grounding(result: TriageResult, ctx: FindingContext) -> TriageResult:
    """Strip any ungrounded ``evidence_used`` and flag for review if needed.

    A piece of claimed evidence is kept only if it actually appears in the
    finding's own text. If the provider claimed evidence that is not present
    (i.e. it invented it), that item is dropped and the finding is forced into
    manual review. This makes the "do not invent evidence" rule enforceable
    rather than merely requested.
    """
    corpus = grounding_corpus(ctx)
    kept: list[str] = []
    invented = False
    for item in result.evidence_used or []:
        snippet = (item or "").strip()
        if not snippet:
            continue
        # Keep the snippet only if it (or a meaningful prefix) is grounded in
        # the finding's own data.
        probe = snippet.lower()[:120]
        if probe and probe in corpus:
            kept.append(snippet)
        else:
            invented = True

    result.evidence_used = kept
    if invented or not kept:
        # No grounded evidence, or the model tried to invent some -> a human
        # must verify before this finding is acted upon.
        result.manual_review_required = True
    return result


class AITriageProvider(abc.ABC):
    """Interface every triage provider must implement."""

    name: str = "base"

    @abc.abstractmethod
    def triage(self, context: FindingContext) -> TriageResult:
        """Return a structured triage assessment for the given finding context."""
        raise NotImplementedError
