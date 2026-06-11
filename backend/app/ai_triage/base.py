"""Abstraction layer for AI triage providers.

A provider receives a *read-only snapshot* of an existing finding and returns a
structured triage assessment. The contract is deliberately strict:

**The provider must never invent evidence.** It may only reason over the data
present in the supplied :class:`FindingContext`. The mock provider demonstrates
this by echoing/condensing existing fields rather than fabricating details.

Swapping in a real LLM provider later means implementing :class:`AITriageProvider`
and wiring it into :class:`~app.ai_triage.triage_service.TriageService`.
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


class AITriageProvider(abc.ABC):
    """Interface every triage provider must implement."""

    name: str = "base"

    @abc.abstractmethod
    def triage(self, context: FindingContext) -> TriageResult:
        """Return a structured triage assessment for the given finding context."""
        raise NotImplementedError
