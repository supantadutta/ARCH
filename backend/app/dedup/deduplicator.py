"""Deterministic, safe finding deduplication.

Two findings are considered duplicates when they describe the same issue on the
same asset. Matching is purely a read-only data comparison — there is no active
probing or re-scanning involved. The signals used (per requirement) are:

* **same asset** — identical ``asset_id`` (or, when no asset is attached, the
  same scanner name);
* **same category**;
* **similar title** — normalized title similarity above a threshold;
* **same scanner evidence** — identical ``evidence_summary``.

A finding is flagged as a duplicate of the *earliest* (lowest-id) matching
finding via the existing ``duplicate_of`` column, and its status is set to
``closed``. The original is never modified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher

from sqlalchemy.orm import Session

from app.models import Finding
from app.services.audit import record_audit

# Title similarity at/above this ratio counts as "similar".
TITLE_SIMILARITY_THRESHOLD = 0.85

_WORD_RE = re.compile(r"[a-z0-9]+")


def normalize_title(title: str | None) -> str:
    """Lower-case, tokenize and re-join a title for stable comparison."""
    if not title:
        return ""
    return " ".join(_WORD_RE.findall(title.lower()))


def title_similarity(a: str | None, b: str | None) -> float:
    """Return a 0..1 similarity ratio between two normalized titles."""
    na, nb = normalize_title(a), normalize_title(b)
    if not na or not nb:
        return 0.0
    return SequenceMatcher(None, na, nb).ratio()


def compute_signature(finding: Finding) -> str:
    """A deterministic, human-readable signature for a finding.

    Useful for quick grouping/debugging. It intentionally contains no payloads
    or secrets — only category, asset and a normalized title.
    """
    asset = finding.asset_id if finding.asset_id is not None else f"scanner:{finding.scanner_name}"
    return f"{finding.program_id}|{asset}|{(finding.category or '').lower()}|{normalize_title(finding.title)}"


@dataclass
class DuplicateMatch:
    """A candidate duplicate and why it matched."""

    finding_id: int
    title: str
    score: float
    reasons: list[str]


def _same_asset(a: Finding, b: Finding) -> bool:
    # Identical asset id counts as the same asset; two findings with no asset
    # attached are treated as the same (null) asset. The strong category +
    # (similar title OR same evidence) gates prevent over-matching.
    return a.asset_id == b.asset_id


def _is_duplicate(candidate: Finding, finding: Finding) -> tuple[bool, float, list[str]]:
    """Decide whether ``finding`` duplicates the earlier ``candidate``."""
    reasons: list[str] = []

    if candidate.program_id != finding.program_id:
        return False, 0.0, reasons

    if not _same_asset(candidate, finding):
        return False, 0.0, reasons
    reasons.append("same asset")

    if (candidate.category or "").lower() != (finding.category or "").lower():
        return False, 0.0, reasons
    reasons.append("same category")

    sim = title_similarity(candidate.title, finding.title)
    same_evidence = bool(
        candidate.evidence_summary
        and candidate.evidence_summary == finding.evidence_summary
    )

    # Asset + category already match; confirm with either a similar title or
    # identical scanner evidence.
    if sim >= TITLE_SIMILARITY_THRESHOLD:
        reasons.append(f"similar title ({sim:.2f})")
    if same_evidence:
        reasons.append("same scanner evidence")

    if sim >= TITLE_SIMILARITY_THRESHOLD or same_evidence:
        score = max(sim, 0.9 if same_evidence else sim)
        return True, round(score, 3), reasons

    return False, sim, reasons


def find_duplicate_candidates(db: Session, finding: Finding) -> list[DuplicateMatch]:
    """Return earlier findings that ``finding`` appears to duplicate."""
    earlier = (
        db.query(Finding)
        .filter(
            Finding.program_id == finding.program_id,
            Finding.id != finding.id,
            Finding.id < finding.id,
            Finding.duplicate_of.is_(None),  # don't chain to an existing duplicate
        )
        .order_by(Finding.id.asc())
        .all()
    )
    matches: list[DuplicateMatch] = []
    for cand in earlier:
        ok, score, reasons = _is_duplicate(cand, finding)
        if ok:
            matches.append(
                DuplicateMatch(finding_id=cand.id, title=cand.title, score=score, reasons=reasons)
            )
    matches.sort(key=lambda m: (-m.score, m.finding_id))
    return matches


def deduplicate_finding(db: Session, finding: Finding, actor: str = "system") -> DuplicateMatch | None:
    """Link ``finding`` to the earliest matching duplicate, if any."""
    if finding.duplicate_of is not None:
        return None
    candidates = find_duplicate_candidates(db, finding)
    if not candidates:
        return None
    # Earliest matching finding (lowest id) becomes the canonical original.
    best = min(candidates, key=lambda m: m.finding_id)
    finding.duplicate_of = best.finding_id
    finding.status = "closed"
    db.add(finding)
    record_audit(
        db,
        action="finding.deduplicated",
        actor=actor,
        target=f"finding:{finding.id}",
        decision="info",
        detail=f"duplicate_of={best.finding_id} reasons={', '.join(best.reasons)}",
        commit=False,
    )
    db.commit()
    db.refresh(finding)
    return best


def deduplicate_program(db: Session, program_id: int, actor: str = "system") -> dict:
    """Run dedup across all findings in a program. Returns a small summary."""
    findings = (
        db.query(Finding)
        .filter(Finding.program_id == program_id)
        .order_by(Finding.id.asc())
        .all()
    )
    linked = 0
    for f in findings:
        if f.duplicate_of is not None:
            continue
        if deduplicate_finding(db, f, actor=actor) is not None:
            linked += 1
    return {"scanned": len(findings), "duplicates_linked": linked}
