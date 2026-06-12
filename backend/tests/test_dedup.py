"""Tests for safe finding deduplication."""

from __future__ import annotations

from app.dedup import (
    deduplicate_finding,
    deduplicate_program,
    find_duplicate_candidates,
)
from app.models import Asset, Finding


def _asset(db, program, value="localhost"):
    a = Asset(program_id=program.id, value=value, scheme="http")
    db.add(a)
    db.flush()
    return a


def _finding(db, program, asset, title, category="misconfiguration", evidence="ev-1"):
    f = Finding(
        program_id=program.id,
        asset_id=asset.id if asset else None,
        title=title,
        category=category,
        evidence_summary=evidence,
        scanner_name="recon",
        severity="low",
        confidence="low",
        status="new",
    )
    db.add(f)
    db.commit()
    db.refresh(f)
    return f


def test_similar_findings_on_same_asset_are_duplicates(db, program_with_scope):
    a = _asset(db, program_with_scope)
    first = _finding(db, program_with_scope, a, "Missing security headers")
    second = _finding(db, program_with_scope, a, "Missing security header")  # near-identical

    match = deduplicate_finding(db, second)
    assert match is not None
    assert match.finding_id == first.id
    db.refresh(second)
    assert second.duplicate_of == first.id
    assert second.status == "closed"
    # The original is untouched.
    db.refresh(first)
    assert first.duplicate_of is None


def test_same_scanner_evidence_marks_duplicate(db, program_with_scope):
    a = _asset(db, program_with_scope)
    first = _finding(db, program_with_scope, a, "Header issue A", evidence="identical-evidence")
    second = _finding(db, program_with_scope, a, "Completely different title", evidence="identical-evidence")
    match = deduplicate_finding(db, second)
    assert match is not None
    assert "same scanner evidence" in match.reasons


def test_different_category_is_not_duplicate(db, program_with_scope):
    a = _asset(db, program_with_scope)
    _finding(db, program_with_scope, a, "Missing security headers", category="misconfiguration")
    other = _finding(db, program_with_scope, a, "Missing security headers", category="secret",
                     evidence="different")
    assert find_duplicate_candidates(db, other) == []
    assert deduplicate_finding(db, other) is None


def test_different_asset_is_not_duplicate(db, program_with_scope):
    a1 = _asset(db, program_with_scope, "host-a")
    a2 = _asset(db, program_with_scope, "host-b")
    _finding(db, program_with_scope, a1, "Missing security headers")
    other = _finding(db, program_with_scope, a2, "Missing security headers", evidence="different")
    assert deduplicate_finding(db, other) is None


def test_deduplicate_program_links_all(db, program_with_scope):
    a = _asset(db, program_with_scope)
    _finding(db, program_with_scope, a, "Missing security headers")
    _finding(db, program_with_scope, a, "Missing security headers")
    _finding(db, program_with_scope, a, "Missing security headers")
    summary = deduplicate_program(db, program_with_scope.id)
    assert summary["scanned"] == 3
    assert summary["duplicates_linked"] == 2  # 2nd and 3rd link to the 1st
