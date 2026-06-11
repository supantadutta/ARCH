"""Tests for finding creation."""

from app.models import Asset, Finding


def test_finding_creation_defaults_manual_review(db, program_with_scope):
    asset = Asset(program_id=program_with_scope.id, value="localhost", scheme="http")
    db.add(asset)
    db.flush()

    finding = Finding(
        program_id=program_with_scope.id,
        asset_id=asset.id,
        title="Test finding",
        severity="medium",
        confidence="low",
        status="new",
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    assert finding.id is not None
    assert finding.status == "new"
    # Safety default: findings require manual review unless explicitly cleared.
    assert finding.manual_review_required is True
    assert finding.severity == "medium"
