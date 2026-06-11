"""Seed sample data: an authorized localhost-only demo program.

Run with ``python -m app.seed`` (or via the docker compose helper). It is
idempotent — re-running will not create duplicates.
"""

from __future__ import annotations

from app.database import Base, SessionLocal, engine
from app.models import (
    Asset,
    Finding,
    Program,
    ScopeItem,
    SystemSetting,
    User,
)
from app.services.killswitch import KILL_SWITCH_KEY


def seed() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Default operator user.
        if not db.query(User).filter(User.email == "analyst@localhost").first():
            db.add(User(email="analyst@localhost", full_name="Demo Analyst", role="admin"))

        # Kill switch default (disabled).
        if not db.query(SystemSetting).filter(SystemSetting.key == KILL_SWITCH_KEY).first():
            db.add(
                SystemSetting(
                    key=KILL_SWITCH_KEY,
                    value="false",
                    description="Global kill switch — blocks all new scans when true.",
                )
            )

        # Example authorized program: localhost only.
        program = db.query(Program).filter(Program.name == "Localhost Demo Program").first()
        if not program:
            program = Program(
                name="Localhost Demo Program",
                description="Authorized demo program scoped to localhost only.",
                status="active",
            )
            db.add(program)
            db.flush()

            # Explicit, authorized localhost scope entries.
            db.add_all(
                [
                    ScopeItem(
                        program_id=program.id,
                        scope_type="domain",
                        value="localhost",
                        is_allowed=True,
                        notes="Authorized loopback target for the demo flow.",
                    ),
                    ScopeItem(
                        program_id=program.id,
                        scope_type="ip",
                        value="127.0.0.1",
                        is_allowed=True,
                        notes="Authorized loopback IP.",
                    ),
                    # Demonstrate an explicit deny entry.
                    ScopeItem(
                        program_id=program.id,
                        scope_type="domain",
                        value="example.com",
                        is_allowed=False,
                        notes="Explicitly out of scope (deny example).",
                    ),
                ]
            )

            # A sample asset.
            asset = Asset(
                program_id=program.id,
                asset_type="web",
                value="localhost",
                scheme="http",
                port=8000,
                status="active",
                technologies="FastAPI,uvicorn",
                risk_score=3.0,
            )
            db.add(asset)
            db.flush()

            # A sample finding (manual review required by default).
            db.add(
                Finding(
                    program_id=program.id,
                    asset_id=asset.id,
                    title="Missing security headers on localhost demo app",
                    description=(
                        "The demo application does not set common security headers "
                        "(Content-Security-Policy, X-Frame-Options)."
                    ),
                    severity="low",
                    confidence="medium",
                    status="new",
                    category="misconfiguration",
                    cwe="CWE-693",
                    owasp="A05:2021 Security Misconfiguration",
                    evidence_summary="Response from http://localhost:8000 lacked CSP and X-Frame-Options.",
                    scanner_name="recon",
                    manual_review_required=True,
                )
            )

        db.commit()
        print("Seed complete: 'Localhost Demo Program' is ready (localhost only).")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
