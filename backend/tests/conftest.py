"""Pytest fixtures — uses an in-memory SQLite database for fast, isolated tests."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import Program, ScopeItem


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=eng)
    return eng


@pytest.fixture
def db(engine):
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


# Default API key used by the test client (matches the config default).
API_KEY = "dev-local-key"


@pytest.fixture
def client(engine, monkeypatch):
    """A FastAPI TestClient backed by the in-memory SQLite engine.

    The ``get_db`` dependency is overridden so the API and tests share the same
    database. The app's startup hook is intentionally not triggered (no
    context manager) so it never reaches for Postgres. Celery dispatch is
    stubbed so launching a scan never touches the Redis broker.
    """
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker

    from app.database import get_db
    from app.main import app
    from app.tasks import scan_tasks

    # Don't dispatch to the real broker during tests.
    monkeypatch.setattr(scan_tasks.run_scan_job, "delay", lambda *a, **k: None)

    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def _override_get_db():
        session = TestingSession()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override_get_db
    test_client = TestClient(app)
    # Authenticate every request by default.
    test_client.headers.update({"X-API-Key": API_KEY})
    try:
        yield test_client
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def program_with_scope(db):
    """A program authorized for localhost and example.org, denying secret.example.org."""
    program = Program(name="Test Program", description="test", status="active")
    db.add(program)
    db.flush()
    db.add_all(
        [
            ScopeItem(program_id=program.id, scope_type="domain", value="localhost", is_allowed=True),
            ScopeItem(program_id=program.id, scope_type="ip", value="127.0.0.1", is_allowed=True),
            ScopeItem(program_id=program.id, scope_type="wildcard_domain", value="*.example.org", is_allowed=True),
            ScopeItem(program_id=program.id, scope_type="domain", value="secret.example.org", is_allowed=False),
        ]
    )
    db.commit()
    return program
