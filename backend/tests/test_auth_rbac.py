"""Tests for JWT auth, RBAC roles, program permissions, pagination, SLA, CSV."""

from __future__ import annotations

import pytest

from app.models import User
from app.security import create_access_token, hash_password, verify_password


# --------------------------------------------------------------------------
# Password + JWT primitives
# --------------------------------------------------------------------------
def test_password_hash_roundtrip():
    h = hash_password("s3cret!")
    assert verify_password("s3cret!", h)
    assert not verify_password("wrong", h)
    assert not verify_password("x", None)


def _make_user(db, email, role, password="pw12345"):
    u = User(email=email, role=role, hashed_password=hash_password(password), is_active=True)
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def _bearer(user):
    return {"Authorization": f"Bearer {create_access_token(user_id=user.id, email=user.email, role=user.role)}"}


# --------------------------------------------------------------------------
# JWT login
# --------------------------------------------------------------------------
def test_login_succeeds_and_returns_token(client, db):
    _make_user(db, "a@x.com", "admin", "hunter2")
    r = client.post("/api/v1/auth/login", json={"email": "a@x.com", "password": "hunter2"})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["role"] == "admin"
    assert body["access_token"]


def test_login_bad_password_rejected(client, db):
    _make_user(db, "a@x.com", "admin", "hunter2")
    r = client.post("/api/v1/auth/login", json={"email": "a@x.com", "password": "nope"})
    assert r.status_code == 401


def test_jwt_authenticates_requests(client, db):
    user = _make_user(db, "v@x.com", "viewer")
    client.headers.pop("X-API-Key", None)
    r = client.get("/api/v1/programs", headers=_bearer(user))
    assert r.status_code == 200


# --------------------------------------------------------------------------
# RBAC
# --------------------------------------------------------------------------
def test_viewer_cannot_create_program(client, db):
    user = _make_user(db, "v@x.com", "viewer")
    client.headers.pop("X-API-Key", None)
    r = client.post("/api/v1/programs", json={"name": "P"}, headers=_bearer(user))
    assert r.status_code == 403


def test_researcher_cannot_create_program_but_admin_can(client, db):
    res = _make_user(db, "r@x.com", "researcher")
    adm = _make_user(db, "ad@x.com", "admin")
    client.headers.pop("X-API-Key", None)
    assert client.post("/api/v1/programs", json={"name": "P"}, headers=_bearer(res)).status_code == 403
    assert client.post("/api/v1/programs", json={"name": "P"}, headers=_bearer(adm)).status_code == 201


def test_viewer_cannot_create_finding(client, db):
    # admin (api key) creates program
    pid = client.post("/api/v1/programs", json={"name": "P"}).json()["id"]
    viewer = _make_user(db, "v@x.com", "viewer")
    client.headers.pop("X-API-Key", None)
    r = client.post(
        f"/api/v1/programs/{pid}/findings",
        json={"title": "t", "severity": "low", "confidence": "low"},
        headers=_bearer(viewer),
    )
    assert r.status_code == 403


# --------------------------------------------------------------------------
# Program permissions — only assigned members see a program's findings
# --------------------------------------------------------------------------
def test_non_member_cannot_view_program_findings(client, db):
    pid = client.post("/api/v1/programs", json={"name": "Private"}).json()["id"]
    client.post(
        f"/api/v1/programs/{pid}/findings",
        json={"title": "secret finding", "severity": "high", "confidence": "low"},
    )
    outsider = _make_user(db, "out@x.com", "researcher")
    client.headers.pop("X-API-Key", None)
    r = client.get(f"/api/v1/programs/{pid}/findings", headers=_bearer(outsider))
    assert r.status_code == 403


def test_member_can_view_program_findings(client, db):
    pid = client.post("/api/v1/programs", json={"name": "Shared"}).json()["id"]
    member = _make_user(db, "m@x.com", "triager")
    # admin (api key) assigns membership
    client.post(f"/api/v1/programs/{pid}/members", json={"user_id": member.id})
    client.headers.pop("X-API-Key", None)
    r = client.get(f"/api/v1/programs/{pid}/findings", headers=_bearer(member))
    assert r.status_code == 200


# --------------------------------------------------------------------------
# Pagination envelope
# --------------------------------------------------------------------------
def test_findings_list_is_paginated(client):
    pid = client.post("/api/v1/programs", json={"name": "P"}).json()["id"]
    for i in range(3):
        client.post(
            f"/api/v1/programs/{pid}/findings",
            json={"title": f"f{i}", "severity": "low", "confidence": "low"},
        )
    r = client.get(f"/api/v1/programs/{pid}/findings?limit=2&offset=0")
    body = r.json()
    assert set(body) == {"items", "total", "limit", "offset"}
    assert body["total"] == 3
    assert len(body["items"]) == 2


def test_findings_search_filter(client):
    pid = client.post("/api/v1/programs", json={"name": "P"}).json()["id"]
    client.post(f"/api/v1/programs/{pid}/findings", json={"title": "XSS in search", "severity": "low", "confidence": "low"})
    client.post(f"/api/v1/programs/{pid}/findings", json={"title": "Open redirect", "severity": "low", "confidence": "low"})
    r = client.get(f"/api/v1/programs/{pid}/findings?q=redirect")
    assert r.json()["total"] == 1


# --------------------------------------------------------------------------
# SLA
# --------------------------------------------------------------------------
def test_sla_due_date_set_on_creation(client):
    pid = client.post("/api/v1/programs", json={"name": "P"}).json()["id"]
    f = client.post(
        f"/api/v1/programs/{pid}/findings",
        json={"title": "high sev", "severity": "high", "confidence": "low"},
    ).json()
    assert f["sla_due_at"] is not None  # high severity is SLA-tracked


def test_info_severity_has_no_sla(client):
    pid = client.post("/api/v1/programs", json={"name": "P"}).json()["id"]
    f = client.post(
        f"/api/v1/programs/{pid}/findings",
        json={"title": "info", "severity": "info", "confidence": "low"},
    ).json()
    assert f["sla_due_at"] is None


# --------------------------------------------------------------------------
# CSV + program markdown export
# --------------------------------------------------------------------------
def test_findings_csv_export(client):
    pid = client.post("/api/v1/programs", json={"name": "P"}).json()["id"]
    client.post(f"/api/v1/programs/{pid}/findings", json={"title": "csv me", "severity": "low", "confidence": "low"})
    r = client.get(f"/api/v1/programs/{pid}/findings.csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert "csv me" in r.text
    assert r.text.splitlines()[0].startswith("id,title,severity")


def test_program_markdown_export(client):
    pid = client.post("/api/v1/programs", json={"name": "Acme"}).json()["id"]
    client.post(f"/api/v1/programs/{pid}/findings", json={"title": "md me", "severity": "medium", "confidence": "low"})
    r = client.get(f"/api/v1/programs/{pid}/report.md")
    assert r.status_code == 200
    assert "# Program Report — Acme" in r.text
    assert "md me" in r.text
