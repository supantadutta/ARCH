"""Tests for the scope guard — scope validation and out-of-scope rejection."""

import pytest

from app.policy.scope_guard import (
    ScopeError,
    is_target_in_scope,
    normalize_target,
    validate_scan_request,
)


def test_normalize_target_strips_scheme_and_path():
    assert normalize_target("https://localhost:8000/foo") == "localhost"
    assert normalize_target("HTTP://Example.ORG/") == "example.org"
    assert normalize_target("127.0.0.1") == "127.0.0.1"


def test_in_scope_domain_allowed(db, program_with_scope):
    decision = is_target_in_scope(db, program_with_scope.id, "localhost")
    assert decision.allowed is True


def test_wildcard_domain_matches_subdomain(db, program_with_scope):
    decision = is_target_in_scope(db, program_with_scope.id, "api.example.org")
    assert decision.allowed is True


def test_out_of_scope_target_rejected(db, program_with_scope):
    decision = is_target_in_scope(db, program_with_scope.id, "evil.com")
    assert decision.allowed is False
    assert "not in the authorized scope" in decision.reason


def test_explicit_deny_overrides_wildcard(db, program_with_scope):
    # secret.example.org matches the *.example.org allow but has an explicit deny.
    decision = is_target_in_scope(db, program_with_scope.id, "secret.example.org")
    assert decision.allowed is False
    assert "deny" in decision.reason.lower()


def test_private_ip_rejected_when_not_in_scope(db, program_with_scope):
    decision = is_target_in_scope(db, program_with_scope.id, "192.168.1.10")
    assert decision.allowed is False


def test_loopback_allowed_because_explicitly_scoped(db, program_with_scope):
    decision = is_target_in_scope(db, program_with_scope.id, "127.0.0.1")
    assert decision.allowed is True


def test_forbidden_scan_type_rejected(db, program_with_scope):
    with pytest.raises(ScopeError) as exc:
        validate_scan_request(db, program_with_scope.id, "localhost", "dos")
    assert "forbidden" in exc.value.decision.reason.lower()


def test_unknown_scan_type_rejected(db, program_with_scope):
    with pytest.raises(ScopeError):
        validate_scan_request(db, program_with_scope.id, "localhost", "bananas")


def test_validate_scan_request_happy_path(db, program_with_scope):
    decision = validate_scan_request(db, program_with_scope.id, "localhost", "recon")
    assert decision.allowed is True
