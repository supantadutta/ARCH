"""Scope guard — the hard security control for AutoBugHunter.

This module is the single source of truth for deciding whether a given target
may be scanned. **Every** scanner and every API route that triggers scanning
must call :func:`validate_scan_request` before doing any work.

Design principles
-----------------
* Default deny. A target is out of scope unless an explicit allow entry exists.
* Private / internal / loopback targets are rejected unless explicitly added to
  scope (loopback is permitted only when ``settings.allow_private_targets`` is
  on, or when a matching localhost scope item exists — supporting the demo).
* Forbidden scan types (DoS, brute force, exploitation, etc.) are always
  rejected, regardless of scope.
* Every decision is auditable: this module returns structured results that the
  caller records in the audit log.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.config import settings
from app.models import ScopeItem


@dataclass
class ScopeDecision:
    """Result of a scope / scan-request evaluation."""

    allowed: bool
    reason: str
    normalized_target: str
    scope_type: str | None = None


class ScopeError(Exception):
    """Raised when a scan request violates policy."""

    def __init__(self, decision: ScopeDecision):
        self.decision = decision
        super().__init__(decision.reason)


# Hostnames that always resolve to the local machine. Allowed only for the
# explicit demo / authorized-localhost workflow.
_LOOPBACK_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def normalize_target(target: str) -> str:
    """Normalize a raw target string into a comparable canonical form.

    * URLs are reduced to their hostname (and port if present is dropped for
      matching purposes — scope matches on host/IP/CIDR).
    * Hostnames are lower-cased and stripped of trailing dots.
    * IPs are normalized via :mod:`ipaddress`.
    """

    if not target:
        return ""

    value = target.strip()

    # If it looks like a URL, extract the host.
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or parsed.path

    # Strip any leftover path / port for host comparison.
    value = value.split("/")[0]
    if value.count(":") == 1 and not _looks_like_ipv6(value):
        # host:port -> host
        value = value.split(":")[0]

    value = value.strip().rstrip(".").lower()

    # Canonicalize IP addresses.
    try:
        ip = ipaddress.ip_address(value)
        return str(ip)
    except ValueError:
        return value


def _looks_like_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def _is_loopback(value: str) -> bool:
    if value in _LOOPBACK_HOSTNAMES:
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _is_private_or_internal(value: str) -> bool:
    """Return True for private, reserved, link-local or loopback targets."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        # Not an IP; only treat known loopback hostnames as internal.
        return value in _LOOPBACK_HOSTNAMES
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _matches_scope_item(item: ScopeItem, normalized: str) -> bool:
    """Return True if ``normalized`` matches a single scope item."""
    item_value = (item.value or "").strip().lower().rstrip(".")

    if item.scope_type == "domain":
        return normalized == item_value

    if item.scope_type == "wildcard_domain":
        # "*.example.com" matches example.com and any subdomain.
        base = item_value.lstrip("*.")
        return normalized == base or normalized.endswith("." + base)

    if item.scope_type == "ip":
        try:
            return ipaddress.ip_address(normalized) == ipaddress.ip_address(item_value)
        except ValueError:
            return normalized == item_value

    if item.scope_type == "cidr":
        try:
            return ipaddress.ip_address(normalized) in ipaddress.ip_network(item_value, strict=False)
        except ValueError:
            return False

    if item.scope_type in ("repo", "mobile_app"):
        return normalized == item_value or item_value in normalized

    return False


def is_target_in_scope(db: Session, program_id: int, target: str) -> ScopeDecision:
    """Evaluate whether ``target`` is within the authorized scope of a program.

    Deny entries take precedence over allow entries.
    """

    normalized = normalize_target(target)
    if not normalized:
        return ScopeDecision(False, "Empty or unparsable target.", normalized)

    items = (
        db.query(ScopeItem)
        .filter(ScopeItem.program_id == program_id)
        .all()
    )

    matched_allow: ScopeItem | None = None
    for item in items:
        if _matches_scope_item(item, normalized):
            if not item.is_allowed:
                # Explicit deny wins immediately.
                return ScopeDecision(
                    False,
                    f"Target '{normalized}' matches an explicit deny scope entry.",
                    normalized,
                    item.scope_type,
                )
            matched_allow = item

    if matched_allow is None:
        return ScopeDecision(
            False,
            f"Target '{normalized}' is not in the authorized scope allowlist.",
            normalized,
        )

    # The target matched an allow entry. Now apply the private/internal guard.
    if _is_private_or_internal(normalized):
        # Loopback is permitted specifically because an operator explicitly
        # added it to scope (the authorized-localhost demo flow), OR because
        # the platform has been configured to allow private targets.
        if _is_loopback(normalized) or settings.allow_private_targets:
            return ScopeDecision(
                True,
                f"Target '{normalized}' is explicitly authorized (private/loopback allowed).",
                normalized,
                matched_allow.scope_type,
            )
        return ScopeDecision(
            False,
            (
                f"Target '{normalized}' resolves to a private/internal range and "
                "ALLOW_PRIVATE_TARGETS is disabled."
            ),
            normalized,
            matched_allow.scope_type,
        )

    return ScopeDecision(
        True,
        f"Target '{normalized}' is within authorized scope.",
        normalized,
        matched_allow.scope_type,
    )


def validate_scan_request(
    db: Session, program_id: int, target: str, scan_type: str
) -> ScopeDecision:
    """Validate a complete scan request: scan type *and* scope.

    Raises :class:`ScopeError` if the request must be rejected, otherwise
    returns an allowing :class:`ScopeDecision`.
    """

    # 1. Forbidden scan types are always rejected.
    if scan_type in settings.forbidden_scan_types:
        decision = ScopeDecision(
            False,
            f"Scan type '{scan_type}' is forbidden by platform policy.",
            normalize_target(target),
        )
        raise ScopeError(decision)

    # 2. Only known-safe scan types are permitted.
    if scan_type not in settings.allowed_scan_types:
        decision = ScopeDecision(
            False,
            f"Scan type '{scan_type}' is not in the allowed scan-type list.",
            normalize_target(target),
        )
        raise ScopeError(decision)

    # 3. Scope enforcement.
    decision = is_target_in_scope(db, program_id, target)
    if not decision.allowed:
        raise ScopeError(decision)

    return decision
