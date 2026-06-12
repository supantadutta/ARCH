"""SourceRouteAnalyzer — static route/auth analysis of authorized local repos.

Works only on an explicitly authorized local repository path (same path
allowlist used by the SAST scanners). It statically extracts routes (FastAPI /
Flask / Express style), inspects nearby decorators / middleware for
authentication and authorization markers, flags routes that appear to be
missing auth, and maps source routes to discovered live API endpoints.

Read-only static analysis — it never executes the code or sends requests.
"""

from __future__ import annotations

import os
import re

from sqlalchemy.orm import Session

from app.models import ApiEndpoint, Finding, SourceRoute
from app.policy.scope_guard import ScopeError, is_path_authorized
from app.services.audit import record_audit

# Python (FastAPI/Flask/Django-rest-ish) route decorators.
_PY_ROUTE = re.compile(
    r"@(?:\w+)\.(get|post|put|patch|delete)\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE
)
# Express/Koa style route registration.
_JS_ROUTE = re.compile(
    r"(?:app|router)\.(get|post|put|patch|delete)\(\s*[\"']([^\"']+)[\"']\s*(,[^;]*)?",
    re.IGNORECASE,
)

_AUTH_MARKERS = (
    "login_required", "requires_auth", "jwt_required", "isauthenticated",
    "current_user", "authenticate", "auth_required", "verifytoken", "verify_token",
    "ensureauth", "requireauth", "@protected", "passport.authenticate",
)
_AUTHZ_MARKERS = (
    "permission", "require_role", "requires_role", "has_perm", "isadmin",
    "authorize", "role_required", "permission_classes", "can(", "acl",
)

_SOURCE_EXTS = (".py", ".js", ".ts", ".mjs")
_MAX_FILES = 2000
_MAX_BYTES = 200_000


def _has_marker(window: str, markers) -> bool:
    low = window.lower()
    return any(m in low for m in markers)


def _route_match(line: str):
    """Return (method, path, kind, extra) if a line registers a route."""
    for rx, kind in ((_PY_ROUTE, "py"), (_JS_ROUTE, "js")):
        m = rx.search(line)
        if m:
            extra = m.group(m.lastindex) if (kind == "js" and m.lastindex) else ""
            return m.group(1).upper(), m.group(2), kind, (extra or "")
    return None


def _scan_file(path: str) -> list[dict]:
    """Extract routes and their nearby auth/authz markers from one file.

    The inspection window for each route is bounded by the neighboring route so
    one route's auth marker can never be mis-attributed to another.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read(_MAX_BYTES)
    except OSError:
        return []
    lines = text.splitlines()
    route_lines = [i for i, ln in enumerate(lines) if _route_match(ln)]
    routes: list[dict] = []

    for pos, i in enumerate(route_lines):
        method, route_path, kind, extra = _route_match(lines[i])
        # Window: a few decorator lines above, down to just before the next route.
        start = max(0, i - 3)
        prev_route = route_lines[pos - 1] if pos > 0 else -1
        start = max(start, prev_route + 1)
        next_route = route_lines[pos + 1] if pos + 1 < len(route_lines) else len(lines)
        end = min(next_route, i + 4)
        window = "\n".join(lines[start:end]) + "\n" + extra
        routes.append(
            {
                "method": method,
                "route_path": route_path,
                "has_auth": _has_marker(window, _AUTH_MARKERS),
                "has_authz": _has_marker(window, _AUTHZ_MARKERS),
            }
        )
    return routes


def analyze_repo(db: Session, program_id: int, repo_path: str, actor: str = "system") -> dict:
    """Analyze an authorized local repo for routes missing auth/authorization."""
    # Hard gate: the path must be explicitly authorized (same allowlist as SAST).
    decision = is_path_authorized(db, program_id, repo_path)
    if not decision.allowed:
        record_audit(
            db, action="source_route.rejected", actor=actor, target=repo_path,
            decision="rejected", detail=decision.reason, commit=False,
        )
        db.commit()
        raise ScopeError(decision)

    root = decision.normalized_target
    extracted = 0
    missing_auth = 0
    findings_created = 0
    files_seen = 0

    # Pre-index live endpoints for mapping (method+path).
    live = db.query(ApiEndpoint).filter(ApiEndpoint.program_id == program_id).all()
    live_index = {(e.method.upper(), e.path): e.id for e in live}

    for dirpath, _dirs, files in os.walk(root):
        # Skip noisy vendored directories.
        if any(part in dirpath for part in ("node_modules", ".git", "venv", "__pycache__")):
            continue
        for fname in files:
            if not fname.endswith(_SOURCE_EXTS):
                continue
            files_seen += 1
            if files_seen > _MAX_FILES:
                break
            fpath = os.path.join(dirpath, fname)
            for r in _scan_file(fpath):
                mapped = live_index.get((r["method"], r["route_path"]))
                db.add(
                    SourceRoute(
                        program_id=program_id,
                        file_path=fpath,
                        method=r["method"],
                        route_path=r["route_path"][:1024],
                        has_authentication=r["has_auth"],
                        has_authorization=r["has_authz"],
                        mapped_endpoint_id=mapped,
                    )
                )
                extracted += 1
                # Flag routes that appear to lack authentication entirely.
                if not r["has_auth"]:
                    missing_auth += 1
                    db.add(
                        Finding(
                            program_id=program_id,
                            title=f"Route may be missing authentication: {r['method']} {r['route_path']}",
                            description=(
                                f"Static analysis found no authentication marker near "
                                f"`{r['method']} {r['route_path']}` in {os.path.basename(fpath)}. "
                                "Verify whether this route is intentionally public."
                            ),
                            severity="medium",
                            confidence="low",
                            status="needs_review",
                            category="source_route",
                            cwe="CWE-306",
                            owasp="A01:2021 Broken Access Control",
                            evidence_summary=f"{fpath}: {r['method']} {r['route_path']} (no auth marker found)",
                            scanner_name="source_route",
                            manual_review_required=True,
                        )
                    )
                    findings_created += 1

    record_audit(
        db, action="source_route.analyze", actor=actor, target=f"program:{program_id}",
        decision="info",
        detail=f"path={root} routes={extracted} missing_auth={missing_auth} findings={findings_created}",
        commit=False,
    )
    db.commit()
    return {
        "path": root,
        "routes_extracted": extracted,
        "routes_missing_auth": missing_auth,
        "findings_created": findings_created,
    }
