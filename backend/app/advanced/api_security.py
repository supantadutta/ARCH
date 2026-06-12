"""APISecurityModule — API inventory + safe authorization test-case generation.

Imports OpenAPI / Swagger / Postman collections, normalizes endpoints into the
inventory, flags endpoints carrying object-id parameters (``user_id``,
``order_id``, ``invoice_id``, ``team_id``, ``account_id`` …), and generates
*safe* authorization test cases as a checklist for a human to execute. No
requests are sent here — this is parsing and planning only.
"""

from __future__ import annotations

import json
import re

from sqlalchemy.orm import Session

from app.models import ApiEndpoint
from app.services.audit import record_audit

# Object-id parameter names of particular interest for authorization testing.
OBJECT_ID_NAMES = (
    "user_id", "order_id", "invoice_id", "team_id", "account_id", "customer_id",
    "org_id", "organization_id", "project_id", "group_id", "company_id", "id",
)
_PATH_PARAM_RE = re.compile(r"[{:<]([a-zA-Z_][a-zA-Z0-9_]*)[}>]?")


def detect_object_id_params(path: str, param_names: list[str]) -> list[str]:
    """Return the object-id-like parameters found in a path or param list."""
    found: list[str] = []
    candidates = list(param_names) + _PATH_PARAM_RE.findall(path or "")
    for name in candidates:
        lname = name.lower()
        if lname in OBJECT_ID_NAMES or lname.endswith("_id"):
            if name not in found:
                found.append(name)
    return found


def parse_openapi(spec: dict) -> list[dict]:
    """Parse an OpenAPI / Swagger spec into endpoint dicts."""
    endpoints: list[dict] = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            params = []
            if isinstance(op, dict):
                for p in op.get("parameters", []) or []:
                    if isinstance(p, dict) and p.get("name"):
                        params.append(p["name"])
            endpoints.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "params": params,
                    "auth_required": "yes" if (isinstance(op, dict) and op.get("security")) else "unknown",
                }
            )
    return endpoints


def parse_postman(collection: dict) -> list[dict]:
    """Parse a Postman collection (v2) into endpoint dicts."""
    endpoints: list[dict] = []

    def _walk(items):
        for it in items or []:
            if "item" in it:
                _walk(it["item"])
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            method = (req.get("method") or "GET").upper()
            url = req.get("url")
            if isinstance(url, dict):
                raw = url.get("raw") or "/" + "/".join(url.get("path", []) or [])
            else:
                raw = str(url or "")
            # Strip scheme/host to keep just the path template.
            path = re.sub(r"^https?://[^/]+", "", raw) or raw
            has_auth = bool(req.get("auth")) or any(
                (h.get("key", "").lower() == "authorization") for h in req.get("header", []) or []
            )
            endpoints.append(
                {"method": method, "path": path, "params": [], "auth_required": "yes" if has_auth else "unknown"}
            )

    _walk(collection.get("item"))
    return endpoints


def import_collection(db: Session, program_id: int, content: str, actor: str = "system") -> dict:
    """Import a collection (auto-detecting OpenAPI/Swagger/Postman) into inventory."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Not valid JSON: {exc}") from exc

    if "paths" in data:
        source = "openapi" if str(data.get("openapi", "")).startswith("3") else "swagger"
        raw_endpoints = parse_openapi(data)
    elif "item" in data and "info" in data:
        source = "postman"
        raw_endpoints = parse_postman(data)
    else:
        raise ValueError("Unrecognized collection format (expected OpenAPI/Swagger/Postman).")

    created = 0
    object_id_endpoints = 0
    for ep in raw_endpoints:
        oid = detect_object_id_params(ep["path"], ep["params"])
        if oid:
            object_id_endpoints += 1
        db.add(
            ApiEndpoint(
                program_id=program_id,
                method=ep["method"],
                path=ep["path"][:1024],
                source=source,
                object_id_params=",".join(oid) or None,
                auth_required=ep["auth_required"],
            )
        )
        created += 1
    record_audit(
        db, action="api.import", actor=actor, target=f"program:{program_id}",
        detail=f"source={source} endpoints={created} with_object_ids={object_id_endpoints}",
        commit=False,
    )
    db.commit()
    return {"source": source, "imported": created, "object_id_endpoints": object_id_endpoints}


def generate_authorization_test_cases(endpoint: ApiEndpoint) -> list[str]:
    """Generate SAFE, human-executable authorization test cases for an endpoint.

    These are review instructions only — the platform does not auto-execute
    them. They never include exploitation payloads.
    """
    oids = [p for p in (endpoint.object_id_params or "").split(",") if p]
    cases = [
        f"Confirm `{endpoint.method} {endpoint.path}` is in authorized scope before testing.",
        "With an authorized low-privilege test account, call the endpoint and confirm "
        "the response is appropriate for that role (no data belonging to others).",
    ]
    for oid in oids:
        cases.append(
            f"Using two authorized test accounts, take a `{oid}` value owned by account A "
            f"and request it as account B. Expect 403/404 — flag if B can read A's object "
            f"(potential IDOR). Do NOT enumerate or bulk-download; check one or two ids only."
        )
    cases.append(
        "Any state-changing method (POST/PUT/PATCH/DELETE) must be validated manually with "
        "explicit approval — do not auto-execute."
    )
    return cases
