"""AuthenticatedCrawlerModule — safe authenticated discovery.

Logs in with an AUTHORIZED test account (never brute force, never real user
credentials), stores the resulting session encrypted, and performs a small,
bounded, read-only crawl of authenticated pages to discover URLs and API
endpoints.

Hard safety controls:

* Scope-gated (every URL), kill-switch gated, rate limited.
* Single login attempt with the account's stored credentials — no guessing.
* GET only; bounded by ``CRAWLER_MAX_PAGES`` / ``CRAWLER_MAX_DEPTH``.
* Default dry-run: describe the plan without sending any request.
* Sessions are stored encrypted at rest.
"""

from __future__ import annotations

import json
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.advanced.crypto import decrypt, encrypt
from app.config import settings
from app.models import ApiEndpoint, Asset, TestAccount
from app.policy.scope_guard import ScopeError, is_target_in_scope, validate_scan_request
from app.services.audit import record_audit
from app.services.killswitch import is_kill_switch_enabled

_TIMEOUT = 8
_UA = "AutoBugHunter-AuthCrawler/0.1 (authorized testing only)"


def _login(account: TestAccount) -> requests.Session | None:
    """Perform a single authorized login and return an authenticated session."""
    sess = requests.Session()
    sess.headers.update({"User-Agent": _UA})
    creds_raw = decrypt(account.encrypted_secret)
    if not account.login_url or not creds_raw:
        return None
    try:
        form = json.loads(creds_raw)
    except json.JSONDecodeError:
        return None
    try:
        # A single login attempt only — never retried/guessed.
        sess.post(account.login_url, data=form, timeout=_TIMEOUT, allow_redirects=True)
    except requests.RequestException:
        return None
    return sess


def _looks_like_api(path: str) -> bool:
    p = path.lower()
    return "/api/" in p or p.endswith(".json") or "/v1/" in p or "/v2/" in p


def run_authenticated_crawl(
    db: Session,
    program_id: int,
    account_id: int,
    start_url: str,
    dry_run: bool = True,
    actor: str = "system",
) -> dict:
    """Log in and crawl authenticated pages within scope (bounded, read-only)."""
    if is_kill_switch_enabled(db):
        record_audit(
            db, action="auth_crawl.rejected", actor=actor, target=start_url,
            decision="rejected", detail="Kill switch engaged.", commit=False,
        )
        db.commit()
        raise ScopeError(type("D", (), {"reason": "Kill switch engaged.", "normalized_target": start_url})())

    account = db.get(TestAccount, account_id)
    if not account or account.program_id != program_id:
        raise ValueError("Test account not found for this program.")
    if not account.is_authorized:
        raise ValueError("Test account is not marked authorized.")

    # Scope-gate the start URL (raises ScopeError if out of scope / forbidden).
    decision = validate_scan_request(db, program_id, start_url, "auth_crawl")
    start = start_url if "://" in start_url else f"https://{decision.normalized_target}"
    host = urlparse(start).hostname

    if dry_run:
        record_audit(
            db, action="auth_crawl.plan", actor=actor, target=decision.normalized_target,
            decision="allowed",
            detail=f"account={account_id} dry_run=True max_pages={settings.crawler_max_pages}",
            commit=False,
        )
        db.commit()
        return {
            "dry_run": True,
            "plan": (
                f"Would log in as authorized account '{account.label}' and crawl up to "
                f"{settings.crawler_max_pages} in-scope pages (depth {settings.crawler_max_depth}) "
                f"from {start}, read-only, discovering URLs and API endpoints."
            ),
        }

    sess = _login(account)
    if sess is None:
        record_audit(
            db, action="auth_crawl.login_failed", actor=actor, target=decision.normalized_target,
            decision="info", detail=f"account={account_id}", commit=False,
        )
        db.commit()
        return {"dry_run": False, "error": "Login did not succeed (no retry/guessing performed)."}

    # Persist the session (encrypted) for reuse by other modules.
    cookie_str = "; ".join(f"{c.name}={c.value}" for c in sess.cookies)
    if cookie_str:
        account.encrypted_session = encrypt(f"Cookie: {cookie_str}")
        db.add(account)

    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(start, 0)]
    pages = 0
    apis_found = 0
    rate = 1.0 / max(settings.scanner_rate_limit_per_sec, 0.5)

    while queue and pages < settings.crawler_max_pages:
        url, depth = queue.pop(0)
        if url in seen or depth > settings.crawler_max_depth:
            continue
        seen.add(url)

        # Re-check each URL against scope before fetching.
        if not is_target_in_scope(db, program_id, url).allowed:
            continue

        time.sleep(rate)
        try:
            resp = sess.get(url, timeout=_TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue
        pages += 1

        path = urlparse(url).path or "/"
        if _looks_like_api(path):
            if not (
                db.query(ApiEndpoint)
                .filter(ApiEndpoint.program_id == program_id, ApiEndpoint.path == path)
                .first()
            ):
                db.add(
                    ApiEndpoint(
                        program_id=program_id, method="GET", path=path, source="crawl",
                        auth_required="yes",
                    )
                )
                apis_found += 1
        else:
            if not (
                db.query(Asset)
                .filter(Asset.program_id == program_id, Asset.value == url)
                .first()
            ):
                db.add(Asset(program_id=program_id, asset_type="auth_page", value=url, status="active"))

        # Extract same-host links to continue the bounded crawl.
        if depth < settings.crawler_max_depth:
            try:
                soup = BeautifulSoup(resp.text, "html.parser")
            except Exception:
                soup = None
            if soup:
                for a in soup.find_all("a", href=True):
                    nxt = urljoin(url, a["href"])
                    if urlparse(nxt).hostname == host and nxt not in seen:
                        queue.append((nxt, depth + 1))

    record_audit(
        db, action="auth_crawl.run", actor=actor, target=decision.normalized_target,
        decision="info", detail=f"account={account_id} pages={pages} apis={apis_found}",
        commit=False,
    )
    db.commit()
    return {"dry_run": False, "pages_crawled": pages, "api_endpoints_found": apis_found}
