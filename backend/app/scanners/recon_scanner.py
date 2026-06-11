"""Recon scanner — safe, pure-Python asset discovery.

For the MVP this performs only *passive, non-intrusive* checks:

* Resolve and probe HTTP/HTTPS availability with safe GET requests.
* Capture status code, page title, ``Server`` header and naive technology hints.

It deliberately avoids aggressive techniques (port sweeps, fuzzing, directory
brute forcing). Placeholders are noted for integrating subfinder / httpx /
katana later — those would also be gated by the scope guard.
"""

from __future__ import annotations

import socket

import requests
from bs4 import BeautifulSoup

from app.scanners.base import BaseScanner, ScannerResult

# Future integrations (all must remain scope-gated and passive):
#   * subfinder  -> subdomain enumeration
#   * httpx      -> fast HTTP probing
#   * katana     -> safe crawling
_PLACEHOLDER_TOOLS = ("subfinder", "httpx", "katana")

_SAFE_TIMEOUT = 8
_USER_AGENT = "AutoBugHunter-Recon/0.1 (authorized scanning only)"


class ReconScanner(BaseScanner):
    name = "recon"
    scan_type = "recon"
    binary = None  # pure Python, no external binary

    def run_native(self, target: str, result: ScannerResult) -> None:
        """Probe the target over HTTP and HTTPS and record discovered assets."""
        log: list[str] = [f"[recon] probing '{target}' (passive HTTP/HTTPS checks)"]

        # Dry-run safety: do NOT touch the network at all. Describe the actions
        # that would be taken and return without any DNS or HTTP requests.
        if result.dry_run:
            log.append("[recon] DRY-RUN — no DNS resolution or HTTP requests performed.")
            for scheme in ("https", "http"):
                log.append(f"[recon] would GET {scheme}://{target} (passive)")
            log.append(f"[recon] placeholder integrations available later: {_PLACEHOLDER_TOOLS}")
            result.logs = "\n".join(log)
            result.returncode = 0
            return

        # Best-effort DNS resolution (no failure if it does not resolve).
        ip_address: str | None = None
        try:
            ip_address = socket.gethostbyname(target)
            log.append(f"[recon] resolved {target} -> {ip_address}")
        except OSError:
            log.append(f"[recon] DNS resolution failed for {target}")

        for scheme in ("https", "http"):
            url = f"{scheme}://{target}"
            try:
                resp = requests.get(
                    url,
                    timeout=_SAFE_TIMEOUT,
                    headers={"User-Agent": _USER_AGENT},
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                log.append(f"[recon] {url} unreachable: {exc.__class__.__name__}")
                continue

            title = _extract_title(resp.text)
            server = resp.headers.get("Server")
            technologies = _detect_technologies(resp)

            log.append(
                f"[recon] {url} -> {resp.status_code} "
                f"title={title!r} server={server!r} tech={technologies}"
            )

            result.assets.append(
                {
                    "value": target,
                    "asset_type": "web",
                    "ip_address": ip_address,
                    "scheme": scheme,
                    "port": 443 if scheme == "https" else 80,
                    "status": "active",
                    "technologies": ",".join(technologies) if technologies else None,
                    "status_code": resp.status_code,
                    "title": title,
                    "server": server,
                }
            )

        if not result.assets:
            log.append("[recon] no live HTTP/HTTPS endpoints found.")

        log.append(f"[recon] placeholder integrations available later: {_PLACEHOLDER_TOOLS}")
        result.logs = "\n".join(log)
        result.returncode = 0


def _extract_title(html: str) -> str | None:
    try:
        soup = BeautifulSoup(html, "html.parser")
        if soup.title and soup.title.string:
            return soup.title.string.strip()[:200]
    except Exception:  # pragma: no cover - parsing is best-effort
        return None
    return None


def _detect_technologies(resp: requests.Response) -> list[str]:
    """Very small, heuristic technology fingerprint from response headers."""
    tech: list[str] = []
    headers = {k.lower(): v for k, v in resp.headers.items()}
    if "x-powered-by" in headers:
        tech.append(headers["x-powered-by"])
    if "server" in headers:
        tech.append(headers["server"])
    if "x-aspnet-version" in headers:
        tech.append("ASP.NET")
    if "set-cookie" in headers and "wordpress" in headers["set-cookie"].lower():
        tech.append("WordPress")
    # De-duplicate while preserving order.
    seen: set[str] = set()
    return [t for t in tech if not (t in seen or seen.add(t))]
