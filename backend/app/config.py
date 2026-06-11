"""Application configuration loaded from environment variables.

All risky behaviour is gated behind safe-by-default settings. In particular,
``DRY_RUN`` defaults to ``True`` so that scanners never execute real external
commands unless an operator deliberately opts in.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration object.

    Values can be overridden through environment variables (see
    ``.env.example``). The defaults are intentionally conservative.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- Core infrastructure ---------------------------------------------
    app_name: str = "AutoBugHunter"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "postgresql://abh:abh@postgres:5432/autobughunter"
    redis_url: str = "redis://redis:6379/0"

    # --- Storage paths ---------------------------------------------------
    evidence_dir: str = "/evidence"
    reports_dir: str = "/reports"

    # --- Safety controls -------------------------------------------------
    # When True, scanners log the command they *would* have run but never
    # actually execute external tooling. This is the default for safety.
    dry_run: bool = True

    # Global kill switch. When enabled, no new scan jobs may be queued or run.
    kill_switch_enabled: bool = False

    # Rate limiting for scanner execution (requests per second budget).
    scanner_rate_limit_per_sec: float = 2.0

    # Allow scanning of private / internal IP ranges. Off by default to
    # prevent accidental scans of internal infrastructure. localhost is
    # handled as an explicit, opt-in exception for the demo flow.
    allow_private_targets: bool = False

    # --- Authorization ---------------------------------------------------
    # When True, every API request must present a valid API key in the
    # ``X-API-Key`` header. Enabled by default to enforce strict
    # authorization. The default dev key is intended for local use only and
    # MUST be overridden in any real deployment.
    auth_enabled: bool = True
    api_key: str = "dev-local-key"

    # --- Optional local vulnerable target -------------------------------
    # A deliberately misconfigured *local* web app used only as a safe scan
    # target for demos. Disabled by default; enable explicitly (and only in
    # an isolated lab) via the compose ``vuln`` profile / this flag.
    enable_vulnerable_target: bool = False
    vulnerable_target_url: str = "http://vulnerable-target:9000"

    # Scan types that are categorically forbidden by this platform. These map
    # to destructive / abusive techniques the platform must never perform.
    forbidden_scan_types: tuple[str, ...] = (
        "dos",
        "ddos",
        "bruteforce",
        "credential_stuffing",
        "phishing",
        "malware",
        "exploit",
        "auth_bypass",
        "exfiltration",
    )

    # Scan types the platform is allowed to run (passive / safe by design).
    allowed_scan_types: tuple[str, ...] = (
        "recon",
        "nuclei",
        "zap_baseline",
        "semgrep",
        "gitleaks",
        "trivy",
        "ai_triage",
    )


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings instance."""
    return Settings()


settings = get_settings()
