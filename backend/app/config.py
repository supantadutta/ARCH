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

    # --- JWT authentication ----------------------------------------------
    # Secret used to sign JWTs. MUST be overridden in any real deployment.
    jwt_secret: str = "change-me-dev-secret"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 1440  # 24h

    # Seed admin account created on first boot (change in production).
    default_admin_email: str = "admin@localhost"
    default_admin_password: str = "admin12345"

    # --- SLA policy (days to remediate, per severity) --------------------
    sla_days_critical: int = 3
    sla_days_high: int = 7
    sla_days_medium: int = 30
    sla_days_low: int = 90
    sla_days_info: int = 0  # 0 => no SLA tracked

    def sla_days_for(self, severity: str) -> int:
        """Return the SLA window (days) for a severity, 0 meaning untracked."""
        return {
            "critical": self.sla_days_critical,
            "high": self.sla_days_high,
            "medium": self.sla_days_medium,
            "low": self.sla_days_low,
            "info": self.sla_days_info,
        }.get(severity, 0)

    # --- Background job retry policy -------------------------------------
    task_max_retries: int = 3
    task_retry_backoff: int = 5  # seconds, exponential base

    # --- Notifications (placeholder) -------------------------------------
    # "log" writes notifications to the application log; "webhook" posts to
    # NOTIFY_WEBHOOK_URL (placeholder, off by default).
    notify_provider: str = "log"
    notify_webhook_url: str = ""

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
        # Advanced authorized modules (still scope-gated, rate-limited, and
        # — where they send requests — restricted to authorized test accounts).
        "auth_crawl",
        "access_control",
    )

    # --- Advanced modules ------------------------------------------------
    # Key used to encrypt test-account secrets / sessions at rest. If empty it
    # is derived from JWT_SECRET. Set a dedicated key in production.
    advanced_secret_key: str = ""

    # Authenticated crawler limits (kept small and safe — never a bulk crawl).
    crawler_max_pages: int = 25
    crawler_max_depth: int = 2

    # Access-control comparator caps (never bulk download).
    access_control_max_objects: int = 20
    # Maximum bytes of any response body retained as (redacted) evidence.
    evidence_max_bytes: int = 2048

    # Payment review modules operate only against sandbox/staging by default.
    payment_sandbox_only: bool = True

    # --- AI triage provider ----------------------------------------------
    # Which triage provider to use: "mock" (default, offline, deterministic),
    # "openai" (any OpenAI-compatible chat-completions endpoint), or "local"
    # (placeholder for a self-hosted LLM, e.g. Ollama/vLLM). The mock provider
    # keeps the platform fully runnable and safe with no external calls.
    ai_provider: str = "mock"

    # OpenAI-compatible provider settings. Used only when ai_provider="openai".
    ai_openai_base_url: str = "https://api.openai.com/v1"
    ai_openai_api_key: str = ""
    ai_openai_model: str = "gpt-4o-mini"

    # Local LLM provider settings (placeholder; ai_provider="local").
    ai_local_base_url: str = "http://localhost:11434/v1"
    ai_local_model: str = "llama3"

    # Hard timeout (seconds) for any AI provider HTTP call.
    ai_request_timeout: int = 30

    # --- External scanner integration -----------------------------------
    # Each external scanner is OPT-IN and disabled by default. A scanner only
    # executes for real when it is BOTH enabled here AND its binary is
    # installed. Recon is pure-Python and always available. Dry-run preview
    # works regardless of these flags.
    enable_nuclei: bool = False
    enable_zap: bool = False
    enable_semgrep: bool = False
    enable_gitleaks: bool = False
    enable_trivy: bool = False

    # Per-scan wall-clock timeout (seconds) for external tools.
    scanner_timeout_seconds: int = 600

    # Nuclei: only run safe/non-intrusive templates by default. These tags are
    # always excluded so intrusive checks never run.
    nuclei_excluded_tags: str = "dos,fuzz,brute,intrusive,sqli-exploit,xss-exploit"

    # Explicitly authorized LOCAL paths for path-based scanners (semgrep,
    # gitleaks, trivy). Comma-separated absolute paths / roots. A target path
    # must live under one of these roots or it is rejected. Empty => no local
    # path scanning is permitted. This is the hard authorization gate for
    # source/image scanning.
    authorized_scan_paths: str = ""

    @property
    def authorized_scan_path_list(self) -> tuple[str, ...]:
        """Parsed, normalized list of authorized local scan roots."""
        return tuple(
            p.strip().rstrip("/") for p in self.authorized_scan_paths.split(",") if p.strip()
        )

    def scanner_enabled(self, name: str) -> bool:
        """Return whether a given external scanner is enabled in settings."""
        return {
            "recon": True,  # pure-Python, always available
            "nuclei": self.enable_nuclei,
            "zap_baseline": self.enable_zap,
            "semgrep": self.enable_semgrep,
            "gitleaks": self.enable_gitleaks,
            "trivy": self.enable_trivy,
        }.get(name, False)


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings instance."""
    return Settings()


settings = get_settings()
