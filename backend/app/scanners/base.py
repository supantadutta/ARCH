"""Base class for safe scanner wrappers.

All scanner wrappers inherit from :class:`BaseScanner`, which centralizes the
mandatory safety controls:

* Scope enforcement (delegates to the scope guard).
* Kill-switch checking.
* Rate limiting.
* Command logging + stdout/stderr capture.
* Dry-run mode (default ON).
* A strict command allowlist so a wrapper can never run an arbitrary binary.

Subclasses implement :meth:`build_command` and :meth:`parse_output`. They never
call :func:`subprocess` directly.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.config import settings
from app.policy.scope_guard import ScopeError, validate_scan_request
from app.services.audit import record_audit


@dataclass
class ScanFinding:
    """A normalized finding produced by a scanner, ready to become a Finding."""

    title: str
    description: str = ""
    severity: str = "info"
    confidence: str = "low"
    category: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    evidence_summary: str | None = None
    raw_output: str | None = None
    scanner_name: str | None = None
    # Risky validation must always require manual review.
    manual_review_required: bool = True


@dataclass
class ScannerResult:
    """The outcome of a scanner run."""

    scanner: str
    target: str
    dry_run: bool
    command: list[str]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    findings: list[ScanFinding] = field(default_factory=list)
    assets: list[dict] = field(default_factory=list)
    logs: str = ""
    error: str | None = None


class BaseScanner:
    """Abstract safe scanner.

    Attributes
    ----------
    name: scanner identifier matching the ScanJob.job_type values.
    binary: the only executable this wrapper is permitted to invoke.
    scan_type: the policy scan-type key validated by the scope guard.
    """

    name: str = "base"
    binary: str | None = None
    scan_type: str = "recon"
    # Tokens that must never appear in a constructed command — defence in depth
    # against accidental introduction of dangerous flags.
    FORBIDDEN_TOKENS = (";", "&&", "||", "|", "`", "$(", "rm ", "-rf", ">", "<")

    def __init__(self, db: Session, program_id: int):
        self.db = db
        self.program_id = program_id
        self._last_call_ts = 0.0

    # -- Safety helpers ----------------------------------------------------
    def _rate_limit(self) -> None:
        """Throttle scanner execution to the configured budget."""
        budget = max(settings.scanner_rate_limit_per_sec, 0.01)
        min_interval = 1.0 / budget
        elapsed = time.monotonic() - self._last_call_ts
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_call_ts = time.monotonic()

    def _assert_command_is_safe(self, command: list[str]) -> None:
        """Reject any command that contains shell metacharacters or unknown binaries."""
        if not command:
            raise ValueError("Empty command refused.")
        if self.binary and command[0] != self.binary:
            raise ValueError(
                f"Command binary '{command[0]}' is not the allowed binary '{self.binary}'."
            )
        joined = " ".join(command)
        for token in self.FORBIDDEN_TOKENS:
            if token in joined:
                raise ValueError(f"Refusing command containing forbidden token '{token}'.")

    # -- To be implemented by subclasses ----------------------------------
    def build_command(self, target: str) -> list[str]:
        """Return the argv list to execute. Must be overridden."""
        raise NotImplementedError

    def parse_output(self, result: ScannerResult) -> list[ScanFinding]:
        """Normalize raw output into ScanFinding objects. Override as needed."""
        return []

    def run_native(self, target: str, result: ScannerResult) -> None:
        """Optional pure-Python execution path (e.g. recon).

        Subclasses that do not shell out override this instead of
        ``build_command``/``parse_output``.
        """
        raise NotImplementedError

    # -- Main entry point --------------------------------------------------
    def run(self, target: str, dry_run: bool | None = None) -> ScannerResult:
        """Validate, then run the scanner under all safety controls."""
        effective_dry_run = settings.dry_run if dry_run is None else dry_run
        log_lines: list[str] = []

        def log(msg: str) -> None:
            log_lines.append(msg)

        # 1. Scope + scan-type validation (hard control).
        try:
            decision = validate_scan_request(self.db, self.program_id, target, self.scan_type)
        except ScopeError as exc:
            record_audit(
                self.db,
                action="scan.rejected",
                target=target,
                decision="rejected",
                detail=f"{self.name}: {exc.decision.reason}",
            )
            return ScannerResult(
                scanner=self.name,
                target=target,
                dry_run=effective_dry_run,
                command=[],
                error=exc.decision.reason,
                logs=exc.decision.reason,
            )

        normalized = decision.normalized_target
        log(f"[{self.name}] scope OK for '{normalized}' ({decision.reason})")

        record_audit(
            self.db,
            action="scan.allowed",
            target=normalized,
            decision="allowed",
            detail=f"{self.name} dry_run={effective_dry_run}",
        )

        result = ScannerResult(
            scanner=self.name,
            target=normalized,
            dry_run=effective_dry_run,
            command=[],
        )

        # 2. Rate limit.
        self._rate_limit()

        # 3. Native (pure-Python) scanners.
        try:
            self.run_native(normalized, result)
            result.logs = "\n".join(log_lines + [result.logs]).strip()
            return result
        except NotImplementedError:
            pass  # fall through to subprocess path

        # 4. Subprocess-based scanners.
        command = self.build_command(normalized)
        result.command = command
        try:
            self._assert_command_is_safe(command)
        except ValueError as exc:
            result.error = str(exc)
            log(f"[{self.name}] command rejected: {exc}")
            result.logs = "\n".join(log_lines)
            return result

        log(f"[{self.name}] command: {' '.join(command)}")

        if effective_dry_run:
            log(f"[{self.name}] DRY-RUN — command not executed.")
            result.returncode = 0
            result.stdout = ""
            result.findings = []
            result.logs = "\n".join(log_lines)
            return result

        # Real execution path. Refuse if the binary is not installed.
        if not self.binary or shutil.which(self.binary) is None:
            result.error = f"Binary '{self.binary}' not available in this environment."
            log(f"[{self.name}] {result.error}")
            result.logs = "\n".join(log_lines)
            return result

        try:
            proc = subprocess.run(  # noqa: S603 — argv list, validated, shell=False
                command,
                capture_output=True,
                text=True,
                timeout=600,
                shell=False,
                check=False,
            )
            result.returncode = proc.returncode
            result.stdout = proc.stdout
            result.stderr = proc.stderr
            result.findings = self.parse_output(result)
            log(f"[{self.name}] exited with code {proc.returncode}")
        except subprocess.TimeoutExpired:
            result.error = "Scanner timed out."
            log(f"[{self.name}] timed out")
        except Exception as exc:  # pragma: no cover - defensive
            result.error = str(exc)
            log(f"[{self.name}] error: {exc}")

        result.logs = "\n".join(log_lines)
        return result
