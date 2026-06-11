"""Registry mapping scan-job types to their scanner wrapper classes."""

from __future__ import annotations

from app.scanners.base import BaseScanner
from app.scanners.gitleaks_scanner import GitleaksScanner
from app.scanners.nuclei_scanner import NucleiScanner
from app.scanners.recon_scanner import ReconScanner
from app.scanners.semgrep_scanner import SemgrepScanner
from app.scanners.trivy_scanner import TrivyScanner
from app.scanners.zap_scanner import ZapScanner

SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {
    "recon": ReconScanner,
    "nuclei": NucleiScanner,
    "zap_baseline": ZapScanner,
    "semgrep": SemgrepScanner,
    "gitleaks": GitleaksScanner,
    "trivy": TrivyScanner,
}


def get_scanner_class(job_type: str) -> type[BaseScanner] | None:
    """Return the scanner class for a job type, or None if unsupported."""
    return SCANNER_REGISTRY.get(job_type)
