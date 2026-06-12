"""Trivy vulnerability scanner wrapper.

Scans a filesystem path or image reference for known-vulnerable dependencies.
Read-only analysis against vulnerability databases.
"""

from __future__ import annotations

import json

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult

_TRIVY_SEVERITY = {
    "UNKNOWN": "info",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


class TrivyScanner(BaseScanner):
    name = "trivy"
    scan_type = "trivy"
    binary = "trivy"
    # Operates on an explicitly authorized local repo/image path only.
    target_kind = "path"

    def build_command(self, target: str) -> list[str]:
        # ``target`` is an in-scope local path (filesystem mode is safest).
        return ["trivy", "fs", "--quiet", "--format", "json", target]

    def parse_output(self, result: ScannerResult) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return findings
        for res in data.get("Results", []):
            for vuln in res.get("Vulnerabilities", []) or []:
                severity = _TRIVY_SEVERITY.get(vuln.get("Severity", "UNKNOWN"), "info")
                findings.append(
                    ScanFinding(
                        title=f"{vuln.get('VulnerabilityID')} in {vuln.get('PkgName')}",
                        description=vuln.get("Description", "")[:2000],
                        severity=severity,
                        confidence="high",
                        category="dependency",
                        cwe=_first(vuln.get("CweIDs")),
                        remediation=(
                            f"Upgrade {vuln.get('PkgName')} to {vuln.get('FixedVersion')}"
                            if vuln.get("FixedVersion")
                            else "No fixed version available yet."
                        ),
                        evidence_summary=(
                            f"{vuln.get('PkgName')} {vuln.get('InstalledVersion')}"
                        ),
                        raw_output=json.dumps(vuln)[:4000],
                        scanner_name=self.name,
                        manual_review_required=True,
                    )
                )
        return findings


def _first(value):
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value) if value else None
