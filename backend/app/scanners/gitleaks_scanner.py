"""Gitleaks secret-scanning wrapper.

Detects committed secrets in an in-scope repository path. Read-only.
"""

from __future__ import annotations

import json

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult


class GitleaksScanner(BaseScanner):
    name = "gitleaks"
    scan_type = "gitleaks"
    binary = "gitleaks"

    def build_command(self, target: str) -> list[str]:
        # ``target`` is a local repo path in scope.
        return [
            "gitleaks",
            "detect",
            "--source",
            target,
            "--report-format",
            "json",
            "--report-path",
            "/dev/stdout",
            "--no-banner",
        ]

    def parse_output(self, result: ScannerResult) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return findings
        for item in data if isinstance(data, list) else []:
            # NOTE: we record the location, never the secret value itself.
            findings.append(
                ScanFinding(
                    title=f"Potential secret: {item.get('RuleID', 'unknown rule')}",
                    description=item.get("Description", "Potential committed secret detected."),
                    severity="high",
                    confidence="medium",
                    category="secret",
                    cwe="CWE-798",
                    evidence_summary=(
                        f"{item.get('File')}:{item.get('StartLine')} "
                        f"(commit {item.get('Commit', '')[:10]})"
                    ),
                    raw_output=json.dumps(
                        {k: v for k, v in item.items() if k not in ("Secret", "Match")}
                    )[:4000],
                    scanner_name=self.name,
                    manual_review_required=True,
                )
            )
        return findings
