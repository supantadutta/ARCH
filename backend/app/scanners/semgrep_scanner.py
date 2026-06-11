"""Semgrep SAST scanner wrapper.

Semgrep performs static analysis on a local code path (e.g. a cloned repo in
scope). It is entirely read-only over source files.
"""

from __future__ import annotations

import json

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult

_SEMGREP_SEVERITY = {"INFO": "info", "WARNING": "medium", "ERROR": "high"}


class SemgrepScanner(BaseScanner):
    name = "semgrep"
    scan_type = "semgrep"
    binary = "semgrep"

    def build_command(self, target: str) -> list[str]:
        # ``target`` here is a local filesystem path to in-scope source code.
        return ["semgrep", "scan", "--config", "auto", "--json", "--quiet", target]

    def parse_output(self, result: ScannerResult) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return findings
        for item in data.get("results", []):
            extra = item.get("extra", {})
            severity = _SEMGREP_SEVERITY.get(extra.get("severity", "INFO"), "info")
            metadata = extra.get("metadata", {})
            findings.append(
                ScanFinding(
                    title=item.get("check_id", "Semgrep finding"),
                    description=extra.get("message", ""),
                    severity=severity,
                    confidence="medium",
                    category="sast",
                    cwe=_first(metadata.get("cwe")),
                    owasp=_first(metadata.get("owasp")),
                    evidence_summary=f"{item.get('path')}:{item.get('start', {}).get('line')}",
                    raw_output=json.dumps(item)[:4000],
                    scanner_name=self.name,
                    manual_review_required=True,
                )
            )
        return findings


def _first(value):
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value) if value else None
