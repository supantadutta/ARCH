"""Nuclei scanner wrapper (safe template-based scanning).

Nuclei is run with passive / non-intrusive settings only. We explicitly exclude
templates tagged as intrusive (``dos``, ``fuzz``, ``brute``, ``intrusive``) and
never enable interactive / exploitation features. In dry-run mode the command
is logged but not executed.
"""

from __future__ import annotations

import json

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult

# Severity strings emitted by nuclei map directly onto our taxonomy.
_NUCLEI_SEVERITIES = {"info", "low", "medium", "high", "critical"}


class NucleiScanner(BaseScanner):
    name = "nuclei"
    scan_type = "nuclei"
    binary = "nuclei"

    def build_command(self, target: str) -> list[str]:
        url = target if "://" in target else f"https://{target}"
        return [
            "nuclei",
            "-target",
            url,
            "-jsonl",
            "-silent",
            # Safety: rate limit and exclude any intrusive template tags.
            "-rate-limit",
            "10",
            "-exclude-tags",
            "dos,fuzz,brute,intrusive,sqli-exploit",
            "-no-interactsh",
        ]

    def parse_output(self, result: ScannerResult) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = data.get("info", {})
            severity = info.get("severity", "info")
            if severity not in _NUCLEI_SEVERITIES:
                severity = "info"
            findings.append(
                ScanFinding(
                    title=info.get("name", data.get("template-id", "Nuclei finding")),
                    description=info.get("description", ""),
                    severity=severity,
                    confidence="medium",
                    category="nuclei-template",
                    evidence_summary=data.get("matched-at", ""),
                    raw_output=line[:4000],
                    scanner_name=self.name,
                    manual_review_required=True,
                )
            )
        return findings
