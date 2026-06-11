"""OWASP ZAP baseline scanner wrapper.

Only the *baseline* (passive) scan is supported — it spiders and passively
analyzes traffic but performs no active attacks. Active scanning, fuzzing and
attack modes are intentionally not exposed.
"""

from __future__ import annotations

import json

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult

_RISK_TO_SEVERITY = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
}


class ZapScanner(BaseScanner):
    name = "zap_baseline"
    scan_type = "zap_baseline"
    binary = "zap-baseline.py"

    def build_command(self, target: str) -> list[str]:
        url = target if "://" in target else f"https://{target}"
        # zap-baseline.py is passive-only by design (-I = do not fail on warnings).
        return ["zap-baseline.py", "-t", url, "-J", "zap_report.json", "-I"]

    def parse_output(self, result: ScannerResult) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return findings
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                severity = _RISK_TO_SEVERITY.get(str(alert.get("riskcode", "0")).lower(), "info")
                findings.append(
                    ScanFinding(
                        title=alert.get("name", "ZAP alert"),
                        description=alert.get("desc", ""),
                        severity=severity,
                        confidence="medium",
                        category="zap-passive",
                        cwe=str(alert.get("cweid")) if alert.get("cweid") else None,
                        remediation=alert.get("solution"),
                        evidence_summary=alert.get("reference", ""),
                        raw_output=json.dumps(alert)[:4000],
                        scanner_name=self.name,
                        manual_review_required=True,
                    )
                )
        return findings
