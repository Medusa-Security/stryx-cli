"""SARIF 2.1.0 report generator for CI/CD integration.

Generates Static Analysis Results Interchange Format (SARIF) reports
compatible with GitHub Security tab, Azure DevOps, and other SARIF consumers.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from stryx.utils.evidence import Finding
from stryx.utils.logging import get_logger

logger = get_logger("reports.sarif")

# SARIF severity mapping
SEVERITY_MAP = {
    "critical": {"level": "error", "score": 1.0},
    "high": {"level": "error", "score": 0.8},
    "medium": {"level": "warning", "score": 0.5},
    "low": {"level": "note", "score": 0.2},
    "info": {"level": "none", "score": 0.0},
}


class SarifReport:
    """Generates SARIF 2.1.0 compliant reports."""

    def __init__(
        self,
        target_url: str,
        findings: list[Finding],
        scan_time: str | None = None,
    ):
        self.target_url = target_url
        self.findings = findings
        self.scan_time = scan_time or datetime.now(datetime.UTC).isoformat()

    def generate(self) -> dict[str, Any]:
        """Generate SARIF report as a dictionary."""
        # Build rules from findings
        rules: list[dict[str, Any]] = []
        rule_ids: set[str] = set()

        for finding in self.findings:
            rule_id = self._get_rule_id(finding)
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append(self._build_rule(finding, rule_id))

        # Build results
        results = [self._build_result(f) for f in self.findings]

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "STRYX",
                            "version": "0.1.0",
                            "semanticVersion": "0.1.0",
                            "informationUri": "https://github.com/medusa-Security/stryx",
                            "rules": rules,
                        }
                    },
                    "artifacts": [
                        {
                            "location": {
                                "uri": self.target_url,
                                "uriBaseId": "%SRCROOT%",
                            },
                        }
                    ],
                    "results": results,
                    "invocations": [
                        {
                            "startTimeUtc": self.scan_time,
                            "toolExecutionNotifications": [],
                        }
                    ],
                }
            ],
        }

        return sarif

    def to_json(self, indent: int = 2) -> str:
        """Generate SARIF report as JSON string."""
        return json.dumps(self.generate(), indent=indent, default=str)

    def save(self, path: str) -> None:
        """Save SARIF report to file."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        logger.info(f"SARIF report saved to {path}")

    def _get_rule_id(self, finding: Finding) -> str:
        """Generate a stable rule ID for a finding."""
        # Use CWE if available
        if finding.cwe:
            cwe_num = finding.cwe.replace("CWE-", "")
            return f"stryx-cwe-{cwe_num}"

        # Use scanner + title hash
        import hashlib

        title_hash = hashlib.md5(finding.title.encode()).hexdigest()[:8]
        return f"stryx-{finding.scanner}-{title_hash}"

    def _build_rule(self, finding: Finding, rule_id: str) -> dict[str, Any]:
        """Build a SARIF rule definition."""
        rule: dict[str, Any] = {
            "id": rule_id,
            "name": finding.title[:80],
            "shortDescription": {
                "text": finding.title,
            },
            "fullDescription": {
                "text": finding.description or finding.title,
            },
            "helpUri": "",
            "properties": {
                "tags": finding.tags if hasattr(finding, "tags") and finding.tags else [],
            },
        }

        # Add CWE reference
        if finding.cwe:
            cwe_num = finding.cwe.replace("CWE-", "")
            rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
            rule["properties"]["tags"].append("security")
            rule["properties"]["tags"].append(f"external/cwe/cwe-{cwe_num}")

        # Add OWASP reference
        if finding.owasp:
            rule["properties"]["owasp"] = finding.owasp

        return rule

    def _build_result(self, finding: Finding) -> dict[str, Any]:
        """Build a SARIF result for a finding."""
        sev_data = SEVERITY_MAP.get(finding.severity.value, SEVERITY_MAP["info"])

        result: dict[str, Any] = {
            "ruleId": self._get_rule_id(finding),
            "level": sev_data["level"],
            "message": {
                "text": finding.description or finding.title,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.endpoint or self.target_url,
                        },
                        "region": {
                            "startLine": 1,
                        },
                    }
                }
            ],
            "properties": {
                "severity": finding.severity.value,
                "confidence": finding.evidence.confidence,
                "scanner": finding.scanner,
            },
        }

        # Add CWE/OWASP to properties
        if finding.cwe:
            result["properties"]["cwe"] = finding.cwe
        if finding.owasp:
            result["properties"]["owasp"] = finding.owasp

        # Add remediation as help text
        if finding.remediation:
            result["fixes"] = [
                {
                    "description": {
                        "text": finding.remediation,
                    },
                }
            ]

        # Add request/response evidence
        if finding.evidence:
            evidence_parts = []
            evidence_parts.append(f"Request: {finding.evidence.request_method} {finding.evidence.request_url}")
            evidence_parts.append(f"Status: {finding.evidence.response_status}")
            if finding.evidence.payload:
                evidence_parts.append(f"Payload: {finding.evidence.payload}")
            if finding.evidence.response_snippet:
                evidence_parts.append(f"Response: {finding.evidence.response_snippet[:200]}")

            result["properties"]["evidence"] = "\n".join(evidence_parts)

        return result
