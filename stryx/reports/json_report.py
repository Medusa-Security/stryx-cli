"""JSON report generator -- MEDUSA integration contract."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from stryx.attacks.attack_chain import AttackChain
from stryx.utils.evidence import Finding
from stryx.utils.logging import get_logger

logger = get_logger("reports.json")


class JsonReport:
    """Generates machine-readable JSON reports for MEDUSA ingestion.

    This is the stable integration contract -- MEDUSA parses this output.
    Schema is documented in docs/DOCS.md.
    """

    def __init__(
        self,
        target_url: str,
        findings: list[Finding],
        attack_chains: list[AttackChain] | None = None,
    ):
        self.target_url = target_url
        self.findings = findings
        self.attack_chains = attack_chains or []

    def generate(self) -> dict[str, Any]:
        """Generate the JSON report."""
        severity_counts = {}
        for f in self.findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "report": {
                "tool": "stryx",
                "version": "0.1.0",
                "generated_at": datetime.now(UTC).isoformat(),
                "target": self.target_url,
            },
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": severity_counts,
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "info": severity_counts.get("info", 0),
            },
            "findings": [f.to_dict() for f in self.findings],
            "attack_chains": [c.to_dict() for c in self.attack_chains],
            "metadata": {
                "scanners_used": list(set(f.scanner for f in self.findings)),
                "total_endpoints_tested": len(set(f.endpoint for f in self.findings)),
            },
        }

    def to_json(self, indent: int = 2) -> str:
        """Generate JSON string."""
        return json.dumps(self.generate(), indent=indent, default=str)

    def save(self, path: str) -> None:
        """Save report to file."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        logger.info(f"JSON report saved to {path}")
