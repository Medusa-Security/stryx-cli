"""Markdown report generator."""

from __future__ import annotations

from stryx.attacks.attack_chain import AttackChain
from stryx.utils.evidence import Finding
from stryx.utils.logging import get_logger

logger = get_logger("reports.markdown")


class MarkdownReport:
    """Generates Markdown reports for PR comments and CI logs."""

    def __init__(
        self,
        target_url: str,
        findings: list[Finding],
        attack_chains: list[AttackChain] | None = None,
    ):
        self.target_url = target_url
        self.findings = findings
        self.attack_chains = attack_chains or []

    def generate(self) -> str:
        """Generate the Markdown report."""
        lines = [
            "# STRYX Security Scan Report",
            "",
            f"**Target:** {self.target_url}",
            f"**Findings:** {len(self.findings)}",
            "",
        ]

        # Summary
        severity_counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append("## Summary")
        lines.append("")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(f"- **{sev.upper()}:** {count}")
        lines.append("")

        # Findings
        if self.findings:
            lines.append("## Findings")
            lines.append("")

            for i, f in enumerate(self.findings, 1):
                lines.append(f"### {i}. [{f.severity.value.upper()}] {f.title}")
                lines.append("")
                lines.append(f"**Endpoint:** `{f.endpoint}`")
                lines.append(f"**CWE:** {f.cwe}")
                lines.append(f"**OWASP:** {f.owasp}")
                lines.append(f"**Scanner:** {f.scanner}")
                lines.append(f"**Confidence:** {f.evidence.confidence:.0%}")
                lines.append("")
                lines.append(f"**Description:** {f.description}")
                lines.append("")
                lines.append(f"**Remediation:** {f.remediation}")
                lines.append("")
                lines.append("**Evidence:**")
                lines.append(f"- Method: `{f.evidence.request_method}`")
                lines.append(f"- URL: `{f.evidence.request_url}`")
                lines.append(f"- Status: `{f.evidence.response_status}`")
                if f.evidence.payload:
                    lines.append(f"- Payload: `{f.evidence.payload}`")
                if f.evidence.response_snippet:
                    lines.append("- Response snippet:")
                    lines.append("```")
                    lines.append(f.evidence.response_snippet[:500])
                    lines.append("```")
                lines.append("")
                lines.append("---")
                lines.append("")

        # Attack chains
        if self.attack_chains:
            lines.append("## Attack Chains")
            lines.append("")
            for chain in self.attack_chains:
                lines.append(f"### {chain.name}")
                lines.append(f"**Impact:** {chain.total_impact}")
                lines.append(f"**Severity:** {chain.estimated_severity.upper()}")
                lines.append("")
                for j, step in enumerate(chain.steps, 1):
                    lines.append(f"{j}. **{step.finding.title}** - {step.description}")
                lines.append("")

        return "\n".join(lines)

    def save(self, path: str) -> None:
        """Save report to file."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.generate())
        logger.info(f"Markdown report saved to {path}")
