"""Report generator -- orchestrates all report format outputs."""

from __future__ import annotations

from stryx.attacks.attack_chain import AttackChain
from stryx.reports.json_report import JsonReport
from stryx.reports.markdown_report import MarkdownReport
from stryx.reports.terminal_report import TerminalReport
from stryx.utils.evidence import Finding
from stryx.utils.logging import get_logger

logger = get_logger("reports.generator")


class ReportGenerator:
    """Generates security reports in multiple formats."""

    def __init__(
        self,
        target_url: str,
        findings: list[Finding],
        attack_chains: list[AttackChain] | None = None,
    ):
        self.target_url = target_url
        self.findings = findings
        self.attack_chains = attack_chains or []

    def generate_terminal(self) -> None:
        """Display results in terminal."""
        report = TerminalReport(self.target_url, self.findings, self.attack_chains)
        report.display()

    def generate_json(self, path: str) -> str:
        """Generate JSON report."""
        report = JsonReport(self.target_url, self.findings, self.attack_chains)
        report.save(path)
        return path

    def generate_markdown(self, path: str) -> str:
        """Generate Markdown report."""
        report = MarkdownReport(self.target_url, self.findings, self.attack_chains)
        report.save(path)
        return path

    def generate_html(self, path: str) -> str:
        """Generate HTML report using Jinja2."""
        try:
            import os

            from jinja2 import Environment, FileSystemLoader

            template_dir = os.path.join(os.path.dirname(__file__), "templates")
            env = Environment(loader=FileSystemLoader(template_dir))
            template = env.get_template("report.html.j2")

            # Count severities
            severity_counts = {}
            for f in self.findings:
                sev = f.severity.value
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            # Prepare finding data for template
            findings_data = []
            for f in self.findings:
                findings_data.append(
                    {
                        "title": f.title,
                        "severity": f.severity.value,
                        "endpoint": f.endpoint,
                        "description": f.description,
                        "remediation": f.remediation,
                        "cwe": f.cwe,
                        "owasp": f.owasp,
                        "evidence": f.evidence,
                    }
                )

            # Prepare chain data
            chains_data = []
            for c in self.attack_chains:
                chains_data.append(
                    {
                        "name": c.name,
                        "total_impact": c.total_impact,
                        "estimated_severity": c.estimated_severity,
                        "steps": [
                            {
                                "title": step.finding.title,
                                "description": step.description,
                            }
                            for step in c.steps
                        ],
                    }
                )

            html = template.render(
                target=self.target_url,
                generated_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
                total_findings=len(self.findings),
                critical_count=severity_counts.get("critical", 0),
                high_count=severity_counts.get("high", 0),
                medium_count=severity_counts.get("medium", 0),
                low_count=severity_counts.get("low", 0),
                findings=findings_data,
                attack_chains=chains_data,
            )

            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            logger.info(f"HTML report saved to {path}")
            return path

        except ImportError:
            logger.warning("Jinja2 not available, HTML report not generated")
            return ""
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            return ""
