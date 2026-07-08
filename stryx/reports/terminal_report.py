"""Terminal report generator using Rich."""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table

from stryx.attacks.attack_chain import AttackChain
from stryx.utils.evidence import Finding
from stryx.utils.logging import console as stryx_console


class TerminalReport:
    """Generates rich terminal output for scan results."""

    def __init__(
        self,
        target_url: str,
        findings: list[Finding],
        attack_chains: list[AttackChain] | None = None,
    ):
        self.target_url = target_url
        self.findings = findings
        self.attack_chains = attack_chains or []
        self.console = stryx_console

    def display(self) -> None:
        """Display the terminal report."""
        self._display_summary()
        self._display_findings_table()
        self._display_findings_detail()
        self._display_attack_chains()

    def _display_summary(self) -> None:
        """Display summary panel."""
        severity_counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary_parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                summary_parts.append(f"[severity.{sev}]{sev.upper()}: {count}[/]")

        summary = " | ".join(summary_parts) if summary_parts else "No findings"

        self.console.print(Panel(
            f"[bold]Target:[/] {self.target_url}\n"
            f"[bold]Total Findings:[/] {len(self.findings)}\n"
            f"[bold]Breakdown:[/] {summary}",
            title="[bold]STRYX Scan Results[/]",
            border_style="cyan",
        ))

    def _display_findings_table(self) -> None:
        """Display findings in a table."""
        if not self.findings:
            self.console.print("[green]No findings detected.[/]")
            return

        table = Table(title="Findings", show_lines=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Title", min_width=30)
        table.add_column("Endpoint", min_width=20)
        table.add_column("Confidence", width=10)

        for i, f in enumerate(self.findings, 1):
            severity_colors = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "info": "dim",
            }
            color = severity_colors.get(f.severity.value, "white")

            table.add_row(
                str(i),
                f"[{color}]{f.severity.value.upper()}[/]",
                f.title,
                f.endpoint[:50] + ("..." if len(f.endpoint) > 50 else ""),
                f"{f.evidence.confidence:.0%}",
            )

        self.console.print(table)

    def _display_findings_detail(self) -> None:
        """Display detailed findings."""
        if not self.findings:
            return

        self.console.print("\n[bold]Detailed Findings:[/]\n")

        for i, f in enumerate(self.findings, 1):
            severity_colors = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "info": "dim",
            }
            color = severity_colors.get(f.severity.value, "white")

            detail = (
                f"[bold]{f.title}[/]\n"
                f"  Severity: [{color}]{f.severity.value.upper()}[/] | "
                f"CWE: {f.cwe} | Scanner: {f.scanner}\n"
                f"  Endpoint: {f.endpoint}\n"
                f"  Description: {f.description}\n"
                f"  Remediation: {f.remediation}\n"
                f"  Evidence: {f.evidence.request_method} {f.evidence.request_url} "
                f"-> {f.evidence.response_status}"
            )
            if f.evidence.payload:
                detail += f"\n  Payload: {f.evidence.payload}"
            if f.evidence.response_snippet:
                detail += f"\n  Response: {f.evidence.response_snippet[:200]}"

            self.console.print(Panel(detail, border_style=color))

    def _display_attack_chains(self) -> None:
        """Display attack chains."""
        if not self.attack_chains:
            return

        self.console.print("\n[bold]Attack Chains:[/]\n")

        for chain in self.attack_chains:
            chain_text = f"[bold]{chain.name}[/]\n"
            chain_text += f"Impact: {chain.total_impact}\n"
            chain_text += f"Severity: {chain.estimated_severity.upper()}\n\n"
            for j, step in enumerate(chain.steps, 1):
                chain_text += f"  {j}. {step.finding.title} - {step.description}\n"

            self.console.print(Panel(chain_text, border_style="magenta"))
