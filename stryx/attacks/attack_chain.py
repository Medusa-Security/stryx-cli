"""Attack chain builder -- constructs multi-step attack paths from findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from stryx.utils.evidence import Finding
from stryx.utils.logging import get_logger

logger = get_logger("attacks.chain")


@dataclass
class AttackStep:
    """A single step in an attack chain."""

    finding: Finding
    description: str = ""
    prerequisites: list[str] = field(default_factory=list)
    impact: str = ""


@dataclass
class AttackChain:
    """A multi-step attack path constructed from individual findings."""

    name: str
    steps: list[AttackStep] = field(default_factory=list)
    total_impact: str = ""
    estimated_severity: str = "high"

    def add_step(self, finding: Finding, description: str = "", impact: str = "") -> None:
        """Add a step to the attack chain."""
        self.steps.append(AttackStep(
            finding=finding,
            description=description or finding.description,
            impact=impact,
        ))

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "steps": [
                {
                    "title": step.finding.title,
                    "description": step.description,
                    "severity": step.finding.severity.value,
                    "impact": step.impact,
                    "endpoint": step.finding.endpoint,
                }
                for step in self.steps
            ],
            "total_impact": self.total_impact,
            "estimated_severity": self.estimated_severity,
        }


class ChainBuilder:
    """Builds attack chains from individual findings."""

    def __init__(self, findings: list[Finding]):
        self.findings = findings

    def build_chains(self) -> list[AttackChain]:
        """Analyze findings and construct attack chains."""
        chains: list[AttackChain] = []

        # Group findings by type
        auth_findings = [f for f in self.findings if "auth" in f.tags]
        injection_findings = [f for f in self.findings if "injection" in f.tags]
        access_findings = [
            f for f in self.findings
            if "idor" in f.tags or "broken-access-control" in f.tags
        ]
        ssrf_findings = [f for f in self.findings if "ssrf" in f.tags]
        traversal_findings = [f for f in self.findings if "path_traversal" in f.tags]

        # Chain: Auth bypass -> IDOR -> Data exfiltration
        if auth_findings and access_findings:
            chain = AttackChain(name="Authentication Bypass to Data Exfiltration")
            chain.add_step(auth_findings[0], "Bypass authentication", "Gain unauthorized access")
            chain.add_step(access_findings[0], "Exploit IDOR", "Access other users' data")
            chain.total_impact = "Unauthorized access to sensitive user data"
            chain.estimated_severity = "critical"
            chains.append(chain)

        # Chain: Injection -> Command execution
        if injection_findings:
            chain = AttackChain(name="Injection to Remote Code Execution")
            for f in injection_findings[:2]:
                chain.add_step(f, f.title, "Potential code execution")
            chain.total_impact = "Remote code execution on the server"
            chain.estimated_severity = "critical"
            chains.append(chain)

        # Chain: SSRF -> Internal access
        if ssrf_findings:
            chain = AttackChain(name="SSRF to Internal Network Access")
            chain.add_step(ssrf_findings[0], "Trigger SSRF", "Access internal services")
            if traversal_findings:
                chain.add_step(
                    traversal_findings[0], "Read sensitive files",
                    "Access configuration files",
                )
            chain.total_impact = "Access to internal network and sensitive files"
            chain.estimated_severity = "high"
            chains.append(chain)

        logger.info(f"Built {len(chains)} attack chains from {len(self.findings)} findings")
        return chains
