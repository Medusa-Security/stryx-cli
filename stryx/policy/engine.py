"""Policy engine for pass/fail evaluation of scan results.

Enables CI/CD quality gates by defining security policies
that scan results must satisfy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

from stryx.utils.evidence import Finding
from stryx.utils.logging import get_logger

logger = get_logger("policy.engine")


@dataclass
class PolicyViolation:
    """A single policy violation."""

    rule: str
    message: str
    severity: str = "high"
    details: str = ""


@dataclass
class PolicyResult:
    """Result of policy evaluation."""

    passed: bool
    violations: list[PolicyViolation] = field(default_factory=list)
    summary: str = ""

    def __str__(self) -> str:
        if self.passed:
            return f"✅ Policy PASSED: {self.summary}"
        lines = [f"❌ Policy FAILED: {self.summary}"]
        for v in self.violations:
            lines.append(f"  - [{v.severity.upper()}] {v.rule}: {v.message}")
        return "\n".join(lines)


class PolicyEngine:
    """Evaluates scan findings against a security policy.

    Policy YAML format:
        policy:
          max_critical: 0
          max_high: 3
          max_medium: 10
          max_low: 50
          max_findings: 100
          required_headers:
            - X-Content-Type-Options
            - X-Frame-Options
          blocked_cwe:
            - CWE-89
            - CWE-79
          blocked_scanners:
            - cloud-ssrf
          min_confidence: 0.5
    """

    def __init__(self, policy_config: dict[str, Any] | None = None):
        self.config = policy_config or {}

    @classmethod
    def from_file(cls, path: str) -> PolicyEngine:
        """Load policy from a YAML file."""
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            config = data.get("policy", data) if isinstance(data, dict) else {}
            return cls(config)
        except Exception as e:
            logger.error(f"Failed to load policy from {path}: {e}")
            return cls({})

    def evaluate(self, findings: list[Finding]) -> PolicyResult:
        """Evaluate findings against the policy."""
        violations: list[PolicyViolation] = []

        # Count by severity
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Check max severity counts
        max_critical = self.config.get("max_critical")
        if max_critical is not None and severity_counts.get("critical", 0) > max_critical:
            violations.append(
                PolicyViolation(
                    rule="max_critical",
                    message=f"Found {severity_counts['critical']} critical findings (max: {max_critical})",
                    severity="critical",
                )
            )

        max_high = self.config.get("max_high")
        if max_high is not None and severity_counts.get("high", 0) > max_high:
            violations.append(
                PolicyViolation(
                    rule="max_high",
                    message=f"Found {severity_counts['high']} high findings (max: {max_high})",
                    severity="high",
                )
            )

        max_medium = self.config.get("max_medium")
        if max_medium is not None and severity_counts.get("medium", 0) > max_medium:
            violations.append(
                PolicyViolation(
                    rule="max_medium",
                    message=f"Found {severity_counts['medium']} medium findings (max: {max_medium})",
                    severity="medium",
                )
            )

        max_low = self.config.get("max_low")
        if max_low is not None and severity_counts.get("low", 0) > max_low:
            violations.append(
                PolicyViolation(
                    rule="max_low",
                    message=f"Found {severity_counts['low']} low findings (max: {max_low})",
                    severity="low",
                )
            )

        max_findings = self.config.get("max_findings")
        if max_findings is not None and len(findings) > max_findings:
            violations.append(
                PolicyViolation(
                    rule="max_findings",
                    message=f"Found {len(findings)} total findings (max: {max_findings})",
                    severity="high",
                )
            )

        # Check blocked CWEs
        blocked_cwe = set(self.config.get("blocked_cwe", []))
        if blocked_cwe:
            for f in findings:
                if f.cwe in blocked_cwe:
                    violations.append(
                        PolicyViolation(
                            rule="blocked_cwe",
                            message=f"Blocked CWE found: {f.cwe} at {f.endpoint}",
                            severity=f.severity.value,
                            details=f.title,
                        )
                    )

        # Check blocked scanners
        blocked_scanners = set(self.config.get("blocked_scanners", []))
        if blocked_scanners:
            for f in findings:
                if f.scanner in blocked_scanners:
                    violations.append(
                        PolicyViolation(
                            rule="blocked_scanners",
                            message=f"Finding from blocked scanner '{f.scanner}': {f.title}",
                            severity=f.severity.value,
                            details=f.endpoint,
                        )
                    )

        # Check minimum confidence
        min_confidence = self.config.get("min_confidence")
        if min_confidence is not None:
            low_conf_count = sum(1 for f in findings if f.evidence.confidence < min_confidence)
            if low_conf_count > 0:
                violations.append(
                    PolicyViolation(
                        rule="min_confidence",
                        message=f"{low_conf_count} findings below confidence threshold {min_confidence}",
                        severity="info",
                    )
                )

        # Build summary
        total = len(findings)
        passed = len(violations) == 0
        if passed:
            summary = f"{total} findings, all within policy limits"
        else:
            summary = f"{total} findings, {len(violations)} policy violation(s)"

        return PolicyResult(
            passed=passed,
            violations=violations,
            summary=summary,
        )


# Default policy (permissive)
DEFAULT_POLICY = {
    "max_critical": 0,
    "max_high": 10,
    "max_medium": 50,
    "max_low": 200,
    "max_findings": 500,
}


def save_default_policy(path: str) -> None:
    """Save the default policy to a YAML file."""
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump({"policy": DEFAULT_POLICY}, f, default_flow_style=False, sort_keys=False)
    logger.info(f"Default policy saved to {path}")
