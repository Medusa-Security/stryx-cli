"""Scan comparison and baseline tracking.

Compares current scan results against a previous baseline to detect
new vulnerabilities, resolved issues, and severity changes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from stryx.utils.logging import get_logger

logger = get_logger("comparison.differ")


@dataclass
class FindingDiff:
    """A single finding change between scans."""

    title: str
    endpoint: str
    severity: str
    status: str  # "new", "resolved", "severity_changed"
    old_severity: str | None = None
    new_severity: str | None = None


@dataclass
class ScanDiff:
    """Result of comparing two scans."""

    baseline_file: str
    current_file: str
    baseline_time: str
    current_time: str
    new_findings: list[FindingDiff] = field(default_factory=list)
    resolved_findings: list[FindingDiff] = field(default_factory=list)
    severity_changes: list[FindingDiff] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def has_regressions(self) -> bool:
        """Check if there are new critical/high findings."""
        return any(d.severity in ("critical", "high") for d in self.new_findings)

    @property
    def total_changes(self) -> int:
        return len(self.new_findings) + len(self.resolved_findings) + len(self.severity_changes)

    def summary(self) -> str:
        """Generate a human-readable summary."""
        lines = [
            "📊 Scan Comparison",
            f"Baseline: {self.baseline_file} ({self.baseline_time})",
            f"Current:  {self.current_file} ({self.current_time})",
            "",
        ]

        if self.new_findings:
            lines.append(f"🆕 New findings: {len(self.new_findings)}")
            for f in self.new_findings[:10]:
                lines.append(f"  - [{f.severity.upper()}] {f.title} @ {f.endpoint}")
            if len(self.new_findings) > 10:
                lines.append(f"  ... and {len(self.new_findings) - 10} more")

        if self.resolved_findings:
            lines.append(f"✅ Resolved findings: {len(self.resolved_findings)}")
            for f in self.resolved_findings[:5]:
                lines.append(f"  - [{f.severity.upper()}] {f.title}")

        if self.severity_changes:
            lines.append(f"⚡ Severity changes: {len(self.severity_changes)}")
            for f in self.severity_changes[:5]:
                lines.append(f"  - {f.title}: {f.old_severity} → {f.new_severity}")

        if not self.new_findings and not self.resolved_findings and not self.severity_changes:
            lines.append("✅ No changes detected between scans")

        if self.has_regressions:
            lines.append("")
            lines.append("⚠️  REGRESSION DETECTED: New critical/high findings!")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "baseline": {
                "file": self.baseline_file,
                "timestamp": self.baseline_time,
            },
            "current": {
                "file": self.current_file,
                "timestamp": self.current_time,
            },
            "summary": {
                "new_findings": len(self.new_findings),
                "resolved_findings": len(self.resolved_findings),
                "severity_changes": len(self.severity_changes),
                "unchanged": self.unchanged_count,
                "has_regressions": self.has_regressions,
            },
            "new_findings": [
                {"title": d.title, "endpoint": d.endpoint, "severity": d.severity} for d in self.new_findings
            ],
            "resolved_findings": [
                {"title": d.title, "endpoint": d.endpoint, "severity": d.severity} for d in self.resolved_findings
            ],
            "severity_changes": [
                {
                    "title": d.title,
                    "endpoint": d.endpoint,
                    "old_severity": d.old_severity,
                    "new_severity": d.new_severity,
                }
                for d in self.severity_changes
            ],
        }


def _fingerprint_finding(finding: dict) -> str:
    """Create a unique fingerprint for a finding."""
    title = finding.get("title", "")
    endpoint = finding.get("endpoint", "")
    return f"{title}::{endpoint}"


class ScanDiffer:
    """Compares two scan JSON files."""

    def __init__(self, baseline_path: str, current_path: str):
        self.baseline_path = baseline_path
        self.current_path = current_path
        self._baseline: dict[str, Any] = {}
        self._current: dict[str, Any] = {}

    def load(self) -> bool:
        """Load both scan files."""
        try:
            with open(self.baseline_path, encoding="utf-8") as f:
                self._baseline = json.load(f)
            with open(self.current_path, encoding="utf-8") as f:
                self._current = json.load(f)
            return True
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Failed to load scan files: {e}")
            return False

    def compare(self) -> ScanDiff:
        """Compare the two scans and return the diff."""
        if not self._baseline or not self._current:
            if not self.load():
                return ScanDiff(
                    baseline_file=self.baseline_path,
                    current_file=self.current_path,
                    baseline_time="unknown",
                    current_time="unknown",
                )

        baseline_findings = self._index_findings(self._baseline.get("findings", []))
        current_findings = self._index_findings(self._current.get("findings", []))

        baseline_fps = set(baseline_findings.keys())
        current_fps = set(current_findings.keys())

        # New findings (in current but not baseline)
        new_fps = current_fps - baseline_fps
        resolved_fps = baseline_fps - current_fps
        common_fps = baseline_fps & current_fps

        new_diffs = [
            FindingDiff(
                title=current_findings[fp]["title"],
                endpoint=current_findings[fp].get("endpoint", ""),
                severity=current_findings[fp].get("severity", "info"),
                status="new",
            )
            for fp in sorted(new_fps)
        ]

        resolved_diffs = [
            FindingDiff(
                title=baseline_findings[fp]["title"],
                endpoint=baseline_findings[fp].get("endpoint", ""),
                severity=baseline_findings[fp].get("severity", "info"),
                status="resolved",
            )
            for fp in sorted(resolved_fps)
        ]

        # Check for severity changes
        severity_changes = []
        for fp in common_fps:
            old_sev = baseline_findings[fp].get("severity", "info")
            new_sev = current_findings[fp].get("severity", "info")
            if old_sev != new_sev:
                severity_changes.append(
                    FindingDiff(
                        title=current_findings[fp]["title"],
                        endpoint=current_findings[fp].get("endpoint", ""),
                        severity=new_sev,
                        status="severity_changed",
                        old_severity=old_sev,
                        new_severity=new_sev,
                    )
                )

        return ScanDiff(
            baseline_file=self.baseline_path,
            current_file=self.current_path,
            baseline_time=self._baseline.get("timestamp", "unknown"),
            current_time=self._current.get("timestamp", "unknown"),
            new_findings=new_diffs,
            resolved_findings=resolved_diffs,
            severity_changes=severity_changes,
            unchanged_count=len(common_fps) - len(severity_changes),
        )

    def _index_findings(self, findings: list[dict]) -> dict[str, dict]:
        """Index findings by their fingerprint."""
        indexed = {}
        for f in findings:
            fp = _fingerprint_finding(f)
            indexed[fp] = f
        return indexed


def save_scan_metadata(
    path: str,
    findings_count: int,
    target_url: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Save scan metadata alongside the JSON report for future comparison."""
    meta_path = Path(path).with_suffix(".meta.json")
    meta = {
        "timestamp": datetime.now(datetime.UTC).isoformat(),
        "target_url": target_url,
        "findings_count": findings_count,
        "tool_version": "0.1.0",
    }
    if metadata:
        meta.update(metadata)

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
