"""Evidence and Finding data models -- the core data types for all scan results.

Every scanner MUST produce Findings with populated Evidence. This is enforced
at the data-model level: constructing a Finding without Evidence raises ValueError.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Evidence:
    """Evidence supporting a security finding.

    Every Finding MUST contain a non-empty Evidence. This ensures no
    heuristic-only findings are reported without supporting data.
    """

    request_method: str
    request_url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    response_status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_snippet: str = ""
    payload: str = ""
    confidence: float = 0.0  # 0.0 to 1.0

    def __post_init__(self) -> None:
        if not self.request_method or not self.request_url:
            raise ValueError("Evidence must have request_method and request_url")
        if not self.response_snippet and self.response_body:
            # Auto-generate snippet from response body
            self.response_snippet = self.response_body[:500]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "request_method": self.request_method,
            "request_url": self.request_url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_body": self.response_body[:2000],  # cap for storage
            "response_snippet": self.response_snippet,
            "payload": self.payload,
            "confidence": self.confidence,
        }


@dataclass
class Finding:
    """A security finding with mandatory evidence.

    This is the universal output type for all scanners. No scanner may emit
    a Finding without populated Evidence -- this is enforced by __post_init__.
    """

    title: str
    severity: Severity
    evidence: Evidence
    description: str = ""
    remediation: str = ""
    cwe: str = ""
    owasp: str = ""
    endpoint: str = ""
    scanner: str = ""
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError(
                f"Finding '{self.title}' has no evidence. "
                "All findings MUST include supporting Evidence."
            )
        if self.evidence.confidence < 0.0 or self.evidence.confidence > 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")
        if not self.endpoint:
            self.endpoint = self.evidence.request_url

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "endpoint": self.endpoint,
            "scanner": self.scanner,
            "tags": self.tags,
            "evidence": self.evidence.to_dict(),
        }
