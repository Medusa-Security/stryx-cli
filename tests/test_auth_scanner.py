"""Tests for the authentication scanner."""

from __future__ import annotations

import pytest

from stryx.utils.evidence import Evidence, Finding, Severity


class TestEvidence:
    """Tests for the Evidence dataclass."""

    def test_evidence_creation(self):
        """Test creating Evidence."""
        evidence = Evidence(
            request_method="GET",
            request_url="http://example.com/api/test",
            response_status=200,
            response_body="test response",
        )
        assert evidence.request_method == "GET"
        assert evidence.response_status == 200
        assert evidence.confidence == 0.0

    def test_evidence_requires_method_and_url(self):
        """Test that Evidence requires method and URL."""
        with pytest.raises(ValueError):
            Evidence(request_method="", request_url="http://example.com")
        with pytest.raises(ValueError):
            Evidence(request_method="GET", request_url="")

    def test_evidence_auto_snippet(self):
        """Test auto-generation of response snippet."""
        evidence = Evidence(
            request_method="GET",
            request_url="http://example.com",
            response_body="This is a long response body" * 100,
        )
        assert len(evidence.response_snippet) > 0
        assert len(evidence.response_snippet) <= 500

    def test_evidence_serialization(self):
        """Test Evidence serialization."""
        evidence = Evidence(
            request_method="POST",
            request_url="http://example.com/api",
            response_status=201,
            payload="test",
            confidence=0.8,
        )
        data = evidence.to_dict()
        assert data["request_method"] == "POST"
        assert data["response_status"] == 201
        assert data["payload"] == "test"
        assert data["confidence"] == 0.8


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_finding_creation(self):
        """Test creating a Finding."""
        evidence = Evidence(
            request_method="GET",
            request_url="http://example.com",
            response_status=200,
        )
        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            evidence=evidence,
        )
        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH
        assert finding.endpoint == "http://example.com"

    def test_finding_requires_evidence(self):
        """Test that Finding requires evidence."""
        with pytest.raises(ValueError):
            Finding(
                title="No Evidence",
                severity=Severity.HIGH,
                evidence=None,
            )

    def test_finding_confidence_validation(self):
        """Test confidence range validation."""
        evidence = Evidence(
            request_method="GET",
            request_url="http://example.com",
            response_status=200,
            confidence=1.5,
        )
        with pytest.raises(ValueError):
            Finding(
                title="Bad Confidence",
                severity=Severity.HIGH,
                evidence=evidence,
            )

    def test_finding_serialization(self):
        """Test Finding serialization."""
        evidence = Evidence(
            request_method="GET",
            request_url="http://example.com",
            response_status=200,
            confidence=0.9,
        )
        finding = Finding(
            title="SQL Injection",
            severity=Severity.CRITICAL,
            evidence=evidence,
            cwe="CWE-89",
            scanner="injection",
            tags=["sqli", "injection"],
        )
        data = finding.to_dict()
        assert data["title"] == "SQL Injection"
        assert data["severity"] == "critical"
        assert data["cwe"] == "CWE-89"
        assert "sqli" in data["tags"]
