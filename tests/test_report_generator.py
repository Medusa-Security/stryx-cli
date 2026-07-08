"""Tests for report generation."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from stryx.utils.evidence import Evidence, Finding, Severity
from stryx.attacks.attack_chain import AttackChain
from stryx.reports.json_report import JsonReport
from stryx.reports.markdown_report import MarkdownReport
from stryx.reports.generator import ReportGenerator


def _make_finding(title: str = "Test Finding", severity: Severity = Severity.HIGH) -> Finding:
    """Helper to create test findings."""
    evidence = Evidence(
        request_method="GET",
        request_url="http://example.com/api/test",
        response_status=200,
        response_body="test response body",
        payload="test-payload",
        confidence=0.85,
    )
    return Finding(
        title=title,
        severity=severity,
        evidence=evidence,
        description="Test description",
        remediation="Test remediation",
        cwe="CWE-89",
        owasp="A03:2021",
        scanner="test",
        tags=["test"],
    )


class TestJsonReport:
    """Tests for JSON report generation."""

    def test_json_report_structure(self):
        """Test JSON report has correct structure."""
        finding = _make_finding()
        report = JsonReport("http://example.com", [finding])
        data = report.generate()

        assert "report" in data
        assert "summary" in data
        assert "findings" in data
        assert data["report"]["tool"] == "stryx"
        assert data["summary"]["total_findings"] == 1

    def test_json_report_severity_counts(self):
        """Test severity counting."""
        findings = [
            _make_finding("Critical", Severity.CRITICAL),
            _make_finding("High", Severity.HIGH),
            _make_finding("High2", Severity.HIGH),
            _make_finding("Medium", Severity.MEDIUM),
        ]
        report = JsonReport("http://example.com", findings)
        data = report.generate()

        assert data["summary"]["critical"] == 1
        assert data["summary"]["high"] == 2
        assert data["summary"]["medium"] == 1

    def test_json_report_serialization(self):
        """Test JSON serialization."""
        finding = _make_finding()
        report = JsonReport("http://example.com", [finding])
        json_str = report.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed["summary"]["total_findings"] == 1


class TestMarkdownReport:
    """Tests for Markdown report generation."""

    def test_markdown_report_content(self):
        """Test Markdown report contains expected content."""
        finding = _make_finding()
        report = MarkdownReport("http://example.com", [finding])
        md = report.generate()

        assert "STRYX Security Scan Report" in md
        assert "http://example.com" in md
        assert "Test Finding" in md
        assert "CWE-89" in md

    def test_markdown_empty_findings(self):
        """Test Markdown report with no findings."""
        report = MarkdownReport("http://example.com", [])
        md = report.generate()
        assert "0" in md  # Findings count is 0


class TestReportGenerator:
    """Tests for the ReportGenerator."""

    def test_generator_json_output(self):
        """Test JSON file generation."""
        finding = _make_finding()
        generator = ReportGenerator("http://example.com", [finding])

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            result = generator.generate_json(path)
            assert result == path
            assert Path(path).exists()

            with open(path) as f:
                data = json.load(f)
            assert data["summary"]["total_findings"] == 1
        finally:
            Path(path).unlink(missing_ok=True)

    def test_generator_markdown_output(self):
        """Test Markdown file generation."""
        finding = _make_finding()
        generator = ReportGenerator("http://example.com", [finding])

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = f.name

        try:
            result = generator.generate_markdown(path)
            assert result == path
            assert Path(path).exists()

            content = Path(path).read_text()
            assert "STRYX Security Scan Report" in content
        finally:
            Path(path).unlink(missing_ok=True)
