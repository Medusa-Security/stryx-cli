"""Tests for the injection scanner."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from stryx.scanners.injection import (
    _load_payloads,
    _load_framework_signatures,
    DETECTION_PATTERNS,
    InjectionScanner,
)


class TestPayloadLoading:
    """Tests for payload loading."""

    def test_load_sqli_payloads(self):
        """Test loading SQL injection payloads."""
        payloads = _load_payloads("sqli")
        assert len(payloads) > 10
        assert any("UNION" in p for p in payloads)

    def test_load_nosqli_payloads(self):
        """Test loading NoSQL injection payloads."""
        payloads = _load_payloads("nosqli")
        assert len(payloads) > 10

    def test_load_cmdi_payloads(self):
        """Test loading command injection payloads."""
        payloads = _load_payloads("cmdi")
        assert len(payloads) > 10

    def test_load_path_traversal_payloads(self):
        """Test loading path traversal payloads."""
        payloads = _load_payloads("path_traversal")
        assert len(payloads) > 10

    def test_load_nonexistent_payloads(self):
        """Test loading nonexistent payload file."""
        payloads = _load_payloads("nonexistent")
        assert payloads == []


class TestFrameworkSignatures:
    """Tests for framework signature loading."""

    def test_load_signatures(self):
        """Test loading framework signatures."""
        sigs = _load_framework_signatures()
        assert "frameworks" in sigs
        assert "python_flask" in sigs["frameworks"]
        assert "node_express" in sigs["frameworks"]

    def test_flask_fingerprint(self):
        """Test Flask framework detection."""
        sigs = _load_framework_signatures()
        flask = sigs["frameworks"]["python_flask"]
        assert "headers" in flask
        assert "cookies" in flask


class TestDetectionPatterns:
    """Tests for detection patterns."""

    def test_sqli_patterns(self):
        """Test SQL injection detection patterns."""
        patterns = DETECTION_PATTERNS["sqli"]
        assert len(patterns) > 5
        # Test a pattern matches
        assert any(
            re.search(p, "You have an error in your SQL syntax", re.IGNORECASE)
            for p in patterns
        )

    def test_cmdi_patterns(self):
        """Test command injection detection patterns."""
        patterns = DETECTION_PATTERNS["cmdi"]
        assert len(patterns) > 3
        assert any(
            re.search(p, "uid=0(root)", re.IGNORECASE)
            for p in patterns
        )
