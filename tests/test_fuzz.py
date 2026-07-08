"""Tests for the fuzzer module."""

from __future__ import annotations

import pytest

from stryx.scanners.fuzz import FUZZ_PAYLOADS, _guess_param_type


class TestFuzzPayloads:
    """Tests for fuzz payload sets."""

    def test_integer_payloads(self):
        """Test integer fuzz payloads exist."""
        assert len(FUZZ_PAYLOADS["integer"]) > 5
        assert "0" in FUZZ_PAYLOADS["integer"]
        assert "-1" in FUZZ_PAYLOADS["integer"]

    def test_string_payloads(self):
        """Test string fuzz payloads exist."""
        assert len(FUZZ_PAYLOADS["string"]) > 5
        assert "" in FUZZ_PAYLOADS["string"]

    def test_boundary_payloads(self):
        """Test boundary fuzz payloads exist."""
        assert len(FUZZ_PAYLOADS["boundary"]) > 5

    def test_encoding_payloads(self):
        """Test encoding fuzz payloads exist."""
        assert len(FUZZ_PAYLOADS["encoding"]) > 5
        assert "%00" in FUZZ_PAYLOADS["encoding"]

    def test_nested_json_payloads(self):
        """Test nested JSON fuzz payloads exist."""
        assert len(FUZZ_PAYLOADS["nested_json"]) > 0


class TestParamTypeGuessing:
    """Tests for parameter type guessing."""

    def test_integer_param(self):
        """Test integer parameter detection."""
        types = _guess_param_type("42")
        assert "integer" in types
        assert "boundary" in types

    def test_string_param(self):
        """Test string parameter detection."""
        types = _guess_param_type("hello")
        assert "string" in types
        assert "integer" not in types

    def test_empty_param(self):
        """Test empty parameter detection."""
        types = _guess_param_type("")
        assert "string" in types

    def test_negative_integer(self):
        """Test negative integer detection."""
        types = _guess_param_type("-5")
        assert "integer" in types
