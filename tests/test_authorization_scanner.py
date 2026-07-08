"""Tests for the authorization scanner."""

from __future__ import annotations

import pytest

from stryx.utils.evidence import Evidence, Finding, Severity
from stryx.attacks.attack_chain import AttackChain, ChainBuilder


class TestAttackChain:
    """Tests for attack chain building."""

    def test_chain_creation(self):
        """Test creating an attack chain."""
        chain = AttackChain(name="Test Chain")
        assert chain.name == "Test Chain"
        assert chain.steps == []

    def test_chain_add_step(self):
        """Test adding steps to a chain."""
        evidence = Evidence(
            request_method="GET",
            request_url="http://example.com/admin",
            response_status=200,
        )
        finding = Finding(
            title="Admin Access",
            severity=Severity.CRITICAL,
            evidence=evidence,
        )

        chain = AttackChain(name="Test Chain")
        chain.add_step(finding, "Access admin panel", "Full admin access")

        assert len(chain.steps) == 1
        assert chain.steps[0].finding.title == "Admin Access"
        assert chain.steps[0].impact == "Full admin access"

    def test_chain_serialization(self):
        """Test chain serialization."""
        evidence = Evidence(
            request_method="GET",
            request_url="http://example.com",
            response_status=200,
        )
        finding = Finding(
            title="Test",
            severity=Severity.HIGH,
            evidence=evidence,
        )
        chain = AttackChain(
            name="Chain 1",
            total_impact="Data leak",
            estimated_severity="high",
        )
        chain.add_step(finding)

        data = chain.to_dict()
        assert data["name"] == "Chain 1"
        assert len(data["steps"]) == 1


class TestChainBuilder:
    """Tests for the ChainBuilder."""

    def _make_finding(self, title: str, tags: list[str], severity: Severity = Severity.HIGH):
        """Helper to create test findings."""
        evidence = Evidence(
            request_method="GET",
            request_url="http://example.com/test",
            response_status=200,
        )
        return Finding(
            title=title,
            severity=severity,
            evidence=evidence,
            tags=tags,
        )

    def test_auth_access_chain(self):
        """Test building auth + access control chain."""
        auth_finding = self._make_finding("Missing Auth", ["auth"])
        access_finding = self._make_finding("IDOR", ["idor", "broken-access-control"])

        builder = ChainBuilder([auth_finding, access_finding])
        chains = builder.build_chains()

        assert len(chains) >= 1
        assert chains[0].name == "Authentication Bypass to Data Exfiltration"
        assert len(chains[0].steps) == 2

    def test_injection_chain(self):
        """Test building injection chain."""
        injection = self._make_finding("SQL Injection", ["injection", "sqli"])

        builder = ChainBuilder([injection])
        chains = builder.build_chains()

        assert len(chains) >= 1
        assert "Injection" in chains[0].name
