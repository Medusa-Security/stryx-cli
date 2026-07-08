"""Tests for the crawler/discovery module."""

from __future__ import annotations

import pytest

from stryx.crawler.discovery import Endpoint, DiscoveryAggregator


class TestEndpoint:
    """Tests for the Endpoint dataclass."""

    def test_endpoint_creation(self):
        """Test creating an Endpoint."""
        ep = Endpoint(path="http://example.com/api/users", method="GET")
        assert ep.path == "http://example.com/api/users"
        assert ep.method == "GET"
        assert ep.source == "unknown"
        assert ep.confidence == 1.0

    def test_endpoint_hash(self):
        """Test endpoint hashing for deduplication."""
        ep1 = Endpoint(path="http://example.com/api/users", method="GET")
        ep2 = Endpoint(path="http://example.com/API/USERS", method="get")
        # Should be equal (case-insensitive)
        assert hash(ep1) == hash(ep2)

    def test_endpoint_equality(self):
        """Test endpoint equality."""
        ep1 = Endpoint(path="http://example.com/api/users", method="GET")
        ep2 = Endpoint(path="http://example.com/api/users", method="GET")
        ep3 = Endpoint(path="http://example.com/api/orders", method="GET")
        assert ep1 == ep2
        assert ep1 != ep3

    def test_endpoint_with_params(self):
        """Test endpoint with parameters."""
        ep = Endpoint(
            path="http://example.com/api/search",
            method="GET",
            params=["q", "page"],
            source="openapi",
        )
        assert len(ep.params) == 2
        assert "q" in ep.params


class TestDiscoveryAggregator:
    """Tests for the DiscoveryAggregator."""

    def test_init(self):
        """Test aggregator initialization."""
        agg = DiscoveryAggregator("http://example.com", depth=3)
        assert agg.target_url == "http://example.com"
        assert agg.depth == 3
        assert agg.endpoints == []

    def test_trailing_slash_stripped(self):
        """Test trailing slash is stripped from target URL."""
        agg = DiscoveryAggregator("http://example.com/")
        assert agg.target_url == "http://example.com"
