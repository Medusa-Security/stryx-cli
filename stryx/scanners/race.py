"""Race condition scanner.

Tests for TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities
by sending concurrent requests and detecting inconsistent state changes.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any

from stryx.utils.evidence import Evidence, Finding, Severity
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("scanner.race")

# Number of concurrent requests per race test
RACE_CONCURRENCY = 15


@dataclass
class RaceTestConfig:
    """Configuration for a race condition test."""

    name: str
    url: str
    method: str = "POST"
    body: dict[str, Any] | None = None
    headers: dict[str, str] | None = None
    expected_count: int = 1  # Expected number of successful operations
    description: str = ""


class RaceScanner:
    """Scanner for race condition (TOCTOU) vulnerabilities."""

    def __init__(self, client: HttpClient):
        self.client = client

    async def scan(
        self,
        endpoints: list[str],
        base_url: str,
    ) -> list[Finding]:
        """Run race condition tests against endpoints."""
        findings: list[Finding] = []
        logger.info("Running race condition scanner")

        # Detect potential race condition endpoints
        race_configs = self._build_race_tests(endpoints, base_url)

        for config in race_configs:
            try:
                finding = await self._test_race_condition(config)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.debug(f"Race test error ({config.name}): {e}")

        logger.info(f"Race condition scanner found {len(findings)} findings")
        return findings

    def _build_race_tests(
        self, endpoints: list[str], base_url: str
    ) -> list[RaceTestConfig]:
        """Build race condition test configurations based on discovered endpoints."""
        configs: list[RaceTestConfig] = []

        for endpoint in endpoints:
            ep_lower = endpoint.lower()

            # Balance/transfer endpoints
            if any(kw in ep_lower for kw in ["transfer", "balance", "payment", "checkout", "purchase"]):
                configs.append(RaceTestConfig(
                    name="double-spend",
                    url=endpoint,
                    method="POST",
                    body={"amount": 100, "currency": "USD"},
                    expected_count=1,
                    description="Double-spend via race condition on payment endpoint",
                ))

            # Coupon/discount endpoints
            if any(kw in ep_lower for kw in ["coupon", "discount", "promo", "redeem"]):
                configs.append(RaceTestConfig(
                    name="coupon-reuse",
                    url=endpoint,
                    method="POST",
                    body={"code": "TESTCOUPON"},
                    expected_count=1,
                    description="Coupon reuse via race condition",
                ))

            # Vote/like endpoints
            if any(kw in ep_lower for kw in ["vote", "like", "upvote", "reaction"]):
                configs.append(RaceTestConfig(
                    name="vote-manipulation",
                    url=endpoint,
                    method="POST",
                    body={"id": "1"},
                    expected_count=1,
                    description="Vote manipulation via race condition",
                ))

            # Registration endpoints
            if any(kw in ep_lower for kw in ["register", "signup", "create"]):
                configs.append(RaceTestConfig(
                    name="duplicate-registration",
                    url=endpoint,
                    method="POST",
                    body={"email": "race-test@example.com", "username": "race-test-user"},
                    expected_count=1,
                    description="Duplicate registration via race condition",
                ))

            # Generic POST endpoints (test for idempotency issues)
            if any(kw in ep_lower for kw in ["api", "action", "submit", "process"]):
                configs.append(RaceTestConfig(
                    name="generic-race",
                    url=endpoint,
                    method="POST",
                    body={"test": "race-condition"},
                    expected_count=1,
                    description="Generic race condition test",
                ))

        # Add common race condition paths
        common_paths = [
            "/api/transfer", "/api/payment", "/api/checkout",
            "/api/coupon/redeem", "/api/vote", "/api/like",
        ]
        for path in common_paths:
            url = f"{base_url}{path}"
            if not any(c.url == url for c in configs):
                configs.append(RaceTestConfig(
                    name=f"common-{path.split('/')[-1]}",
                    url=url,
                    method="POST",
                    body={"test": "race"},
                    expected_count=1,
                    description=f"Race condition test on {path}",
                ))

        return configs[:10]  # Limit total tests

    async def _test_race_condition(self, config: RaceTestConfig) -> Finding | None:
        """Test a specific race condition scenario."""
        logger.info(f"Testing race condition: {config.name}")

        # Send concurrent requests
        tasks = []
        for i in range(RACE_CONCURRENCY):
            tasks.append(self._send_request(config, i))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze results
        successful = []
        failed = []
        responses: list[str] = []

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                failed.append(i)
                responses.append(f"Request {i}: ERROR - {result}")
            elif result is not None:
                status, body = result
                responses.append(f"Request {i}: {status}")
                if status in (200, 201, 202):
                    successful.append(i)
            else:
                failed.append(i)
                responses.append(f"Request {i}: None")

        # Check for race condition indicators
        if len(successful) > config.expected_count:
            # More requests succeeded than expected — possible race condition
            confidence = min(0.85, 0.4 + (len(successful) - config.expected_count) * 0.1)

            return Finding(
                title=f"Race condition: {config.name} ({len(successful)}/{RACE_CONCURRENCY} succeeded)",
                severity=Severity.HIGH,
                evidence=Evidence(
                    request_method=config.method,
                    request_url=config.url,
                    response_status=200,
                    response_body=json.dumps(config.body or {}),
                    response_snippet="\n".join(responses[:20]),
                    payload=json.dumps(config.body or {}),
                    confidence=confidence,
                ),
                description=(
                    f"{config.description}. "
                    f"Out of {RACE_CONCURRENCY} concurrent requests, "
                    f"{len(successful)} succeeded (expected: {config.expected_count}). "
                    f"This indicates a race condition vulnerability."
                ),
                remediation=(
                    "Implement proper locking mechanisms (database transactions, "
                    "distributed locks, idempotency keys) to prevent concurrent "
                    "operations from corrupting state."
                ),
                cwe="CWE-362",
                owasp="A04:2021 - Insecure Design",
                endpoint=config.url,
                scanner="race",
                tags=["race-condition", "toctou", "concurrency"],
            )

        # Check for inconsistent responses (some succeed, some fail)
        if successful and failed and len(successful) < RACE_CONCURRENCY:
            # Partial success may indicate timing-dependent behavior
            return Finding(
                title=f"Possible race condition: {config.name}",
                severity=Severity.MEDIUM,
                evidence=Evidence(
                    request_method=config.method,
                    request_url=config.url,
                    response_status=200,
                    response_body=json.dumps(config.body or {}),
                    response_snippet="\n".join(responses[:20]),
                    payload=json.dumps(config.body or {}),
                    confidence=0.5,
                ),
                description=(
                    f"{config.description}. "
                    f"{len(successful)}/{RACE_CONCURRENCY} requests succeeded, "
                    f"indicating timing-dependent behavior that may be exploitable."
                ),
                remediation="Review endpoint for race conditions. Add proper locking.",
                cwe="CWE-362",
                owasp="A04:2021 - Insecure Design",
                endpoint=config.url,
                scanner="race",
                tags=["race-condition", "timing"],
            )

        return None

    async def _send_request(
        self, config: RaceTestConfig, index: int
    ) -> tuple[int, str] | None:
        """Send a single request for the race test."""
        try:
            body = json.dumps(config.body) if config.body else None
            response, _ = await self.client.request(
                method=config.method,
                url=config.url,
                headers=config.headers,
                body=body,
            )
            return (response.status_code, response.text[:200])
        except Exception:
            return None
