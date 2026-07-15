"""Timing-based blind injection scanner.

Detects blind SQL injection, boolean-based blind injection,
and blind SSRF through response timing analysis and content comparison.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from stryx.utils.evidence import Evidence, Finding, Severity
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("scanner.blind")

# Timing thresholds (seconds)
TIME_DELAY_THRESHOLD = 2.0  # Minimum delay to consider as blind injection
TIME_TOLERANCE = 0.5  # Tolerance for timing comparison

# Boolean blind test pairs: (true_condition, false_condition)
BOOLEAN_TESTS = [
    (" AND 1=1--", " AND 1=2--"),
    (" OR 1=1--", " OR 1=2--"),
    ("' AND '1'='1'--", "' AND '1'='2'--"),
    ("' OR '1'='1'--", "' OR '1'='2'--"),
    (" AND 1=1", " AND 1=2"),
    (" AND 'a'='a'", " AND 'a'='b'"),
]

# Time-based blind tests: payloads that cause measurable delays
TIME_TESTS = [
    # MySQL
    (" AND SLEEP(3)--", "MySQL SLEEP"),
    (" AND BENCHMARK(10000000,SHA1('test'))--", "MySQL BENCHMARK"),
    # PostgreSQL
    ("; SELECT pg_sleep(3)--", "PostgreSQL pg_sleep"),
    # MSSQL
    ("; WAITFOR DELAY '0:0:3'--", "MSSQL WAITFOR DELAY"),
    # Oracle
    (" AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--", "Oracle DBMS_PIPE"),
    # SQLite (no sleep, but we can use a busy loop)
    (
        " AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)x WHERE RANDOMBLOB(500000000))>0--",
        "SQLite busy",
    ),
]

# Blind SSRF test URLs (internal services that may respond differently)
BLIND_SSRF_TESTS = [
    ("http://127.0.0.1:80/", "Localhost HTTP"),
    ("http://169.254.169.254/latest/meta-data/", "AWS Metadata"),
    ("http://metadata.google.internal/", "GCP Metadata"),
]


@dataclass
class BlindTestResult:
    """Result of a blind injection test."""

    vulnerable: bool
    test_type: str
    payload: str
    description: str
    confidence: float
    baseline_time: float = 0.0
    test_time: float = 0.0
    response_diff: str = ""


class BlindScanner:
    """Scanner for timing-based and boolean-based blind injection."""

    def __init__(self, client: HttpClient):
        self.client = client

    async def scan(
        self,
        endpoints: list[str],
        base_url: str,
        max_tests_per_endpoint: int = 20,
    ) -> list[Finding]:
        """Run blind injection tests against all endpoints."""
        findings: list[Finding] = []
        logger.info("Running blind injection scanner")

        for endpoint in endpoints[:10]:  # Limit to 10 endpoints
            try:
                # Boolean-based blind tests
                bool_findings = await self._test_boolean_blind(endpoint)
                findings.extend(bool_findings)

                # Time-based blind tests
                time_findings = await self._test_time_blind(endpoint)
                findings.extend(time_findings)

                # Blind SSRF tests
                ssrf_findings = await self._test_blind_ssrf(endpoint)
                findings.extend(ssrf_findings)

            except Exception as e:
                logger.debug(f"Blind test error on {endpoint}: {e}")

        logger.info(f"Blind scanner found {len(findings)} findings")
        return findings

    async def _test_boolean_blind(self, endpoint: str) -> list[Finding]:
        """Test for boolean-based blind injection."""
        findings: list[Finding] = []

        # Get baseline response
        try:
            baseline_response, _ = await self.client.get(endpoint)
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)
            baseline_body = baseline_response.text
        except Exception:
            return findings

        # Parse URL to find injectable parameters
        params = self._get_injectable_params(endpoint)
        if not params:
            return findings

        for param_name, param_value in params:
            for true_payload, false_payload in BOOLEAN_TESTS[:3]:  # Limit tests
                try:
                    # Send true condition
                    true_url = self._modify_param(endpoint, param_name, param_value + true_payload)
                    true_response, _ = await self.client.get(true_url)

                    # Send false condition
                    false_url = self._modify_param(endpoint, param_name, param_value + false_payload)
                    false_response, _ = await self.client.get(false_url)

                    # Compare responses
                    true_len = len(true_response.text)
                    false_len = len(false_response.text)

                    # Significant difference between true and false responses
                    if (
                        true_response.status_code == baseline_status
                        and true_len != false_len
                        and abs(true_len - false_len) > 10
                        and abs(true_len - baseline_length) < abs(false_len - baseline_length)
                    ):

                        confidence = min(0.9, 0.5 + abs(true_len - false_len) / 1000)
                        findings.append(
                            Finding(
                                title=f"Boolean-based blind injection in parameter '{param_name}'",
                                severity=Severity.HIGH,
                                evidence=Evidence(
                                    request_method="GET",
                                    request_url=true_url,
                                    response_status=true_response.status_code,
                                    response_body=true_response.text[:500],
                                    response_snippet=f"True: {true_len} chars, False: {false_len} chars",
                                    payload=true_payload.strip(),
                                    confidence=confidence,
                                ),
                                description=(
                                    f"Boolean-based blind injection detected in parameter '{param_name}'. "
                                    f"True condition returned {true_len} chars, false returned {false_len} chars."
                                ),
                                remediation="Use parameterized queries and input validation.",
                                cwe="CWE-89",
                                owasp="A03:2021 - Injection",
                                endpoint=endpoint,
                                scanner="blind",
                            )
                        )
                        break  # One finding per parameter

                except Exception:
                    continue

        return findings

    async def _test_time_blind(self, endpoint: str) -> list[Finding]:
        """Test for time-based blind injection."""
        findings: list[Finding] = []

        # Get baseline timing
        try:
            start = time.time()
            baseline_response, _ = await self.client.get(endpoint)
            baseline_time = time.time() - start
        except Exception:
            return findings

        params = self._get_injectable_params(endpoint)
        if not params:
            return findings

        for param_name, param_value in params[:3]:  # Limit params
            for payload, db_name in TIME_TESTS[:4]:  # Limit tests
                try:
                    test_url = self._modify_param(endpoint, param_name, param_value + payload)

                    start = time.time()
                    test_response, _ = await self.client.get(test_url)
                    test_time = time.time() - start

                    # Check if response time is significantly longer
                    delay = test_time - baseline_time
                    if delay >= TIME_DELAY_THRESHOLD:
                        confidence = min(0.95, 0.6 + (delay / 10))
                        findings.append(
                            Finding(
                                title=f"Time-based blind injection ({db_name}) in parameter '{param_name}'",
                                severity=Severity.HIGH,
                                evidence=Evidence(
                                    request_method="GET",
                                    request_url=test_url,
                                    response_status=test_response.status_code,
                                    response_body=test_response.text[:500],
                                    response_snippet=f"Baseline: {baseline_time:.2f}s, Test: {test_time:.2f}s, Delay: {delay:.2f}s",
                                    payload=payload.strip(),
                                    confidence=confidence,
                                ),
                                description=(
                                    f"Time-based blind injection detected in parameter '{param_name}' "
                                    f"using {db_name}. Response delay: {delay:.2f}s (baseline: {baseline_time:.2f}s)."
                                ),
                                remediation="Use parameterized queries and input validation.",
                                cwe="CWE-89",
                                owasp="A03:2021 - Injection",
                                endpoint=endpoint,
                                scanner="blind",
                            )
                        )
                        break  # One finding per parameter

                except asyncio.TimeoutError:
                    # Timeout itself may indicate successful blind injection
                    findings.append(
                        Finding(
                            title=f"Possible time-based blind injection in parameter '{param_name}'",
                            severity=Severity.MEDIUM,
                            evidence=Evidence(
                                request_method="GET",
                                request_url=test_url if "test_url" in dir() else endpoint,
                                response_status=0,
                                response_body="Request timed out",
                                payload=payload.strip(),
                                confidence=0.5,
                            ),
                            description=(
                                f"Request timed out after injection payload in parameter '{param_name}'. "
                                f"This may indicate time-based blind injection causing server hang."
                            ),
                            remediation="Use parameterized queries and input validation.",
                            cwe="CWE-89",
                            owasp="A03:2021 - Injection",
                            endpoint=endpoint,
                            scanner="blind",
                        )
                    )
                    break
                except Exception:
                    continue

        return findings

    async def _test_blind_ssrf(self, endpoint: str) -> list[Finding]:
        """Test for blind SSRF via timing differences."""
        findings: list[Finding] = []

        # Get baseline timing
        try:
            start = time.time()
            baseline_response, _ = await self.client.get(endpoint)
            baseline_time = time.time() - start
        except Exception:
            return findings

        params = self._get_injectable_params(endpoint)
        if not params:
            return findings

        for param_name, param_value in params[:2]:
            for internal_url, service_name in BLIND_SSRF_TESTS:
                try:
                    test_url = self._modify_param(endpoint, param_name, internal_url)

                    start = time.time()
                    test_response, _ = await self.client.get(test_url)
                    test_time = time.time() - start

                    # Check for timing difference (internal service may respond faster or slower)
                    delay = abs(test_time - baseline_time)
                    if delay > TIME_DELAY_THRESHOLD:
                        confidence = min(0.8, 0.4 + (delay / 10))
                        findings.append(
                            Finding(
                                title=f"Possible blind SSRF to {service_name} via parameter '{param_name}'",
                                severity=Severity.HIGH,
                                evidence=Evidence(
                                    request_method="GET",
                                    request_url=test_url,
                                    response_status=test_response.status_code,
                                    response_body=test_response.text[:500],
                                    response_snippet=f"Baseline: {baseline_time:.2f}s, Test: {test_time:.2f}s",
                                    payload=internal_url,
                                    confidence=confidence,
                                ),
                                description=(
                                    f"Possible blind SSRF detected. Request to {service_name} via "
                                    f"parameter '{param_name}' caused a {delay:.2f}s timing difference."
                                ),
                                remediation="Validate and sanitize URLs. Block internal IP ranges.",
                                cwe="CWE-918",
                                owasp="A10:2021 - Server-Side Request Forgery",
                                endpoint=endpoint,
                                scanner="blind",
                            )
                        )
                        break  # One finding per parameter

                except Exception:
                    continue

        return findings

    def _get_injectable_params(self, url: str) -> list[tuple[str, str]]:
        """Extract injectable parameters from a URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return [(k, v[0] if v else "") for k, v in params.items()]

    def _modify_param(self, url: str, param_name: str, new_value: str) -> str:
        """Modify a URL parameter value."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [new_value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
