"""GraphQL security scanner."""

from __future__ import annotations

import json

from stryx.utils.evidence import Finding, Severity
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("scanner.graphql")


class GraphQLScanner:
    """Scanner for GraphQL-specific security issues."""

    def __init__(self, client: HttpClient):
        self.client = client

    async def scan(self, graphql_endpoints: list[str]) -> list[Finding]:
        """Run GraphQL security tests."""
        findings: list[Finding] = []
        logger.info("Running GraphQL scanner")

        for endpoint in graphql_endpoints:
            try:
                # Test introspection
                introspection_findings = await self._test_introspection(endpoint)
                findings.extend(introspection_findings)

                # Test query depth
                depth_findings = await self._test_query_depth(endpoint)
                findings.extend(depth_findings)

                # Test batch queries
                batch_findings = await self._test_batch_queries(endpoint)
                findings.extend(batch_findings)

                # Test field suggestion
                suggestion_findings = await self._test_field_suggestion(endpoint)
                findings.extend(suggestion_findings)

                # Test error-based info disclosure
                error_findings = await self._test_error_disclosure(endpoint)
                findings.extend(error_findings)

            except Exception as e:
                logger.debug(f"GraphQL scan error on {endpoint}: {e}")

        logger.info(f"GraphQL scanner found {len(findings)} findings")
        return findings

    async def _test_introspection(self, endpoint: str) -> list[Finding]:
        """Test if GraphQL introspection is enabled."""
        findings: list[Finding] = []

        introspection_query = json.dumps({
            "query": "{ __schema { queryType { name } types { name } } }"
        })

        response, evidence = await self.client.post(
            endpoint,
            body=introspection_query,
            headers={"Content-Type": "application/json"},
        )

        if response.status_code == 200:
            try:
                data = response.json()
                if "data" in data and data["data"] and "__schema" in str(data["data"]):
                    evidence.confidence = 0.9
                    findings.append(Finding(
                        title="GraphQL introspection enabled",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        description=(
                            "GraphQL introspection is enabled, allowing attackers "
                            "to discover the entire API schema."
                        ),
                        remediation="Disable introspection in production environments.",
                        cwe="CWE-200",
                        owasp="A01:2021 - Broken Access Control",
                        scanner="graphql",
                        tags=["graphql", "introspection"],
                    ))
            except (json.JSONDecodeError, ValueError):
                pass

        return findings

    async def _test_query_depth(self, endpoint: str) -> list[Finding]:
        """Test for excessive query depth (DoS potential)."""
        findings: list[Finding] = []

        # Deeply nested query
        deep_query = json.dumps({
            "query": """
            {
                __schema {
                    types {
                        fields {
                            type {
                                fields {
                                    type {
                                        fields {
                                            name
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
        })

        try:
            response, evidence = await self.client.post(
                endpoint,
                body=deep_query,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    if "data" in data:
                        evidence.confidence = 0.7
                        findings.append(Finding(
                            title="GraphQL: no query depth limiting",
                            severity=Severity.LOW,
                            evidence=evidence,
                            description=(
                                "The GraphQL endpoint accepted a deeply nested query "
                                "without error, suggesting no depth limiting."
                            ),
                            remediation="Implement query depth limiting and complexity analysis.",
                            cwe="CWE-400",
                            owasp="A05:2021 - Security Misconfiguration",
                            scanner="graphql",
                            tags=["graphql", "dos"],
                        ))
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            pass

        return findings

    async def _test_batch_queries(self, endpoint: str) -> list[Finding]:
        """Test if query batching is allowed (potential DoS)."""
        findings: list[Finding] = []

        # Batch of queries
        batch_query = json.dumps([
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ])

        try:
            response, evidence = await self.client.post(
                endpoint,
                body=batch_query,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    # Check if batch response was accepted
                    if isinstance(data, list) and len(data) == 5:
                        evidence.confidence = 0.7
                        findings.append(Finding(
                            title="GraphQL: query batching allowed",
                            severity=Severity.MEDIUM,
                            evidence=evidence,
                            description=(
                                "The GraphQL endpoint accepts batch queries, "
                                "which can be abused for denial-of-service attacks."
                            ),
                            remediation=(
                                "Limit query batching or disable it entirely. "
                                "Implement rate limiting for batch operations."
                            ),
                            cwe="CWE-400",
                            owasp="A05:2021 - Security Misconfiguration",
                            scanner="graphql",
                            tags=["graphql", "batching", "dos"],
                        ))
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            pass

        return findings

    async def _test_field_suggestion(self, endpoint: str) -> list[Finding]:
        """Test if GraphQL suggests field names (info disclosure)."""
        findings: list[Finding] = []

        # Query with non-existent fields
        suggestion_query = json.dumps({
            "query": "{ user { nonExistentField12345 } }"
        })

        try:
            response, evidence = await self.client.post(
                endpoint,
                body=suggestion_query,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    errors = data.get("errors", [])
                    for error in errors:
                        message = error.get("message", "").lower()
                        # Check for field suggestion patterns
                        if any(suggestion in message for suggestion in [
                            "did you mean",
                            "suggestion",
                            "perhaps you meant",
                            "field suggestions",
                        ]):
                            evidence.confidence = 0.8
                            findings.append(Finding(
                                title="GraphQL: field suggestion enabled",
                                severity=Severity.LOW,
                                evidence=evidence,
                                description=(
                                    "GraphQL suggests field names for invalid queries, "
                                    "helping attackers enumerate the schema."
                                ),
                                remediation="Disable field suggestions in production.",
                                cwe="CWE-200",
                                owasp="A05:2021 - Security Misconfiguration",
                                scanner="graphql",
                                tags=["graphql", "info-disclosure", "suggestion"],
                            ))
                            break
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            pass

        return findings

    async def _test_error_disclosure(self, endpoint: str) -> list[Finding]:
        """Test if GraphQL errors disclose internal information."""
        findings: list[Finding] = []

        # Malformed query to trigger detailed errors
        malformed_query = json.dumps({
            "query": "{ { invalid syntax } }"
        })

        try:
            response, evidence = await self.client.post(
                endpoint,
                body=malformed_query,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    errors = data.get("errors", [])
                    for error in errors:
                        # Check for internal info disclosure
                        error_str = json.dumps(error).lower()
                        disclosure_patterns = [
                            "stack trace",
                            "traceback",
                            "file",
                            "line",
                            "internal",
                            "debug",
                            "development",
                            "verbose",
                            "exception",
                        ]
                        if any(pattern in error_str for pattern in disclosure_patterns):
                            evidence.confidence = 0.7
                            findings.append(Finding(
                                title="GraphQL: verbose error messages",
                                severity=Severity.LOW,
                                evidence=evidence,
                                description=(
                                    "GraphQL returns detailed error messages that "
                                    "may disclose internal implementation details."
                                ),
                                remediation="Use generic error messages in production.",
                                cwe="CWE-209",
                                owasp="A05:2021 - Security Misconfiguration",
                                scanner="graphql",
                                tags=["graphql", "info-disclosure", "errors"],
                            ))
                            break
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            pass

        return findings
