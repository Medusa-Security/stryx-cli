"""Information disclosure scanner.

Detects server version leaks, debug endpoints, sensitive file exposure,
stack traces, and secrets/credentials in responses.
"""

from __future__ import annotations

import re

from stryx.utils.evidence import Evidence, Finding, Severity
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("scanner.disclosure")

# Sensitive paths to check
SENSITIVE_PATHS = [
    ("/.env", "Environment variables file"),
    ("/.git/HEAD", "Git repository exposure"),
    ("/.git/config", "Git config exposure"),
    ("/robots.txt", "Robots.txt with hidden paths"),
    ("/sitemap.xml", "Sitemap with hidden endpoints"),
    ("/server-info", "Apache server info"),
    ("/server-status", "Apache server status"),
    ("/phpinfo.php", "PHP information disclosure"),
    ("/info.php", "PHP information disclosure"),
    ("/debug", "Debug endpoint exposed"),
    ("/debug/vars", "Debug variables exposed"),
    ("/debug/health", "Debug health endpoint"),
    ("/trace.axd", "ASP.NET trace handler"),
    ("/elmah.axd", "ELMAH error log"),
    ("/actuator", "Spring Boot Actuator"),
    ("/actuator/env", "Spring Boot environment"),
    ("/actuator/health", "Spring Boot health"),
    ("/actuator/configprops", "Spring Boot config properties"),
    ("/swagger-ui.html", "Swagger UI exposed"),
    ("/swagger.json", "Swagger API spec exposed"),
    ("/api-docs", "API documentation exposed"),
    ("/graphql", "GraphQL endpoint exposed"),
    ("/.well-known/security.txt", "Security contact info"),
    ("/crossdomain.xml", "Cross-domain policy"),
    ("/clientaccesspolicy.xml", "Silverlight cross-domain"),
    ("/backup.zip", "Backup file exposed"),
    ("/backup.sql", "Database backup exposed"),
    ("/dump.sql", "Database dump exposed"),
    ("/db.sql", "Database file exposed"),
    ("/config.yml", "Configuration file exposed"),
    ("/config.json", "Configuration file exposed"),
    ("/.htaccess", "Apache config exposed"),
    ("/web.config", "IIS config exposed"),
    ("/wp-config.php.bak", "WordPress config backup"),
    ("/.DS_Store", "macOS directory metadata"),
    ("/Thumbs.db", "Windows thumbnail cache"),
    ("/.svn/entries", "SVN repository exposed"),
    ("/.hg/dirstate", "Mercurial repository exposed"),
]

# Headers that leak information
LEAKED_HEADERS = {
    "Server": "Server version disclosed",
    "X-Powered-By": "Technology stack disclosed",
    "X-AspNet-Version": "ASP.NET version disclosed",
    "X-AspNetMvc-Version": "ASP.NET MVC version disclosed",
    "X-Runtime": "Framework runtime disclosed",
    "X-Generator": "CMS generator disclosed",
    "X-Debug-Token": "Debug token exposed",
    "X-Debug-Token-Link": "Debug token link exposed",
}

# Secret patterns (regex)
SECRET_PATTERNS = [
    (re.compile(r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})'), "API key detected"),
    (re.compile(r'(?i)(?:secret[_-]?key|secretkey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})'), "Secret key detected"),
    (re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})'), "Password detected"),
    (re.compile(r'(?i)(?:aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']?(AKIA[0-9A-Z]{16})'), "AWS access key detected"),
    (
        re.compile(r'(?i)(?:aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})'),
        "AWS secret key detected",
    ),
    (re.compile(r"(?i)(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}"), "GitHub token detected"),
    (re.compile(r"(?i)sk-[a-zA-Z0-9]{20,}"), "OpenAI/Stripe API key detected"),
    (re.compile(r"(?i)sk_live_[a-zA-Z0-9]{20,}"), "Stripe live key detected"),
    (re.compile(r"(?i)sk_test_[a-zA-Z0-9]{20,}"), "Stripe test key detected"),
    (re.compile(r'(?i)(?:jdbc|mysql|postgres|mongodb)://[^\s"\']+'), "Database connection string detected"),
    (re.compile(r"(?i)-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "Private key detected"),
    (re.compile(r'(?i)(?:jwt[_-]?secret)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})'), "JWT secret detected"),
]

# Stack trace indicators
STACK_TRACE_PATTERNS = [
    re.compile(r"(?i)traceback \(most recent call last\)", re.MULTILINE),
    re.compile(r"(?i)at\s+[\w.$]+\([\w.]+:\d+\)", re.MULTILINE),  # Java/.NET stack traces
    re.compile(r'(?i)File "[^"]+", line \d+', re.MULTILINE),  # Python stack traces
    re.compile(r"(?i)Exception in thread", re.MULTILINE),
    re.compile(r"(?i)Uncaught exception", re.MULTILINE),
    re.compile(r"(?i)Stack Trace:", re.MULTILINE),
    re.compile(r"(?i)Internal Server Error.*<pre.*>", re.DOTALL),
]


class DisclosureScanner:
    """Scanner for information disclosure vulnerabilities."""

    def __init__(self, client: HttpClient):
        self.client = client

    async def scan(
        self,
        endpoints: list[str],
        base_url: str,
    ) -> list[Finding]:
        """Run information disclosure tests."""
        findings: list[Finding] = []
        logger.info("Running information disclosure scanner")

        # Test sensitive paths
        path_findings = await self._test_sensitive_paths(base_url)
        findings.extend(path_findings)

        # Test header leaks on main endpoints
        header_findings = await self._test_header_leaks(endpoints[:5])
        findings.extend(header_findings)

        # Test for stack traces via error triggering
        trace_findings = await self._test_error_disclosure(endpoints[:5])
        findings.extend(trace_findings)

        # Test for secrets in responses
        secret_findings = await self._test_secret_disclosure(endpoints[:5])
        findings.extend(secret_findings)

        logger.info(f"Disclosure scanner found {len(findings)} findings")
        return findings

    async def _test_sensitive_paths(self, base_url: str) -> list[Finding]:
        """Test for exposed sensitive files and endpoints."""
        findings: list[Finding] = []

        for path, description in SENSITIVE_PATHS:
            try:
                url = f"{base_url}{path}"
                response, evidence = await self.client.get(url)

                if response.status_code == 200:
                    # Verify it's not a generic 404 page
                    body_lower = response.text.lower()
                    if "not found" in body_lower or "404" in body_lower:
                        continue

                    # Determine severity based on path
                    severity = Severity.MEDIUM
                    if path in (
                        "/.env",
                        "/.git/HEAD",
                        "/.git/config",
                        "/backup.sql",
                        "/dump.sql",
                        "/db.sql",
                        "/web.config",
                        "/wp-config.php.bak",
                    ):
                        severity = Severity.CRITICAL
                    elif path in (
                        "/actuator/env",
                        "/actuator/configprops",
                        "/phpinfo.php",
                        "/info.php",
                        "/trace.axd",
                        "/elmah.axd",
                    ):
                        severity = Severity.HIGH
                    elif path in (
                        "/server-info",
                        "/server-status",
                        "/debug",
                        "/swagger-ui.html",
                        "/swagger.json",
                        "/api-docs",
                    ):
                        severity = Severity.MEDIUM

                    evidence.confidence = 0.9
                    findings.append(
                        Finding(
                            title=f"Sensitive path exposed: {path}",
                            severity=severity,
                            evidence=evidence,
                            description=f"{description}. The path {path} is accessible and returns data.",
                            remediation=f"Restrict access to {path} or remove it from production.",
                            cwe="CWE-200",
                            owasp="A01:2021 - Broken Access Control",
                            endpoint=url,
                            scanner="disclosure",
                            tags=["information-disclosure", "sensitive-path"],
                        )
                    )

            except Exception:
                continue

        return findings

    async def _test_header_leaks(self, endpoints: list[str]) -> list[Finding]:
        """Test for information-leaking HTTP headers."""
        findings: list[Finding] = []
        seen_headers: set[str] = set()

        for endpoint in endpoints:
            try:
                response, _ = await self.client.get(endpoint)

                for header_name, description in LEAKED_HEADERS.items():
                    if header_name in response.headers and header_name not in seen_headers:
                        seen_headers.add(header_name)
                        value = response.headers[header_name]

                        # Determine severity
                        severity = Severity.LOW
                        if header_name in ("X-Debug-Token", "X-Debug-Token-Link"):
                            severity = Severity.HIGH
                        elif header_name in ("Server", "X-Powered-By"):
                            severity = Severity.INFO

                        findings.append(
                            Finding(
                                title=f"Information leak via {header_name} header",
                                severity=severity,
                                evidence=Evidence(
                                    request_method="GET",
                                    request_url=endpoint,
                                    response_status=response.status_code,
                                    response_headers=dict(response.headers),
                                    response_body=f"{header_name}: {value}",
                                    confidence=0.95,
                                ),
                                description=f"{description}: {header_name}: {value}",
                                remediation=f"Remove or obfuscate the {header_name} header.",
                                cwe="CWE-200",
                                owasp="A05:2021 - Security Misconfiguration",
                                endpoint=endpoint,
                                scanner="disclosure",
                                tags=["information-disclosure", "header-leak"],
                            )
                        )

            except Exception:
                continue

        return findings

    async def _test_error_disclosure(self, endpoints: list[str]) -> list[Finding]:
        """Test for stack traces and error disclosure."""
        findings: list[Finding] = []

        # Payloads that may trigger error responses
        error_triggers = [
            "'",
            "NULL",
            "{{7*7}}",
            "${7*7}",
            "<%7*7%>",
            "\\",
            "%00",
            "../../../etc/passwd",
        ]

        for endpoint in endpoints:
            for trigger in error_triggers[:4]:
                try:
                    # Try as query parameter
                    if "?" in endpoint:
                        test_url = f"{endpoint}&q={trigger}"
                    else:
                        test_url = f"{endpoint}?q={trigger}"

                    response, _ = await self.client.get(test_url)

                    # Check for stack traces
                    for pattern in STACK_TRACE_PATTERNS:
                        if pattern.search(response.text):
                            findings.append(
                                Finding(
                                    title="Stack trace / error disclosure",
                                    severity=Severity.MEDIUM,
                                    evidence=Evidence(
                                        request_method="GET",
                                        request_url=test_url,
                                        response_status=response.status_code,
                                        response_body=response.text[:1000],
                                        response_snippet=response.text[:500],
                                        payload=trigger,
                                        confidence=0.85,
                                    ),
                                    description=(
                                        "The application returns stack traces or detailed error messages "
                                        "when triggered with malicious input. "
                                        "This leaks internal implementation details."
                                    ),
                                    remediation=(
                                        "Implement custom error pages. Disable debug mode in production. "
                                        "Use structured logging instead of exposing errors to users."
                                    ),
                                    cwe="CWE-209",
                                    owasp="A05:2021 - Security Misconfiguration",
                                    endpoint=endpoint,
                                    scanner="disclosure",
                                    tags=["information-disclosure", "stack-trace"],
                                )
                            )
                            break  # One finding per endpoint

                except Exception:
                    continue

        return findings

    async def _test_secret_disclosure(self, endpoints: list[str]) -> list[Finding]:
        """Scan responses for leaked secrets and credentials."""
        findings: list[Finding] = []
        seen_secrets: set[str] = set()

        for endpoint in endpoints:
            try:
                response, _ = await self.client.get(endpoint)

                for pattern, description in SECRET_PATTERNS:
                    matches = pattern.findall(response.text)
                    for match in matches:
                        # Deduplicate
                        secret_key = f"{description}:{match[:20]}"
                        if secret_key in seen_secrets:
                            continue
                        seen_secrets.add(secret_key)

                        # Mask the secret in evidence
                        masked = match[:4] + "*" * (len(match) - 8) + match[-4:] if len(match) > 8 else "****"

                        findings.append(
                            Finding(
                                title=f"Secret/credential exposed: {description}",
                                severity=Severity.HIGH,
                                evidence=Evidence(
                                    request_method="GET",
                                    request_url=endpoint,
                                    response_status=response.status_code,
                                    response_body=response.text[:500],
                                    response_snippet=f"Pattern matched: {masked}",
                                    confidence=0.8,
                                ),
                                description=(
                                    f"{description} found in HTTP response. " f"The value appears to be: {masked}"
                                ),
                                remediation=(
                                    "Remove secrets from code and responses. "
                                    "Use environment variables or secret management services. "
                                    "Rotate the exposed credentials immediately."
                                ),
                                cwe="CWE-798",
                                owasp="A07:2021 - Identification and Authentication Failures",
                                endpoint=endpoint,
                                scanner="disclosure",
                                tags=["information-disclosure", "secret-leak"],
                            )
                        )

            except Exception:
                continue

        return findings
