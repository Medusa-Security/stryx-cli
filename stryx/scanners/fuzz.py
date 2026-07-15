"""API fuzzer module.

Mutates parameters, headers, cookies, JSON bodies, and query strings
to test for type confusion, boundary values, integer overflow, missing
validation, invalid encodings, deeply nested JSON, and large payloads.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from stryx.utils.evidence import Evidence, Finding, Severity
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("scanner.fuzz")

# Fuzz payloads for different mutation types
FUZZ_PAYLOADS = {
    "integer": [
        "0",
        "-1",
        "1",
        "999999999999",
        "2147483647",
        "2147483648",
        "-2147483648",
        "-2147483649",
        "0x7FFFFFFF",
        "0x80000000",
        "99999999999999999999",
        "1.5",
        "NaN",
        "Infinity",
    ],
    "string": [
        "",
        "a",
        "a" * 1000,
        "a" * 10000,
        "'",
        '"',
        "\\",
        "\\'",
        '\\"',
        "<script>alert(1)</script>",
        "{{7*7}}",
        "${7*7}",
        "%00",
        "%0a",
        "%0d%0a",
        "true",
        "false",
        "null",
        "undefined",
        "[]",
        "{}",
        "[[]]",
    ],
    "boundary": [
        "0",
        "-0",
        "+0",
        "0.0",
        "-0.0",
        "1.7976931348623157E+308",
        "4.9E-324",
        "1e999",
        "-1e999",
        "99999999999999999999999999",
    ],
    "encoding": [
        "%00",
        "%0a",
        "%0d",
        "%0d%0a",
        "%ef%bb%bf",
        "%c0%80",
        "%e0%80%80",
        "\\u0000",
        "\\n",
        "\\r",
        "\x00",
        "\n",
        "\r\n",
    ],
    "nested_json": [
        json.dumps({"a": {"b": {"c": {"d": {"e": "f"}}}}}),
        json.dumps({"a": [1, [2, [3, [4]]]]}),
        json.dumps({"__proto__": {"admin": True}}),
        json.dumps({"constructor": {"prototype": {"admin": True}}}),
    ],
}


class FuzzScanner:
    """Scanner for API fuzzing and input validation."""

    def __init__(self, client: HttpClient):
        self.client = client

    async def scan(
        self,
        endpoints: list[str],
        base_url: str,
        tests: list[str] | None = None,
    ) -> list[Finding]:
        """Run fuzzing tests against endpoints.

        Args:
            endpoints: List of endpoint URLs to test.
            base_url: Base URL of the target.
            tests: List of test types to run (None = all).
                   Valid: parameters, body, headers, cookies, multipart.
        """
        findings: list[Finding] = []
        logger.info("Running fuzz scanner")

        all_tests = ["parameters", "body", "headers", "cookies", "multipart"]
        active_tests = tests or all_tests

        for endpoint in endpoints:
            try:
                if "parameters" in active_tests:
                    param_findings = await self._fuzz_parameters(endpoint)
                    findings.extend(param_findings)

                if "body" in active_tests:
                    body_findings = await self._fuzz_body(endpoint)
                    findings.extend(body_findings)

                if "headers" in active_tests:
                    header_findings = await self._fuzz_headers(endpoint)
                    findings.extend(header_findings)

                if "cookies" in active_tests:
                    cookie_findings = await self._fuzz_cookies(endpoint)
                    findings.extend(cookie_findings)

                if "multipart" in active_tests:
                    multipart_findings = await self._fuzz_multipart(endpoint)
                    findings.extend(multipart_findings)

            except Exception as e:
                logger.debug(f"Fuzz error on {endpoint}: {e}")

        logger.info(f"Fuzz scanner found {len(findings)} findings")
        return findings

    async def _fuzz_parameters(self, endpoint: str) -> list[Finding]:
        """Fuzz query parameters of an endpoint."""
        findings: list[Finding] = []
        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        for param_name, param_values in params.items():
            original_value = param_values[0] if param_values else ""

            # Determine fuzz category based on original value
            categories = _guess_param_type(original_value)

            for category in categories:
                for payload in FUZZ_PAYLOADS.get(category, [])[:8]:
                    try:
                        test_params = dict(params)
                        test_params[param_name] = [payload]
                        test_url = (
                            f"{parsed.scheme}://{parsed.netloc}{parsed.path}" f"?{urlencode(test_params, doseq=True)}"
                        )

                        response, evidence = await self.client.get(test_url)

                        # Check for error-based indicators
                        if self._detect_fuzz_issue(response, payload, evidence):
                            evidence.confidence = 0.6
                            evidence.payload = payload
                            findings.append(
                                Finding(
                                    title=f"Fuzzing issue in parameter '{param_name}' ({category})",
                                    severity=Severity.MEDIUM,
                                    evidence=evidence,
                                    description=(
                                        f"Fuzzing parameter '{param_name}' with {category} "
                                        f"payload caused an unexpected response."
                                    ),
                                    remediation="Validate and sanitize all input parameters.",
                                    cwe="CWE-20",
                                    owasp="A03:2021 - Injection",
                                    scanner="fuzz",
                                    tags=["fuzzing", "input-validation"],
                                )
                            )
                            break  # One finding per category per param
                    except Exception:
                        continue

        return findings

    async def _fuzz_body(self, endpoint: str) -> list[Finding]:
        """Fuzz the request body."""
        findings: list[Finding] = []

        # Try nested JSON
        for payload in FUZZ_PAYLOADS["nested_json"][:3]:
            try:
                response, evidence = await self.client.post(
                    endpoint,
                    body=payload,
                    headers={"Content-Type": "application/json"},
                )
                if self._detect_fuzz_issue(response, payload, evidence):
                    evidence.confidence = 0.5
                    evidence.payload = payload
                    findings.append(
                        Finding(
                            title="Potential prototype pollution or nested JSON issue",
                            severity=Severity.MEDIUM,
                            evidence=evidence,
                            description=(
                                "Deeply nested or prototype-polluting JSON payload caused an " "unexpected response."
                            ),
                            remediation="Validate JSON structure depth and reject prototype-polluting keys.",
                            cwe="CWE-1321",
                            owasp="A03:2021 - Injection",
                            scanner="fuzz",
                            tags=["fuzzing", "prototype-pollution"],
                        )
                    )
                    break
            except Exception:
                continue

        return findings

    def _detect_fuzz_issue(self, response: Any, payload: str, evidence: Evidence) -> bool:
        """Detect if a fuzzing payload caused an issue."""
        status = response.status_code
        body = response.text.lower() if hasattr(response, "text") else ""

        # Error indicators
        error_patterns = [
            "traceback",
            "exception",
            "error",
            "internal server error",
            "500",
            "stack trace",
            "debug",
            "unhandled",
            "panic",
        ]

        if status >= 500:
            return True

        return any(p in body for p in error_patterns)

    async def _fuzz_headers(self, endpoint: str) -> list[Finding]:
        """Fuzz HTTP headers for injection and bypass."""
        findings: list[Finding] = []

        # Headers to fuzz
        fuzz_headers = [
            "User-Agent",
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Custom-IP-Authorization",
            "X-Forwarded-Host",
            "X-Host",
            "X-Remote-Addr",
            "Content-Type",
            "Accept",
            "Authorization",
        ]

        # Payloads for header fuzzing
        header_payloads = [
            "<script>alert(1)</script>",
            "{{7*7}}",
            "' OR '1'='1",
            "../../etc/passwd",
            "A" * 1000,  # Long header
            "%0d%0a%0d%0a",  # CRLF injection
            "\x00",  # Null byte
        ]

        for header_name in fuzz_headers:
            for payload in header_payloads[:5]:  # Limit payloads
                try:
                    response, evidence = await self.client.get(
                        endpoint,
                        headers={header_name: payload},
                    )
                    if self._detect_fuzz_issue(response, payload, evidence):
                        evidence.confidence = 0.6
                        evidence.payload = payload
                        findings.append(
                            Finding(
                                title=f"Fuzzing issue in header '{header_name}'",
                                severity=Severity.MEDIUM,
                                evidence=evidence,
                                description=(
                                    f"Fuzzing header '{header_name}' with payload " f"caused an unexpected response."
                                ),
                                remediation="Validate and sanitize all header values.",
                                cwe="CWE-20",
                                owasp="A03:2021 - Injection",
                                scanner="fuzz",
                                tags=["fuzzing", "header-injection"],
                            )
                        )
                        break  # One finding per header
                except Exception:
                    continue

        return findings

    async def _fuzz_cookies(self, endpoint: str) -> list[Finding]:
        """Fuzz cookies for injection and session manipulation."""
        findings: list[Finding] = []

        # Cookie names to fuzz
        cookie_names = [
            "session_id",
            "token",
            "user_id",
            "role",
            "admin",
            "debug",
            "test",
            "language",
            "theme",
        ]

        # Payloads for cookie fuzzing
        cookie_payloads = [
            "admin",
            "true",
            "1",
            "<script>alert(1)</script>",
            "' OR '1'='1",
            "../../etc/passwd",
            "A" * 500,  # Long cookie
            "%0d%0a",  # CRLF injection
        ]

        for cookie_name in cookie_names:
            for payload in cookie_payloads[:5]:
                try:
                    response, evidence = await self.client.get(
                        endpoint,
                        cookies={cookie_name: payload},
                    )
                    if self._detect_fuzz_issue(response, payload, evidence):
                        evidence.confidence = 0.6
                        evidence.payload = f"{cookie_name}={payload}"
                        findings.append(
                            Finding(
                                title=f"Fuzzing issue in cookie '{cookie_name}'",
                                severity=Severity.MEDIUM,
                                evidence=evidence,
                                description=(
                                    f"Fuzzing cookie '{cookie_name}' with payload " f"caused an unexpected response."
                                ),
                                remediation="Validate and sanitize all cookie values.",
                                cwe="CWE-20",
                                owasp="A03:2021 - Injection",
                                scanner="fuzz",
                                tags=["fuzzing", "cookie-injection"],
                            )
                        )
                        break  # One finding per cookie
                except Exception:
                    continue

        return findings

    async def _fuzz_multipart(self, endpoint: str) -> list[Finding]:
        """Fuzz multipart form-data uploads."""
        findings: list[Finding] = []

        # Payloads for multipart fuzzing
        multipart_payloads = [
            # Normal file with XSS content
            ("test.txt", b"<script>alert(1)</script>"),
            # Oversized filename
            ("A" * 1000 + ".txt", b"test"),
            # Path traversal in filename
            ("../../etc/passwd", b"test"),
            # Null byte in filename
            ("test\x00.txt", b"test"),
            # Deeply nested JSON
            ("test.json", b'{"a":{"b":{"c":{"d":"e"}}}}'),
            # Prototype pollution
            ("test.json", b'{"__proto__":{"admin":true}}'),
        ]

        for filename, content in multipart_payloads:
            try:
                # Build multipart form-data manually
                body = (
                    (
                        f"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
                        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                        f"Content-Type: application/octet-stream\r\n\r\n"
                    ).encode()
                    + content
                    + b"\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
                )

                response, evidence = await self.client.post(
                    endpoint,
                    body=body.decode("latin-1"),
                    headers={
                        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
                    },
                )
                if self._detect_fuzz_issue(response, filename, evidence):
                    evidence.confidence = 0.5
                    evidence.payload = f"filename={filename}"
                    findings.append(
                        Finding(
                            title=f"Fuzzing issue in multipart upload: {filename}",
                            severity=Severity.MEDIUM,
                            evidence=evidence,
                            description=(
                                f"Multipart upload with filename '{filename}' " f"caused an unexpected response."
                            ),
                            remediation="Validate and sanitize file uploads.",
                            cwe="CWE-20",
                            owasp="A03:2021 - Injection",
                            scanner="fuzz",
                            tags=["fuzzing", "multipart", "file-upload"],
                        )
                    )
                    break  # One finding for multipart
            except Exception:
                continue

        return findings


def _guess_param_type(value: str) -> list[str]:
    """Guess the type of a parameter value."""
    categories = ["string"]

    if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
        categories.append("integer")
        categories.append("boundary")
    elif value.replace(".", "").replace("-", "").isdigit():
        categories.append("boundary")

    categories.extend(["encoding", "nested_json"])
    return categories
