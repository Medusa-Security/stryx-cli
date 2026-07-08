"""Authentication vulnerability scanner.

Tests: missing authentication, weak JWT validation, expired JWT acceptance,
unsigned JWTs, session fixation, cookie security, OAuth/provider misconfiguration.
Detects: JWT, OAuth2, Clerk, Supabase, Firebase, Auth0, Better Auth, session cookies.
"""

from __future__ import annotations

import base64
import json
import re
import time

from stryx.utils.evidence import Finding, Severity
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("scanner.auth")


# --- Provider fingerprinting ---

PROVIDER_FINGERPRINTS = {
    "jwt": {
        "headers": ["authorization"],
        "header_patterns": [r"Bearer\s+eyJ"],
        "cookie_patterns": [r"token=", r"jwt=", r"access_token="],
        "response_patterns": [r"jwt", r"bearer", r"token"],
    },
    "oauth2": {
        "headers": ["x-oauth-token", "x-auth-token"],
        "header_patterns": [r"Bearer"],
        "cookie_patterns": [r"oauth", r"_oauth2", r"gsession"],
        "response_patterns": [r"oauth", r"authorize", r"redirect_uri"],
    },
    "clerk": {
        "headers": ["x-clerk-auth-status", "x-clerk-user-id"],
        "header_patterns": [],
        "cookie_patterns": [r"__session", r"__client"],
        "response_patterns": [r"clerk", r"clerk\.publishable"],
    },
    "supabase": {
        "headers": ["x-supabase-auth"],
        "header_patterns": [r"supabase"],
        "cookie_patterns": [r"sb-", r"supabase"],
        "response_patterns": [r"supabase", r"supabase\.co"],
    },
    "firebase": {
        "headers": ["x-firebase-auth"],
        "header_patterns": [],
        "cookie_patterns": [r"__session", r"firebase"],
        "response_patterns": [r"firebase", r"firebaseio\.com", r"firebaseapp"],
    },
    "auth0": {
        "headers": ["x-auth0-request-id"],
        "header_patterns": [r"auth0"],
        "cookie_patterns": [r"auth0", r"_auth0"],
        "response_patterns": [r"auth0\.", r"auth0\.com"],
    },
    "better_auth": {
        "headers": ["x-better-auth"],
        "header_patterns": [r"better-auth"],
        "cookie_patterns": [r"better-auth", r"ba_"],
        "response_patterns": [r"better-auth", r"better\.auth"],
    },
    "session_cookie": {
        "headers": [],
        "header_patterns": [],
        "cookie_patterns": [
            r"session", r"sid", r"connect\.sid", r"JSESSIONID",
            r"_session_id", r"laravel_session", r"csrftoken",
        ],
        "response_patterns": [],
    },
}


def detect_auth_providers(
    response_headers: dict[str, str],
    response_cookies: dict[str, str],
    response_body: str = "",
) -> list[str]:
    """Detect authentication providers from response headers, cookies, and body.

    Returns list of detected provider names.
    """
    detected = []
    header_str = json.dumps(response_headers).lower()
    cookie_str = json.dumps(response_cookies).lower()
    body_lower = response_body.lower()

    for provider, fp in PROVIDER_FINGERPRINTS.items():
        found = False

        # Check response headers
        for h in fp["headers"]:
            if h in header_str:
                found = True
                break

        # Check header patterns
        for pattern in fp["header_patterns"]:
            if re.search(pattern, header_str, re.IGNORECASE):
                found = True
                break

        # Check cookie patterns
        for pattern in fp["cookie_patterns"]:
            if re.search(pattern, cookie_str, re.IGNORECASE):
                found = True
                break

        # Check response body patterns
        for pattern in fp["response_patterns"]:
            if re.search(pattern, body_lower, re.IGNORECASE):
                found = True
                break

        if found:
            detected.append(provider)

    return detected


class AuthScanner:
    """Scanner for authentication vulnerabilities."""

    def __init__(self, client: HttpClient):
        self.client = client
        self.detected_providers: list[str] = []

    async def scan(
        self, endpoints: list[str], base_url: str
    ) -> list[Finding]:
        """Run authentication tests against the target."""
        findings: list[Finding] = []
        logger.info("Running authentication scanner")

        # Stage 1: Fingerprint providers from a real response
        await self._fingerprint_providers(base_url)

        # Stage 2: Test unauthenticated access to protected endpoints
        findings.extend(await self._test_missing_auth(endpoints, base_url))

        # Stage 3: Test JWT weaknesses based on detected provider
        findings.extend(await self._test_jwt_weaknesses(endpoints, base_url))

        # Stage 4: Test session fixation
        findings.extend(await self._test_session_fixation(base_url))

        # Stage 5: Test cookie security
        findings.extend(await self._test_cookie_security(base_url))

        logger.info(f"Auth scanner found {len(findings)} findings")
        return findings

    async def _fingerprint_providers(self, base_url: str) -> None:
        """Fingerprint authentication providers from the target."""
        try:
            response, evidence = await self.client.get(base_url)
            self.detected_providers = detect_auth_providers(
                dict(response.headers),
                dict(response.cookies),
                response.text,
            )
            if self.detected_providers:
                logger.info(
                    f"Detected auth providers: {', '.join(self.detected_providers)}"
                )
        except Exception as e:
            logger.debug(f"Provider fingerprinting failed: {e}")

    async def _test_missing_auth(
        self, endpoints: list[str], base_url: str
    ) -> list[Finding]:
        """Test if endpoints are accessible without authentication."""
        findings: list[Finding] = []

        protected_paths = [
            "/admin", "/admin/", "/api/admin", "/dashboard",
            "/api/users", "/api/user", "/api/profile",
            "/settings", "/api/settings", "/api/config",
            "/api/internal", "/internal", "/debug",
            "/api/me", "/api/account", "/api/account/settings",
            "/api/billing", "/api/keys", "/api/secrets",
        ]

        for path in protected_paths:
            url = f"{base_url}{path}"
            try:
                response, evidence = await self.client.get(url)
                if response.status_code == 200:
                    body_lower = response.text.lower()
                    # Confirm it's actual content, not a redirect or error page
                    if not any(x in body_lower for x in [
                        "login", "sign in", "unauthorized", "forbidden",
                    ]):
                        evidence.confidence = 0.7
                        findings.append(Finding(
                            title=f"Unauthenticated access to {path}",
                            severity=Severity.HIGH,
                            evidence=evidence,
                            description=(
                                f"The endpoint {path} is accessible without any "
                                f"authentication. This may expose sensitive data "
                                f"or administrative functions."
                            ),
                            remediation="Implement authentication middleware to protect this endpoint.",
                            cwe="CWE-306",
                            owasp="A07:2021 - Identification and Authentication Failures",
                            scanner="auth",
                            tags=["missing-auth", "no-auth"],
                        ))
            except Exception:
                continue

        return findings

    async def _test_jwt_weaknesses(
        self, endpoints: list[str], base_url: str
    ) -> list[Finding]:
        """Test for JWT implementation weaknesses.

        Tests: empty JWT, unsigned JWT, algorithm none, expired JWT,
        malformed token, missing signature.
        """
        findings: list[Finding] = []

        # Build test JWTs
        test_jwts = _build_jwt_test_cases()

        for jwt_header, jwt_desc in test_jwts:
            for endpoint in endpoints[:15]:
                try:
                    headers = {"Authorization": f"Bearer {jwt_header}"} if jwt_header else {}
                    response, evidence = await self.client.get(endpoint, headers=headers)
                    if response.status_code == 200 and jwt_header:
                        evidence.confidence = 0.8
                        findings.append(Finding(
                            title=f"Weak JWT accepted: {jwt_desc} at {endpoint}",
                            severity=Severity.CRITICAL,
                            evidence=evidence,
                            description=(
                                f"The endpoint accepted {jwt_desc}. "
                                f"This indicates weak token validation that could "
                                f"allow authentication bypass."
                            ),
                            remediation=(
                                "Validate JWT signatures, algorithm, expiration. "
                                "Reject 'none' algorithm. Enforce signature verification."
                            ),
                            cwe="CWE-347",
                            owasp="A07:2021 - Identification and Authentication Failures",
                            scanner="auth",
                            tags=["jwt", "weak-auth", "jwt-weakness"],
                        ))
                        break  # One finding per JWT type
                except Exception:
                    continue

        return findings

    async def _test_session_fixation(self, base_url: str) -> list[Finding]:
        """Test for session fixation vulnerabilities.

        Checks if session cookie changes after login attempt.
        """
        findings: list[Finding] = []

        try:
            # Make initial request to get session
            response1, _ = await self.client.get(f"{base_url}/")
            if response1.status_code != 200:
                return findings

            session_cookies = dict(response1.cookies)
            if not session_cookies:
                return findings

            # Make login request keeping the same session cookie
            response2, evidence = await self.client.post(
                f"{base_url}/login",
                json_data={"username": "test", "password": "test"},
            )

            new_cookies = dict(response2.cookies)
            # Check if session cookie was NOT regenerated
            for cookie_name in session_cookies:
                if cookie_name in new_cookies:
                    if new_cookies[cookie_name] == session_cookies[cookie_name]:
                        evidence.confidence = 0.6
                        findings.append(Finding(
                            title="Potential session fixation",
                            severity=Severity.MEDIUM,
                            evidence=evidence,
                            description=(
                                f"The session cookie '{cookie_name}' did not change "
                                f"after login, which may indicate session fixation. "
                                f"An attacker could set a known session ID before the "
                                f"user authenticates."
                            ),
                            remediation="Regenerate session ID after successful authentication.",
                            cwe="CWE-384",
                            owasp="A07:2021 - Identification and Authentication Failures",
                            scanner="auth",
                            tags=["session-fixation"],
                        ))
        except Exception:
            pass

        return findings

    async def _test_cookie_security(self, base_url: str) -> list[Finding]:
        """Test for insecure cookie configurations."""
        findings: list[Finding] = []

        try:
            response, evidence = await self.client.get(base_url)
            set_cookie_headers = []
            for key, value in response.headers.items():
                if key.lower() == "set-cookie":
                    set_cookie_headers.append(value)

            if not set_cookie_headers:
                return findings

            for cookie_header in set_cookie_headers:
                cookie_lower = cookie_header.lower()

                # Missing Secure flag
                if "secure" not in cookie_lower:
                    evidence.confidence = 0.6
                    findings.append(Finding(
                        title="Cookie missing Secure flag",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        description=(
                            f"Cookie '{cookie_header[:60]}...' is set without "
                            f"the Secure flag, allowing it to be sent over HTTP."
                        ),
                        remediation="Set the Secure flag on all session cookies.",
                        cwe="CWE-614",
                        owasp="A05:2021 - Security Misconfiguration",
                        scanner="auth",
                        tags=["cookie", "insecure-flag"],
                    ))
                    break  # One finding per type

                # Missing HttpOnly flag
                if "httponly" not in cookie_lower:
                    evidence.confidence = 0.6
                    findings.append(Finding(
                        title="Cookie missing HttpOnly flag",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        description=(
                            f"Cookie '{cookie_header[:60]}...' is set without "
                            f"the HttpOnly flag, exposing it to XSS attacks."
                        ),
                        remediation="Set the HttpOnly flag on all session cookies.",
                        cwe="CWE-1004",
                        owasp="A05:2021 - Security Misconfiguration",
                        scanner="auth",
                        tags=["cookie", "httponly"],
                    ))
                    break

                # Missing SameSite attribute
                if "samesite" not in cookie_lower:
                    evidence.confidence = 0.5
                    findings.append(Finding(
                        title="Cookie missing SameSite attribute",
                        severity=Severity.LOW,
                        evidence=evidence,
                        description=(
                            f"Cookie '{cookie_header[:60]}...' is set without "
                            f"the SameSite attribute."
                        ),
                        remediation="Set SameSite=Strict or SameSite=Lax on cookies.",
                        cwe="CWE-1275",
                        owasp="A05:2021 - Security Misconfiguration",
                        scanner="auth",
                        tags=["cookie", "samesite"],
                    ))
                    break

        except Exception:
            pass

        return findings


def _build_jwt_test_cases() -> list[tuple[str, str]]:
    """Build JWT test cases for weakness testing."""
    cases = []

    # 1. Empty JWT
    cases.append(("", "empty Bearer token"))

    # 2. Unsigned JWT (alg: none)
    header_b64 = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps({"sub": "1", "name": "admin", "role": "admin"}).encode()
    ).rstrip(b"=").decode()
    cases.append((f"{header_b64}.{payload_b64}.", "unsigned JWT (alg: none)"))

    # 3. JWT with "none" algorithm variant
    header_b64 = base64.urlsafe_b64encode(
        json.dumps({"alg": "None", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    cases.append((f"{header_b64}.{payload_b64}.", "JWT with None algorithm (mixed case)"))

    # 4. Expired JWT
    expired_payload = base64.urlsafe_b64encode(
        json.dumps({
            "sub": "1",
            "exp": int(time.time()) - 3600,  # 1 hour ago
            "iat": int(time.time()) - 7200,
        }).encode()
    ).rstrip(b"=").decode()
    header_hs256 = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    cases.append((
        f"{header_hs256}.{expired_payload}.fake_signature",
        "expired JWT",
    ))

    # 5. JWT with no signature
    cases.append((
        f"{header_hs256}.{payload_b64}",
        "JWT with missing signature",
    ))

    # 6. Malformed token
    cases.append(("not.a.valid.jwt.token", "malformed JWT token"))

    # 7. Just "Bearer" with no token
    cases.append(("Bearer", "Bearer keyword with no token"))

    return cases
