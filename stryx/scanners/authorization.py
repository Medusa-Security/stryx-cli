"""Authorization vulnerability scanner.

Tests for IDOR, horizontal/vertical privilege escalation, multi-tenant escape,
admin endpoint access, and resource ownership bypass.
Uses the ReplayEngine for proper IDOR testing.
"""

from __future__ import annotations

from stryx.attacks.replay import ReplayEngine
from stryx.utils.evidence import Finding, Severity
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("scanner.authorization")


class AuthorizationScanner:
    """Scanner for authorization vulnerabilities."""

    def __init__(self, client: HttpClient):
        self.client = client
        self.replay = ReplayEngine(client)

    async def scan(self, endpoints: list[str], base_url: str, cookies: str = "") -> list[Finding]:
        """Run authorization tests."""
        findings: list[Finding] = []
        logger.info("Running authorization scanner")

        # Test IDOR on discovered endpoints with numeric IDs
        findings.extend(await self._test_idor(endpoints, base_url, cookies))

        # Test privilege escalation
        findings.extend(await self._test_privilege_escalation(endpoints, base_url, cookies))

        # Test admin access
        findings.extend(await self._test_admin_access(base_url, cookies))

        # Test horizontal privilege escalation
        findings.extend(await self._test_horizontal_escalation(endpoints, base_url, cookies))

        logger.info(f"Authorization scanner found {len(findings)} findings")
        return findings

    async def _test_idor(self, endpoints: list[str], base_url: str, cookies: str) -> list[Finding]:
        """Test for Insecure Direct Object Reference using replay engine."""
        findings: list[Finding] = []

        # Find endpoints that likely contain IDs
        idor_candidates = [ep for ep in endpoints if ReplayEngine.is_idor_candidate(ep)]

        # If no IDOR candidates from endpoints, test common patterns
        if not idor_candidates:
            idor_candidates = [
                f"{base_url}/api/users/1",
                f"{base_url}/api/users/2",
                f"{base_url}/api/orders/1",
                f"{base_url}/api/orders/2",
                f"{base_url}/api/documents/1",
                f"{base_url}/api/documents/2",
                f"{base_url}/users/1",
                f"{base_url}/profile/1",
            ]

        cookie_dict = _parse_cookies(cookies)

        for url in idor_candidates:
            # Extract IDs from the URL
            ids = ReplayEngine.extract_ids_from_url(url)
            if not ids:
                continue

            original_id = ids[0]
            finding = await self.replay.test_idor(
                url=url,
                original_id=original_id,
                headers={"Cookie": _format_cookies(cookie_dict)} if cookie_dict else None,
            )
            if finding:
                findings.append(finding)
                break  # One IDOR finding is sufficient

        return findings

    async def _test_privilege_escalation(self, endpoints: list[str], base_url: str, cookies: str) -> list[Finding]:
        """Test for privilege escalation."""
        findings: list[Finding] = []
        cookie_dict = _parse_cookies(cookies)

        # Test vertical escalation - accessing admin endpoints as regular user
        admin_paths = [
            "/admin",
            "/admin/",
            "/api/admin",
            "/api/admin/users",
            "/api/admin/config",
            "/api/admin/settings",
            "/api/admin/stats",
            "/api/admin/logs",
        ]

        for path in admin_paths:
            url = f"{base_url}{path}"
            try:
                response, evidence = await self.client.get(url, cookies=cookie_dict)
                if response.status_code == 200:
                    evidence.confidence = 0.7
                    findings.append(
                        Finding(
                            title=f"Admin endpoint accessible: {path}",
                            severity=Severity.CRITICAL,
                            evidence=evidence,
                            description=(
                                f"The admin endpoint {path} is accessible. " f"This may allow privilege escalation."
                            ),
                            remediation="Restrict admin endpoints to authorized administrators.",
                            cwe="CWE-269",
                            owasp="A01:2021 - Broken Access Control",
                            scanner="authorization",
                            tags=["privilege-escalation", "admin-access"],
                        )
                    )
            except Exception:
                continue

        return findings

    async def _test_admin_access(self, base_url: str, cookies: str) -> list[Finding]:
        """Test for unauthorized admin access."""
        findings: list[Finding] = []

        # Try accessing admin with and without auth
        admin_endpoints = [
            "/admin",
            "/admin/dashboard",
            "/api/admin",
            "/admin/panel",
            "/administrator",
        ]

        for path in admin_endpoints:
            # Without cookies
            try:
                url = f"{base_url}{path}"
                response, evidence = await self.client.get(url)
                if response.status_code == 200:
                    evidence.confidence = 0.8
                    findings.append(
                        Finding(
                            title=f"Admin panel accessible without auth: {path}",
                            severity=Severity.CRITICAL,
                            evidence=evidence,
                            description=(
                                f"The admin panel at {path} is accessible without "
                                f"authentication. This is a critical security issue."
                            ),
                            remediation=("Implement authentication and authorization " "for admin interfaces."),
                            cwe="CWE-284",
                            owasp="A01:2021 - Broken Access Control",
                            scanner="authorization",
                            tags=["admin-panel", "no-auth"],
                        )
                    )
            except Exception:
                continue

        return findings

    async def _test_horizontal_escalation(self, endpoints: list[str], base_url: str, cookies: str) -> list[Finding]:
        """Test horizontal privilege escalation across user resources."""
        findings: list[Finding] = []
        cookie_dict = _parse_cookies(cookies)

        # Find endpoints with {user_id} pattern or numeric IDs
        user_endpoints = [ep for ep in endpoints if "{user_id}" in ep or "/users/" in ep or "/profile/" in ep]

        # Add common patterns if none found
        if not user_endpoints:
            user_endpoints = [
                f"{base_url}/api/users/{{user_id}}",
                f"{base_url}/api/profile/{{user_id}}",
                f"{base_url}/users/{{user_id}}",
            ]

        for url_template in user_endpoints:
            finding = await self.replay.test_horizontal_escalation(
                url=url_template,
                user_ids=["1", "2", "3", "4", "5"],
                headers={"Cookie": _format_cookies(cookie_dict)} if cookie_dict else None,
            )
            if finding:
                findings.append(finding)
                break  # One finding is sufficient

        return findings


def _parse_cookies(cookie_str: str) -> dict[str, str]:
    """Parse cookie string into dictionary."""
    cookies: dict[str, str] = {}
    if not cookie_str:
        return cookies
    for pair in cookie_str.split(";"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            cookies[key.strip()] = value.strip()
    return cookies


def _format_cookies(cookie_dict: dict[str, str]) -> str:
    """Format cookie dictionary as Cookie header string."""
    return "; ".join(f"{k}={v}" for k, v in cookie_dict.items())
