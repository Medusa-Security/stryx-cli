"""Request replay engine with identity substitution for authorization testing."""

from __future__ import annotations

import re

from stryx.utils.evidence import Finding, Severity
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("attacks.replay")


class ReplayEngine:
    """Replays HTTP requests with modified identities for authorization testing."""

    def __init__(self, client: HttpClient):
        self.client = client

    async def test_idor(
        self,
        url: str,
        method: str = "GET",
        original_id: str = "1",
        test_ids: list[str] | None = None,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> Finding | None:
        """Test for IDOR by replaying requests with different IDs.

        Correctly substitutes IDs in URL paths and query parameters.
        """
        if test_ids is None:
            test_ids = ["2", "3", "4", "5", "100", "999", "0", "-1"]

        # Get baseline response with original ID
        try:
            baseline_response, baseline_evidence = await self.client.request(
                method=method,
                url=url,
                headers=headers,
                body=body,
            )
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)
        except Exception:
            return None

        if baseline_status != 200:
            return None

        # Test with different IDs
        for test_id in test_ids:
            test_url = self._substitute_id(url, original_id, test_id)
            if test_url == url:
                continue

            try:
                response, evidence = await self.client.request(
                    method=method,
                    url=test_url,
                    headers=headers,
                    body=body,
                )

                # If we get same-status response with different ID, it's likely IDOR
                if (response.status_code == baseline_status and
                    response.status_code == 200 and
                    abs(len(response.text) - baseline_length) < 100):

                    evidence.confidence = 0.7
                    evidence.payload = f"ID substitution: {original_id} -> {test_id}"
                    return Finding(
                        title=f"IDOR: ID substitution {original_id} -> {test_id}",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        description=(
                            f"Changing the resource ID from {original_id} to {test_id} "
                            f"returned the same response, indicating Insecure Direct "
                            f"Object Reference."
                        ),
                        remediation="Implement proper authorization checks for resource access.",
                        cwe="CWE-639",
                        owasp="A01:2021 - Broken Access Control",
                        scanner="authorization",
                        tags=["idor", "replay"],
                    )
            except Exception:
                continue

        return None

    async def test_horizontal_escalation(
        self,
        url: str,
        user_ids: list[str],
        headers: dict[str, str] | None = None,
    ) -> Finding | None:
        """Test horizontal privilege escalation by accessing other users' resources."""
        if len(user_ids) < 2:
            return None

        # Access resources as user 1
        user1_url = self._substitute_id(url, "{user_id}", user_ids[0])
        try:
            response1, _ = await self.client.get(user1_url, headers=headers)
            if response1.status_code != 200:
                return None
        except Exception:
            return None

        # Try to access user 1's resources as user 2
        for other_id in user_ids[1:]:
            other_url = self._substitute_id(url, "{user_id}", other_id)
            try:
                response, evidence = await self.client.get(other_url, headers=headers)
                if response.status_code == 200:
                    evidence.confidence = 0.6
                    evidence.payload = (
                        f"User {other_id} accessing {user_ids[0]}'s resource"
                    )
                    return Finding(
                        title=(
                            f"Horizontal privilege escalation: user {other_id} "
                            f"accessed user {user_ids[0]}'s resource"
                        ),
                        severity=Severity.HIGH,
                        evidence=evidence,
                        description=(
                            f"User {other_id} was able to access resources "
                            f"belonging to user {user_ids[0]}."
                        ),
                        remediation="Verify resource ownership before granting access.",
                        cwe="CWE-639",
                        owasp="A01:2021 - Broken Access Control",
                        scanner="authorization",
                        tags=["horizontal-escalation", "replay"],
                    )
            except Exception:
                continue

        return None

    @staticmethod
    def _substitute_id(url: str, old_id: str, new_id: str) -> str:
        """Substitute an ID in a URL path or query parameter."""
        # Replace in path segments: /users/1/ -> /users/2/
        # Replace in query params: ?id=1& -> ?id=2&
        # Be careful not to replace partial matches
        result = url

        # Try path replacement: /{old_id} or /{old_id}/
        path_pattern = rf"/{re.escape(old_id)}(?=/|$|\?)"
        result = re.sub(path_pattern, f"/{new_id}", result)

        # Try query parameter replacement: {old_id}& or {old_id}$
        query_pattern = rf"(?<=[?&=]){re.escape(old_id)}(?=[&]|$)"
        result = re.sub(query_pattern, new_id, result)

        return result

    @staticmethod
    def extract_ids_from_url(url: str) -> list[str]:
        """Extract numeric IDs from a URL path."""
        ids = []
        # Match numeric segments in path
        for match in re.finditer(r"/(\d+)(?:/|$|\?)", url):
            ids.append(match.group(1))
        # Match numeric query parameters
        for match in re.finditer(r"[?&](\w+)=(\d+)", url):
            ids.append(match.group(2))
        return ids

    @staticmethod
    def is_idor_candidate(url: str) -> bool:
        """Check if a URL likely contains an ID parameter."""
        # Check for numeric path segments
        if re.search(r"/\d+(?:/|$|\?)", url):
            return True
        # Check for numeric query parameters
        if re.search(r"[?&]\w+=\d+(?:&|$)", url):
            return True
        # Check for common ID parameter names
        if re.search(r"[?&](id|user_id|userId|account_id|item_id|order_id)=", url):
            return True
        return False
