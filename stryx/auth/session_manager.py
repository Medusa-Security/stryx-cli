"""Session state machine for authenticated scanning.

Handles auto-detection of login forms, session cookie persistence,
JWT/OAuth token refresh, and multi-step authentication flows.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("auth.session")


@dataclass
class LoginEndpoint:
    """Detected login endpoint."""

    url: str
    method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    additional_fields: dict[str, str] = field(default_factory=dict)
    content_type: str = "application/json"


class SessionManager:
    """Manages authentication state for DAST scanning.

    Features:
    - Auto-detect login forms from HTML responses
    - Maintain session cookies across requests
    - JWT/OAuth token refresh
    - Multi-step authentication flows
    """

    def __init__(
        self,
        client: HttpClient,
        base_url: str,
        username: str | None = None,
        password: str | None = None,
        login_url: str | None = None,
        headers: dict[str, str] | None = None,
    ):
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.login_url = login_url
        self.custom_headers = headers or {}
        self._authenticated = False
        self._session_token: str | None = None
        self._token_expiry: float = 0
        self._login_endpoints: list[LoginEndpoint] = []
        self._session_data: dict[str, Any] = {}

    async def setup(self) -> bool:
        """Detect login endpoints and attempt authentication.

        Returns True if authentication was successful or not needed.
        """
        if not self.username or not self.password:
            logger.info("No credentials provided, skipping authentication")
            self._authenticated = True
            return True

        # Discover login endpoints
        await self._discover_login_endpoints()

        if not self.login_url and not self._login_endpoints:
            logger.warning("No login endpoints found")
            return False

        # Attempt login
        return await self.login()

    async def _discover_login_endpoints(self) -> None:
        """Crawl the target to find login forms."""
        logger.info("Discovering login endpoints")

        # Check explicit login URL first
        if self.login_url:
            try:
                response, _ = await self.client.get(self._ensure_absolute(self.login_url))
                if response.status_code == 200:
                    endpoints = self._extract_login_forms(response.text, self.login_url)
                    self._login_endpoints.extend(endpoints)
            except Exception as e:
                logger.debug(f"Failed to check login URL: {e}")

        # Crawl common login paths
        login_paths = [
            "/login",
            "/signin",
            "/auth/login",
            "/api/auth/login",
            "/api/login",
            "/account/login",
            "/wp-login.php",
        ]
        for path in login_paths:
            url = f"{self.base_url}{path}"
            try:
                response, _ = await self.client.get(url)
                if response.status_code == 200:
                    endpoints = self._extract_login_forms(response.text, path)
                    self._login_endpoints.extend(endpoints)
                    if endpoints:
                        logger.info(f"Found login form at {path}")
            except Exception:
                continue

        logger.info(f"Discovered {len(self._login_endpoints)} login endpoint(s)")

    def _extract_login_forms(self, html: str, page_path: str) -> list[LoginEndpoint]:
        """Extract login form details from HTML."""
        endpoints: list[LoginEndpoint] = []
        base = self.base_url

        # Find <form> tags
        form_pattern = re.compile(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']?(\w+)["\']?[^>]*>',
            re.IGNORECASE | re.DOTALL,
        )
        input_pattern = re.compile(
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:type=["\'](\w+)["\'])?[^>]*>',
            re.IGNORECASE,
        )

        forms = form_pattern.findall(html)
        for action, method in forms:
            # Get form content (simplified — find the form body)
            form_start = html.lower().find(f'action="{action}"')
            if form_start == -1:
                form_start = html.lower().find(f"action='{action}'")
            if form_start == -1:
                continue

            # Find the closing </form> tag
            form_end = html.lower().find("</form>", form_start)
            if form_end == -1:
                form_end = form_start + 2000
            form_html = html[form_start:form_end]

            # Extract input fields
            inputs = input_pattern.findall(form_html)
            field_names = [name for name, _ in inputs]
            field_types = {name: typ for name, typ in inputs}

            # Check if this looks like a login form
            password_fields = [f for f in field_names if field_types.get(f) == "password"]
            text_fields = [f for f in field_names if field_types.get(f) in ("text", "email", "")]

            if password_fields and text_fields:
                # Determine username and password field names
                username_field = text_fields[0]
                password_field = password_fields[0]

                # Build full URL
                if action.startswith("http"):
                    form_url = action
                elif action.startswith("/"):
                    form_url = f"{base}{action}"
                else:
                    form_url = (
                        f"{base}/{page_path.rsplit('/', 1)[0]}/{action}" if "/" in page_path else f"{base}/{action}"
                    )

                # Determine content type
                content_type = "application/json"
                if "multipart" in form_html.lower() or "form-data" in form_html.lower():
                    content_type = "multipart/form-data"
                elif "urlencoded" in form_html.lower():
                    content_type = "application/x-www-form-urlencoded"

                endpoints.append(
                    LoginEndpoint(
                        url=form_url,
                        method=method.upper(),
                        username_field=username_field,
                        password_field=password_field,
                        content_type=content_type,
                    )
                )

        return endpoints

    async def login(self) -> bool:
        """Attempt to login using discovered or configured credentials."""
        if not self.username or not self.password:
            return False

        for endpoint in self._login_endpoints:
            success = await self._try_login(endpoint)
            if success:
                self._authenticated = True
                logger.info(f"Successfully authenticated via {endpoint.url}")
                return True

        # Try explicit login URL with common field names
        if self.login_url:
            for username_field in ["username", "email", "user", "login"]:
                for password_field in ["password", "pass", "passwd"]:
                    endpoint = LoginEndpoint(
                        url=self._ensure_absolute(self.login_url),
                        method="POST",
                        username_field=username_field,
                        password_field=password_field,
                    )
                    success = await self._try_login(endpoint)
                    if success:
                        self._authenticated = True
                        logger.info(f"Successfully authenticated via {self.login_url}")
                        return True

        logger.warning("All login attempts failed")
        return False

    async def _try_login(self, endpoint: LoginEndpoint) -> bool:
        """Try logging in with a specific endpoint configuration."""
        try:
            payload = {
                endpoint.username_field: self.username,
                endpoint.password_field: self.password,
            }
            # Add any additional fields
            payload.update(endpoint.additional_fields)

            headers = {**self.custom_headers}
            if endpoint.content_type == "application/json":
                headers["Content-Type"] = "application/json"
                body = json.dumps(payload)
            elif endpoint.content_type == "application/x-www-form-urlencoded":
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                body = "&".join(f"{k}={v}" for k, v in payload.items())
            else:
                headers["Content-Type"] = "application/json"
                body = json.dumps(payload)

            response, evidence = await self.client.request(
                method=endpoint.method,
                url=endpoint.url,
                headers=headers,
                body=body,
            )

            # Check if login was successful
            if response.status_code in (200, 201, 302):
                # Check for token in response
                try:
                    resp_data = json.loads(response.text)
                    if "token" in resp_data:
                        self._session_token = resp_data["token"]
                        self._token_expiry = time.time() + 3600  # Default 1hr
                        self._session_data = resp_data
                        return True
                    if "access_token" in resp_data:
                        self._session_token = resp_data["access_token"]
                        self._token_expiry = time.time() + resp_data.get("expires_in", 3600)
                        self._session_data = resp_data
                        return True
                except (json.JSONDecodeError, KeyError):
                    pass

                # Check for session cookies
                if response.cookies:
                    self._session_data["cookies"] = dict(response.cookies)
                    return True

                # Check for redirect (successful login often redirects)
                if response.status_code == 302:
                    return True

        except Exception as e:
            logger.debug(f"Login attempt failed for {endpoint.url}: {e}")

        return False

    async def refresh(self) -> bool:
        """Refresh the session token if expired."""
        if not self._session_token:
            return await self.login()

        if time.time() < self._token_expiry - 60:  # Refresh 1 min before expiry
            return True

        logger.info("Token expired, refreshing...")
        # Try to refresh the token
        refresh_token = self._session_data.get("refresh_token")
        if refresh_token:
            try:
                response, _ = await self.client.request(
                    method="POST",
                    url=f"{self.base_url}/api/auth/refresh",
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"refresh_token": refresh_token}),
                )
                if response.status_code == 200:
                    data = json.loads(response.text)
                    self._session_token = data.get("token") or data.get("access_token")
                    self._token_expiry = time.time() + data.get("expires_in", 3600)
                    return True
            except Exception as e:
                logger.debug(f"Token refresh failed: {e}")

        # Fallback: re-login
        return await self.login()

    def is_authenticated(self) -> bool:
        """Check if we have an active authenticated session."""
        return self._authenticated

    def get_session_headers(self) -> dict[str, str]:
        """Get headers to include in authenticated requests."""
        headers = {**self.custom_headers}

        if self._session_token:
            headers["Authorization"] = f"Bearer {self._session_token}"

        cookies = self._session_data.get("cookies", {})
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            headers["Cookie"] = cookie_str

        return headers

    def get_session_cookies(self) -> dict[str, str]:
        """Get session cookies as a dictionary."""
        return self._session_data.get("cookies", {})

    def _ensure_absolute(self, url: str) -> str:
        """Ensure a URL is absolute."""
        if url.startswith("http"):
            return url
        if url.startswith("/"):
            return f"{self.base_url}{url}"
        return f"{self.base_url}/{url}"
