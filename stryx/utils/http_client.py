"""Async HTTP client wrapper with session cookies, rate limiting, and evidence collection."""

from __future__ import annotations

from typing import Any

import httpx

from stryx.utils.evidence import Evidence
from stryx.utils.rate_limiter import RateLimiter


class HttpClient:
    """Async HTTP client with session cookie jar, rate limiting, and evidence collection.

    Maintains cookies across requests (Set-Cookie responses update the jar)
    so authenticated sessions persist naturally.
    """

    def __init__(
        self,
        timeout: int = 10,
        proxy: str | None = None,
        rate_limit: int | None = None,
        headers: dict[str, str] | None = None,
        cookies: str | None = None,
    ):
        self.timeout = timeout
        self.proxy = proxy
        self.base_headers = headers or {}
        self.rate_limiter = RateLimiter(rate_limit) if rate_limit else None
        self._cookie_jar: dict[str, str] = {}

        # Parse initial cookies from string
        if cookies:
            for pair in cookies.split(";"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    self._cookie_jar[k.strip()] = v.strip()

    def _format_cookies(self) -> str:
        """Format cookie jar as Cookie header string."""
        return "; ".join(f"{k}={v}" for k, v in self._cookie_jar.items())

    def _update_cookies_from_response(self, response: httpx.Response) -> None:
        """Extract Set-Cookie headers and update the jar."""
        for cookie in response.cookies.items():
            self._cookie_jar[cookie[0]] = cookie[1]

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        json_data: dict | None = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> tuple[httpx.Response, Evidence]:
        """Make an HTTP request and return response with Evidence.

        Cookies from the jar are sent automatically. Set-Cookie responses
        update the jar for subsequent requests (session persistence).
        """
        if self.rate_limiter:
            await self.rate_limiter.acquire()

        merged_headers = dict(self.base_headers)
        if headers:
            merged_headers.update(headers)

        # Merge explicit cookies into jar
        if cookies:
            self._cookie_jar.update(cookies)

        request_headers = dict(merged_headers)

        # Add cookies from jar
        cookie_str = self._format_cookies()
        if cookie_str:
            merged_headers["Cookie"] = cookie_str

        kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(self.timeout),
            "follow_redirects": follow_redirects,
            "verify": False,
        }
        if self.proxy:
            kwargs["proxy"] = self.proxy

        try:
            async with httpx.AsyncClient(**kwargs) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=merged_headers,
                    content=body,
                    json=json_data,
                )

                # Update cookie jar from response
                self._update_cookies_from_response(response)

                response_headers = dict(response.headers)
                response_text = response.text

                evidence = Evidence(
                    request_method=method,
                    request_url=url,
                    request_headers=request_headers,
                    request_body=body,
                    response_status=response.status_code,
                    response_headers=response_headers,
                    response_body=response_text,
                    response_snippet=response_text[:500],
                    confidence=0.0,
                )
                return response, evidence

        except httpx.RequestError as e:
            evidence = Evidence(
                request_method=method,
                request_url=url,
                request_headers=request_headers,
                request_body=body,
                response_status=0,
                response_body=str(e),
                response_snippet=str(e)[:500],
                confidence=0.0,
            )
            error_response = httpx.Response(
                status_code=0,
                request=httpx.Request(method=method, url=url),
            )
            return error_response, evidence

    async def get(self, url: str, **kwargs: Any) -> tuple[httpx.Response, Evidence]:
        """Send GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> tuple[httpx.Response, Evidence]:
        """Send POST request."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> tuple[httpx.Response, Evidence]:
        """Send PUT request."""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> tuple[httpx.Response, Evidence]:
        """Send DELETE request."""
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> tuple[httpx.Response, Evidence]:
        """Send HEAD request."""
        return await self.request("HEAD", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> tuple[httpx.Response, Evidence]:
        """Send PATCH request."""
        return await self.request("PATCH", url, **kwargs)
