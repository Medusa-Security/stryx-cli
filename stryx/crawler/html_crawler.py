"""Recursive HTML web crawler with depth-limited link following.

Follows <a href>, <form action>, <img src>, <script src>, <link href>,
and <iframe src> to discover endpoints recursively.
Respects crawl_depth and deduplicates URLs.
"""

from __future__ import annotations

import re
from urllib.parse import urldefrag, urljoin, urlparse

from stryx.crawler.discovery import Endpoint
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("crawler.html")

# Patterns to extract URLs from HTML
_LINK_PATTERNS = [
    # <a href="...">
    re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\']', re.I),
    # <form action="...">
    re.compile(r'<form\s+[^>]*action=["\']([^"\']+)["\']', re.I),
    # <img src="...">
    re.compile(r'<img\s+[^>]*src=["\']([^"\']+)["\']', re.I),
    # <script src="...">
    re.compile(r'<script\s+[^>]*src=["\']([^"\']+)["\']', re.I),
    # <link href="...">
    re.compile(r'<link\s+[^>]*href=["\']([^"\']+)["\']', re.I),
    # <iframe src="...">
    re.compile(r'<iframe\s+[^>]*src=["\']([^"\']+)["\']', re.I),
]

# Patterns to extract form inputs
_FORM_INPUT_PATTERN = re.compile(r'<input\s+[^>]*name=["\']([^"\']+)["\']', re.I)
_FORM_SELECT_PATTERN = re.compile(r'<select\s+[^>]*name=["\']([^"\']+)["\']', re.I)
_FORM_TEXTAREA_PATTERN = re.compile(r'<textarea\s+[^>]*name=["\']([^"\']+)["\']', re.I)

# Patterns to extract API-like paths from JavaScript
_JS_API_PATTERNS = [
    re.compile(r"""(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["']([^"']+)["']"""),
    re.compile(r"""(?:url|endpoint|path|api)\s*[:=]\s*["']([^"']+)["']"""),
    re.compile(r"""["'](/api/[^"']+)["']"""),
    re.compile(r"""["'](/v[12]/[^"']+)["']"""),
]

# File extensions to skip (not HTML)
_SKIP_EXTENSIONS = {
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".mp4",
    ".webm",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
}

# Common ignored paths
_IGNORED_PATHS = {
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/apple-touch-icon.png",
    "/manifest.json",
}


class HTMLCrawler:
    """Recursive HTML crawler that follows links to discover endpoints."""

    def __init__(
        self,
        target_url: str,
        max_depth: int = 5,
        max_pages: int = 500,
        respect_robots: bool = False,
    ):
        self.target_url = target_url.rstrip("/")
        self.base_domain = urlparse(self.target_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        self.client = HttpClient(timeout=10)
        self.visited: set[str] = set()
        self.endpoints: list[Endpoint] = []
        self._robots_paths: set[str] = set()

    async def crawl(self) -> list[Endpoint]:
        """Start recursive crawling from the target URL."""
        logger.info(f"Starting recursive crawl from {self.target_url} (depth={self.max_depth})")

        if self.respect_robots:
            await self._load_robots_txt()

        await self._crawl_page(self.target_url, depth=0)

        logger.info(f"Crawl complete: {len(self.endpoints)} endpoints discovered from {len(self.visited)} pages")
        return self.endpoints

    async def _crawl_page(self, url: str, depth: int) -> None:
        """Crawl a single page and follow links."""
        # Normalize URL
        url = self._normalize_url(url)

        # Check limits
        if depth > self.max_depth:
            return
        if len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return

        # Check if same domain
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != self.base_domain:
            return

        # Check robots.txt
        if self.respect_robots and self._is_disallowed(parsed.path):
            return

        # Skip non-HTML resources
        path_lower = parsed.path.lower()
        if any(path_lower.endswith(ext) for ext in _SKIP_EXTENSIONS):
            return
        if parsed.path in _IGNORED_PATHS:
            return

        self.visited.add(url)
        logger.debug(f"Crawling [{depth}]: {url}")

        try:
            response, evidence = await self.client.get(url)

            if response.status_code >= 400:
                return

            content_type = response.headers.get("content-type", "").lower()
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                return

            body = response.text

            # Register this URL as an endpoint
            self.endpoints.append(
                Endpoint(
                    path=url,
                    method="GET",
                    source="html_crawler",
                    confidence=0.9,
                )
            )

            # Extract and follow links
            links = self._extract_links(body, url)
            for link in links:
                await self._crawl_page(link, depth + 1)

            # Extract form actions and inputs
            forms = self._extract_forms(body, url)
            for form_url, params in forms:
                self.endpoints.append(
                    Endpoint(
                        path=form_url,
                        method="POST",
                        source="html_form",
                        confidence=0.85,
                        params=params,
                    )
                )

            # Extract API endpoints from inline JavaScript
            js_endpoints = self._extract_js_endpoints(body, url)
            for js_url in js_endpoints:
                self.endpoints.append(
                    Endpoint(
                        path=js_url,
                        method="GET",
                        source="html_js_inline",
                        confidence=0.7,
                    )
                )

        except Exception as e:
            logger.debug(f"Failed to crawl {url}: {e}")

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract all links from HTML content."""
        links = set()
        for pattern in _LINK_PATTERNS:
            for match in pattern.finditer(html):
                href = match.group(1).strip()
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                full_url = self._resolve_url(href, base_url)
                if full_url:
                    links.add(full_url)
        return list(links)

    def _extract_forms(self, html: str, base_url: str) -> list[tuple[str, list[str]]]:
        """Extract form actions and input parameter names."""
        forms = []
        # Find all <form> blocks
        form_pattern = re.compile(r'<form\s+[^>]*action=["\']([^"\']+)["\'][^>]*>(.*?)</form>', re.I | re.S)
        for match in form_pattern.finditer(html):
            action = match.group(1).strip()
            form_body = match.group(2)
            full_url = self._resolve_url(action, base_url)
            if not full_url:
                continue

            # Extract input names
            params = []
            for p in _FORM_INPUT_PATTERN.finditer(form_body):
                params.append(p.group(1))
            for p in _FORM_SELECT_PATTERN.finditer(form_body):
                params.append(p.group(1))
            for p in _FORM_TEXTAREA_PATTERN.finditer(form_body):
                params.append(p.group(1))

            forms.append((full_url, params))

        return forms

    def _extract_js_endpoints(self, html: str, base_url: str) -> list[str]:
        """Extract API endpoints from inline JavaScript."""
        endpoints = set()
        # Find <script> blocks with inline code
        script_pattern = re.compile(r"<script[^>]*>(.*?)</script>", re.I | re.S)
        for match in script_pattern.finditer(html):
            script_content = match.group(1)
            if not script_content.strip():
                continue
            for pattern in _JS_API_PATTERNS:
                for api_match in pattern.finditer(script_content):
                    path = api_match.group(1)
                    if path.startswith("/"):
                        full_url = f"{self.base_domain}{path}"
                        endpoints.add(full_url)
        return list(endpoints)

    def _resolve_url(self, href: str, base_url: str) -> str | None:
        """Resolve a relative URL to absolute and normalize."""
        try:
            if href.startswith(("http://", "https://")):
                full_url = href
            else:
                full_url = urljoin(base_url, href)

            # Remove fragment
            full_url, _ = urldefrag(full_url)

            # Normalize
            full_url = self._normalize_url(full_url)

            return full_url
        except Exception:
            return None

    def _normalize_url(self, url: str) -> str:
        """Normalize a URL for deduplication."""
        parsed = urlparse(url)
        # Lowercase scheme and host
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        # Remove default ports
        if netloc.endswith(":80") and scheme == "http":
            netloc = netloc[:-3]
        elif netloc.endswith(":443") and scheme == "https":
            netloc = netloc[:-4]
        # Normalize path
        path = parsed.path.rstrip("/") or "/"
        # Rebuild
        normalized = f"{scheme}://{netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized

    async def _load_robots_txt(self) -> None:
        """Load and parse robots.txt Disallow rules."""
        try:
            robots_url = f"{self.base_domain}/robots.txt"
            response, _ = await self.client.get(robots_url)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            self._robots_paths.add(path)
                logger.info(f"Loaded {len(self._robots_paths)} disallowed paths from robots.txt")
        except Exception:
            pass

    def _is_disallowed(self, path: str) -> bool:
        """Check if a path is disallowed by robots.txt."""
        for disallowed in self._robots_paths:
            if path.startswith(disallowed):
                return True
        return False
