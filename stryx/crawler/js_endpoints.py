"""JavaScript endpoint extraction.

Downloads and analyzes JavaScript files to discover API endpoints,
HTTP methods, and URL patterns. Handles bundled/minified JS.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

from stryx.crawler.discovery import Endpoint
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("crawler.js_endpoints")

# Patterns that commonly indicate API endpoints in JS
ENDPOINT_PATTERNS = [
    # fetch/axios/http client URLs
    re.compile(r"""(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch|\.request)\s*\(\s*['"`]([^'"`]+)['"`]"""),
    # URL assignments
    re.compile(r"""(?:url|endpoint|api|path|href|baseUrl|baseURL)\s*[=:]\s*['"`]([^'"`]+)['"`]"""),
    # Template literal API calls
    re.compile(r"""`(/api/[^`]+)`"""),
    re.compile(r"""`(/v\d/[^`]+)`"""),
    re.compile(r"""`(/auth/[^`]+)`"""),
    re.compile(r"""`(/admin/[^`]+)`"""),
    # String concatenation API paths
    re.compile(r"""['"]([^'"]*api[^'"]*)['"]"""),
    re.compile(r"""['"]([^'"]*\/users\/[^'"]*)['"]"""),
    re.compile(r"""['"]([^'"]*\/admin[^'"]*)['"]"""),
    re.compile(r"""['"]([^'"]*\/login[^'"]*)['"]"""),
    re.compile(r"""['"]([^'"]*\/auth[^'"]*)['"]"""),
    re.compile(r"""['"]([^'"]*\/register[^'"]*)['"]"""),
    re.compile(r"""['"]([^'"]*\/profile[^'"]*)['"]"""),
    re.compile(r"""['"]([^'"]*\/settings[^'"]*)['"]"""),
    re.compile(r"""['"]([^'"]*\/upload[^'"]*)['"]"""),
    re.compile(r"""['"]([^'"]*\/search[^'"]*)['"]"""),
    re.compile(r"""['"]([^'"]*\/graphql[^'"]*)['"]"""),
    re.compile(r"""['"]([^'"]*\/websocket[^'"]*)['"]"""),
    re.compile(r"""['"]([^'"]*\/ws[^'"]*)['"]"""),
    # HTTP method detection
    re.compile(r"""method\s*:\s*['"]?(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"]?"""),
    # Common SPA routes
    re.compile(r"""(?:path|route)\s*:\s*['"]\/([a-zA-Z][a-zA-Z0-9_\/-]*)['"]"""),
]

# HTTP method patterns (to detect which methods are used)
METHOD_PATTERNS = {
    "GET": re.compile(r"""\.get\s*\("""),
    "POST": re.compile(r"""\.post\s*\("""),
    "PUT": re.compile(r"""\.put\s*\("""),
    "DELETE": re.compile(r"""\.delete\s*\("""),
    "PATCH": re.compile(r"""\.patch\s*\("""),
}

# Patterns to skip (not endpoints)
SKIP_PATTERNS = [
    re.compile(r"""node_modules"""),
    re.compile(r"""\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$"""),
    re.compile(r"""webpack"""),
    re.compile(r"""bundle"""),
    re.compile(r"""chunk"""),
    re.compile(r"""favicon"""),
    re.compile(r"""\.min\."""),
    re.compile(r"""^(https?:)?//[a-z0-9.-]+\.(com|org|net|io)/$"""),  # Just a domain
]


async def discover_js_endpoints(target_url: str) -> list[Endpoint]:
    """Discover endpoints embedded in JavaScript files."""
    logger.info("Scanning JavaScript files for embedded endpoints")
    endpoints: list[Endpoint] = []
    client = HttpClient(timeout=10)
    seen_urls: set[str] = set()

    # First, try to find JS files from the page
    try:
        response, _ = await client.get(target_url)
        if response.status_code == 200:
            js_files = _extract_js_files(response.text, target_url)
            logger.info(f"Found {len(js_files)} JS files to analyze")

            for js_url in js_files[:20]:  # Limit to 20 files
                try:
                    js_response, _ = await client.get(js_url)
                    if js_response.status_code == 200:
                        found = _extract_endpoints_from_js(js_response.text, target_url)
                        for ep in found:
                            if ep.path not in seen_urls:
                                seen_urls.add(ep.path)
                                endpoints.append(ep)
                except Exception:
                    continue
    except Exception as e:
        logger.warning(f"Failed to scan JS files: {e}")

    logger.info(f"Extracted {len(endpoints)} endpoints from JS files")
    return endpoints


def _extract_js_files(html: str, base_url: str) -> list[str]:
    """Extract JavaScript file URLs from HTML."""
    # Match script tags with src attribute
    src_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
    matches = re.findall(src_pattern, html, re.IGNORECASE)
    return [urljoin(base_url, src) for src in matches]


def _extract_endpoints_from_js(js_content: str, base_url: str) -> list[Endpoint]:
    """Extract API endpoints from JavaScript source code."""
    endpoints: list[Endpoint] = []
    seen: set[str] = set()

    # Detect HTTP methods used in this JS file
    detected_methods: dict[str, str] = {}
    for method, pattern in METHOD_PATTERNS.items():
        if pattern.search(js_content):
            detected_methods[method.lower()] = method

    for pattern in ENDPOINT_PATTERNS:
        matches = pattern.findall(js_content)
        for match in matches:
            # Skip very short or generic matches
            if len(match) < 3 or match in seen:
                continue
            seen.add(match)

            # Skip common non-endpoint strings
            if any(re.search(skip, match, re.I) for skip in SKIP_PATTERNS):
                continue

            # Skip data URIs, blob URLs, etc.
            if match.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:")):
                continue

            # Determine if this is an absolute or relative URL
            if match.startswith("http"):
                url = match
            elif match.startswith("/"):
                url = f"{base_url.rstrip('/')}{match}"
            else:
                continue  # Skip relative paths without /

            # Determine likely HTTP method from context
            method = "GET"
            # Look at surrounding context for method hints
            for http_method, m_pattern in METHOD_PATTERNS.items():
                # Check if this URL appears near a method call
                context_start = max(0, js_content.find(match) - 100)
                context_end = min(len(js_content), js_content.find(match) + len(match) + 100)
                context = js_content[context_start:context_end]
                if m_pattern.search(context):
                    method = http_method
                    break

            endpoints.append(
                Endpoint(
                    path=url,
                    method=method,
                    source="js-endpoints",
                    confidence=0.65,
                )
            )

    return endpoints
