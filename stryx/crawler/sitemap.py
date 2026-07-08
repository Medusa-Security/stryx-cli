"""Sitemap and robots.txt endpoint discovery."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from stryx.crawler.discovery import Endpoint
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("crawler.sitemap")


async def discover_sitemap(target_url: str) -> list[Endpoint]:
    """Discover endpoints from robots.txt and sitemap.xml."""
    logger.info("Scanning robots.txt and sitemap.xml")
    endpoints: list[Endpoint] = []
    client = HttpClient(timeout=5)

    # Check robots.txt
    try:
        response, _ = await client.get(f"{target_url}/robots.txt")
        if response.status_code == 200:
            text = response.text
            # Extract paths from Disallow and Allow directives
            paths = re.findall(r'(?:Disallow|Allow):\s*(.+)', text)
            for path in paths:
                path = path.strip()
                if path and path != "/":
                    endpoints.append(Endpoint(
                        path=f"{target_url}{path}",
                        method="GET",
                        source="robots.txt",
                        confidence=0.8,
                    ))

            # Extract sitemap URLs
            sitemap_urls = re.findall(r'Sitemap:\s*(.+)', text)
            for sitemap_url in sitemap_urls:
                sitemap_url = sitemap_url.strip()
                sitemap_endpoints = await _parse_sitemap(client, sitemap_url)
                endpoints.extend(sitemap_endpoints)
    except Exception as e:
        logger.warning(f"Failed to check robots.txt: {e}")

    # Check common sitemap locations
    sitemap_paths = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt"]
    for path in sitemap_paths:
        url = f"{target_url}{path}"
        try:
            response, _ = await client.get(url)
            if response.status_code == 200:
                sitemap_endpoints = await _parse_sitemap_content(client, response.text, target_url)
                endpoints.extend(sitemap_endpoints)
        except Exception:
            continue

    return endpoints


async def _parse_sitemap(client: HttpClient, sitemap_url: str) -> list[Endpoint]:
    """Parse a sitemap XML file for URLs."""
    try:
        response, _ = await client.get(sitemap_url)
        if response.status_code == 200:
            return await _parse_sitemap_content(client, response.text, sitemap_url)
    except Exception:
        pass
    return []


async def _parse_sitemap_content(
    client: HttpClient, content: str, source_url: str
) -> list[Endpoint]:
    """Parse sitemap XML content for URLs."""
    endpoints: list[Endpoint] = []

    # Simple XML URL extraction
    urls = re.findall(r'<loc>(.*?)</loc>', content)
    target_host = urlparse(source_url).hostname

    for url in urls:
        parsed = urlparse(url)
        if parsed.hostname == target_host or not parsed.hostname:
            path = parsed.path or "/"
            endpoints.append(Endpoint(
                path=f"{parsed.scheme}://{parsed.netloc}{path}",
                method="GET",
                source="sitemap",
                confidence=0.7,
            ))

    return endpoints
