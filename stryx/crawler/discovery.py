"""Main discovery aggregator -- merges results from all crawler modules."""

from __future__ import annotations

from dataclasses import dataclass, field

from stryx.utils.logging import get_logger

logger = get_logger("crawler.discovery")


@dataclass
class Endpoint:
    """A discovered endpoint with metadata."""

    path: str
    method: str = "GET"
    source: str = "unknown"
    confidence: float = 1.0
    params: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None

    @property
    def url(self) -> str:
        """Full URL if path starts with http, else just the path."""
        return self.path

    def __hash__(self) -> int:
        return hash((self.path.lower(), self.method.upper()))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Endpoint):
            return NotImplemented
        return self.path.lower() == other.path.lower() and self.method.upper() == other.method.upper()


class DiscoveryAggregator:
    """Aggregates endpoint discovery from all crawler modules.

    Merges and deduplicates results into a single Endpoint list.
    """

    def __init__(
        self,
        target_url: str,
        depth: int = 5,
        wordlist: str | None = None,
        respect_robots: bool = False,
    ):
        self.target_url = target_url.rstrip("/")
        self.depth = depth
        self.wordlist = wordlist
        self.respect_robots = respect_robots
        self.endpoints: list[Endpoint] = []

    async def discover(self) -> list[Endpoint]:
        """Run all discovery modules and return merged endpoints."""
        logger.info(f"Starting endpoint discovery for {self.target_url}")

        # 1. Run passive discovery modules in parallel (OpenAPI, Sitemap, GraphQL, external JS)
        from stryx.crawler.graphql_discovery import discover_graphql
        from stryx.crawler.js_endpoints import discover_js_endpoints
        from stryx.crawler.openapi import discover_openapi
        from stryx.crawler.sitemap import discover_sitemap

        passive_tasks = [
            discover_openapi(self.target_url),
            discover_sitemap(self.target_url),
            discover_graphql(self.target_url),
            discover_js_endpoints(self.target_url),
        ]

        import asyncio

        passive_results = await asyncio.gather(*passive_tasks, return_exceptions=True)
        for result in passive_results:
            if isinstance(result, list):
                self.endpoints.extend(result)
            elif isinstance(result, Exception):
                logger.warning(f"Discovery module failed: {result}")

        # 2. Run recursive HTML crawler (follows links, extracts forms)
        from stryx.crawler.html_crawler import HTMLCrawler

        crawler = HTMLCrawler(
            self.target_url,
            max_depth=self.depth,
            max_pages=500,
            respect_robots=self.respect_robots,
        )
        try:
            html_endpoints = await crawler.crawl()
            self.endpoints.extend(html_endpoints)
        except Exception as e:
            logger.warning(f"HTML crawler failed: {e}")

        # 3. Wordlist-based discovery if a wordlist was provided
        if self.wordlist:
            await self._discover_from_wordlist()

        # Deduplicate
        seen: set[tuple[str, str]] = set()
        unique: list[Endpoint] = []
        for ep in self.endpoints:
            key = (ep.path.lower(), ep.method.upper())
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        self.endpoints = unique

        self._log_summary()
        return self.endpoints

    async def _discover_from_wordlist(self) -> None:
        """Discover endpoints from a wordlist file."""
        from pathlib import Path

        wordlist_path = Path(self.wordlist)
        if not wordlist_path.exists():
            logger.warning(f"Wordlist not found: {self.wordlist}")
            return

        logger.info(f"Loading wordlist from {self.wordlist}")
        lines = wordlist_path.read_text().splitlines()
        words = [line.strip() for line in lines if line.strip() and not line.startswith("#")]

        if not words:
            logger.warning("Wordlist is empty")
            return

        logger.info(f"Testing {len(words)} paths from wordlist")

        from stryx.utils.http_client import HttpClient

        client = HttpClient(timeout=5)
        batch_size = 50

        for i in range(0, len(words), batch_size):
            batch = words[i : i + batch_size]
            tasks = []
            for word in batch:
                url = f"{self.target_url}/{word.lstrip('/')}"
                tasks.append(self._probe_path(client, url, f"wordlist:{word}"))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Endpoint):
                    self.endpoints.append(result)

    async def _probe_path(self, client, url: str, source: str) -> Endpoint | None:
        """Probe a single path and return an Endpoint if it exists."""
        try:
            response, _ = await client.get(url)
            if response.status_code < 400:
                return Endpoint(
                    path=url,
                    method="GET",
                    source=source,
                    confidence=0.7,
                )
        except Exception:
            pass
        return None

    def _log_summary(self) -> None:
        """Log endpoint summary statistics."""
        method_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}
        for ep in self.endpoints:
            method = ep.method.upper()
            method_counts[method] = method_counts.get(method, 0) + 1
            source_counts[ep.source] = source_counts.get(ep.source, 0) + 1

        logger.info(f"{len(self.endpoints)} Endpoints")
        for method, count in sorted(method_counts.items(), key=lambda x: -x[1]):
            logger.info(f"  {count} {method}")
        for source, count in sorted(source_counts.items(), key=lambda x: -x[1]):
            logger.info(f"  {count} from {source}")
