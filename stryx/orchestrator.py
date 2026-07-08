"""Attack orchestrator -- coordinates the full scan pipeline.

Pipeline:
Discover Target -> Crawl Application -> Identify Endpoints -> Fingerprint Framework
-> Authenticate (optional) -> Run Scanner Modules -> Generate AI Attack Chains
-> Validate Findings -> Generate Report
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from stryx.ai.attack_planner import AttackPlanner
from stryx.config.schema import StryxConfig
from stryx.crawler.discovery import DiscoveryAggregator, Endpoint
from stryx.reports.generator import ReportGenerator
from stryx.scanners.auth import AuthScanner
from stryx.scanners.authorization import AuthorizationScanner
from stryx.scanners.blind import BlindScanner
from stryx.scanners.cloud_ssrf import CloudSSRFScanner
from stryx.scanners.cors import CorsScanner
from stryx.scanners.dependencies import DependencyScanner
from stryx.scanners.disclosure import DisclosureScanner
from stryx.scanners.fuzz import FuzzScanner
from stryx.scanners.graphql import GraphQLScanner
from stryx.scanners.injection import InjectionScanner
from stryx.scanners.race import RaceScanner
from stryx.utils.evidence import Finding
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("orchestrator")


@dataclass
class ScanContext:
    """Shared state object passed between all modules during a scan."""

    target_url: str
    endpoints: list[Endpoint] = field(default_factory=list)
    endpoint_urls: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    graphql_endpoints: list[str] = field(default_factory=list)
    cookies: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    framework: str | None = None
    auth_tokens: dict[str, str] = field(default_factory=dict)
    session_headers: dict[str, str] = field(default_factory=dict)


class Orchestrator:
    """Coordinates the full STRYX scan pipeline."""

    def __init__(self, config: StryxConfig):
        self.config = config
        self.context = ScanContext(
            target_url=config.target_url or "",
            cookies=config.cookies or "",
            headers=config.headers or {},
        )
        self.client = HttpClient(
            timeout=config.timeout,
            proxy=config.proxy,
            rate_limit=config.rate,
            headers=config.headers,
            cookies=config.cookies,
        )
        self._semaphore: asyncio.Semaphore | None = None

    async def run(self) -> list[Finding]:
        """Execute the full scan pipeline."""
        logger.info(f"Starting STRYX scan against {self.context.target_url}")

        # Set up concurrency control based on threads config
        if self.config.threads and self.config.threads > 1:
            self._semaphore = asyncio.Semaphore(self.config.threads)
            logger.info(f"Concurrency limit: {self.config.threads} threads")

        # Stage 1: Discover endpoints
        await self._stage_discover()

        # Stage 2: Fingerprint framework
        await self._stage_fingerprint()

        # Stage 2.5: Authenticate (if credentials provided)
        await self._stage_authenticate()

        # Stage 3: Run scanner modules
        await self._stage_scan()

        # Stage 4: Generate AI attack chains
        attack_chains = await self._stage_attack_planning()

        # Stage 5: Generate reports
        self._stage_report(attack_chains)

        logger.info(f"Scan complete. {len(self.context.findings)} findings.")
        return self.context.findings

    async def _stage_discover(self) -> None:
        """Stage 1: Crawl and discover endpoints."""
        logger.info("Stage 1: Discovering endpoints")

        # Apply --deep flag: increase crawl depth
        depth = self.config.crawl_depth
        if self.config.deep:
            depth = max(depth, 15)
            logger.info(f"Deep mode: crawl depth increased to {depth}")

        aggregator = DiscoveryAggregator(
            self.context.target_url,
            depth=depth,
            wordlist=self.config.wordlist,
            respect_robots=self.config.respect_robots,
        )
        endpoints = await aggregator.discover()

        self.context.endpoints = endpoints
        self.context.endpoint_urls = [ep.path for ep in endpoints]

        # Separate GraphQL endpoints
        for ep in endpoints:
            if "graphql" in ep.source.lower():
                self.context.graphql_endpoints.append(ep.path)

        # If no endpoints found, at least test the base URL
        if not self.context.endpoint_urls:
            self.context.endpoint_urls = [self.context.target_url]
            logger.info("No endpoints discovered, testing base URL")

    async def _stage_fingerprint(self) -> None:
        """Stage 2: Fingerprint the target framework."""
        logger.info("Stage 2: Fingerprinting framework")

        try:
            response, _ = await self.client.get(self.context.target_url)
            scanner = InjectionScanner(self.client)
            self.context.framework = scanner.fingerprint_framework(
                dict(response.headers), response.text
            )
            if self.context.framework:
                logger.info(f"Detected framework: {self.context.framework}")
        except Exception as e:
            logger.warning(f"Fingerprinting failed: {e}")

    async def _stage_authenticate(self) -> None:
        """Stage 2.5: Authenticate if credentials are provided."""
        session_config = self.config.session
        if not session_config.username or not session_config.password:
            return

        logger.info("Stage 2.5: Authenticating")

        try:
            from stryx.auth.session_manager import SessionManager

            manager = SessionManager(
                client=self.client,
                base_url=self.context.target_url,
                username=session_config.username,
                password=session_config.password,
                login_url=session_config.login_url,
                headers=self.context.headers,
            )

            if await manager.setup():
                self.context.session_headers = manager.get_session_headers()
                self.context.cookies = str(manager.get_session_cookies())
                logger.info("Authentication successful")
            else:
                logger.warning("Authentication failed, continuing unauthenticated")
        except Exception as e:
            logger.warning(f"Authentication error: {e}")

    async def _stage_scan(self) -> None:
        """Stage 3: Run all enabled scanner modules concurrently."""
        logger.info("Stage 3: Running scanner modules")

        endpoints = self.context.endpoint_urls
        base_url = self.context.target_url
        deep = self.config.deep
        modules = self.config.modules

        # Build list of scanner coroutines to run concurrently
        scanner_tasks: list[tuple[str, asyncio.Task]] = []

        async def _safe_run(name: str, coro) -> list[Finding]:
            """Run a scanner and return findings, catching exceptions."""
            try:
                return await coro
            except Exception as e:
                logger.error(f"{name} scanner failed: {e}")
                return []

        # Auth scanner
        if deep or modules.auth:
            auth_scanner = AuthScanner(self.client)
            scanner_tasks.append(("auth", asyncio.create_task(
                _safe_run("Auth", auth_scanner.scan(endpoints, base_url))
            )))

        # Authorization scanner
        if deep or modules.authorization:
            authz_scanner = AuthorizationScanner(self.client)
            scanner_tasks.append(("authorization", asyncio.create_task(
                _safe_run("Authorization", authz_scanner.scan(endpoints, base_url, self.context.cookies))
            )))

        # Injection scanner
        if deep or modules.injection:
            injection_scanner = InjectionScanner(self.client)
            if self.context.framework:
                injection_scanner.framework = self.context.framework
            scanner_tasks.append(("injection", asyncio.create_task(
                _safe_run("Injection", injection_scanner.scan(endpoints, base_url))
            )))

        # Fuzz scanner
        if deep or modules.fuzzing:
            fuzz_scanner = FuzzScanner(self.client)
            scanner_tasks.append(("fuzz", asyncio.create_task(
                _safe_run("Fuzz", fuzz_scanner.scan(endpoints, base_url))
            )))

        # CORS scanner (always runs)
        cors_scanner = CorsScanner(self.client)
        scanner_tasks.append(("cors", asyncio.create_task(
            _safe_run("CORS", cors_scanner.scan(base_url))
        )))

        # GraphQL scanner
        if self.context.graphql_endpoints:
            graphql_scanner = GraphQLScanner(self.client)
            scanner_tasks.append(("graphql", asyncio.create_task(
                _safe_run("GraphQL", graphql_scanner.scan(self.context.graphql_endpoints))
            )))

        # === NEW SCANNERS ===

        # Blind injection scanner
        if deep or modules.blind:
            blind_scanner = BlindScanner(self.client)
            scanner_tasks.append(("blind", asyncio.create_task(
                _safe_run("Blind", blind_scanner.scan(endpoints, base_url))
            )))

        # Information disclosure scanner
        if deep or modules.disclosure:
            disclosure_scanner = DisclosureScanner(self.client)
            scanner_tasks.append(("disclosure", asyncio.create_task(
                _safe_run("Disclosure", disclosure_scanner.scan(endpoints, base_url))
            )))

        # Race condition scanner
        if deep or modules.race:
            race_scanner = RaceScanner(self.client)
            scanner_tasks.append(("race", asyncio.create_task(
                _safe_run("Race", race_scanner.scan(endpoints, base_url))
            )))

        # Cloud metadata SSRF scanner
        if deep or modules.cloud_ssrf:
            cloud_ssrf_scanner = CloudSSRFScanner(self.client)
            scanner_tasks.append(("cloud-ssrf", asyncio.create_task(
                _safe_run("CloudSSRF", cloud_ssrf_scanner.scan(endpoints, base_url))
            )))

        # JS dependency scanner
        if deep or modules.dependencies:
            dep_scanner = DependencyScanner(self.client)
            scanner_tasks.append(("dependencies", asyncio.create_task(
                _safe_run("Dependencies", dep_scanner.scan(endpoints, base_url))
            )))

        # Wait for all scanners to complete
        if scanner_tasks:
            logger.info(f"Running {len(scanner_tasks)} scanners concurrently")
            names = [name for name, _ in scanner_tasks]
            tasks = [task for _, task in scanner_tasks]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for name, result in zip(names, results):
                if isinstance(result, list):
                    self.context.findings.extend(result)
                    logger.info(f"  {name}: {len(result)} findings")
                elif isinstance(result, Exception):
                    logger.error(f"  {name}: {result}")

    async def _stage_attack_planning(self) -> list:
        """Stage 4: AI-assisted attack chain planning."""
        if not self.config.ai_attack_planning:
            logger.info("AI attack planning disabled, skipping")
            return []

        logger.info("Stage 4: Planning attack chains")

        planner = AttackPlanner(
            provider_name=self.config.provider,
            model=self.config.model,
            api_key=self.config.api_key,
        )

        return await planner.plan_attack_chains(self.context.findings)

    def _stage_report(self, attack_chains: list) -> None:
        """Stage 5: Generate reports."""
        logger.info("Stage 5: Generating reports")

        generator = ReportGenerator(
            self.context.target_url,
            self.context.findings,
            attack_chains,
        )

        # Always show terminal report
        generator.generate_terminal()

        # Generate additional formats if requested
        if self.config.json_output:
            generator.generate_json(self.config.json_output)
        if self.config.html_output:
            generator.generate_html(self.config.html_output)
        if self.config.markdown_output:
            generator.generate_markdown(self.config.markdown_output)

        # SARIF output
        if self.config.sarif_output:
            from stryx.reports.sarif_report import SarifReport
            sarif = SarifReport(self.context.target_url, self.context.findings)
            sarif.save(self.config.sarif_output)

        # Policy evaluation
        if self.config.policy_file:
            from stryx.policy.engine import PolicyEngine
            policy = PolicyEngine.from_file(self.config.policy_file)
            result = policy.evaluate(self.context.findings)
            logger.info(str(result))
            if not result.passed:
                self._policy_failed = True

        # Baseline comparison
        if self.config.baseline_file and self.config.json_output:
            from stryx.comparison.differ import ScanDiffer
            differ = ScanDiffer(self.config.baseline_file, self.config.json_output)
            diff = differ.compare()
            logger.info(diff.summary())
