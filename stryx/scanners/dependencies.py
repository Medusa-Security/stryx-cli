"""JavaScript dependency scanner.

Analyzes frontend JavaScript files to detect known vulnerable libraries
and versions. Identifies supply chain vulnerabilities in frontend dependencies.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from stryx.utils.evidence import Evidence, Finding, Severity
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("scanner.dependencies")

# Path to known vulnerabilities database
VULN_DB_PATH = Path(__file__).parent.parent / "signatures" / "known_vulns.yaml"


def _load_vuln_db() -> dict[str, Any]:
    """Load the known vulnerabilities database."""
    if VULN_DB_PATH.exists():
        try:
            with open(VULN_DB_PATH, encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return data if isinstance(data, dict) else {}
        except Exception:
            logger.warning("Failed to load vulnerability database")
    return {}


def _version_tuple(version_str: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple."""
    # Remove pre-release suffixes
    clean = re.split(r"[-+]", version_str)[0]
    parts = []
    for part in clean.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            break
    return tuple(parts) if parts else (0,)


# Patterns to extract library names and versions from JS files
VERSION_PATTERNS = [
    # jQuery
    (re.compile(r"jquery[/-](\d+\.\d+\.\d+)", re.I), "jQuery"),
    (re.compile(r"jQuery v(\d+\.\d+\.\d+)", re.I), "jQuery"),
    (re.compile(r"@version (\d+\.\d+\.\d+).*jquery", re.I), "jQuery"),
    # Angular
    (re.compile(r"angular[/-](\d+\.\d+\.\d+)", re.I), "Angular"),
    (re.compile(r"angular\.js v(\d+\.\d+\.\d+)", re.I), "Angular"),
    (re.compile(r"@version (\d+\.\d+\.\d+).*angular", re.I), "Angular"),
    # React
    (re.compile(r"react[/-](\d+\.\d+\.\d+)", re.I), "React"),
    (re.compile(r"React v(\d+\.\d+\.\d+)", re.I), "React"),
    # Vue
    (re.compile(r"vue[/-](\d+\.\d+\.\d+)", re.I), "Vue.js"),
    (re.compile(r"Vue\.js v(\d+\.\d+\.\d+)", re.I), "Vue.js"),
    # Lodash
    (re.compile(r"lodash[/-](\d+\.\d+\.\d+)", re.I), "Lodash"),
    (re.compile(r"@version (\d+\.\d+\.\d+).*lodash", re.I), "Lodash"),
    # Bootstrap
    (re.compile(r"bootstrap[/-](\d+\.\d+\.\d+)", re.I), "Bootstrap"),
    (re.compile(r"Bootstrap v(\d+\.\d+\.\d+)", re.I), "Bootstrap"),
    # Moment.js
    (re.compile(r"moment[/-](\d+\.\d+\.\d+)", re.I), "Moment.js"),
    (re.compile(r"@version (\d+\.\d+\.\d+).*moment", re.I), "Moment.js"),
    # Underscore
    (re.compile(r"underscore[/-](\d+\.\d+\.\d+)", re.I), "Underscore.js"),
    (re.compile(r"@version (\d+\.\d+\.\d+).*underscore", re.I), "Underscore.js"),
    # Backbone
    (re.compile(r"backbone[/-](\d+\.\d+\.\d+)", re.I), "Backbone.js"),
    # Ember
    (re.compile(r"ember[/-](\d+\.\d+\.\d+)", re.I), "Ember.js"),
    # Mootools
    (re.compile(r"mootools[/-](\d+\.\d+\.\d+)", re.I), "MooTools"),
    # Dojo
    (re.compile(r"dojo[/-](\d+\.\d+\.\d+)", re.I), "Dojo"),
    # ExtJS
    (re.compile(r"extjs[/-](\d+\.\d+\.\d+)", re.I), "ExtJS"),
    # Prototype
    (re.compile(r"prototype[/-](\d+\.\d+\.\d+)", re.I), "Prototype.js"),
    # Three.js
    (re.compile(r"three[/-]js[/-](\d+\.\d+\.\d+)", re.I), "Three.js"),
    (re.compile(r"three\.js v(\d+\.\d+\.\d+)", re.I), "Three.js"),
    # D3
    (re.compile(r"d3[/-](\d+\.\d+\.\d+)", re.I), "D3.js"),
    (re.compile(r"d3\.js v(\d+\.\d+\.\d+)", re.I), "D3.js"),
    # Chart.js
    (re.compile(r"chart[/-]js[/-](\d+\.\d+\.\d+)", re.I), "Chart.js"),
    # Lodash (already covered above, but CDN pattern)
    (re.compile(r"cdn.*lodash.*?/(\d+\.\d+\.\d+)/lodash", re.I), "Lodash"),
    # jQuery CDN
    (re.compile(r"cdn.*jquery.*?/(\d+\.\d+\.\d+)/jquery", re.I), "jQuery"),
    # Generic version comment pattern
    (re.compile(r"@version\s+(\d+\.\d+\.\d+)"), "Unknown"),
    (re.compile(r"v(\d+\.\d+\.\d+)\s"), "Unknown"),
]

# Patterns to detect library name from file path
LIBRARY_PATH_PATTERNS = [
    (re.compile(r"/jquery[-.]?(\d+\.\d+\.\d+)", re.I), "jQuery"),
    (re.compile(r"/angular[-.]?(\d+\.\d+\.\d+)", re.I), "Angular"),
    (re.compile(r"/react[-.]?(\d+\.\d+\.\d+)", re.I), "React"),
    (re.compile(r"/vue[-.]?(\d+\.\d+\.\d+)", re.I), "Vue.js"),
    (re.compile(r"/lodash[-.]?(\d+\.\d+\.\d+)", re.I), "Lodash"),
    (re.compile(r"/bootstrap[-.]?(\d+\.\d+\.\d+)", re.I), "Bootstrap"),
    (re.compile(r"/moment[-.]?(\d+\.\d+\.\d+)", re.I), "Moment.js"),
    (re.compile(r"/underscore[-.]?(\d+\.\d+\.\d+)", re.I), "Underscore.js"),
]


class DependencyScanner:
    """Scanner for vulnerable JavaScript dependencies."""

    def __init__(self, client: HttpClient):
        self.client = client
        self._vuln_db = _load_vuln_db()

    async def scan(
        self,
        endpoints: list[str],
        base_url: str,
    ) -> list[Finding]:
        """Scan for vulnerable JavaScript dependencies."""
        findings: list[Finding] = []
        logger.info("Running dependency scanner")

        seen_libraries: set[str] = set()

        # Scan each endpoint for JS files
        for endpoint in endpoints[:5]:  # Limit to 5 pages
            try:
                response, _ = await self.client.get(endpoint)
                if response.status_code != 200:
                    continue

                # Extract script sources
                script_srcs = self._extract_script_sources(response.text, endpoint)

                for js_url, js_content in script_srcs:
                    # Detect libraries
                    libraries = self._detect_libraries(js_content, js_url)

                    for lib_name, version in libraries:
                        lib_key = f"{lib_name}@{version}"
                        if lib_key in seen_libraries:
                            continue
                        seen_libraries.add(lib_key)

                        # Check against vulnerability database
                        vulns = self._check_vulnerabilities(lib_name, version)
                        for vuln in vulns:
                            findings.append(
                                Finding(
                                    title=f"Vulnerable library: {lib_name} {version} - {vuln['cve']}",
                                    severity=Severity(vuln.get("severity", "high")),
                                    evidence=Evidence(
                                        request_method="GET",
                                        request_url=js_url,
                                        response_status=200,
                                        response_body=f"Library: {lib_name}, Version: {version}",
                                        response_snippet=f"CVE: {vuln['cve']}, Description: {vuln.get('description', 'N/A')}",
                                        confidence=0.9,
                                    ),
                                    description=(
                                        f"The JavaScript library {lib_name} version {version} is installed. "
                                        f"This version has known vulnerabilities: {vuln['cve']}. "
                                        f"{vuln.get('description', '')}"
                                    ),
                                    remediation=(
                                        f"Update {lib_name} to version {vuln.get('fixed_version', 'latest')} "
                                        f"or later. See {vuln.get('reference', 'N/A')} for details."
                                    ),
                                    cwe=vuln.get("cwe", "CWE-1395"),
                                    owasp="A06:2021 - Vulnerable and Outdated Components",
                                    endpoint=endpoint,
                                    scanner="dependencies",
                                    tags=["supply-chain", "vulnerable-dependency", lib_name.lower()],
                                )
                            )

            except Exception as e:
                logger.debug(f"Dependency scan error on {endpoint}: {e}")

        logger.info(f"Dependency scanner found {len(findings)} findings")
        return findings

    def _extract_script_sources(self, html: str, base_url: str) -> list[tuple[str, str]]:
        """Extract script tag sources from HTML."""
        from urllib.parse import urljoin

        results = []
        pattern = re.compile(
            r'<script[^>]+src=["\']([^"\']+)["\']',
            re.IGNORECASE,
        )

        for match in pattern.finditer(html):
            src = match.group(1)
            if src.startswith(("data:", "javascript:", "blob:")):
                continue

            full_url = urljoin(base_url, src)
            # Only fetch same-origin scripts
            if full_url.startswith(base_url):
                results.append((full_url, ""))  # Content fetched lazily

        return results[:10]  # Limit to 10 scripts

    def _detect_libraries(self, js_content: str, js_url: str) -> list[tuple[str, str]]:
        """Detect library names and versions from JS content or URL."""
        libraries: list[tuple[str, str]] = []

        # Try version patterns on content
        for pattern, lib_name in VERSION_PATTERNS:
            match = pattern.search(js_content)
            if match:
                version = match.group(1)
                if lib_name != "Unknown" or js_url:
                    libraries.append((lib_name if lib_name != "Unknown" else js_url, version))

        # Try path patterns on URL
        for pattern, lib_name in LIBRARY_PATH_PATTERNS:
            match = pattern.search(js_url)
            if match:
                version = match.group(1)
                libraries.append((lib_name, version))

        return libraries

    def _check_vulnerabilities(self, library_name: str, version_str: str) -> list[dict[str, Any]]:
        """Check a library version against the vulnerability database."""
        vulns: list[dict[str, Any]] = []
        version = _version_tuple(version_str)

        # Check built-in vulnerability database
        lib_vulns = self._vuln_db.get(library_name.lower(), {})
        for cve, vuln_data in lib_vulns.items():
            affected_range = vuln_data.get("affected", "")
            fixed_version = vuln_data.get("fixed_version", "")

            if self._version_in_range(version, affected_range, fixed_version):
                vulns.append(
                    {
                        "cve": cve,
                        "severity": vuln_data.get("severity", "high"),
                        "description": vuln_data.get("description", ""),
                        "fixed_version": fixed_version,
                        "reference": vuln_data.get("reference", ""),
                        "cwe": vuln_data.get("cwe", "CWE-1395"),
                    }
                )

        return vulns

    def _version_in_range(self, version: tuple[int, ...], affected: str, fixed: str) -> bool:
        """Check if a version falls within an affected range."""
        try:
            if fixed:
                fixed_tuple = _version_tuple(fixed)
                return version < fixed_tuple
            if affected:
                # Parse range like "<4.17.21" or ">=1.0.0,<2.0.0"
                parts = affected.split(",")
                for part in parts:
                    part = part.strip()
                    if part.startswith("<"):
                        upper = _version_tuple(part[1:])
                        if version >= upper:
                            return False
                    elif part.startswith(">="):
                        lower = _version_tuple(part[2:])
                        if version < lower:
                            return False
                    elif part.startswith(">"):
                        lower = _version_tuple(part[1:])
                        if version <= lower:
                            return False
                    elif part.startswith("<="):
                        upper = _version_tuple(part[1:])
                        if version > upper:
                            return False
                return True
        except Exception:
            pass
        return False
