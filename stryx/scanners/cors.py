"""CORS misconfiguration scanner."""

from __future__ import annotations

from stryx.utils.evidence import Finding, Severity
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("scanner.cors")


class CorsScanner:
    """Scanner for CORS misconfiguration vulnerabilities."""

    def __init__(self, client: HttpClient):
        self.client = client

    async def scan(self, base_url: str) -> list[Finding]:
        """Run CORS tests against the target."""
        findings: list[Finding] = []
        logger.info("Running CORS scanner")

        # Extract domain from base URL
        domain = base_url.split("//")[-1].split("/")[0].split(":")[0]

        # Test various origin patterns
        test_origins = [
            # Evil domains
            ("https://evil.com", "external evil domain"),
            ("https://attacker.com", "external attacker domain"),
            # Null origin (sandboxed iframes, file:// protocol)
            ("null", "null origin"),
            # Subdomain attacks
            (f"https://{domain}.evil.com", "subdomain takeover"),
            (f"https://evil{domain}", "domain prefix"),
            (f"https://{domain}evil.com", "domain suffix"),
            # HTTP downgrade
            (f"http://{domain}", "HTTP downgrade"),
            # Unicode/Punycode
            (f"https://evil{domain}.com", "homograph domain"),
        ]

        seen_origins: set[str] = set()

        for origin, desc in test_origins:
            if origin in seen_origins:
                continue
            seen_origins.add(origin)

            try:
                response, evidence = await self.client.get(
                    base_url,
                    headers={"Origin": origin},
                )

                acao = response.headers.get("access-control-allow-origin", "")
                acac = response.headers.get("access-control-allow-credentials", "")

                if not acao:
                    continue

                # Check for dangerous patterns
                finding = self._check_origin_reflection(origin, acao, acac, desc, evidence)
                if finding:
                    findings.append(finding)

                # Check for wildcard with credentials (very dangerous)
                finding = self._check_wildcard_credentials(acao, acac, evidence)
                if finding:
                    findings.append(finding)

            except Exception as e:
                logger.debug(f"CORS test error: {e}")

        logger.info(f"CORS scanner found {len(findings)} findings")
        return findings

    def _check_origin_reflection(
        self,
        origin: str,
        acao: str,
        acac: str,
        desc: str,
        evidence,
    ) -> Finding | None:
        """Check if origin is reflected in ACAO header."""
        if acao == origin or acao == "null":
            severity = Severity.MEDIUM
            if acac.lower() == "true":
                severity = Severity.HIGH

            evidence.confidence = 0.8
            evidence.payload = f"Origin: {origin}"
            return Finding(
                title=f"CORS reflects {desc} origin: {origin}",
                severity=severity,
                evidence=evidence,
                description=(
                    f"The server reflects the Origin header '{origin}' in "
                    f"Access-Control-Allow-Origin. "
                    f"Credentials allowed: {acac}. "
                    f"This allows cross-origin requests from {desc}."
                ),
                remediation=(
                    "Whitelist specific trusted origins. "
                    "Never reflect arbitrary origins when credentials are allowed."
                ),
                cwe="CWE-942",
                owasp="A05:2021 - Security Misconfiguration",
                scanner="cors",
                tags=["cors", "misconfiguration", desc.replace(" ", "-")],
            )
        return None

    def _check_wildcard_credentials(
        self,
        acao: str,
        acac: str,
        evidence,
    ) -> Finding | None:
        """Check for wildcard ACAO with credentials (very dangerous)."""
        if acao == "*" and acac.lower() == "true":
            evidence.confidence = 0.9
            evidence.payload = "Access-Control-Allow-Origin: *, Credentials: true"
            return Finding(
                title="CORS: wildcard with credentials",
                severity=Severity.CRITICAL,
                evidence=evidence,
                description=(
                    "The server returns Access-Control-Allow-Origin: * with "
                    "Access-Control-Allow-Credentials: true. This is a critical "
                    "misconfiguration that allows any origin to make credentialed requests."
                ),
                remediation=(
                    "Remove wildcard CORS or disable credentials. " "Whitelist specific trusted origins instead."
                ),
                cwe="CWE-942",
                owasp="A05:2021 - Security Misconfiguration",
                scanner="cors",
                tags=["cors", "wildcard", "credentials"],
            )
        elif acao == "*":
            evidence.confidence = 0.5
            return Finding(
                title="CORS: wildcard Access-Control-Allow-Origin",
                severity=Severity.LOW,
                evidence=evidence,
                description="The server returns Access-Control-Allow-Origin: * for all requests.",
                remediation="Restrict CORS to specific trusted origins.",
                cwe="CWE-942",
                owasp="A05:2021 - Security Misconfiguration",
                scanner="cors",
                tags=["cors", "wildcard"],
            )
        return None
