"""AI-powered attack planner.

Uses AI providers to analyze findings and construct attack chains.
Falls back to rule-based chain building if AI is unavailable.
Generates per-finding remediation via AI when available.
"""

from __future__ import annotations

import json

from stryx.ai.prompts import (
    ATTACK_CHAIN_PROMPT,
    REMEDIATION_PROMPT,
    SYSTEM_PROMPT,
    format_findings_for_prompt,
)
from stryx.ai.providers import AIProvider, get_provider
from stryx.attacks.attack_chain import AttackChain, ChainBuilder
from stryx.utils.evidence import Finding
from stryx.utils.logging import get_logger

logger = get_logger("ai.attack_planner")


class AttackPlanner:
    """AI-assisted attack chain planner."""

    def __init__(
        self,
        provider_name: str = "groq",
        model: str | None = None,
        api_key: str | None = None,
    ):
        self.provider_name = provider_name
        self.model = model
        self.api_key = api_key
        self._provider: AIProvider | None = None

    def _get_provider(self) -> AIProvider | None:
        """Get or create the AI provider."""
        if self._provider is None:
            try:
                self._provider = get_provider(
                    self.provider_name,
                    api_key=self.api_key,
                    model=self.model,
                )
            except Exception as e:
                logger.warning(f"Failed to initialize AI provider: {e}")
                return None
        return self._provider

    async def plan_attack_chains(self, findings: list[Finding]) -> list[AttackChain]:
        """Plan attack chains using AI or rule-based fallback."""
        if not findings:
            logger.info("No findings to analyze")
            return []

        # Always build rule-based chains as a baseline
        builder = ChainBuilder(findings)
        chains = builder.build_chains()

        # Try AI-enhanced planning
        provider = self._get_provider()
        if provider and self.api_key:
            try:
                ai_chains = await self._ai_plan_chains(findings, provider)
                if ai_chains:
                    chains.extend(ai_chains)
                    logger.info(f"AI generated {len(ai_chains)} additional attack chains")
            except Exception as e:
                logger.warning(f"AI attack planning failed, using rule-based chains: {e}")

            # Generate AI remediation for findings
            try:
                await self._generate_remediation(findings, provider)
            except Exception as e:
                logger.warning(f"AI remediation generation failed: {e}")
        else:
            logger.info("AI provider not configured, using rule-based attack chains only")

        return chains

    async def _generate_remediation(self, findings: list[Finding], provider: AIProvider) -> None:
        """Generate AI-powered remediation for each finding."""
        logger.info(f"Generating remediation for {len(findings)} findings")

        # Process findings in batches to avoid token limits
        batch_size = 10
        for i in range(0, len(findings), batch_size):
            batch = findings[i : i + batch_size]

            for finding in batch:
                if finding.remediation:
                    continue  # Skip if already has remediation

                try:
                    prompt = REMEDIATION_PROMPT.format(
                        title=finding.title,
                        severity=finding.severity.value,
                        cwe=finding.cwe,
                        endpoint=finding.endpoint,
                        description=finding.description,
                    )

                    response = await provider.generate(prompt, SYSTEM_PROMPT)
                    if not response:
                        continue

                    # Parse response
                    response = response.strip()
                    if response.startswith("```"):
                        response = response.split("\n", 1)[1]
                        if response.endswith("```"):
                            response = response[:-3]

                    data = json.loads(response)
                    if isinstance(data, dict):
                        fix = data.get("fix", "")
                        if fix:
                            finding.remediation = fix
                            logger.debug(f"Generated remediation for: {finding.title}")

                except (json.JSONDecodeError, ValueError, Exception) as e:
                    logger.debug(f"Failed to generate remediation for {finding.title}: {e}")
                    continue

    async def _ai_plan_chains(self, findings: list[Finding], provider: AIProvider) -> list[AttackChain]:
        """Use AI to generate attack chains."""
        findings_data = [f.to_dict() for f in findings]
        findings_text = format_findings_for_prompt(findings_data)

        prompt = ATTACK_CHAIN_PROMPT.format(findings_json=findings_text)

        response = await provider.generate(prompt, SYSTEM_PROMPT)
        if not response:
            return []

        # Parse AI response
        try:
            # Try to extract JSON from response
            response = response.strip()
            if response.startswith("```"):
                response = response.split("\n", 1)[1]
                if response.endswith("```"):
                    response = response[:-3]

            chains_data = json.loads(response)
            if not isinstance(chains_data, list):
                return []

            chains: list[AttackChain] = []
            for chain_data in chains_data:
                if not isinstance(chain_data, dict):
                    continue

                chain = AttackChain(
                    name=chain_data.get("name", "AI-Generated Chain"),
                    total_impact=chain_data.get("total_impact", ""),
                    estimated_severity=chain_data.get("estimated_severity", "high"),
                )

                for step_data in chain_data.get("steps", []):
                    if isinstance(step_data, dict):
                        # Find matching finding
                        matching_finding = self._find_matching_finding(findings, step_data.get("title", ""))
                        if matching_finding:
                            chain.add_step(
                                matching_finding,
                                step_data.get("description", ""),
                                step_data.get("impact", ""),
                            )

                if chain.steps:
                    chains.append(chain)

            return chains

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse AI response: {e}")
            return []

    def _find_matching_finding(self, findings: list[Finding], title: str) -> Finding | None:
        """Find a finding matching the given title."""
        title_lower = title.lower()
        for f in findings:
            if title_lower in f.title.lower() or f.title.lower() in title_lower:
                return f
        # Fallback: return first finding
        return findings[0] if findings else None
