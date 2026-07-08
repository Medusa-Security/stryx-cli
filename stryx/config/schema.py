"""Pydantic schema for STRYX configuration."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ModuleConfig(BaseModel):
    """Which scanner modules are enabled."""

    auth: bool = True
    authorization: bool = True
    injection: bool = True
    fuzzing: bool = True
    blind: bool = True
    disclosure: bool = True
    race: bool = True
    cloud_ssrf: bool = True
    dependencies: bool = True


class SessionConfig(BaseModel):
    """Authentication session configuration."""

    username: str | None = None
    password: str | None = None
    login_url: str | None = None


class PolicyConfig(BaseModel):
    """Security policy for CI/CD quality gates."""

    enabled: bool = False
    policy_file: str | None = None
    max_critical: int | None = None
    max_high: int | None = None
    max_medium: int | None = None
    max_low: int | None = None
    max_findings: int | None = None
    blocked_cwe: list[str] = Field(default_factory=list)


class ComparisonConfig(BaseModel):
    """Baseline comparison configuration."""

    enabled: bool = False
    baseline_file: str | None = None


class StryxConfig(BaseModel):
    """Root configuration model with validation."""

    provider: str = Field(default="groq", description="AI provider name")
    model: str = Field(default="openai/gpt-oss-120b", description="AI model identifier")
    api_key: str | None = Field(default=None, description="API key for the AI provider")
    threads: int = Field(default=20, ge=1, le=200, description="Concurrent threads")
    timeout: int = Field(default=10, ge=1, le=120, description="HTTP timeout in seconds")
    crawl_depth: int = Field(default=5, ge=1, le=50, description="Max crawl depth")
    respect_robots: bool = Field(default=False, description="Respect robots.txt rules")
    ai_attack_planning: bool = True
    ai_payload_generation: bool = True
    modules: ModuleConfig = Field(default_factory=ModuleConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    comparison: ComparisonConfig = Field(default_factory=ComparisonConfig)

    # CLI overrides (not from config file)
    target_url: str | None = None
    deep: bool = False
    json_output: str | None = None
    html_output: str | None = None
    markdown_output: str | None = None
    sarif_output: str | None = None
    headers: dict[str, str] | None = None
    cookies: str | None = None
    proxy: str | None = None
    wordlist: str | None = None
    rate: int | None = None
    policy_file: str | None = None
    baseline_file: str | None = None
