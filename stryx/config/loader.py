"""Configuration loader with priority: CLI flags > file config > defaults."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from stryx.config.schema import StryxConfig

_DEFAULT_CONFIG_PATH = Path(__file__).parent / "default_config.yaml"
_USER_CONFIG_PATH = Path.home() / ".stryx" / "config.yaml"
_LOCAL_CONFIG_PATH = Path("stryx.config.yaml")


def _read_yaml(path: Path) -> dict[str, Any]:
    """Read and parse a YAML file, returning empty dict on failure."""
    if path.exists() and path.is_file():
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
                return data if isinstance(data, dict) else {}
        except (yaml.YAMLError, OSError):
            return {}
    return {}


def load_config(cli_overrides: dict[str, Any] | None = None) -> StryxConfig:
    """Load configuration with priority: CLI > user file > local file > defaults.

    Priority order:
    1. CLI flags (passed as cli_overrides)
    2. ~/.stryx/config.yaml (user-level config)
    3. ./stryx.config.yaml (project-level config)
    4. default_config.yaml (built-in defaults)
    """
    # Start with defaults
    defaults = _read_yaml(_DEFAULT_CONFIG_PATH)

    # Layer local project config
    local = _read_yaml(_LOCAL_CONFIG_PATH)

    # Layer user config
    user = _read_yaml(_USER_CONFIG_PATH)

    # Merge: defaults < local < user
    merged: dict[str, Any] = defaults
    for key, value in local.items():
        if key == "modules" and isinstance(value, dict) and isinstance(merged.get("modules"), dict):
            merged["modules"].update(value)
        else:
            merged[key] = value
    for key, value in user.items():
        if key == "modules" and isinstance(value, dict) and isinstance(merged.get("modules"), dict):
            merged["modules"].update(value)
        else:
            merged[key] = value

    # Apply CLI overrides (non-None values only)
    if cli_overrides:
        for key, value in cli_overrides.items():
            if value is not None:
                if key == "modules" and isinstance(value, dict) and isinstance(merged.get("modules"), dict):
                    merged["modules"].update(value)
                else:
                    merged[key] = value

    # Read API key from environment if not set
    if merged.get("api_key") is None:
        provider = merged.get("provider", "groq")
        env_key_map = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "groq": "GROQ_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
            "nvidia_nim": "NVIDIA_NIM_API_KEY",
            "xai": "XAI_API_KEY",
        }
        env_var = env_key_map.get(provider)
        if env_var:
            merged["api_key"] = os.environ.get(env_var)

    # Also check Ollama (no key needed for local)
    if merged.get("provider") == "ollama":
        merged["api_key"] = "ollama"  # dummy key, not needed

    return StryxConfig(**merged)


def get_effective_config(config: StryxConfig) -> dict[str, Any]:
    """Return the resolved effective config as a dictionary (for display)."""
    return config.model_dump(exclude_none=True)


def save_config(config: StryxConfig, path: Path | None = None) -> Path:
    """Save configuration to the user config path."""
    target = path or _USER_CONFIG_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    data = config.model_dump(exclude_none=True)
    # Remove CLI-only fields
    cli_fields = {
        "target_url",
        "deep",
        "json_output",
        "html_output",
        "markdown_output",
        "headers",
        "cookies",
        "proxy",
        "wordlist",
        "rate",
    }
    for field in cli_fields:
        data.pop(field, None)
    with open(target, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    return target
