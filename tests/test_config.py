"""Tests for STRYX configuration."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from stryx.config.schema import StryxConfig, ModuleConfig
from stryx.config.loader import load_config, get_effective_config


class TestStryxConfig:
    """Tests for the StryxConfig schema."""

    def test_default_config(self):
        """Test default configuration values."""
        config = StryxConfig()
        assert config.provider == "groq"
        assert config.model == "openai/gpt-oss-120b"
        assert config.threads == 20
        assert config.timeout == 10
        assert config.crawl_depth == 5
        assert config.respect_robots is False
        assert config.ai_attack_planning is True

    def test_module_defaults(self):
        """Test default module configuration."""
        config = StryxConfig()
        assert config.modules.auth is True
        assert config.modules.authorization is True
        assert config.modules.injection is True
        assert config.modules.fuzzing is True

    def test_thread_validation(self):
        """Test thread count validation."""
        # Valid
        config = StryxConfig(threads=1)
        assert config.threads == 1
        config = StryxConfig(threads=200)
        assert config.threads == 200

        # Invalid
        with pytest.raises(Exception):
            StryxConfig(threads=0)
        with pytest.raises(Exception):
            StryxConfig(threads=201)

    def test_timeout_validation(self):
        """Test timeout validation."""
        config = StryxConfig(timeout=1)
        assert config.timeout == 1
        config = StryxConfig(timeout=120)
        assert config.timeout == 120

        with pytest.raises(Exception):
            StryxConfig(timeout=0)
        with pytest.raises(Exception):
            StryxConfig(timeout=121)

    def test_config_serialization(self):
        """Test config serialization."""
        config = StryxConfig(provider="openai", model="gpt-4")
        data = config.model_dump()
        assert data["provider"] == "openai"
        assert data["model"] == "gpt-4"


class TestConfigLoader:
    """Tests for configuration loading."""

    def test_load_defaults(self):
        """Test loading default config."""
        config = load_config()
        assert config.provider == "groq"
        assert config.threads == 20

    def test_cli_overrides(self):
        """Test CLI overrides."""
        config = load_config({"provider": "openai", "threads": 50})
        assert config.provider == "openai"
        assert config.threads == 50

    def test_none_overrides_ignored(self):
        """Test that None overrides are ignored."""
        config = load_config({"provider": None, "threads": None})
        assert config.provider == "groq"  # default
        assert config.threads == 20  # default

    def test_effective_config(self):
        """Test effective config output."""
        config = load_config()
        effective = get_effective_config(config)
        assert "provider" in effective
        assert "threads" in effective
        assert isinstance(effective, dict)
