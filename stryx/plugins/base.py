"""Base scanner plugin interface.

This defines the contract for custom scanner plugins (v0.5+).
The plugin loader will not be functional until v0.5, but the interface
is documented here for contributors who want to plan ahead.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from stryx.utils.evidence import Finding


@dataclass
class PluginMetadata:
    """Metadata for a scanner plugin."""

    name: str
    version: str = "0.1.0"
    author: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)


class BaseScanner(ABC):
    """Abstract base class for scanner plugins.

    All scanner plugins must implement this interface. The plugin loader
    (v0.5) will discover and instantiate classes that extend BaseScanner.

    Required attributes:
        metadata: PluginMetadata with name, version, description.

    Required methods:
        scan(): Run the scan and return a list of Finding objects.
        validate_config(): Validate plugin-specific configuration.
    """

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        ...

    @abstractmethod
    async def scan(
        self,
        target_url: str,
        endpoints: list[str],
        config: dict[str, Any],
    ) -> list[Finding]:
        """Run the security scan.

        Args:
            target_url: The base URL of the target application.
            endpoints: List of discovered endpoint URLs to test.
            config: Plugin-specific configuration dictionary.

        Returns:
            List of Finding objects with full Evidence.
        """
        ...

    @abstractmethod
    def validate_config(self, config: dict[str, Any]) -> bool:
        """Validate plugin-specific configuration.

        Args:
            config: Configuration dictionary to validate.

        Returns:
            True if configuration is valid, False otherwise.
        """
        ...

    def get_required_dependencies(self) -> list[str]:
        """Return list of required Python packages for this plugin.

        Override this if your plugin needs additional dependencies.
        The plugin loader (v0.5) will check these before loading.
        """
        return []
