"""Logging configuration for STRYX using Rich."""

from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Custom theme for STRYX
STRYX_THEME = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "critical": "bold white on red",
        "success": "bold green",
        "severity.critical": "bold red",
        "severity.high": "red",
        "severity.medium": "yellow",
        "severity.low": "blue",
        "severity.info": "dim",
    }
)

console = Console(theme=STRYX_THEME)


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure Rich-based logging for STRYX."""
    logger = logging.getLogger("stryx")
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    handler = RichHandler(
        console=console,
        show_path=False,
        show_time=True,
        markup=True,
        rich_tracebacks=True,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)

    return logger


def get_logger(name: str = "stryx") -> logging.Logger:
    """Get a named logger under the stryx namespace."""
    return logging.getLogger(f"stryx.{name}" if name != "stryx" else "stryx")
