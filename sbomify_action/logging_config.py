"""Logging configuration for sbomify-action."""

import logging
import os
import sys
from typing import Any, Dict

from rich.logging import RichHandler

from .console import IS_CI, IS_GITHUB_ACTIONS, console


def setup_logging(level: str = "INFO", structured: bool = False, use_rich: bool = True) -> logging.Logger:
    """
    Set up logging configuration with Rich integration.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        structured: Whether to use structured JSON logging (disables Rich)
        use_rich: Whether to use Rich handler (default True, disabled if structured=True)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("sbomify_action")

    # Avoid duplicate handlers
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, level.upper()))

    handler: logging.Handler
    if structured:
        # Structured JSON logging for production/parsing
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(getattr(logging, level.upper()))
        formatter: logging.Formatter = StructuredFormatter()
        handler.setFormatter(formatter)
    elif use_rich:
        # Rich handler for beautiful output
        # In CI, show slightly more compact format
        handler = RichHandler(
            console=console,
            show_time=not IS_GITHUB_ACTIONS,  # GHA has its own timestamps
            show_path=False,
            rich_tracebacks=True,
            tracebacks_show_locals=not IS_CI,  # Don't show locals in CI (too verbose)
            markup=True,
        )
        handler.setLevel(getattr(logging, level.upper()))
    else:
        # Fallback to simple formatter
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(getattr(logging, level.upper()))
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s - %(name)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        import json
        from datetime import datetime

        log_entry: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


def get_verbose_mode() -> bool:
    """Check if verbose mode is enabled via environment variable."""
    verbose = os.getenv("VERBOSE", "false").lower()
    return verbose in ("true", "1", "yes", "on")


# Global logger instance
logger = setup_logging()
