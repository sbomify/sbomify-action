"""Logging configuration for sbomify-action."""

import logging
import os
import sys
from typing import Any, Dict

from rich.logging import RichHandler

from ._runtime import get_platform
from .console import console


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
        # Resolved once: two calls could disagree if the environment or an
        # override changed between them, and one handler must not be half
        # configured for one platform and half for another.
        platform = get_platform()
        handler = RichHandler(
            console=console,
            # Platforms that timestamp every log line themselves ask us not to.
            show_time=platform.log_formatter().show_log_time,
            show_path=False,
            rich_tracebacks=True,
            # Frame locals are too verbose for a build log, and can carry
            # secrets. Asked of the platform rather than an import-time
            # snapshot, so every CI system we recognise is covered.
            tracebacks_show_locals=not platform.is_ci,
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


#: Key set on a log record (via ``extra=``) to say that an ERROR-level record
#: is already accounted for and must not become a Sentry event.
#:
#: Two kinds of record carry it. A *user-side* condition -- an OIDC binding
#: that was never created, a Dependency Track project the user never named --
#: is not a defect in the action, and the message already says what to change.
#: A *step-level echo* -- "Step 5 (upload) failed: ..." -- only re-states a
#: failure that was logged one layer down, so reporting it again doubles every
#: issue and, worse, smuggles the occurrence past the classification the first
#: record was subject to: a 403 correctly dropped at the upload line came back
#: as the largest issue in the project because the step that wrapped it said
#: only "Upload failed for destination(s): sbomify".
#:
#: Sentry's logging integration copies unrecognised record attributes into
#: ``event["extra"]``, which is where ``initialize_sentry``'s ``before_send``
#: looks for this. The record itself is untouched -- the user still sees the
#: error, at error level, in the build log.
TELEMETRY_SKIP_KEY = "sbomify_telemetry_skip"


def skip_telemetry() -> dict[str, bool]:
    """``extra=`` payload marking a log record as "not for Sentry".

    A fresh dict each call: ``logging`` copies it into the record, and a
    shared constant would be one accidental ``update()`` away from marking
    records nobody meant to mark.
    """
    return {TELEMETRY_SKIP_KEY: True}


def already_reported(exc: BaseException) -> dict[str, bool] | None:
    """``extra=`` for a log record that only re-states ``exc``.

    Returns the skip marker when the occurrence is already accounted for --
    the layer that raised it logged it at error level
    (``telemetry_reported``), or the type says it is the user's to fix
    (``user_side``, the same classification ``before_send`` applies to the
    exception itself). Returns ``None`` -- the ``logging`` default --
    otherwise, so a failure that surfaces for the first time at a step
    boundary is still reported exactly once.
    """
    if getattr(exc, "telemetry_reported", False) or getattr(exc, "user_side", False):
        return skip_telemetry()
    return None
