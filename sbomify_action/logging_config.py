"""Logging configuration for sbomify-action."""

import logging
import os
import re
import sys
from typing import Any, Dict

from rich.logging import RichHandler

from ._runtime import get_platform
from .console import console

# Terminal escape sequences and other control characters. cdxgen colours its
# diagnostics, and the escape bytes end up inside the log message (and
# therefore inside the Sentry issue title). Colour codes are not the only
# thing that arrives here, though: a generator that fetches over git relays
# whatever the remote sent on the sideband (CVE-2024-52005,
# CVE-2018-1000021), so a malicious server can put OSC, DCS or bare carriage
# returns in a failing generator's stderr to retitle, hide or spoof lines in
# a terminal reading the log. Strip every escape sequence (7-bit and C1) and
# every control character except tab and newline.
ESCAPE_RE = re.compile(
    r"""
      \x1b\[[0-?]*[\x20-/]*[@-~]                    # CSI, e.g. colours
    | \x1b[\]PX^_][^\x07\x1b]*(?:\x07|\x1b\\)?      # OSC, DCS, SOS, PM, APC
    | \x1b[\x20-/]*[0-~]                            # other two-byte escapes
    | [\x00-\x08\x0b-\x1f\x7f-\x9f]                 # remaining C0/C1, incl. CR
    """,
    re.VERBOSE,
)

# The GitHub Actions runner treats any output line starting with ``::`` as a
# workflow command (``::add-mask::``, ``::error::``, ``::stop-commands::``).
# Logged text from a tool or a remote can span lines, so a line it controls
# could issue one. A zero-width space after the first colon keeps the line
# readable but stops the runner from parsing it.
_WORKFLOW_COMMAND_RE = re.compile(r"^(\s*):(?=:)", re.MULTILINE)


def sanitize_log_text(text: str) -> str:
    """Make text safe to write to a terminal or CI log.

    Strips escape sequences and control characters (keeping tab and
    newline) and defuses lines that a CI runner would read as a workflow
    command.
    """
    return _WORKFLOW_COMMAND_RE.sub("\\1:\u200b", ESCAPE_RE.sub("", text))


class SanitizingFilter(logging.Filter):
    """Apply :func:`sanitize_log_text` to every record a handler emits.

    Log messages interpolate text the action does not control: generator
    stderr, git ref names from a submodule remote, server error bodies.
    Sanitizing at the handler covers every call site, including ones added
    later.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        clean = sanitize_log_text(message)
        if clean != message:
            record.msg = clean
            record.args = None
        return True


#: Most logged warnings one run raises as annotations. GitHub shows ten warning
#: annotations per step at most, and the job summary carries the full count.
MAX_WARNING_ANNOTATIONS = 10


class WarningAnnotations(logging.Handler):
    """Raise logged warnings as CI annotations, a few per run at most.

    A run-level warning -- a substituted lock file, an invalid sbomify.json --
    is easy to miss in a green run's log, so it goes on the run page too. Each
    call site is raised once at most: a warning logged for every component (a
    registry timeout, say) becomes one annotation, never one per component.
    Every warning is counted, annotated or not, for the job summary.

    Whether to annotate is the platform's call; elsewhere this only counts.
    """

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.addFilter(SanitizingFilter())
        self.reset()

    def reset(self) -> None:
        """Forget every warning seen so far."""
        self.count = 0
        self.annotated = 0
        self._sites: set[tuple[str, int]] = set()

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno != logging.WARNING:
            return  # warnings only: a failed run already ends with an error annotation
        self.count += 1
        site = (record.pathname, record.lineno)
        if site in self._sites or self.annotated >= MAX_WARNING_ANNOTATIONS:
            return
        try:
            formatter = get_platform().log_formatter()
            if formatter.annotates_warnings:
                self._sites.add(site)
                self.annotated += 1
                formatter.warning(record.getMessage())
        except Exception:
            self.handleError(record)


#: The one instance, attached to the sbomify_action logger by setup_logging().
warning_annotations = WarningAnnotations()


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
            # Messages carry text from tools and remotes, so Rich must not
            # parse it: ``[link=...]`` would become a terminal hyperlink.
            markup=False,
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

    handler.addFilter(SanitizingFilter())
    logger.addHandler(handler)
    logger.addHandler(warning_annotations)

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
