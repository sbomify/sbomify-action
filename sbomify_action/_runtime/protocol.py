"""Protocols for the CI runtime platform plugin subsystem.

A ``CIPlatform`` carries everything the action knows about the CI system it is
running under: where the checkout lives, how to read VCS metadata, how to format
log output, and how (if at all) to mint an OIDC token.

The rest of the codebase asks the resolved platform rather than reading
``GITHUB_ACTIONS`` (or any other vendor variable) directly. Adding support for a
new CI system means adding one platform, not editing console, logging, path
resolution and telemetry.

Unlike the generation / enrichment / augmentation / upload registries, platform
resolution is *exclusive*: exactly one platform is active per run. The registry
returns the first platform whose ``detects()`` is true, in priority order, and
``LocalPlatform`` (priority 100) always matches as a last resort.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class VcsInfo:
    """Repository coordinates for the commit being built."""

    url: str | None = None
    commit_sha: str | None = None
    ref: str | None = None
    commit_url: str | None = None

    def has_data(self) -> bool:
        """True when at least a repository URL was resolved."""
        return bool(self.url)


class LogFormatter(Protocol):
    """Renders structural log output in the active platform's dialect.

    GitHub Actions gets workflow commands (``::group::``, ``::error::``);
    everything else gets Rich-styled terminal output.
    """

    @property
    def name(self) -> str:
        """Formatter name, for diagnostics."""
        ...

    @property
    def force_terminal(self) -> bool | None:
        """Value for Rich's ``Console(force_terminal=...)``.

        ``True`` where the platform supports ANSI but Rich cannot detect it,
        ``None`` to let Rich decide.
        """
        ...

    @property
    def show_log_time(self) -> bool:
        """Whether the log handler should print its own timestamps.

        False on platforms that already timestamp every log line.
        """
        ...

    def group_start(self, title: str) -> None:
        """Open a collapsible output group (no-op where unsupported)."""
        ...

    def group_end(self) -> None:
        """Close the most recently opened group (no-op where unsupported)."""
        ...

    def step_header(self, title: str) -> None:
        """Render a pipeline step header."""
        ...

    def step_footer(self) -> None:
        """Render whatever closes a pipeline step."""
        ...

    def warning(self, message: str, title: str | None = None) -> None:
        """Emit a warning annotation."""
        ...

    def error(self, message: str, title: str | None = None) -> None:
        """Emit an error annotation."""
        ...

    def notice(self, message: str, title: str | None = None) -> None:
        """Emit an informational annotation."""
        ...

    def final_success(self) -> None:
        """Render the terminal success banner."""
        ...

    def final_failure(self, message: str) -> None:
        """Render the terminal failure banner.

        The error annotation is emitted separately by the caller, so a platform
        whose annotation already says everything can make this a no-op.
        """
        ...


class OidcProvider(Protocol):
    """Mints a CI-provided OIDC JWT for trusted publishing."""

    @property
    def exchange_slug(self) -> str:
        """Path segment identifying this issuer to the sbomify exchange endpoint.

        ``"github"`` maps to ``/api/v1/auth/oidc/github/exchange``.
        """
        ...

    def available(self) -> bool:
        """True when the runner currently exposes an OIDC token endpoint.

        On GitHub Actions this requires ``permissions: id-token: write``, so it
        can be false even when the platform itself is detected.
        """
        ...

    def request_token(self, audience: str) -> str:
        """Mint a JWT with the given ``aud`` claim.

        Raises:
            OIDCExchangeError: if the runner endpoint is unreachable or returns
                an unexpected payload.
        """
        ...


class CIPlatform(Protocol):
    """The CI system this run is executing under.

    Example:
        class GitHubPlatform:
            name = "github-actions"
            priority = 10

            def detects(self) -> bool:
                return _truthy("GITHUB_ACTIONS")
    """

    @property
    def name(self) -> str:
        """Stable platform slug, e.g. ``"github-actions"``.

        Surfaces in audit trails as the augmentation source and in telemetry as
        the ``ci.platform`` tag, so changing it is a user-visible change.
        """
        ...

    @property
    def priority(self) -> int:
        """Detection order (lower wins). Vendor platforms 1-50, generic CI 90, local 100."""
        ...

    @property
    def is_ci(self) -> bool:
        """True for automated builds, False for a developer's machine."""
        ...

    @property
    def confines_working_dir(self) -> bool:
        """Whether ``--working-dir`` must resolve inside :meth:`workspace`.

        True only where the runtime mounts a fixed checkout path that user input
        must not escape (GitHub Actions' container workspace).
        """
        ...

    def detects(self) -> bool:
        """True when the current environment is this platform."""
        ...

    def workspace(self) -> Path | None:
        """Root of the repository checkout, or None if the platform cannot say."""
        ...

    def vcs(self) -> VcsInfo | None:
        """Repository coordinates, or None when they cannot be determined."""
        ...

    def log_formatter(self) -> LogFormatter:
        """Formatter for this platform's log dialect."""
        ...

    def oidc(self) -> OidcProvider | None:
        """OIDC provider, or None when this platform offers no usable token."""
        ...

    def telemetry_tags(self) -> dict[str, str]:
        """Sentry tags. Must never include data from a private repository."""
        ...

    def telemetry_context(self) -> dict[str, str]:
        """Sentry ``ci`` context. Empty when repository visibility is not public."""
        ...
