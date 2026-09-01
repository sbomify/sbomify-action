"""Shared helpers for CI platform implementations."""

import logging
import os
from pathlib import Path

from ..formatters import PlainFormatter
from ..git import detect_vcs
from ..protocol import LogFormatter, OidcProvider, VcsInfo

logger = logging.getLogger("sbomify_action")

#: Values CI systems use for boolean environment variables.
TRUTHY = frozenset({"true", "1", "yes", "on"})


def env_truthy(name: str) -> bool:
    """True when ``name`` is set to any conventional truthy value.

    Accepts ``true``/``1``/``yes``/``on``, case- and whitespace-insensitive,
    because CI systems disagree about which one they set. Use this for genuine
    booleans: a variable set to ``false`` must not read as set.
    """
    return os.environ.get(name, "").strip().lower() in TRUTHY


def env_present(*names: str) -> bool:
    """True when any of ``names`` is set to a non-empty value.

    For markers that carry a value rather than a boolean -- ``TEAMCITY_VERSION``,
    ``JENKINS_URL`` -- where presence is the signal.
    """
    return any(os.environ.get(name, "").strip() for name in names)


def env_first(*names: str) -> str | None:
    """Return the first of ``names`` that is set to a non-empty value."""
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


class GitCheckoutPlatform:
    """Base for platforms whose VCS metadata comes from the git checkout itself.

    Used where the runtime exposes no repository environment variables worth
    trusting: a developer's machine, and CI systems we have no integration for.
    Subclasses supply ``name``, ``priority``, ``is_ci``, ``detects()`` and
    ``workspace()``.
    """

    name: str = "git-checkout"
    priority: int = 100
    is_ci: bool = False
    confines_working_dir: bool = False

    def detects(self) -> bool:
        """Subclasses decide; the base never claims a run on its own."""
        return False

    def workspace(self) -> Path | None:
        """Default to the process working directory."""
        return Path.cwd()

    def vcs(self) -> VcsInfo | None:
        """Read repository coordinates from the checkout via ``git``."""
        return detect_vcs(self.workspace())

    def log_formatter(self) -> LogFormatter:
        """Plain Rich output -- no annotation dialect to speak."""
        return PlainFormatter()

    def oidc(self) -> OidcProvider | None:
        """No OIDC issuer available."""
        return None

    def telemetry_tags(self) -> dict[str, str]:
        """Report only the platform name; nothing here is known to be public."""
        return {"ci.platform": self.name}

    def telemetry_context(self) -> dict[str, str]:
        """No context -- repository visibility is unknown."""
        return {}
