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


def env_checkout_dir(platform: str, *names: str) -> Path | None:
    """Return the first of ``names`` that names a directory that exists here.

    A vendor's checkout-path variable is expanded and checked before it is
    trusted. CircleCI's default ``working_directory`` is the literal string
    ``~/project``, and that is exactly what ``CIRCLE_WORKING_DIRECTORY``
    contains, so taking it at face value yields a *relative* path with a
    literal ``~`` component: git would then run against a directory that does
    not exist and report nothing. The same check covers any vendor variable
    holding a host-side path that is not mounted inside the container.

    Every name is tried, not just the first one that is set: Azure Pipelines
    publishes ``BUILD_REPOSITORY_LOCALPATH`` and
    ``SYSTEM_DEFAULTWORKINGDIRECTORY``, and a container job sees the first as a
    host-side path that is not mounted. Stopping there would fall through to
    the cwd while the second variable named the checkout all along.

    Args:
        platform: Platform name, for the debug line when a path does not resolve.
        *names: Environment variables to try, in order.

    Returns:
        The expanded directory, or None when no variable resolves to one --
        callers fall back to the process working directory, which is correct
        for every vendor that mounts the checkout as the command's cwd.
    """
    for name in names:
        checkout = os.environ.get(name, "").strip()
        if not checkout:
            continue
        expanded = Path(checkout).expanduser()
        if expanded.is_dir():
            return expanded
        logger.debug(f"{platform} reported checkout '{checkout}' in {name}, which is not a directory here")
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
        """Report the platform without changing what ``ci.platform`` means.

        These platforms are the ones that used to report ``ci.platform=unknown``
        -- anything that was not GitHub Actions, GitLab CI, Bitbucket or
        TeamCity. Saved Sentry searches, alert rules and dashboards are keyed on
        that value, so it stays put and the newly available detail goes in
        ``ci.vendor`` alongside it, which is additive.

        ``repo.public`` is deliberately absent, because it was absent before for
        exactly these platforms -- it is only meaningful where the vendor tells
        us the visibility, and none of these do.
        """
        return {"ci.platform": "unknown", "ci.vendor": self.name}

    def telemetry_context(self) -> dict[str, str]:
        """No context -- repository visibility is unknown."""
        return {}
