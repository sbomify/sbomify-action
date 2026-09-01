"""CI runtime plugin architecture.

Resolves which CI system the action is running under and exposes everything
platform-specific behind one object, so the rest of the codebase never reads
``GITHUB_ACTIONS`` (or any other vendor variable) directly.

Platforms (in detection order):
- github-actions: GitHub Actions runner (priority 10)
- gitlab-ci: GitLab CI job (priority 20)
- bitbucket-pipelines: Bitbucket Pipelines step (priority 30)
- teamcity: TeamCity agent, VCS from the build properties file (priority 40)
- generic-ci: any other recognised CI system, VCS from git (priority 90)
- local: developer machine, VCS from git (priority 100, always matches)

**Adding a CI platform** is one module under ``platforms/`` and one
``register()`` line below. Nothing else changes: console formatting, workspace
resolution, VCS augmentation, OIDC and telemetry all route through the
protocol. Subclass ``GitCheckoutPlatform`` when the system just checks out a
git repository; write the methods out when it publishes its own repository
details or needs a different log dialect.

Usage:
    from sbomify_action._runtime import get_platform

    platform = get_platform()
    workspace = platform.workspace()
    platform.log_formatter().warning("something looks off")

The platform is resolved on every call rather than cached, so a process that
changes its environment -- most often a test -- sees the change. Resolution is a
handful of environment lookups. Use :func:`use_platform` to pin one explicitly.

Nothing in this package may import from the rest of ``sbomify_action`` beyond
leaf modules (``exceptions``, ``http_client``): ``console`` resolves a platform
while it is still being imported, so a reach into ``_augmentation`` or
``logging_config`` would close an import cycle. That is why the VCS-URL helpers
and ``git_safe_directory_env`` live here, re-exported from their old homes.
"""

from collections.abc import Iterator
from contextlib import contextmanager

from .protocol import CIPlatform, LogFormatter, OidcProvider, VcsInfo
from .registry import PlatformRegistry

__all__ = [
    "CIPlatform",
    "LogFormatter",
    "OidcProvider",
    "PlatformRegistry",
    "VcsInfo",
    "create_default_registry",
    "get_platform",
    "set_platform",
    "reset_platform",
    "use_platform",
]

#: Explicit override, set by :func:`set_platform` / :func:`use_platform`.
_override: CIPlatform | None = None


def create_default_registry() -> PlatformRegistry:
    """Create a registry with the standard platforms.

    Returns:
        PlatformRegistry with vendor platforms ahead of the generic and local
        fallbacks. ``LocalPlatform`` always detects, so resolution never fails.
    """
    from .platforms import (
        BitbucketPlatform,
        GenericCIPlatform,
        GitHubPlatform,
        GitLabPlatform,
        LocalPlatform,
        TeamCityPlatform,
    )

    registry = PlatformRegistry()
    registry.register(GitHubPlatform())
    registry.register(GitLabPlatform())
    registry.register(BitbucketPlatform())
    registry.register(TeamCityPlatform())
    registry.register(GenericCIPlatform())
    registry.register(LocalPlatform())
    return registry


def get_platform() -> CIPlatform:
    """Return the CI platform for the current environment.

    Always returns a platform: ``LocalPlatform`` is the floor.
    """
    if _override is not None:
        return _override

    from .platforms import LocalPlatform

    return create_default_registry().resolve() or LocalPlatform()


def set_platform(platform: CIPlatform | None) -> None:
    """Pin the active platform, or pass None to resume auto-detection.

    Intended for tests and for callers that already know the platform.
    """
    global _override
    _override = platform


def reset_platform() -> None:
    """Clear any pinned platform and resume auto-detection."""
    set_platform(None)


@contextmanager
def use_platform(platform: CIPlatform) -> Iterator[CIPlatform]:
    """Pin ``platform`` for the duration of the block, restoring the previous one.

    Example:
        with use_platform(GitHubPlatform()):
            assert get_platform().name == "github-actions"
    """
    global _override
    previous = _override
    _override = platform
    try:
        yield platform
    finally:
        _override = previous
