"""Deprecated per-vendor augmentation providers.

Before the CI platforms existed, each vendor had its own provider class here.
They collapsed into :class:`~.providers.ci_platform.CIPlatformProvider`, which
asks whichever platform ``sbomify_action._runtime`` resolved -- so supporting a
new CI system no longer adds a provider.

The old names keep working. Each is a CIPlatformProvider pinned to one platform,
so it still returns metadata only when that vendor's environment is present,
exactly as before. New code should register ``CIPlatformProvider`` once instead.
"""

from typing import Any

from .._runtime import CIPlatform, use_platform
from .._runtime.platforms import (
    BitbucketPlatform,
    GitHubPlatform,
    GitLabPlatform,
    TeamCityPlatform,
)
from .metadata import AugmentationMetadata
from .providers.ci_platform import CIPlatformProvider


class _PinnedPlatformProvider(CIPlatformProvider):
    """A CIPlatformProvider that only speaks for one vendor.

    Reproduces the old per-vendor behaviour: nothing is emitted unless that
    vendor's environment is actually present.
    """

    #: The platform this provider stands in for.
    platform_factory: type[CIPlatform]

    def fetch(self, *args: Any, **kwargs: Any) -> AugmentationMetadata | None:
        """Return metadata only when this provider's own platform detects."""
        platform = self.platform_factory()
        if not platform.detects():
            return None
        with use_platform(platform):
            return super().fetch(*args, **kwargs)


class GitHubActionsProvider(_PinnedPlatformProvider):
    """Deprecated. Use CIPlatformProvider; GitHub Actions is a platform now."""

    name: str = "github-actions"
    platform_factory = GitHubPlatform


class GitLabCIProvider(_PinnedPlatformProvider):
    """Deprecated. Use CIPlatformProvider; GitLab CI is a platform now."""

    name: str = "gitlab-ci"
    platform_factory = GitLabPlatform


class BitbucketPipelinesProvider(_PinnedPlatformProvider):
    """Deprecated. Use CIPlatformProvider; Bitbucket Pipelines is a platform now."""

    name: str = "bitbucket-pipelines"
    platform_factory = BitbucketPlatform


class TeamCityProvider(_PinnedPlatformProvider):
    """Deprecated. Use CIPlatformProvider; TeamCity is a platform now."""

    name: str = "teamcity"
    platform_factory = TeamCityPlatform


__all__ = [
    "BitbucketPipelinesProvider",
    "GitHubActionsProvider",
    "GitLabCIProvider",
    "TeamCityProvider",
]
