"""Augmentation providers for fetching organizational metadata."""

# Re-export utility from parent module for backwards compatibility
from .._runtime_shims import (
    BitbucketPipelinesProvider,
    GitHubActionsProvider,
    GitLabCIProvider,
    TeamCityProvider,
)
from ..utils import is_vcs_augmentation_disabled
from .ci_platform import CIPlatformProvider
from .docker_image import DockerImageProvider
from .json_config import JsonConfigProvider
from .sbomify_api import SbomifyApiProvider

__all__ = [
    # The one provider the default registry uses: it asks whichever CI platform
    # sbomify_action._runtime resolved, so a new CI system is a new platform
    # rather than another entry here.
    "CIPlatformProvider",
    "DockerImageProvider",
    "JsonConfigProvider",
    "SbomifyApiProvider",
    # Deprecated per-vendor providers, kept so existing imports keep working.
    "BitbucketPipelinesProvider",
    "GitHubActionsProvider",
    "GitLabCIProvider",
    "TeamCityProvider",
    "is_vcs_augmentation_disabled",
]
