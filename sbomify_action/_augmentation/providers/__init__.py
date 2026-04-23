"""Augmentation providers for fetching organizational metadata."""

# Re-export utility from parent module for backwards compatibility
from ..utils import is_vcs_augmentation_disabled
from .bitbucket import BitbucketPipelinesProvider
from .docker_image import DockerImageProvider
from .github import GitHubActionsProvider
from .gitlab import GitLabCIProvider
from .json_config import JsonConfigProvider
from .sbomify_api import SbomifyApiProvider

__all__ = [
    "BitbucketPipelinesProvider",
    "DockerImageProvider",
    "GitHubActionsProvider",
    "GitLabCIProvider",
    "JsonConfigProvider",
    "SbomifyApiProvider",
    "is_vcs_augmentation_disabled",
]
