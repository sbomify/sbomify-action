"""Augmentation providers for fetching organizational metadata."""

# Re-export utility from parent module for backwards compatibility
from ..utils import is_vcs_augmentation_disabled
from .ci_platform import CIPlatformProvider
from .docker_image import DockerImageProvider
from .json_config import JsonConfigProvider
from .sbomify_api import SbomifyApiProvider

__all__ = [
    "CIPlatformProvider",
    "DockerImageProvider",
    "JsonConfigProvider",
    "SbomifyApiProvider",
    "is_vcs_augmentation_disabled",
]
