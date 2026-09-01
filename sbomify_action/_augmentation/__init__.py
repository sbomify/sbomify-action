"""Augmentation plugin architecture for SBOM metadata providers.

This module provides a plugin-based approach to fetching organizational
metadata for SBOM augmentation. Multiple providers can supply metadata
(supplier, authors, licenses, lifecycle_phase, VCS info), which is merged by priority.

Providers (in priority order):
- json-config: Reads from sbomify.json config file (priority 10)
- docker-image: Emits lifecycle_phase=post-build when the input is a
  container image (--docker-image / DOCKER_IMAGE) (priority 15)
- ci-platform: Auto-detects VCS info from the active CI platform (priority 20)
- sbomify-api: Fetches from sbomify backend API (priority 50)

VCS Augmentation:
The ci-platform provider automatically detects repository URL, commit SHA, and
branch/ref by asking the resolved CI platform (see ``sbomify_action._runtime``).
Each platform reads whatever its vendor publishes -- GitHub Actions' and GitLab
CI's environment variables, TeamCity's build-properties file -- and falls back
to the git checkout where the vendor publishes nothing, which covers Jenkins,
CircleCI, Azure Pipelines and a local machine. Adding a CI system means adding
a platform, not a provider. This can be:
- Overridden via sbomify.json config (vcs_url, vcs_commit_sha, vcs_ref)
- Disabled entirely via DISABLE_VCS_AUGMENTATION=true environment variable

Usage:
    from sbomify_action._augmentation import create_default_registry

    registry = create_default_registry()
    metadata = registry.fetch_metadata(
        component_id="xxx",
        api_base_url="https://app.sbomify.com",
        token="your-token",
    )
"""

from .metadata import AugmentationMetadata
from .protocol import AugmentationProvider
from .registry import ProviderRegistry

__all__ = [
    "AugmentationMetadata",
    "AugmentationProvider",
    "ProviderRegistry",
    "create_default_registry",
]


def create_default_registry() -> ProviderRegistry:
    """
    Create a registry with default augmentation providers.

    Providers are registered in priority order (lower number = higher priority):
    - Priority 10: JsonConfigProvider (local config, can override CI-detected VCS)
    - Priority 15: DockerImageProvider (lifecycle_phase=post-build for container images)
    - Priority 20: CIPlatformProvider (VCS from the active CI platform)
    - Priority 50: SbomifyApiProvider (backend metadata)

    Returns:
        ProviderRegistry configured with standard providers
    """
    from .providers import (
        CIPlatformProvider,
        DockerImageProvider,
        JsonConfigProvider,
        SbomifyApiProvider,
    )

    registry = ProviderRegistry()

    # Priority 10: Local config (can override CI-detected VCS)
    registry.register(JsonConfigProvider())

    # Priority 15: Docker-image input sets lifecycle_phase=post-build.
    # Beats the CI platform's pre-build default; loses to json_config so
    # operators can still override.
    registry.register(DockerImageProvider())

    # Priority 20: VCS from whichever CI platform this run is under. Supporting
    # another CI system adds a platform, not a provider.
    registry.register(CIPlatformProvider())

    # Priority 50: API provider (backend metadata)
    registry.register(SbomifyApiProvider())

    return registry
