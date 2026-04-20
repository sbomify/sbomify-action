"""Augmentation plugin architecture for SBOM metadata providers.

This module provides a plugin-based approach to fetching organizational
metadata for SBOM augmentation. Multiple providers can supply metadata
(supplier, authors, licenses, lifecycle_phase, VCS info), which is merged by priority.

Providers (in priority order):
- json-config: Reads from sbomify.json config file (priority 10)
- docker-image: Emits lifecycle_phase=post-build when the input is a
  container image (--docker-image / DOCKER_IMAGE) (priority 15)
- github-actions: Auto-detects VCS info from GitHub Actions env (priority 20)
- gitlab-ci: Auto-detects VCS info from GitLab CI env (priority 20)
- bitbucket-pipelines: Auto-detects VCS info from Bitbucket Pipelines env (priority 20)
- sbomify-api: Fetches from sbomify backend API (priority 50)

VCS Augmentation:
CI providers automatically detect repository URL, commit SHA, and branch/ref
from CI environment variables. This can be:
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
    - Priority 20: CI providers (GitHub Actions, GitLab CI, Bitbucket Pipelines)
    - Priority 50: SbomifyApiProvider (backend metadata)

    Returns:
        ProviderRegistry configured with standard providers
    """
    from .providers import (
        BitbucketPipelinesProvider,
        DockerImageProvider,
        GitHubActionsProvider,
        GitLabCIProvider,
        JsonConfigProvider,
        SbomifyApiProvider,
    )

    registry = ProviderRegistry()

    # Priority 10: Local config (can override CI-detected VCS)
    registry.register(JsonConfigProvider())

    # Priority 15: Docker-image input sets lifecycle_phase=post-build.
    # Beats CI providers' pre-build default; loses to json_config so
    # operators can still override.
    registry.register(DockerImageProvider())

    # Priority 20: CI providers (auto-detect VCS from environment)
    registry.register(GitHubActionsProvider())
    registry.register(GitLabCIProvider())
    registry.register(BitbucketPipelinesProvider())

    # Priority 50: API provider (backend metadata)
    registry.register(SbomifyApiProvider())

    return registry
