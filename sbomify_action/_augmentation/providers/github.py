"""GitHub Actions provider for VCS augmentation metadata.

This provider detects when running in GitHub Actions and extracts
VCS information from environment variables. Supports both GitHub.com
and GitHub Enterprise Server via GITHUB_SERVER_URL.

Environment variables used:
- GITHUB_ACTIONS: Detection ("true" when in GitHub Actions)
- GITHUB_SERVER_URL: Server URL (e.g., https://github.com or https://github.mycompany.com)
- GITHUB_REPOSITORY: Repository in owner/repo format
- GITHUB_SHA: Full commit SHA
- GITHUB_REF: Git ref (e.g., refs/heads/main, refs/tags/v1.0.0)
- GITHUB_REF_NAME: Short ref name (e.g., main, v1.0.0)

Set DISABLE_VCS_AUGMENTATION=true to disable VCS enrichment.
"""

import os
from typing import Any, Optional

from sbomify_action.logging_config import logger

from ..metadata import AugmentationMetadata
from ..utils import is_vcs_augmentation_disabled, truncate_sha


class GitHubActionsProvider:
    """
    Provider that extracts VCS metadata from GitHub Actions environment.

    This provider has priority 20, which is lower than sbomify.json (10),
    allowing local config to override auto-detected values.
    """

    name: str = "github-actions"
    priority: int = 20

    def fetch(
        self,
        component_id: Optional[str] = None,
        api_base_url: Optional[str] = None,
        token: Optional[str] = None,
        config_path: Optional[str] = None,
        **kwargs: Any,
    ) -> Optional[AugmentationMetadata]:
        """
        Extract VCS metadata from GitHub Actions environment variables.

        Args:
            component_id: Ignored (not needed for CI provider)
            api_base_url: Ignored (not needed for CI provider)
            token: Ignored (not needed for CI provider)
            config_path: Ignored (not needed for CI provider)
            **kwargs: Additional arguments (ignored)

        Returns:
            AugmentationMetadata with VCS info if in GitHub Actions, None otherwise
        """
        # Check if VCS augmentation is disabled
        if is_vcs_augmentation_disabled():
            logger.debug("VCS augmentation disabled, skipping GitHub Actions provider")
            return None

        # Check if we're running in GitHub Actions
        if os.getenv("GITHUB_ACTIONS") != "true":
            return None

        # Extract VCS information
        server_url = os.getenv("GITHUB_SERVER_URL", "https://github.com")
        repository = os.getenv("GITHUB_REPOSITORY")
        commit_sha = os.getenv("GITHUB_SHA")
        ref = os.getenv("GITHUB_REF_NAME") or os.getenv("GITHUB_REF")

        if not repository:
            logger.warning("GitHub Actions detected but GITHUB_REPOSITORY not set")
            return None

        # Construct URLs
        vcs_url = f"{server_url}/{repository}"
        vcs_commit_url = f"{server_url}/{repository}/commit/{commit_sha}" if commit_sha else None

        # Clean up ref (remove refs/heads/ or refs/tags/ prefix if present)
        if ref:
            if ref.startswith("refs/heads/"):
                ref = ref[len("refs/heads/") :]
            elif ref.startswith("refs/tags/"):
                ref = ref[len("refs/tags/") :]

        logger.info(f"Detected GitHub Actions: {repository} @ {truncate_sha(commit_sha)}")

        # CycloneDX 1.7 schema meta:enum defines the lifecycle phases as:
        #   * pre-build  — "information obtained prior to a build process
        #                  and may contain source files and development
        #                  artifacts and manifests" (lockfiles are manifests)
        #   * build      — "information obtained during a build process"
        #                  (emitted by compiler / build tool itself)
        #   * post-build — "information obtained after a build process has
        #                  completed and the resulting component(s) are
        #                  available for further analysis" (e.g. scanning
        #                  a built container image)
        # The common GitHub Actions usage of sbomify-action is scanning
        # lockfiles / source manifests, so default to ``pre-build``. When
        # the action runs against a built artifact (``--docker-image``),
        # the docker-image augmentation overrides to ``post-build``.
        # Users who emit a BOM mid-compilation (Maven / Gradle plugins,
        # ``cargo bom`` and similar) can override via ``sbomify.json`` /
        # ``json_config`` (priority 10 beats this provider at 20).
        return AugmentationMetadata(
            source=self.name,
            vcs_url=vcs_url,
            vcs_commit_sha=commit_sha,
            vcs_ref=ref,
            vcs_commit_url=vcs_commit_url,
            lifecycle_phase="pre-build",
        )
