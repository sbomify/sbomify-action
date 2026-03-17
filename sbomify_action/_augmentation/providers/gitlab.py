"""GitLab CI provider for VCS augmentation metadata.

This provider detects when running in GitLab CI and extracts
VCS information from environment variables. Supports both GitLab.com
and self-managed GitLab instances via CI_SERVER_URL/CI_PROJECT_URL.

Environment variables used:
- GITLAB_CI: Detection ("true" when in GitLab CI)
- CI_PROJECT_URL: Full project URL (e.g., https://gitlab.com/owner/repo)
- CI_SERVER_URL: Server URL (e.g., https://gitlab.com or https://gitlab.mycompany.com)
- CI_COMMIT_SHA: Full commit SHA
- CI_COMMIT_REF_NAME: Branch or tag name
- CI_PROJECT_PATH: Project path in owner/repo format

Set DISABLE_VCS_AUGMENTATION=true to disable VCS enrichment.
"""

import os
from typing import Any, Optional

from sbomify_action.logging_config import logger

from ..metadata import AugmentationMetadata
from ..utils import is_vcs_augmentation_disabled, truncate_sha


class GitLabCIProvider:
    """
    Provider that extracts VCS metadata from GitLab CI environment.

    This provider has priority 20, which is lower than sbomify.json (10),
    allowing local config to override auto-detected values.
    """

    name: str = "gitlab-ci"
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
        Extract VCS metadata from GitLab CI environment variables.

        Args:
            component_id: Ignored (not needed for CI provider)
            api_base_url: Ignored (not needed for CI provider)
            token: Ignored (not needed for CI provider)
            config_path: Ignored (not needed for CI provider)
            **kwargs: Additional arguments (ignored)

        Returns:
            AugmentationMetadata with VCS info if in GitLab CI, None otherwise
        """
        # Check if VCS augmentation is disabled
        if is_vcs_augmentation_disabled():
            logger.debug("VCS augmentation disabled, skipping GitLab CI provider")
            return None

        # Check if we're running in GitLab CI
        if os.getenv("GITLAB_CI") != "true":
            return None

        # Extract VCS information
        # CI_PROJECT_URL contains the full URL including server for self-managed instances
        project_url = os.getenv("CI_PROJECT_URL")
        commit_sha = os.getenv("CI_COMMIT_SHA")
        ref = os.getenv("CI_COMMIT_REF_NAME")

        # Fallback: construct URL from server and project path
        if not project_url:
            server_url = os.getenv("CI_SERVER_URL", "https://gitlab.com")
            project_path = os.getenv("CI_PROJECT_PATH")
            if project_path:
                project_url = f"{server_url}/{project_path}"

        if not project_url:
            logger.warning("GitLab CI detected but could not determine project URL")
            return None

        # Construct commit URL
        vcs_commit_url = f"{project_url}/-/commit/{commit_sha}" if commit_sha else None

        logger.info(f"Detected GitLab CI: {project_url} @ {truncate_sha(commit_sha)}")

        return AugmentationMetadata(
            source=self.name,
            vcs_url=project_url,
            vcs_commit_sha=commit_sha,
            vcs_ref=ref,
            vcs_commit_url=vcs_commit_url,
        )
