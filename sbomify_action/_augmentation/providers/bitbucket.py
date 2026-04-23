"""Bitbucket Pipelines provider for VCS augmentation metadata.

This provider detects when running in Bitbucket Pipelines and extracts
VCS information from environment variables. Supports both Bitbucket Cloud
and attempts best-effort support for Bitbucket Data Center.

Environment variables used (Cloud):
- BITBUCKET_PIPELINE_UUID: Detection (present when in Bitbucket Pipelines)
- BITBUCKET_GIT_HTTP_ORIGIN: Repository URL
- BITBUCKET_COMMIT: Full commit SHA
- BITBUCKET_BRANCH: Branch name (not set for tags)
- BITBUCKET_TAG: Tag name (not set for branches)
- BITBUCKET_WORKSPACE: Workspace name
- BITBUCKET_REPO_SLUG: Repository slug

For Bitbucket Data Center, environment variables may differ. Use sbomify.json
to configure VCS URL manually if auto-detection fails.

Set DISABLE_VCS_AUGMENTATION=true to disable VCS enrichment.
"""

import os
from typing import Any, Optional

from sbomify_action.logging_config import logger

from ..metadata import AugmentationMetadata
from ..utils import is_vcs_augmentation_disabled, truncate_sha


class BitbucketPipelinesProvider:
    """
    Provider that extracts VCS metadata from Bitbucket Pipelines environment.

    This provider has priority 20, which is lower than sbomify.json (10),
    allowing local config to override auto-detected values.
    """

    name: str = "bitbucket-pipelines"
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
        Extract VCS metadata from Bitbucket Pipelines environment variables.

        Args:
            component_id: Ignored (not needed for CI provider)
            api_base_url: Ignored (not needed for CI provider)
            token: Ignored (not needed for CI provider)
            config_path: Ignored (not needed for CI provider)
            **kwargs: Additional arguments (ignored)

        Returns:
            AugmentationMetadata with VCS info if in Bitbucket Pipelines, None otherwise
        """
        # Check if VCS augmentation is disabled
        if is_vcs_augmentation_disabled():
            logger.debug("VCS augmentation disabled, skipping Bitbucket Pipelines provider")
            return None

        # Check if we're running in Bitbucket Pipelines
        if not os.getenv("BITBUCKET_PIPELINE_UUID"):
            return None

        # Extract VCS information
        # BITBUCKET_GIT_HTTP_ORIGIN contains the full repo URL for Cloud
        vcs_url = os.getenv("BITBUCKET_GIT_HTTP_ORIGIN")
        commit_sha = os.getenv("BITBUCKET_COMMIT")
        # Branch or tag
        ref = os.getenv("BITBUCKET_BRANCH") or os.getenv("BITBUCKET_TAG")

        # Fallback: try to construct URL from workspace and repo slug
        if not vcs_url:
            workspace = os.getenv("BITBUCKET_WORKSPACE")
            repo_slug = os.getenv("BITBUCKET_REPO_SLUG")
            if workspace and repo_slug:
                vcs_url = f"https://bitbucket.org/{workspace}/{repo_slug}"
                logger.debug("Constructed Bitbucket URL from workspace/repo slug")

        if not vcs_url:
            logger.warning(
                "Bitbucket Pipelines detected but could not determine repository URL. "
                "For Bitbucket Data Center, configure vcs_url in sbomify.json."
            )
            return None

        # Construct commit URL
        vcs_commit_url = f"{vcs_url}/commits/{commit_sha}" if commit_sha else None

        logger.info(f"Detected Bitbucket Pipelines: {vcs_url} @ {truncate_sha(commit_sha)}")

        # Default to ``pre-build`` — see GitHubActionsProvider for the
        # full CycloneDX 1.7 schema rationale. Lockfile / manifest scans
        # are ``pre-build``; the docker-image augmentation overrides to
        # ``post-build`` when the input is a built artifact; ``json_config``
        # (priority 10) beats this provider for operator overrides.
        return AugmentationMetadata(
            source=self.name,
            vcs_url=vcs_url,
            vcs_commit_sha=commit_sha,
            vcs_ref=ref,
            vcs_commit_url=vcs_commit_url,
            lifecycle_phase="pre-build",
        )
