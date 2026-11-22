"""VCS augmentation from the active CI platform.

This provider holds no knowledge of any particular CI system. It asks the
resolved platform for repository coordinates and normalises whatever comes back
into augmentation metadata. Where those coordinates come from -- GitHub Actions'
environment, GitLab's, or a ``git`` invocation in the checkout -- is the
platform's business.

That is what makes the action work across CI systems without this module
growing: a platform reads whatever its vendor publishes -- GitHub Actions'
environment, Jenkins' Git plugin variables, TeamCity's build-properties file --
and falls back to the git checkout otherwise, so even a CI system nobody has
written a platform for gets VCS metadata automatically instead of the user
hand-writing ``vcs_url`` into ``sbomify.json``.

Supporting one more CI system is a module under ``_runtime/platforms/``; this
provider does not change.

Set DISABLE_VCS_AUGMENTATION=true to disable VCS enrichment.
"""

from typing import Any

from sbomify_action._runtime import get_platform
from sbomify_action.logging_config import logger

from ..metadata import AugmentationMetadata
from ..utils import is_vcs_augmentation_disabled, truncate_sha


class CIPlatformProvider:
    """
    Provider that extracts VCS metadata from the active CI platform.

    This provider has priority 20, which is lower than sbomify.json (10),
    allowing local config to override auto-detected values.
    """

    name: str = "ci-platform"
    priority: int = 20

    def fetch(
        self,
        component_id: str | None = None,
        api_base_url: str | None = None,
        token: str | None = None,
        config_path: str | None = None,
        **kwargs: Any,
    ) -> AugmentationMetadata | None:
        """
        Extract VCS metadata from the active CI platform.

        Args:
            component_id: Ignored (not needed for CI provider)
            api_base_url: Ignored (not needed for CI provider)
            token: Ignored (not needed for CI provider)
            config_path: Ignored (not needed for CI provider)
            **kwargs: Additional arguments (ignored)

        Returns:
            AugmentationMetadata with VCS info if the platform could determine
            it, None otherwise.
        """
        if is_vcs_augmentation_disabled():
            logger.debug("VCS augmentation disabled, skipping CI platform provider")
            return None

        platform = get_platform()
        vcs = platform.vcs()
        if vcs is None or not vcs.has_data():
            return None

        logger.info(f"Detected {platform.name}: {vcs.url} @ {truncate_sha(vcs.commit_sha)}")

        # The metadata is attributed to the platform, not to this provider, so
        # audit trails keep naming the actual source ("github-actions").
        #
        # No lifecycle phase. Running in CI says where the action ran, not
        # what it was given: this used to stamp ``pre-build`` on everything,
        # including a user's SBOM_FILE of a built image. The pipeline now
        # derives the phase from the input itself (_finalize_sbom_fields in
        # cli/main.py), and ``sbomify.json`` can still set one explicitly.
        return AugmentationMetadata(
            source=platform.name,
            vcs_url=vcs.url,
            vcs_commit_sha=vcs.commit_sha,
            vcs_ref=vcs.ref,
            vcs_commit_url=vcs.commit_url,
        )
