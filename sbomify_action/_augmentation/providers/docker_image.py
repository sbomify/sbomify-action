"""Docker-image provider for lifecycle-phase augmentation.

This provider fires when the action input is a container image
(``--docker-image`` / ``DOCKER_IMAGE``) rather than a lockfile or
source tree. Per the CycloneDX 1.7 schema ``meta:enum`` for the
lifecycle ``phase`` property, scanning a built container image
is ``post-build``:

    post-build — "BOM consisting of information obtained after a
    build process has completed and the resulting component(s) are
    available for further analysis."

The provider registers at priority 15 so it beats the CI providers
(priority 20, default ``pre-build``) but still loses to ``json_config``
(priority 10) — operators keep the final word via ``sbomify.json``.

Environment variables used:
- ``DOCKER_IMAGE``: container image reference (e.g. ``ubuntu:24.04``).
  The CLI sets this from ``--docker-image`` for consistency with the
  existing CI provider pattern.
"""

import os
from typing import Any, Optional

from sbomify_action.logging_config import logger

from ..metadata import AugmentationMetadata


class DockerImageProvider:
    """Sets ``lifecycle_phase="post-build"`` when the input is a built
    container image. Emits no other fields — the CI providers still
    contribute VCS metadata, and ``json_config`` / ``sbomify-api`` fill
    the rest of the augmentation surface.
    """

    name: str = "docker-image"
    # Priority 15 — beats CI providers (20) so post-build wins over the
    # CI default pre-build when the input is a container image; still
    # loses to json_config (10) so operators can override.
    priority: int = 15

    def fetch(
        self,
        component_id: Optional[str] = None,
        api_base_url: Optional[str] = None,
        token: Optional[str] = None,
        config_path: Optional[str] = None,
        **kwargs: Any,
    ) -> Optional[AugmentationMetadata]:
        docker_image = os.getenv("DOCKER_IMAGE")
        if not docker_image:
            return None

        logger.info(f"Detected container image input: {docker_image} — lifecycle_phase=post-build")
        return AugmentationMetadata(
            source=self.name,
            lifecycle_phase="post-build",
        )
