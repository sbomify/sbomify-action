"""Local platform -- a developer's machine, or any environment we cannot place.

This is the last resort in the registry: it always detects, so there is always
an active platform and no caller has to handle "no platform".
"""

import os

from ..protocol import VcsInfo
from .base import TRUTHY, GitCheckoutPlatform

#: Opt in to reading VCS metadata from the checkout on a non-CI run.
VCS_OPT_IN_VAR = "SBOMIFY_LOCAL_VCS"


class LocalPlatform(GitCheckoutPlatform):
    """Fallback platform. Always matches."""

    name: str = "local"
    priority: int = 100
    is_ci: bool = False

    def detects(self) -> bool:
        """Always true -- this is the floor of the registry."""
        return True

    def vcs(self) -> VcsInfo | None:
        """Read the checkout only when explicitly asked to.

        Every other platform detects VCS metadata automatically, because on CI
        the repository coordinates are part of what the build is *for*. A
        developer's machine is different: the same lock file would start
        producing a different SBOM depending on whether a git remote happens to
        be configured, and an internal remote would be written into a document
        that is often shared outside the company. Neither was true before
        platforms existed, and neither should become true as a side effect.

        Set ``SBOMIFY_LOCAL_VCS=true`` to opt in. ``sbomify.json`` remains the
        way to state VCS fields for a local run, exactly as before.
        """
        if os.environ.get(VCS_OPT_IN_VAR, "").strip().lower() not in TRUTHY:
            return None
        return super().vcs()
