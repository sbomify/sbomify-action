"""Local platform -- a developer's machine, or any environment we cannot place.

This is the last resort in the registry: it always detects, so there is always
an active platform and no caller has to handle "no platform". Everything it
reports comes from the working directory and the git checkout in it.
"""

from .base import GitCheckoutPlatform


class LocalPlatform(GitCheckoutPlatform):
    """Fallback platform. Always matches."""

    name: str = "local"
    priority: int = 100
    is_ci: bool = False

    def detects(self) -> bool:
        """Always true -- this is the floor of the registry."""
        return True
