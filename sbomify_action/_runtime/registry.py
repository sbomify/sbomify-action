"""Registry for CI platform plugins.

Resolution is *exclusive*, unlike the augmentation and enrichment registries
which merge results from every source: exactly one platform is active per run.
"""

import logging

from .protocol import CIPlatform

logger = logging.getLogger("sbomify_action")


class PlatformRegistry:
    """Holds the known CI platforms and picks the one this run is under.

    Example:
        registry = PlatformRegistry()
        registry.register(GitHubPlatform())
        registry.register(LocalPlatform())
        platform = registry.resolve()
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._platforms: list[CIPlatform] = []

    def register(self, platform: CIPlatform) -> None:
        """Register a platform.

        Args:
            platform: CIPlatform implementation to register.
        """
        self._platforms.append(platform)

    def get_platforms(self) -> list[CIPlatform]:
        """Return registered platforms sorted by priority (lowest number first)."""
        return sorted(self._platforms, key=lambda p: p.priority)

    def resolve(self) -> CIPlatform | None:
        """Return the first platform that detects the current environment.

        Returns None if nothing matched -- which only happens when a caller
        builds a registry without a catch-all platform.
        """
        for platform in self.get_platforms():
            if platform.detects():
                logger.debug(f"Resolved CI platform: {platform.name}")
                return platform
        return None
