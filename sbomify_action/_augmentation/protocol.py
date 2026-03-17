"""AugmentationProvider protocol for SBOM augmentation plugins."""

from typing import Any, Optional, Protocol

from .metadata import AugmentationMetadata


class AugmentationProvider(Protocol):
    """
    Protocol defining the interface for augmentation provider plugins.

    Each provider implements this protocol to supply organizational metadata
    for SBOM augmentation (supplier, authors, licenses, lifecycle_phase).
    Providers have priorities - lower numbers indicate higher priority (tried first).

    Example:
        class JsonConfigProvider:
            name = "json-config"
            priority = 10  # High priority - local config takes precedence

            def fetch(self, component_id: str | None = None, **kwargs) -> Optional[AugmentationMetadata]:
                # Read from sbomify.json and return metadata
                ...
    """

    @property
    def name(self) -> str:
        """
        Human-readable name of this provider.

        Used for logging and tracking which provider supplied metadata.
        Examples: "json-config", "sbomify-api", "env-vars"
        """
        ...

    @property
    def priority(self) -> int:
        """
        Priority of this provider (lower = higher priority).

        When multiple providers are available, they are tried in priority order.
        Local/static sources should have low priorities (e.g., 10), API sources
        should have higher priorities (e.g., 50).

        Recommended priority ranges:
        - 1-20: Local config files (JSON, YAML)
        - 21-40: Environment variables
        - 41-60: API sources (sbomify API)
        - 61-100: Fallback sources
        """
        ...

    def fetch(
        self,
        component_id: Optional[str] = None,
        api_base_url: Optional[str] = None,
        token: Optional[str] = None,
        config_path: Optional[str] = None,
        **kwargs: Any,
    ) -> Optional[AugmentationMetadata]:
        """
        Fetch augmentation metadata from this provider.

        Implementations should:
        1. Retrieve metadata from their source (file, API, env vars, etc.)
        2. Return normalized AugmentationMetadata
        3. Handle errors gracefully (return None on failure)
        4. Set the 'source' field on the returned metadata

        Args:
            component_id: Component ID (required for API providers)
            api_base_url: API base URL (for API providers)
            token: Authentication token (for API providers)
            config_path: Path to config file (for file-based providers)
            **kwargs: Additional provider-specific arguments

        Returns:
            AugmentationMetadata if successful, None if fetch fails or no data
        """
        ...
