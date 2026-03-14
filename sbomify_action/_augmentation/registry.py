"""Provider registry for managing augmentation provider plugins."""

from typing import Any, Dict, List, Optional

from sbomify_action.logging_config import logger

from .metadata import AugmentationMetadata
from .protocol import AugmentationProvider


class ProviderRegistry:
    """
    Registry for managing and querying augmentation provider plugins.

    The registry maintains a list of providers and provides methods
    to fetch metadata from all providers, merging results by priority.

    Example:
        registry = ProviderRegistry()
        registry.register(JsonConfigProvider())
        registry.register(SbomifyApiProvider())

        # Fetch metadata from all providers (priority order, merged)
        metadata = registry.fetch_metadata(component_id="xxx", token="yyy")
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._providers: List[AugmentationProvider] = []

    def register(self, provider: AugmentationProvider) -> None:
        """
        Register an augmentation provider.

        Providers are stored and later sorted by priority when queried.

        Args:
            provider: AugmentationProvider implementation to register
        """
        self._providers.append(provider)
        logger.debug(f"Registered augmentation provider: {provider.name} (priority={provider.priority})")

    def get_providers(self) -> List[AugmentationProvider]:
        """
        Get all registered providers, sorted by priority.

        Returns:
            List of AugmentationProvider instances sorted by priority
            (sorted by ascending numeric priority: lower number = higher priority, returned first)
        """
        return sorted(self._providers, key=lambda p: p.priority)

    def fetch_metadata(
        self,
        component_id: Optional[str] = None,
        api_base_url: Optional[str] = None,
        token: Optional[str] = None,
        config_path: Optional[str] = None,
        merge_results: bool = True,
        **kwargs: Any,
    ) -> Optional[AugmentationMetadata]:
        """
        Fetch metadata from all providers in priority order.

        Tries providers in priority order, merging results. Higher priority
        providers' values take precedence (are not overwritten by lower
        priority providers).

        Args:
            component_id: Component ID (for API providers)
            api_base_url: API base URL (for API providers)
            token: Authentication token (for API providers)
            config_path: Path to config file (for file-based providers)
            merge_results: If True, merge results from multiple providers
            **kwargs: Additional provider-specific arguments

        Returns:
            AugmentationMetadata if any provider returned data, None otherwise
        """
        providers = self.get_providers()
        if not providers:
            logger.debug("No augmentation providers registered")
            return None

        result: Optional[AugmentationMetadata] = None

        for provider in providers:
            try:
                metadata = provider.fetch(
                    component_id=component_id,
                    api_base_url=api_base_url,
                    token=token,
                    config_path=config_path,
                    **kwargs,
                )

                if metadata and metadata.has_data():
                    logger.debug(f"Fetched augmentation metadata from {provider.name}")

                    if result is None:
                        result = metadata
                    elif merge_results:
                        # Higher priority (already in result) takes precedence
                        result = result.merge(metadata)
                    else:
                        # First result wins, stop here
                        break

            except Exception as e:
                logger.warning(f"Error fetching from augmentation provider {provider.name}: {e}")
                continue

        return result

    def list_providers(self) -> List[Dict[str, Any]]:
        """
        List all registered providers with their priorities.

        Returns:
            List of dicts with 'name' and 'priority' keys
        """
        return [{"name": p.name, "priority": p.priority} for p in sorted(self._providers, key=lambda p: p.priority)]

    def clear(self) -> None:
        """Remove all registered providers."""
        self._providers.clear()
