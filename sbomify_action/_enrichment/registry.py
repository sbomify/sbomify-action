"""Source registry for managing data source plugins."""

from typing import Any, Dict, List, Optional

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from .metadata import NormalizedMetadata
from .protocol import DataSource


class SourceRegistry:
    """
    Registry for managing and querying data source plugins.

    The registry maintains a list of data sources and provides methods
    to find applicable sources for a given PURL, sorted by priority.

    Example:
        registry = SourceRegistry()
        registry.register(PyPISource())
        registry.register(EcosystemsSource())
        registry.register(RepologySource())

        # Get sources for a PyPI package (returns [PyPISource, EcosystemsSource])
        sources = registry.get_sources_for(purl)

        # Fetch metadata using priority chain
        metadata = registry.fetch_metadata(purl, session)
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._sources: List[DataSource] = []

    def register(self, source: DataSource) -> None:
        """
        Register a data source.

        Sources are stored and later sorted by priority when queried.

        Args:
            source: DataSource implementation to register
        """
        self._sources.append(source)
        logger.debug(f"Registered data source: {source.name} (priority={source.priority})")

    def get_sources_for(self, purl: PackageURL) -> List[DataSource]:
        """
        Get all applicable sources for a PURL, sorted by priority.

        Args:
            purl: Parsed PackageURL object

        Returns:
            List of DataSource instances that support this PURL type,
            sorted by priority (lowest/highest priority first)
        """
        applicable = [s for s in self._sources if s.supports(purl)]
        return sorted(applicable, key=lambda s: s.priority)

    def fetch_metadata(
        self,
        purl: PackageURL,
        session: requests.Session,
        merge_results: bool = True,
    ) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata using the priority chain of sources.

        Tries sources in priority order, stopping early when we have
        sufficient data (description, licenses, supplier). Only continues
        to lower-priority sources if critical fields are missing.

        Args:
            purl: Parsed PackageURL object
            session: requests.Session with configured headers
            merge_results: If True, merge results from multiple sources

        Returns:
            NormalizedMetadata if any source returned data, None otherwise
        """
        sources = self.get_sources_for(purl)
        if not sources:
            logger.debug(f"No sources available for PURL type: {purl.type}")
            return None

        result: Optional[NormalizedMetadata] = None

        for source in sources:
            # Stop early if we already have all core NTIA fields + CLE lifecycle data
            if (
                result
                and result.description
                and result.licenses
                and result.supplier
                and result.cle_release_date
            ):
                logger.debug(f"Skipping {source.name} - already have sufficient data for {purl.name}")
                break

            try:
                metadata = source.fetch(purl, session)
                if metadata and metadata.has_data():
                    logger.debug(f"Fetched metadata from {source.name} for {purl.name}")
                    if result is None:
                        result = metadata
                    elif merge_results:
                        # Merge new data into existing result
                        result = result.merge(metadata)
                    else:
                        # First result wins
                        break

            except Exception as e:
                logger.warning(f"Error fetching from {source.name} for {purl.name}: {e}")
                continue

        return result

    def list_sources(self) -> List[Dict[str, Any]]:
        """
        List all registered sources with their priorities.

        Returns:
            List of dicts with 'name' and 'priority' keys
        """
        return [{"name": s.name, "priority": s.priority} for s in sorted(self._sources, key=lambda s: s.priority)]

    def clear(self) -> None:
        """Remove all registered sources."""
        self._sources.clear()
