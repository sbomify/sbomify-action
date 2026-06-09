"""Main Enricher class for SBOM enrichment orchestration.

Enriches SBOM components with metadata from authoritative package registries
to satisfy NTIA Minimum Elements requirements.

References:
    NTIA Minimum Elements: https://sbomify.com/compliance/ntia-minimum-elements/
    Schema Crosswalk: https://sbomify.com/compliance/schema-crosswalk/
"""

from types import TracebackType
from typing import Any, Dict, List, Optional

import requests
from packageurl import PackageURL

from sbomify_action.http_client import USER_AGENT
from sbomify_action.logging_config import logger

from .metadata import NormalizedMetadata
from .registry import SourceRegistry
from .sources import (
    ClearlyDefinedSource,
    ConanSource,
    CratesIOSource,
    DebianSource,
    DepsDevSource,
    EcosystemsSource,
    LicenseDBSource,
    LifecycleSource,
    PubDevSource,
    PURLSource,
    PyPISource,
    RepologySource,
    TeaSource,
)


def create_default_registry() -> SourceRegistry:
    """
    Create a SourceRegistry with default data sources.

    Returns a registry configured with sources in three tiers:

    Tier 0 - Pre-computed Databases (1-9):
    - LicenseDBSource (1) - pre-computed license DB with validated SPDX licenses
      and full metadata for Alpine, Wolfi, Ubuntu, Rocky, Alma, CentOS, Fedora,
      Amazon Linux packages. Top priority as it provides fast, accurate data.
    - LifecycleSource (5) - local lifecycle data (CLE) for language runtimes
      and frameworks (Python, Django, Rails, Laravel, React, Vue)

    Tier 1 - Native Sources (10-19):
    - PyPISource (10) - direct from PyPI for Python packages
    - PubDevSource (10) - direct from pub.dev for Dart packages
    - CratesIOSource (10) - direct from crates.io for Rust packages
    - ConanSource (10) - direct from Conan Center for C/C++ packages
    - DebianSource (10) - direct from sources.debian.org

    Tier 2 - Primary Aggregators (40-49):
    - DepsDevSource (40) - Google Open Source Insights
    - TeaSource (43) - TEA server (auto-discovers from PURL type, TEA_BASE_URL overrides)
    - EcosystemsSource (45) - ecosyste.ms multi-ecosystem aggregator

    Tier 3 - Fallback Sources (70-99):
    - PURLSource (70) - local PURL extraction for OS packages (no API)
    - ClearlyDefinedSource (75) - license and attribution data
    - RepologySource (90) - cross-distro metadata (rate-limited)

    Sources are queried sequentially in priority order with two-phase early exit:
    1. If NTIA fields (description, licenses, supplier) AND all CLE fields
       (release_date, eos, eol) are filled, remaining sources are skipped.
    2. If only NTIA fields are filled but CLE is missing, non-CLE sources
       are skipped while lifecycle-capable sources (provides_cle=True)
       continue to run.

    Returns:
        Configured SourceRegistry
    """
    registry = SourceRegistry()
    registry.register(LicenseDBSource())
    registry.register(LifecycleSource())
    registry.register(PyPISource())
    registry.register(PubDevSource())
    registry.register(CratesIOSource())
    registry.register(ConanSource())
    registry.register(DebianSource())
    registry.register(DepsDevSource())
    registry.register(TeaSource())
    registry.register(EcosystemsSource())
    registry.register(PURLSource())
    registry.register(ClearlyDefinedSource())
    registry.register(RepologySource())
    return registry


class Enricher:
    """
    Main class for orchestrating SBOM enrichment.

    The Enricher uses a SourceRegistry to find and query applicable
    data sources for each package, merging results to provide the
    most complete metadata possible.

    Example:
        enricher = Enricher()

        # Fetch metadata for a single PURL
        metadata = enricher.fetch_metadata("pkg:pypi/requests@2.31.0")

        # Fetch metadata for multiple PURLs
        metadata_map = enricher.fetch_all_metadata([
            "pkg:pypi/requests@2.31.0",
            "pkg:deb/debian/bash@5.1",
        ])
    """

    def __init__(self, registry: Optional[SourceRegistry] = None) -> None:
        """
        Initialize the Enricher.

        Args:
            registry: Optional SourceRegistry. If not provided, creates
                      a default registry with all standard sources.
        """
        self._registry = registry or create_default_registry()
        self._session: Optional[requests.Session] = None

    @property
    def registry(self) -> SourceRegistry:
        """Get the source registry."""
        return self._registry

    def _get_session(self) -> requests.Session:
        """Get or create a requests session."""
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({"User-Agent": USER_AGENT})
        return self._session

    def close(self) -> None:
        """Close the requests session."""
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self) -> "Enricher":
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager exit."""
        self.close()

    def fetch_metadata(self, purl_str: str, merge_results: bool = True) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata for a single PURL.

        Args:
            purl_str: Package URL string (e.g., "pkg:pypi/requests@2.31.0")
            merge_results: If True, merge results from multiple sources

        Returns:
            NormalizedMetadata if any source returned data, None otherwise
        """
        purl = self._parse_purl(purl_str)
        if not purl:
            return None

        session = self._get_session()
        return self._registry.fetch_metadata(purl, session, merge_results)

    def fetch_all_metadata(
        self, purl_strs: List[str], merge_results: bool = True
    ) -> Dict[str, Optional[NormalizedMetadata]]:
        """
        Fetch metadata for multiple PURLs.

        Args:
            purl_strs: List of Package URL strings
            merge_results: If True, merge results from multiple sources

        Returns:
            Dictionary mapping PURL string to NormalizedMetadata (or None)
        """
        results: Dict[str, Optional[NormalizedMetadata]] = {}
        session = self._get_session()

        for purl_str in purl_strs:
            purl = self._parse_purl(purl_str)
            if purl:
                try:
                    metadata = self._registry.fetch_metadata(purl, session, merge_results)
                    results[purl_str] = metadata
                except Exception as e:
                    logger.error(f"Unexpected error fetching metadata for {purl_str}: {e}")
                    results[purl_str] = None
            else:
                results[purl_str] = None

        return results

    def get_enrichment_stats(self, metadata_map: Dict[str, Optional[NormalizedMetadata]]) -> Dict[str, Any]:
        """
        Calculate enrichment statistics from a metadata map.

        Args:
            metadata_map: Dictionary from fetch_all_metadata

        Returns:
            Dictionary with enrichment statistics
        """
        sources: Dict[str, int] = {}
        stats: Dict[str, Any] = {
            "total": len(metadata_map),
            "enriched": 0,
            "descriptions": 0,
            "licenses": 0,
            "suppliers": 0,
            "homepages": 0,
            "repositories": 0,
            "sources": sources,
        }

        for metadata in metadata_map.values():
            if metadata and metadata.has_data():
                stats["enriched"] += 1
                if metadata.description:
                    stats["descriptions"] += 1
                if metadata.licenses:
                    stats["licenses"] += 1
                if metadata.supplier:
                    stats["suppliers"] += 1
                if metadata.homepage:
                    stats["homepages"] += 1
                if metadata.repository_url:
                    stats["repositories"] += 1

                # Track sources
                for source in metadata.source.split(", "):
                    if source:
                        sources[source] = sources.get(source, 0) + 1

        return stats

    def _parse_purl(self, purl_str: str) -> Optional[PackageURL]:
        """
        Safely parse a PURL string.

        Args:
            purl_str: Package URL string

        Returns:
            PackageURL object or None if parsing fails
        """
        try:
            return PackageURL.from_string(purl_str)
        except ValueError as e:
            logger.debug(f"Failed to parse PURL '{purl_str}': {e}")
            return None


def clear_all_caches() -> None:
    """Clear all data source caches."""
    from .sources.clearlydefined import clear_cache as clear_clearlydefined
    from .sources.conan import clear_cache as clear_conan
    from .sources.cratesio import clear_cache as clear_cratesio
    from .sources.debian import clear_cache as clear_debian
    from .sources.depsdev import clear_cache as clear_depsdev
    from .sources.ecosystems import clear_cache as clear_ecosystems
    from .sources.license_db import clear_cache as clear_license_db
    from .sources.lifecycle import clear_cache as clear_lifecycle
    from .sources.pubdev import clear_cache as clear_pubdev
    from .sources.pypi import clear_cache as clear_pypi
    from .sources.repology import clear_cache as clear_repology
    from .sources.tea import clear_cache as clear_tea

    clear_license_db()
    clear_lifecycle()
    clear_pypi()
    clear_pubdev()
    clear_cratesio()
    clear_conan()
    clear_debian()
    clear_depsdev()
    clear_tea()
    clear_ecosystems()
    clear_clearlydefined()
    clear_repology()
    logger.debug("All enrichment caches cleared")
