"""DataSource protocol for SBOM enrichment plugins."""

from typing import Optional, Protocol

import requests
from packageurl import PackageURL

from .metadata import NormalizedMetadata


class DataSource(Protocol):
    """
    Protocol defining the interface for data source plugins.

    Each data source implements this protocol to provide metadata
    for specific package types. Sources have priorities - lower
    numbers indicate higher priority (tried first).

    Example:
        class PyPISource:
            name = "pypi.org"
            priority = 10  # High priority for PyPI packages

            def supports(self, purl: PackageURL) -> bool:
                return purl.type == "pypi"

            def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
                # Fetch from PyPI API and return normalized metadata
                ...
    """

    @property
    def name(self) -> str:
        """
        Human-readable name of this data source.

        Used for logging and tracking which source provided metadata.
        Examples: "pypi.org", "ecosyste.ms", "repology.org", "purl"
        """
        ...

    @property
    def priority(self) -> int:
        """
        Priority of this data source (lower = higher priority).

        When multiple sources support a PURL type, they are tried
        in priority order. Native sources should have low priorities
        (e.g., 10), generic sources higher (e.g., 50), and fallback
        sources highest (e.g., 100).

        Recommended priority ranges:
        - 1-20: Native/authoritative sources (PyPI for pypi, npm for npm)
        - 21-50: Generic multi-ecosystem sources (ecosyste.ms)
        - 51-80: PURL-based extraction (no API calls)
        - 81-100: Fallback sources with rate limits (Repology)
        """
        ...

    def supports(self, purl: PackageURL) -> bool:
        """
        Check if this source can handle the given PURL type.

        Args:
            purl: Parsed PackageURL object

        Returns:
            True if this source can fetch metadata for this PURL type
        """
        ...

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch and normalize metadata for the given PURL.

        Implementations should:
        1. Make API calls to fetch raw metadata
        2. Normalize the response into NormalizedMetadata
        3. Handle errors gracefully (return None on failure)
        4. Set the 'source' field on the returned metadata

        Args:
            purl: Parsed PackageURL object
            session: requests.Session with configured headers (User-Agent, etc.)

        Returns:
            NormalizedMetadata if successful, None if fetch fails or no data
        """
        ...
