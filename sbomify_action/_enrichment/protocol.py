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

    @property
    def provides(self) -> frozenset[str]:
        """The NormalizedMetadata fields this source can actually fill.

        Optional. A source that does not declare it is assumed to be able to
        supply anything, which is what every source was assumed to do before
        this existed.

        The registry uses it to skip a source whose entire contribution is
        already present. Without it, a licence-only source is consulted
        whenever *any* core field is missing -- including `description` and
        `supplier`, which it cannot supply -- and its licence arrives
        redundant.

        Measured on clearlydefined.io, which is exactly that shape: of 400
        cached responses sampled, 400 carried `licenses`, four a `homepage`
        and three a `repository_url`. Across a 251-project run it filled the
        persistent cache with 1,178 entries, 1,020 of them holding real
        licence data, and contributed zero fields to the finished SBOMs --
        because in every one of those cases the licence was already there.
        Those lookups are not free: a cold one runs to a 25-second upstream
        deadline, and five consecutive failures latch the source off for the
        rest of the run.
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
