"""Source registry for managing data source plugins."""

from typing import Any, Dict, List, Optional

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from . import cache
from .exceptions import TransientSourceError
from .metadata import NormalizedMetadata
from .protocol import DataSource

#: Fields the early-stop treats as the point of enrichment. A source that can
#: fill none of the ones still missing is not worth a network round trip.
_CORE_FIELDS = ("description", "licenses", "supplier")


def _still_missing(result: Optional[NormalizedMetadata]) -> set[str]:
    """Which NormalizedMetadata fields are not yet populated."""
    if result is None:
        return set(_CORE_FIELDS) | {"homepage", "repository_url", "license_texts"}
    missing = set()
    for field_name in (*_CORE_FIELDS, "homepage", "repository_url", "license_texts"):
        if not getattr(result, field_name, None):
            missing.add(field_name)
    return missing


def _can_contribute(source: object, missing: set[str]) -> bool:
    """Whether this source can fill anything still absent.

    A source that does not declare `provides` is assumed to be able to fill
    anything, which is how every source behaved before the field existed.
    """
    provides = getattr(source, "provides", None)
    if not provides:
        return True
    return bool(set(provides) & missing)


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
            # Stop early if we already have all core NTIA fields
            if result and result.description and result.licenses and result.supplier:
                logger.debug(f"Skipping {source.name} - already have sufficient data for {purl.name}")
                break

            # And skip a source whose whole contribution is already present.
            # The stop above needs *all three* core fields, so a source that
            # fills only one of them was consulted whenever any of the others
            # was missing, and what it returned arrived redundant. A source
            # that declares nothing is unaffected: it is assumed to be able to
            # fill anything, which is how every source behaved before
            # `provides` existed.
            #
            # A skipped call is not merely a saved round trip. Sources cost
            # real time on a cold coordinate and several give up on
            # themselves after consecutive failures, so consulting one that
            # cannot help spends a budget that should still be there when it
            # can -- see ProvidesFields for the case this was measured on.
            if not _can_contribute(source, _still_missing(result)):
                logger.debug(f"Skipping {source.name} for {purl.name}: it supplies only fields we already have")
                continue

            try:
                # Persistent cache sits here rather than in each source: this is
                # the one place every source is called, and it keys on the same
                # (source, coordinate) pair they all cache on in memory.
                #
                # Only a completed fetch is stored. Anything that raises falls
                # through to the handlers below and is never persisted, which
                # is why sources signal a timeout, connection error, 429 or 5xx
                # with TransientSourceError rather than returning None: a None
                # reaching this line is a definitive "upstream has no data for
                # this package" and is cached as such. Blurring the two would
                # let one throttled run suppress a package's enrichment until
                # the entry expired.
                cache_key = purl.to_string()
                hit, metadata = cache.get(source.name, cache_key)
                if hit:
                    logger.debug(f"Cache hit ({source.name}) for {purl.name}")
                else:
                    metadata = source.fetch(purl, session)
                    cache.set(source.name, cache_key, metadata)

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

            except TransientSourceError as e:
                # Deliberately not cached. A timeout or a 429 says nothing
                # about the package, and persisting it as a miss would
                # suppress this package's enrichment on every run until the
                # entry expired.
                logger.warning(f"Transient failure from {source.name} for {purl.name}: {e} (not cached)")
                continue
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
