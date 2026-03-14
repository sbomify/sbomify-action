"""Conan Center data source for C/C++ package metadata.

Uses the Conan Python API to fetch package metadata from Conan Center on-demand.
This is the authoritative source for Conan packages.
"""

from typing import Any, Dict, Optional

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..metadata import NormalizedMetadata
from ..sanitization import normalize_vcs_url
from .purl import PURL_TYPE_TO_SUPPLIER

# Simple in-memory cache
_cache: Dict[str, Optional[NormalizedMetadata]] = {}

# Cache for Conan API instance and initialization state
_conan_api: Optional[Any] = None
_conan_available: Optional[bool] = None
_profiles: Optional[tuple[Any, Any]] = None


def clear_cache() -> None:
    """Clear the Conan metadata cache."""
    global _conan_api, _conan_available, _profiles
    _cache.clear()
    _conan_api = None
    _conan_available = None
    _profiles = None


def _get_conan_api() -> Optional[Any]:
    """Get or create the Conan API instance."""
    global _conan_api, _conan_available

    if _conan_available is False:
        return None

    if _conan_api is not None:
        return _conan_api

    try:
        from conan.api.conan_api import ConanAPI

        _conan_api = ConanAPI()
        _conan_available = True
        logger.debug("Conan API initialized successfully")
        return _conan_api
    except ImportError:
        logger.debug("Conan library not available")
        _conan_available = False
        return None
    except Exception as e:
        logger.warning(f"Failed to initialize Conan API: {e}")
        _conan_available = False
        return None


def _get_profiles(api: Any) -> Optional[tuple[Any, Any]]:
    """Get or create Conan profiles."""
    global _profiles

    if _profiles is not None:
        return _profiles

    try:
        # Get default profiles (will auto-detect if not configured)
        profile_host = api.profiles.get_profile([])
        profile_build = api.profiles.get_profile([])
        _profiles = (profile_host, profile_build)
        return _profiles
    except Exception as e:
        logger.warning(f"Failed to get Conan profiles: {e}")
        return None


class ConanSource:
    """
    Data source for Conan Center (C/C++ package registry) packages.

    This source uses the Conan Python API to fetch package metadata from Conan Center.
    It's the authoritative source for Conan packages and should be tried first
    before generic sources like ecosyste.ms.

    Priority: 10 (high - native source)
    Supports: pkg:conan/* packages
    """

    @property
    def name(self) -> str:
        return "conan.io"

    @property
    def priority(self) -> int:
        # Tier 1: Native sources (10-19) - Direct from official package registries
        return 10

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL."""
        return bool(purl.type == "conan")

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from Conan Center via Python API.

        Args:
            purl: Parsed PackageURL for a Conan package
            session: requests.Session (not used, but required by protocol)

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        # Get Conan API
        api = _get_conan_api()
        if api is None:
            logger.debug("Conan API not available, skipping Conan enrichment")
            return None

        # Get profiles
        profiles = _get_profiles(api)
        if profiles is None:
            logger.debug("Conan profiles not available, skipping Conan enrichment")
            return None

        profile_host, profile_build = profiles

        # Build cache key
        version = purl.version or "latest"
        cache_key = f"conan:{purl.name}:{version}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (Conan): {purl.name}")
            return _cache[cache_key]

        try:
            # Build the requires string
            if purl.version:
                requires = f"{purl.name}/{purl.version}"
            else:
                requires = purl.name

            logger.debug(f"Fetching Conan metadata for: {requires}")

            # Get remotes
            remotes = api.remotes.list()

            # Load dependency graph
            graph = api.graph.load_graph_requires(
                requires=[requires],
                tool_requires=None,
                profile_host=profile_host,
                profile_build=profile_build,
                lockfile=None,
                remotes=remotes,
                update=False,
            )

            # Find our package in the graph
            metadata = self._extract_metadata_from_graph(purl.name, graph)

            # Cache result
            _cache[cache_key] = metadata
            return metadata

        except Exception as e:
            error_msg = str(e).lower()
            if "not found" in error_msg or "unable to find" in error_msg:
                logger.debug(f"Package not found in Conan Center: {purl.name}")
            else:
                logger.warning(f"Error fetching Conan metadata for {purl.name}: {e}")
            _cache[cache_key] = None
            return None

    def _extract_metadata_from_graph(self, package_name: str, graph: Any) -> Optional[NormalizedMetadata]:
        """
        Extract metadata from a Conan dependency graph.

        Args:
            package_name: Name of the package to find
            graph: Conan Deps graph object

        Returns:
            NormalizedMetadata with extracted fields, or None if not found
        """
        # Find the node matching our package name
        conanfile = None
        for node in graph.nodes:
            if node.conanfile and node.conanfile.name == package_name:
                conanfile = node.conanfile
                break

        if not conanfile:
            logger.debug(f"Package not found in Conan graph: {package_name}")
            return None

        # Extract license
        license_val = getattr(conanfile, "license", None)
        licenses = []
        if license_val:
            # License can be a string or tuple
            if isinstance(license_val, (list, tuple)):
                licenses = list(license_val)
            else:
                licenses = [str(license_val)]

        # Extract other fields
        description = getattr(conanfile, "description", None)
        homepage = getattr(conanfile, "homepage", None)
        url = getattr(conanfile, "url", None)  # Usually the conan-center-index repo
        author = getattr(conanfile, "author", None)

        # Normalize repository URL
        repository_url = normalize_vcs_url(url) if url else None

        # Build field_sources for attribution
        field_sources: Dict[str, str] = {}
        if description:
            field_sources["description"] = self.name
        if licenses:
            field_sources["licenses"] = self.name
        if homepage:
            field_sources["homepage"] = self.name
        if repository_url:
            field_sources["repository_url"] = self.name

        # Supplier is always the distribution platform
        field_sources["supplier"] = self.name

        # Preserve author info as maintainer_name
        maintainer_name = author if author else None

        metadata = NormalizedMetadata(
            description=description,
            licenses=licenses,
            supplier=PURL_TYPE_TO_SUPPLIER["conan"],
            maintainer_name=maintainer_name,
            homepage=homepage,
            repository_url=repository_url,
            registry_url=f"https://conan.io/center/recipes/{package_name}",
            source=self.name,
            field_sources=field_sources,
        )

        if metadata.has_data():
            logger.debug(f"Successfully fetched Conan metadata for: {package_name}")
            return metadata
        return None
