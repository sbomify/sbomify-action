"""crates.io data source for Rust/Cargo package metadata."""

import json
from typing import Any, Dict, Optional

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..license_utils import normalize_license_list
from ..metadata import NormalizedMetadata
from ..sanitization import normalize_vcs_url
from .purl import PURL_TYPE_TO_SUPPLIER

CRATESIO_API_BASE = "https://crates.io/api/v1/crates"
DEFAULT_TIMEOUT = 10  # seconds

# Simple in-memory cache
_cache: Dict[str, Optional[NormalizedMetadata]] = {}


def clear_cache() -> None:
    """Clear the crates.io metadata cache."""
    _cache.clear()


class CratesIOSource:
    """
    Data source for crates.io (Rust package registry) packages.

    This is the authoritative source for Rust packages and should
    be tried first before generic sources like deps.dev or ecosyste.ms.

    Priority: 10 (high - native source)
    Supports: pkg:cargo/* packages
    """

    @property
    def name(self) -> str:
        return "crates.io"

    @property
    def priority(self) -> int:
        # Tier 1: Native sources (10-19) - Direct from official package registries
        return 10

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL."""
        return bool(purl.type == "cargo")

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from crates.io API.

        When a version is specified, uses the version-specific endpoint which
        includes the license field. Otherwise falls back to the crate endpoint.

        Args:
            purl: Parsed PackageURL for a Cargo package
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        # Include version in cache key for version-specific lookups
        version = purl.version or "latest"
        cache_key = f"cratesio:{purl.name}:{version}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (crates.io): {purl.name}")
            return _cache[cache_key]

        try:
            # Use version-specific endpoint if version is available (has license info)
            if purl.version:
                url = f"{CRATESIO_API_BASE}/{purl.name}/{purl.version}"
                logger.debug(f"Fetching crates.io metadata for: {purl.name}@{purl.version}")
            else:
                url = f"{CRATESIO_API_BASE}/{purl.name}"
                logger.debug(f"Fetching crates.io metadata for: {purl.name}")

            response = session.get(url, timeout=DEFAULT_TIMEOUT)

            metadata = None
            if response.status_code == 200:
                data = response.json()
                metadata = self._normalize_response(purl.name, purl.version, data)
            elif response.status_code == 404:
                logger.debug(f"Package not found on crates.io: {purl.name}")
            else:
                logger.warning(f"Failed to fetch crates.io metadata for {purl.name}: HTTP {response.status_code}")

            # Cache result
            _cache[cache_key] = metadata
            return metadata

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching crates.io metadata for {purl.name}")
            _cache[cache_key] = None
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching crates.io metadata for {purl.name}: {e}")
            _cache[cache_key] = None
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error for crates.io {purl.name}: {e}")
            _cache[cache_key] = None
            return None

    def _normalize_response(
        self, package_name: str, version: Optional[str], data: Dict[str, Any]
    ) -> NormalizedMetadata:
        """
        Normalize crates.io API response to NormalizedMetadata.

        The API returns different structures for version vs crate endpoints:
        - Version endpoint: {"version": {...}, "crate": {...}}
        - Crate endpoint: {"crate": {...}, "versions": [...]}

        Args:
            package_name: Name of the package
            version: Requested version (may be None)
            data: Raw crates.io JSON API response

        Returns:
            NormalizedMetadata with extracted fields
        """
        # Extract data from appropriate response structure
        version_data = data.get("version", {})
        crate_data = data.get("crate", {})

        # Description - available in both version and crate data
        description = version_data.get("description") or crate_data.get("description")

        # License - only available in version-specific endpoint
        raw_license = version_data.get("license")
        licenses: list[str] = []
        license_texts: Dict[str, str] = {}
        if raw_license:
            # crates.io licenses are already in SPDX format (e.g., "MIT OR Apache-2.0")
            licenses, license_texts = normalize_license_list([raw_license])

        # Maintainer/Supplier info from published_by
        published_by = version_data.get("published_by", {})
        maintainer_name = published_by.get("name")

        # URLs - available in both version and crate data
        homepage = version_data.get("homepage") or crate_data.get("homepage")
        repository = version_data.get("repository") or crate_data.get("repository")
        documentation = version_data.get("documentation") or crate_data.get("documentation")

        # Normalize repository URL
        repository_url = normalize_vcs_url(repository) if repository else None

        logger.debug(f"Successfully fetched crates.io metadata for: {package_name}")

        # Build field_sources for attribution
        field_sources: Dict[str, str] = {}
        if description:
            field_sources["description"] = self.name
        if licenses:
            field_sources["licenses"] = self.name
        # Supplier is always the distribution platform
        field_sources["supplier"] = self.name
        if homepage:
            field_sources["homepage"] = self.name
        if repository_url:
            field_sources["repository_url"] = self.name
        if documentation:
            field_sources["documentation_url"] = self.name

        return NormalizedMetadata(
            description=description,
            licenses=licenses,
            license_texts=license_texts,
            supplier=PURL_TYPE_TO_SUPPLIER["cargo"],
            homepage=homepage,
            repository_url=repository_url,
            documentation_url=documentation,
            registry_url=f"https://crates.io/crates/{package_name}",
            maintainer_name=maintainer_name,
            source=self.name,
            field_sources=field_sources,
        )
