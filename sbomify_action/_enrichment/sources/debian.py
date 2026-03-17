"""Debian Sources data source for Debian package metadata."""

import json
from typing import Any, Dict, Optional, Tuple

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..metadata import NormalizedMetadata
from ..sanitization import normalize_vcs_url

DEBIAN_SOURCES_BASE = "https://sources.debian.org"
DEFAULT_TIMEOUT = 10  # seconds

# Simple in-memory cache
_cache: Dict[str, Optional[NormalizedMetadata]] = {}


def clear_cache() -> None:
    """Clear the Debian Sources metadata cache."""
    _cache.clear()


class DebianSource:
    """
    Data source for Debian packages using the official Debian Sources API.

    This is the authoritative source for Debian packages and should be tried
    before generic sources like ecosyste.ms for pkg:deb/debian/* packages.

    API Documentation: https://sources.debian.org/doc/api/

    Uses /api/info/package/<name>/<version> endpoint to get package metadata.
    Falls back to 'latest' if specific version is not found.

    Priority: 10 (Tier 1 - native source for Debian packages)
    Supports: pkg:deb/debian/* packages only
    """

    @property
    def name(self) -> str:
        return "sources.debian.org"

    @property
    def priority(self) -> int:
        # Tier 1: Native sources (10-19) - Direct from official package registries
        return 10

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL."""
        # Only support Debian packages (not Ubuntu or other deb-based distros)
        if purl.type != "deb":
            return False
        if not purl.namespace:
            return False
        return bool(purl.namespace.lower() == "debian")

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from Debian Sources API.

        Tries version-specific endpoint first, falls back to 'latest' if not found.
        This is important because licenses and metadata can change between versions.

        Args:
            purl: Parsed PackageURL for a Debian package
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        version = purl.version or "latest"
        cache_key = f"debian:{purl.name}:{version}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (Debian Sources): {purl.name}@{version}")
            return _cache[cache_key]

        metadata = self._fetch_package_info(purl.name, version, session)

        # Cache result (including None for negative caching)
        _cache[cache_key] = metadata
        return metadata

    def _fetch_package_info(
        self, package_name: str, version: str, session: requests.Session
    ) -> Optional[NormalizedMetadata]:
        """
        Fetch package info from Debian Sources API.

        Args:
            package_name: Name of the Debian package
            version: Version to fetch, or "latest"
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        try:
            # Try exact version first
            api_data, actual_version = self._try_fetch_version(package_name, version, session)

            # If exact version not found and we weren't already requesting latest, try latest
            if api_data is None and version != "latest":
                logger.debug(f"Version {version} not found for {package_name}, trying latest")
                api_data, actual_version = self._try_fetch_version(package_name, "latest", session)

            if api_data is None:
                return None

            return self._parse_api_response(package_name, api_data, actual_version)

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching Debian Sources metadata for {package_name}")
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching Debian Sources metadata for {package_name}: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error for Debian Sources {package_name}: {e}")
            return None

    def _try_fetch_version(
        self, package_name: str, version: str, session: requests.Session
    ) -> Tuple[Optional[Dict[str, Any]], str]:
        """
        Try to fetch a specific version from the API.

        Args:
            package_name: Name of the Debian package
            version: Version to fetch
            session: requests.Session with configured headers

        Returns:
            Tuple of (api_data, actual_version) if found, (None, version) if not found
        """
        api_url = f"{DEBIAN_SOURCES_BASE}/api/info/package/{package_name}/{version}/"
        logger.debug(f"Fetching Debian package info: {package_name}@{version}")

        response = session.get(api_url, timeout=DEFAULT_TIMEOUT)

        if response.status_code == 404:
            logger.debug(f"Package/version not found on Debian Sources: {package_name}@{version}")
            return None, version
        elif response.status_code != 200:
            logger.warning(
                f"Failed to fetch Debian Sources metadata for {package_name}@{version}: HTTP {response.status_code}"
            )
            return None, version

        api_data = response.json()

        # Check for API error response
        if "error" in api_data:
            logger.debug(f"Debian Sources API error for {package_name}: {api_data.get('error')}")
            return None, version

        # Get the actual version from the response (important when requesting 'latest')
        actual_version = api_data.get("version", version)

        return api_data, actual_version

    def _parse_api_response(
        self, package_name: str, api_data: Dict[str, Any], version: str
    ) -> Optional[NormalizedMetadata]:
        """
        Parse API response and extract metadata.

        Args:
            package_name: Name of the package
            api_data: API response data
            version: The actual version returned

        Returns:
            NormalizedMetadata with extracted fields
        """
        pkg_infos = api_data.get("pkg_infos", {})

        # Build field_sources for attribution
        field_sources = {}

        # Supplier is always Debian Project for Debian packages
        supplier = "Debian Project"
        field_sources["supplier"] = self.name

        # Extract description - prefer long_description, fallback to description
        description = pkg_infos.get("long_description") or pkg_infos.get("description")
        if description:
            field_sources["description"] = self.name

        # Extract homepage - fallback to Package Tracker
        homepage = pkg_infos.get("homepage")
        if not homepage:
            homepage = f"https://tracker.debian.org/pkg/{package_name}"
        field_sources["homepage"] = self.name

        # Registry URL points to the source browser
        registry_url = f"https://sources.debian.org/src/{package_name}/{version}/"
        field_sources["registry_url"] = self.name

        # Extract VCS/repository URL and normalize to SPDX VCS format
        repository_url = self._parse_vcs(pkg_infos.get("vcs"))
        if repository_url:
            repository_url = normalize_vcs_url(repository_url)
            field_sources["repository_url"] = self.name

        logger.debug(f"Successfully parsed Debian package info for: {package_name}@{version}")

        metadata = NormalizedMetadata(
            description=description,
            supplier=supplier,
            homepage=homepage,
            repository_url=repository_url,
            registry_url=registry_url,
            source=self.name,
            field_sources=field_sources,
        )

        return metadata if metadata.has_data() else None

    def _parse_vcs(self, vcs: Any) -> Optional[str]:
        """
        Parse VCS field from pkg_infos to extract repository URL.

        The VCS field can be:
        - A string like "Git https://salsa.debian.org/debian/bash.git"
        - A string like "https://salsa.debian.org/debian/bash.git"
        - A string like "git://git.debian.org/debian/bash.git"
        - A dict with 'url' and/or 'browser' keys

        Args:
            vcs: VCS field from pkg_infos (string or dict)

        Returns:
            Repository URL if found, None otherwise
        """
        if not vcs:
            return None

        if isinstance(vcs, dict):
            # Prefer 'url' key, fallback to 'browser'
            return vcs.get("url") or vcs.get("browser")

        if isinstance(vcs, str):
            # Handle "Type URL" format (e.g., "Git https://...")
            # Split on space and take last part that looks like a URL
            parts = vcs.split()
            for part in reversed(parts):
                if part.startswith(("https://", "http://", "git://", "ssh://")):
                    return part
            # If no URL-like part found but string exists, return as-is
            return vcs if vcs.startswith(("https://", "http://", "git://", "ssh://")) else None

        return None
