"""Repology data source for OS package metadata."""

import json
from typing import Any, Dict, List, Optional

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..license_utils import normalize_license_list
from ..metadata import NormalizedMetadata

REPOLOGY_API_BASE = "https://repology.org/api/v1"
DEFAULT_TIMEOUT = 10  # seconds

# Rolling release distros - these don't have version numbers in Repology
ROLLING_RELEASE_REPOS: Dict[str, str] = {
    "alpine": "alpine_edge",
    "arch": "arch",
    "opensuse": "opensuse_tumbleweed",
}


def _derive_repo_name_from_purl(purl: PackageURL) -> Optional[str]:
    """
    Derive Repology repository name from PURL.

    Strategy:
    1. Use 'distro' qualifier if present (e.g., distro=debian-12 → debian_12)
    2. For rolling release distros, use known repo names
    3. Fall back to namespace as-is (may not match exactly but Repology is flexible)

    Args:
        purl: PackageURL with potential distro qualifier

    Returns:
        Repology repository name or None
    """
    namespace = purl.namespace.lower() if purl.namespace else None
    if not namespace:
        return None

    # Check for distro qualifier (e.g., "debian-12", "ubuntu-24.04", "fedora-40")
    qualifiers = purl.qualifiers or {}
    distro = qualifiers.get("distro")

    if distro:
        # Convert distro format to Repology format:
        # "debian-12" → "debian_12"
        # "ubuntu-24.04" → "ubuntu_24_04"
        # "fedora-40" → "fedora_40"
        repo_name = distro.replace("-", "_").replace(".", "_")
        return str(repo_name)

    # Rolling release distros have fixed repo names
    if namespace in ROLLING_RELEASE_REPOS:
        return ROLLING_RELEASE_REPOS[namespace]

    # No distro qualifier and not rolling - return namespace as fallback
    # Repology will search across all versions of this distro
    return str(namespace)


# OS package types supported by Repology
SUPPORTED_TYPES = {"deb", "rpm", "apk", "alpm"}

# Simple in-memory cache
_cache: Dict[str, Optional[NormalizedMetadata]] = {}


def clear_cache() -> None:
    """Clear the Repology metadata cache."""
    _cache.clear()


class RepologySource:
    """
    Data source for Repology API.

    Repology aggregates package information from many Linux distributions
    and can provide metadata like description, licenses, and homepage URLs.

    This is a FALLBACK source with lowest priority - Repology has strict
    rate limits (1 request per second) and should only be used when
    other sources don't have data.

    Priority: 90 (Tier 3: Fallback sources - last resort, rate-limited)
    Supports: pkg:deb/*, pkg:rpm/*, pkg:apk/*, pkg:alpm/* packages
    """

    @property
    def name(self) -> str:
        return "repology.org"

    @property
    def priority(self) -> int:
        # Tier 3: Fallback sources (70-99) - Last resort, basic or rate-limited
        return 90

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL type."""
        return purl.type in SUPPORTED_TYPES

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from Repology API.

        Note: Repology has strict rate limits. This source should only be
        used as a last resort when other sources don't have data.

        Args:
            purl: Parsed PackageURL for an OS package
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        if purl.type not in SUPPORTED_TYPES:
            return None

        # Derive repository name from PURL (distro qualifier or namespace)
        repo_name = _derive_repo_name_from_purl(purl)

        cache_key = f"repology:{purl.name}:{repo_name or 'any'}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (Repology): {purl.name}")
            return _cache[cache_key]

        try:
            # Repology project endpoint
            url = f"{REPOLOGY_API_BASE}/project/{purl.name}"
            logger.debug(f"Fetching Repology metadata for: {purl.name}")
            response = session.get(url, timeout=DEFAULT_TIMEOUT)

            metadata = None
            if response.status_code == 200:
                data = response.json()
                metadata = self._normalize_response(purl, data, repo_name)
            elif response.status_code == 404:
                logger.debug(f"Package not found in Repology: {purl.name}")
            elif response.status_code == 429:
                logger.warning(f"Repology rate limit exceeded for {purl.name}. Consider reducing request frequency.")
            else:
                logger.warning(f"Failed to fetch Repology metadata for {purl.name}: HTTP {response.status_code}")

            # Cache result
            _cache[cache_key] = metadata
            return metadata

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching Repology metadata for {purl.name}")
            _cache[cache_key] = None
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching Repology metadata for {purl.name}: {e}")
            _cache[cache_key] = None
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error for Repology {purl.name}: {e}")
            _cache[cache_key] = None
            return None

    def _normalize_response(
        self, purl: PackageURL, data: List[Dict[str, Any]], preferred_repo: Optional[str]
    ) -> Optional[NormalizedMetadata]:
        """
        Normalize Repology API response to NormalizedMetadata.

        Repology returns a list of packages from different repositories.
        We prefer the package from the repository matching the PURL namespace.

        Args:
            purl: Original PackageURL
            data: Raw Repology API response (list of package entries)
            preferred_repo: Preferred repository name based on PURL namespace

        Returns:
            NormalizedMetadata with extracted fields, or None if no data
        """
        if not data:
            return None

        # Find the best package entry
        # Priority: 1) Matching repository, 2) Any entry with summary
        best_entry = None

        for entry in data:
            repo = entry.get("repo", "")

            # Prefer matching repository
            if preferred_repo and repo == preferred_repo:
                best_entry = entry
                break

            # Otherwise, pick first entry with a summary
            if not best_entry and entry.get("summary"):
                best_entry = entry

        # Fallback to first entry if no summary found
        if not best_entry and data:
            best_entry = data[0]

        if not best_entry:
            return None

        # Extract metadata
        description = best_entry.get("summary")
        homepage = best_entry.get("www")
        licenses: list[str] = []
        license_texts: dict[str, str] = {}
        if best_entry.get("licenses"):
            licenses, license_texts = normalize_license_list(best_entry["licenses"])

        # Extract maintainer info
        maintainer_name = None
        maintainers = best_entry.get("maintainers", [])
        if maintainers:
            # Maintainers are typically email addresses
            maintainer_name = maintainers[0]

        # Build field_sources for attribution
        field_sources = {}
        if description:
            field_sources["description"] = self.name
        if homepage:
            field_sources["homepage"] = self.name
        if licenses:
            field_sources["licenses"] = self.name
        if maintainer_name:
            field_sources["maintainer_name"] = self.name

        metadata = NormalizedMetadata(
            description=description,
            licenses=licenses,
            license_texts=license_texts,
            homepage=homepage,
            maintainer_name=maintainer_name,
            source=self.name,
            field_sources=field_sources,
        )

        if metadata.has_data():
            logger.debug(f"Successfully normalized Repology metadata for {purl.name}")
            return metadata
        return None
