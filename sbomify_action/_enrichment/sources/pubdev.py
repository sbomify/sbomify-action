"""pub.dev data source for Dart package metadata."""

import json
from typing import Any, Dict, List, Optional

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..license_utils import normalize_license_list
from ..metadata import NormalizedMetadata
from ..sanitization import normalize_vcs_url
from ..utils import parse_author_string
from .purl import PURL_TYPE_TO_SUPPLIER

PUBDEV_API_BASE = "https://pub.dev/api/packages"
DEFAULT_TIMEOUT = 10  # seconds - pub.dev is generally fast

# Simple in-memory cache
_cache: Dict[str, Optional[NormalizedMetadata]] = {}


def clear_cache() -> None:
    """Clear the pub.dev metadata cache."""
    _cache.clear()


class PubDevSource:
    """
    Data source for pub.dev (Dart Package Repository) packages.

    This is the authoritative source for Dart packages and should
    be tried first before generic sources like ecosyste.ms.

    Priority: 10 (high - native source)
    Supports: pkg:pub/* packages
    """

    @property
    def name(self) -> str:
        return "pub.dev"

    @property
    def priority(self) -> int:
        # Tier 1: Native sources (10-19) - Direct from official package registries
        return 10

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL."""
        return bool(purl.type == "pub")

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from pub.dev API.

        Args:
            purl: Parsed PackageURL for a pub.dev package
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        # Include version in cache key for version-specific lookups
        version = purl.version or "latest"
        cache_key = f"pubdev:{purl.name}:{version}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (pub.dev): {purl.name}")
            return _cache[cache_key]

        try:
            url = f"{PUBDEV_API_BASE}/{purl.name}"
            logger.debug(f"Fetching pub.dev metadata for: {purl.name}")
            response = session.get(url, timeout=DEFAULT_TIMEOUT)

            metadata = None
            if response.status_code == 200:
                metadata = self._normalize_response(purl.name, response.json())
            elif response.status_code == 404:
                logger.debug(f"Package not found on pub.dev: {purl.name}")
            else:
                logger.warning(f"Failed to fetch pub.dev metadata for {purl.name}: HTTP {response.status_code}")

            # Cache result
            _cache[cache_key] = metadata
            return metadata

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching pub.dev metadata for {purl.name}")
            _cache[cache_key] = None
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching pub.dev metadata for {purl.name}: {e}")
            _cache[cache_key] = None
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error for pub.dev {purl.name}: {e}")
            _cache[cache_key] = None
            return None

    def _normalize_response(self, package_name: str, data: Dict[str, Any]) -> Optional[NormalizedMetadata]:
        """
        Normalize pub.dev API response to NormalizedMetadata.

        Args:
            package_name: Name of the package
            data: Raw pub.dev JSON API response

        Returns:
            NormalizedMetadata with extracted fields, or None if no data
        """
        latest = data.get("latest", {})
        pubspec = latest.get("pubspec", {})

        if not pubspec:
            return None

        # Extract description
        description = pubspec.get("description")

        # Extract and normalize license
        raw_licenses: List[str] = []
        if pubspec.get("license"):
            raw_licenses = [pubspec["license"]]

        licenses, license_texts = normalize_license_list(raw_licenses)

        # Extract URLs
        homepage = pubspec.get("homepage")
        repository_url = pubspec.get("repository")
        if repository_url:
            repository_url = normalize_vcs_url(repository_url)
        documentation_url = pubspec.get("documentation")
        issue_tracker_url = pubspec.get("issue_tracker")

        # Extract author info for maintainer_name field
        maintainer_name = None
        maintainer_email = None

        # pub.dev uses 'authors' (list) or 'author' (string) in older pubspecs
        authors = pubspec.get("authors")
        if authors and isinstance(authors, list) and len(authors) > 0:
            maintainer_name, maintainer_email = parse_author_string(authors[0])
        elif pubspec.get("author"):
            maintainer_name, maintainer_email = parse_author_string(pubspec["author"])

        # Check for publisher in the top-level response (newer pub.dev API)
        # Use publisher ID as maintainer_name if available
        if data.get("publisher"):
            publisher_id = data["publisher"].get("publisherId")
            if publisher_id and not maintainer_name:
                maintainer_name = publisher_id

        logger.debug(f"Successfully fetched pub.dev metadata for: {package_name}")

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
        if documentation_url:
            field_sources["documentation_url"] = self.name
        if issue_tracker_url:
            field_sources["issue_tracker_url"] = self.name

        metadata = NormalizedMetadata(
            description=description,
            licenses=licenses,
            license_texts=license_texts,
            supplier=PURL_TYPE_TO_SUPPLIER["pub"],
            homepage=homepage,
            repository_url=repository_url,
            documentation_url=documentation_url,
            registry_url=f"https://pub.dev/packages/{package_name}",
            issue_tracker_url=issue_tracker_url,
            maintainer_name=maintainer_name,
            maintainer_email=maintainer_email,
            source=self.name,
            field_sources=field_sources,
        )

        if metadata.has_data():
            return metadata
        return None
