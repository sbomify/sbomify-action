"""deps.dev data source for package metadata (Google Open Source Insights)."""

import json
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..exceptions import TransientSourceError
from ..license_utils import normalize_license_list
from ..metadata import NormalizedMetadata
from ..sanitization import normalize_vcs_url
from ..utils import get_qualified_name
from .purl import PURL_TYPE_TO_SUPPLIER

DEPSDEV_API_BASE = "https://api.deps.dev/v3"
DEFAULT_TIMEOUT = 10  # seconds - deps.dev is generally fast

# Mapping from PURL type to deps.dev system name
PURL_TYPE_TO_SYSTEM: Dict[str, str] = {
    "pypi": "PYPI",
    "npm": "NPM",
    "cargo": "CARGO",
    "maven": "MAVEN",
    "golang": "GO",
    "gem": "RUBYGEMS",
    "nuget": "NUGET",
}

# Simple in-memory cache
_cache: Dict[str, Optional[NormalizedMetadata]] = {}


def clear_cache() -> None:
    """Clear the deps.dev metadata cache."""
    _cache.clear()


class DepsDevSource:
    """
    Data source for deps.dev (Google Open Source Insights) API.

    deps.dev provides package metadata including licenses, links, and
    security advisories for many package ecosystems.

    Priority: 40 (medium-high - reliable Google-backed source)
    Supports: pypi, npm, cargo, maven, golang, gem, nuget packages
    """

    @property
    def name(self) -> str:
        return "deps.dev"

    @property
    def priority(self) -> int:
        # Tier 2: Primary aggregators (40-49) - High-quality aggregated data
        return 40

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL type."""
        return purl.type in PURL_TYPE_TO_SYSTEM

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from deps.dev API.

        Args:
            purl: Parsed PackageURL
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        system = PURL_TYPE_TO_SYSTEM.get(purl.type)
        if not system:
            return None

        # Build cache key and package name using shared utility
        # Different package types use different separators:
        # - Maven uses ":" (group:artifact)
        # - npm uses "/" (@scope/name)
        # - Go uses "/" (namespace/name)
        version = purl.version or ""
        separator = ":" if purl.type == "maven" else "/"
        package_name = get_qualified_name(purl, separator=separator)
        cache_key = f"depsdev:{purl.type}:{package_name}:{version}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (deps.dev): {package_name}")
            return _cache[cache_key]

        try:
            # URL encode the package name
            encoded_name = quote(package_name, safe="")

            if version:
                # Get specific version info
                encoded_version = quote(version, safe="")
                url = f"{DEPSDEV_API_BASE}/systems/{system}/packages/{encoded_name}/versions/{encoded_version}"
            else:
                # Get package info (default version)
                url = f"{DEPSDEV_API_BASE}/systems/{system}/packages/{encoded_name}"

            logger.debug(f"Fetching deps.dev metadata for: {purl}")
            response = session.get(url, timeout=DEFAULT_TIMEOUT)

            metadata = None
            if response.status_code == 200:
                data = response.json()
                metadata = self._normalize_response(purl.name, purl.type, data)
            elif response.status_code == 404:
                logger.debug(f"Package not found in deps.dev: {purl}")
            else:
                logger.warning(f"Failed to fetch deps.dev metadata for {purl}: HTTP {response.status_code}")

            # Cache result
            _cache[cache_key] = metadata
            return metadata

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching deps.dev metadata for {purl}")
            raise TransientSourceError(f"Timeout from {self.name}") from None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching deps.dev metadata for {purl}: {e}")
            raise TransientSourceError(f"RequestException from {self.name}") from None
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error for deps.dev {purl}: {e}")
            _cache[cache_key] = None
            return None

    def _normalize_response(
        self, package_name: str, purl_type: str, data: Dict[str, Any]
    ) -> Optional[NormalizedMetadata]:
        """
        Normalize deps.dev API response to NormalizedMetadata.

        Args:
            package_name: Name of the package
            purl_type: PURL type (e.g., "pypi", "npm", "cargo")
            data: Raw deps.dev API response

        Returns:
            NormalizedMetadata with extracted fields, or None if no data
        """
        if not data:
            return None

        # Extract and normalize licenses
        raw_licenses: List[str] = data.get("licenses", [])
        licenses, license_texts = normalize_license_list(raw_licenses)

        # Extract links
        homepage = None
        repository_url = None
        links = data.get("links", [])
        for link in links:
            label = link.get("label", "").lower()
            url = link.get("url", "")
            if "homepage" in label or "home" in label:
                homepage = url
            elif "source" in label or "repository" in label or "repo" in label:
                repository_url = url

        # Extract related projects for repository URL
        if not repository_url:
            related_projects = data.get("relatedProjects", [])
            for project in related_projects:
                project_key = project.get("projectKey", {})
                project_id = project_key.get("id", "")
                if project_id:
                    # Convert project ID to URL
                    if project_id.startswith("github.com/"):
                        repository_url = f"https://{project_id}"
                        break
                    elif project_id.startswith("gitlab.com/"):
                        repository_url = f"https://{project_id}"
                        break

        # Normalize repository URL to SPDX VCS standard format
        if repository_url:
            repository_url = normalize_vcs_url(repository_url)

        # Get supplier from PURL type mapping
        supplier = PURL_TYPE_TO_SUPPLIER.get(purl_type)

        # Build field_sources for attribution
        field_sources: dict[str, str] = {}
        if licenses:
            field_sources["licenses"] = self.name
        if homepage:
            field_sources["homepage"] = self.name
        if repository_url:
            field_sources["repository_url"] = self.name
        if supplier:
            field_sources["supplier"] = self.name

        metadata = NormalizedMetadata(
            licenses=licenses,
            license_texts=license_texts,
            supplier=supplier,
            homepage=homepage,
            repository_url=repository_url,
            source=self.name,
            field_sources=field_sources,
        )

        if metadata.has_data():
            logger.debug(f"Successfully normalized deps.dev metadata for {package_name}")
            return metadata
        return None
