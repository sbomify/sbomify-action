"""PyPI data source for Python package metadata."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..license_utils import normalize_license_list
from ..metadata import NormalizedMetadata
from ..sanitization import normalize_vcs_url
from ..utils import parse_author_string
from .purl import PURL_TYPE_TO_SUPPLIER

PYPI_API_BASE = "https://pypi.org/pypi"
DEFAULT_TIMEOUT = 10  # seconds - PyPI is fast

# Simple in-memory cache
_cache: Dict[str, Optional[NormalizedMetadata]] = {}


def clear_cache() -> None:
    """Clear the PyPI metadata cache."""
    _cache.clear()


class PyPISource:
    """
    Data source for PyPI (Python Package Index) packages.

    This is the authoritative source for Python packages and should
    be tried first before generic sources like ecosyste.ms.

    Priority: 10 (high - native source)
    Supports: pkg:pypi/* packages
    """

    @property
    def name(self) -> str:
        return "pypi.org"

    @property
    def priority(self) -> int:
        # Tier 1: Native sources (10-19) - Direct from official package registries
        return 10

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL."""
        return bool(purl.type == "pypi")

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from PyPI JSON API.

        Args:
            purl: Parsed PackageURL for a PyPI package
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        # Include version in cache key for version-specific lookups
        version = purl.version or "latest"
        cache_key = f"pypi:{purl.name}:{version}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (PyPI): {purl.name}")
            return _cache[cache_key]

        try:
            # Prefer the version-specific endpoint when a version is present:
            # it surfaces per-release fields (yanked, upload_time, file hashes)
            # that the latest-only endpoint flattens out. Fall back to the
            # latest-only endpoint when no version is available in the PURL.
            if purl.version:
                url = f"{PYPI_API_BASE}/{purl.name}/{purl.version}/json"
            else:
                url = f"{PYPI_API_BASE}/{purl.name}/json"
            logger.debug(f"Fetching PyPI metadata for: {purl.name}")
            response = session.get(url, timeout=DEFAULT_TIMEOUT)

            metadata = None
            if response.status_code == 200:
                metadata = self._normalize_response(purl.name, response.json())
            elif response.status_code == 404:
                logger.debug(f"Package not found on PyPI: {purl.name}")
            else:
                logger.warning(f"Failed to fetch PyPI metadata for {purl.name}: HTTP {response.status_code}")

            # Cache result
            _cache[cache_key] = metadata
            return metadata

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching PyPI metadata for {purl.name}")
            _cache[cache_key] = None
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching PyPI metadata for {purl.name}: {e}")
            _cache[cache_key] = None
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error for PyPI {purl.name}: {e}")
            _cache[cache_key] = None
            return None

    def _normalize_response(self, package_name: str, data: Dict[str, Any]) -> NormalizedMetadata:
        """
        Normalize PyPI API response to NormalizedMetadata.

        Args:
            package_name: Name of the package
            data: Raw PyPI JSON API response

        Returns:
            NormalizedMetadata with extracted fields
        """
        info = data.get("info", {})

        # Extract and normalize license
        raw_licenses = []
        if info.get("license"):
            raw_licenses = [info["license"]]

        # Normalize to SPDX and extract any license text
        licenses, license_texts = normalize_license_list(raw_licenses)

        # Extract maintainer info
        # Priority: author field > maintainer field > parsed from email fields
        maintainer_name = None
        maintainer_email = None
        if info.get("author"):
            maintainer_name = info["author"]
            maintainer_email = info.get("author_email")
        elif info.get("maintainer"):
            maintainer_name = info["maintainer"]
            maintainer_email = info.get("maintainer_email")

        # If no direct name, try parsing from email field ("Name <email>" format)
        # This handles packages where author/maintainer is empty but author_email contains the name
        if not maintainer_name:
            email_field = info.get("author_email") or info.get("maintainer_email")
            if email_field:
                parsed_name, parsed_email = parse_author_string(email_field)
                if parsed_name:
                    maintainer_name = parsed_name
                    logger.debug(f"Extracted author name from email field: {parsed_name}")
                if parsed_email and not maintainer_email:
                    maintainer_email = parsed_email

        # Extract URLs from project_urls
        project_urls = info.get("project_urls") or {}
        repository_url = None
        documentation_url = None
        issue_tracker_url = None
        homepage = info.get("home_page")

        for key, url_value in project_urls.items():
            key_lower = key.lower()
            if "source" in key_lower or "repository" in key_lower or "github" in key_lower:
                repository_url = normalize_vcs_url(url_value)
            elif "issue" in key_lower or "bug" in key_lower or "tracker" in key_lower:
                issue_tracker_url = url_value
            elif "documentation" in key_lower or "docs" in key_lower:
                documentation_url = url_value
            elif "homepage" in key_lower and not homepage:
                homepage = url_value

        # Extract distribution filename + hashes from release files
        # (BSI TR-03183-2 §5.2.2 filename + hash / NTIA / CISA hash element).
        # Prefer wheel (.whl) over sdist (.tar.gz); take the hashes of the
        # distribution whose filename we record so the two fields describe
        # the same artefact.
        distribution_filename = None
        distribution_hashes: Dict[str, str] = {}
        urls = data.get("urls", [])
        selected_dist: Optional[Dict[str, Any]] = None
        for dist in urls:
            fn = dist.get("filename", "")
            if fn.endswith(".whl"):
                distribution_filename = fn
                selected_dist = dist
                break
            elif fn and not distribution_filename:
                distribution_filename = fn
                selected_dist = dist
        if selected_dist is not None:
            raw_digests = selected_dist.get("digests") or {}
            if isinstance(raw_digests, dict):
                for alg_name, hex_value in raw_digests.items():
                    if isinstance(alg_name, str) and isinstance(hex_value, str) and hex_value.strip():
                        distribution_hashes[alg_name.strip().lower()] = hex_value.strip().lower()

        # Release date + lifecycle-status inference (ECMA-428 CLE).
        # - release_date: upload_time_iso_8601 of the chosen distribution file.
        # - end_of_life: version-level yanked flag. A yanked release has been
        #   withdrawn by its maintainer and should no longer be consumed; we
        #   map that to an EOL date at the upload time (falling back to the
        #   current UTC date if the upload timestamp is unavailable).
        cle_release_date: Optional[str] = None
        cle_eol: Optional[str] = None
        upload_date = None
        if selected_dist is not None:
            upload_time = selected_dist.get("upload_time_iso_8601") or selected_dist.get("upload_time") or ""
            if isinstance(upload_time, str) and upload_time.strip():
                upload_date = upload_time.strip().split("T", 1)[0]
                cle_release_date = upload_date
        is_yanked = bool(info.get("yanked"))
        if not is_yanked and selected_dist is not None:
            is_yanked = bool(selected_dist.get("yanked"))
        if is_yanked:
            cle_eol = upload_date or datetime.now(timezone.utc).strftime("%Y-%m-%d")

        logger.debug(f"Successfully fetched PyPI metadata for: {package_name}")

        # Build field_sources for attribution
        field_sources = {}
        if info.get("summary"):
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
        if distribution_filename:
            field_sources["distribution_filename"] = self.name
        if distribution_hashes:
            field_sources["hashes"] = self.name
        if cle_release_date:
            field_sources["cle_release_date"] = self.name
        if cle_eol:
            field_sources["cle_eol"] = self.name

        return NormalizedMetadata(
            description=info.get("summary"),
            licenses=licenses,
            license_texts=license_texts,
            supplier=PURL_TYPE_TO_SUPPLIER["pypi"],
            homepage=homepage,
            repository_url=repository_url,
            documentation_url=documentation_url,
            registry_url=f"https://pypi.org/project/{package_name}/",
            issue_tracker_url=issue_tracker_url,
            maintainer_name=maintainer_name,
            maintainer_email=maintainer_email,
            distribution_filename=distribution_filename,
            hashes=distribution_hashes,
            cle_release_date=cle_release_date,
            cle_eol=cle_eol,
            source=self.name,
            field_sources=field_sources,
        )
