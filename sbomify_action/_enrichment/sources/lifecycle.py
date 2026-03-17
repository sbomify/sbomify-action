"""Lifecycle data source for CLE (Common Lifecycle Enumeration) enrichment.

This source provides lifecycle dates (release_date, end_of_support, end_of_life)
for language runtimes and frameworks that we explicitly track:
- Python, PHP, Go, Rust
- Django, Rails, Laravel, React, Vue

Note: We do NOT provide lifecycle data for arbitrary OS packages (curl, nginx, etc.)
because the PURL doesn't reliably indicate the distro version, and the package's
lifecycle is not the same as the distro's lifecycle.

Priority: 5 (high priority - local data, no API calls)
Supports: Packages matching PACKAGE_LIFECYCLE patterns only
"""

import fnmatch
from typing import Dict, Optional

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..lifecycle_data import (
    PACKAGE_LIFECYCLE,
    LifecycleDates,
    PackageLifecycleEntry,
    extract_version_cycle,
)
from ..metadata import NormalizedMetadata

# Simple in-memory cache for lifecycle lookups
_cache: Dict[str, Optional[NormalizedMetadata]] = {}


def clear_cache() -> None:
    """Clear the lifecycle metadata cache."""
    _cache.clear()


class LifecycleSource:
    """
    Data source for lifecycle (CLE) information.

    This source provides CLE dates for language runtimes and frameworks:
    - Python, PHP, Go, Rust (matched across all PURL types)
    - Django, Rails, Laravel, React, Vue (matched by ecosystem)

    Matched by name patterns:
    - "python" matches pkg:pypi/python, pkg:deb/ubuntu/python3, etc.
    - "django" matches pkg:pypi/django
    - "rails" matches pkg:gem/rails

    Note: We do NOT provide lifecycle data for arbitrary OS packages.
    A PURL like pkg:apk/alpine/curl@8.0 doesn't tell us the Alpine version,
    and curl's upstream lifecycle is different from the distro's lifecycle.

    Priority: 5 (high - local data, no network calls)
    Supports: Packages matching PACKAGE_LIFECYCLE patterns only
    """

    @property
    def name(self) -> str:
        return "sbomify-lifecycle-db"

    @property
    def priority(self) -> int:
        # Priority 5: Very high - local data with no API calls
        return 5

    def supports(self, purl: PackageURL) -> bool:
        """
        Check if this source supports the given PURL.

        Returns True only if the package name matches a pattern in PACKAGE_LIFECYCLE.
        """
        entry = self._find_package_entry(purl)
        return entry is not None

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch lifecycle metadata for the given PURL.

        Only provides CLE data for packages we explicitly track
        (Python, PHP, Go, Rust, Django, Rails, Laravel, React, Vue).

        Args:
            purl: Parsed PackageURL object
            session: requests.Session (not used - local data only)

        Returns:
            NormalizedMetadata with CLE fields if found, None otherwise
        """
        # Build cache key
        namespace = purl.namespace or ""
        cache_key = f"lifecycle:{purl.type}:{namespace}:{purl.name}:{purl.version or 'latest'}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (lifecycle): {purl.name}")
            return _cache[cache_key]

        # Fetch package lifecycle
        metadata = self._fetch_package_lifecycle(purl)
        _cache[cache_key] = metadata
        return metadata

    def _fetch_package_lifecycle(self, purl: PackageURL) -> Optional[NormalizedMetadata]:
        """Fetch lifecycle data for a language runtime or framework."""
        entry = self._find_package_entry(purl)
        if not entry:
            logger.debug(f"No lifecycle data found for: {purl.name}")
            return None

        # Extract version cycle
        version = purl.version or ""
        version_extract = entry.get("version_extract", "major.minor")
        cycle = extract_version_cycle(version, version_extract)

        if not cycle:
            logger.debug(f"Could not extract version cycle from {purl.name}@{version}")
            return None

        # Look up lifecycle dates for this cycle
        cycles = entry.get("cycles", {})
        lifecycle_dates = cycles.get(cycle)

        if not lifecycle_dates:
            logger.debug(f"No lifecycle data for {purl.name} cycle {cycle}")
            return None

        return self._build_metadata(lifecycle_dates, f"{purl.name} {cycle}")

    def _build_metadata(self, lifecycle_dates: "LifecycleDates", context: str) -> Optional[NormalizedMetadata]:
        """Build NormalizedMetadata from lifecycle dates."""
        cle_eos = lifecycle_dates.get("end_of_support")
        cle_eol = lifecycle_dates.get("end_of_life")
        cle_release_date = lifecycle_dates.get("release_date")

        # Only return metadata if we have at least one CLE field
        if not any([cle_eos, cle_eol, cle_release_date]):
            logger.debug(f"No CLE dates available for {context}")
            return None

        # Build field sources
        field_sources: Dict[str, str] = {}
        if cle_eos:
            field_sources["cle_eos"] = self.name
        if cle_eol:
            field_sources["cle_eol"] = self.name
        if cle_release_date:
            field_sources["cle_release_date"] = self.name

        logger.debug(f"Found lifecycle data for {context}: EOS={cle_eos}, EOL={cle_eol}")

        return NormalizedMetadata(
            cle_eos=cle_eos,
            cle_eol=cle_eol,
            cle_release_date=cle_release_date,
            source=self.name,
            field_sources=field_sources,
        )

    def _find_package_entry(self, purl: PackageURL) -> Optional[PackageLifecycleEntry]:
        """
        Find the PACKAGE_LIFECYCLE entry matching the given PURL.

        Checks name patterns, namespace (for composer packages), and PURL type filters.

        For composer packages (like Laravel), the namespace is significant:
        - pkg:composer/laravel/framework matches patterns against both "laravel" and "framework"

        Args:
            purl: Parsed PackageURL object

        Returns:
            PackageLifecycleEntry if found, None otherwise
        """
        name_lower = purl.name.lower()
        namespace_lower = (purl.namespace or "").lower()
        purl_type = purl.type.lower()

        # Build list of names to check (name + namespace for namespaced packages)
        names_to_check = [name_lower]
        if namespace_lower:
            names_to_check.append(namespace_lower)
            # Also check combined namespace/name format
            names_to_check.append(f"{namespace_lower}/{name_lower}")

        for entry_key, entry in PACKAGE_LIFECYCLE.items():
            # Check name patterns against all possible name variations
            patterns = entry.get("name_patterns", [])
            name_matches = False

            for pattern in patterns:
                pattern_lower = pattern.lower()
                for name in names_to_check:
                    if fnmatch.fnmatch(name, pattern_lower):
                        name_matches = True
                        break
                if name_matches:
                    break

            if not name_matches:
                continue

            # Check PURL type filter
            allowed_types = entry.get("purl_types")
            if allowed_types is not None:
                if purl_type not in [t.lower() for t in allowed_types]:
                    continue

            return entry

        return None
