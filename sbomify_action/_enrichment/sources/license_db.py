"""License Database data source for Linux distro package licenses.

Downloads and uses pre-computed license databases from GitHub Releases
to provide license information for Linux distro packages (Alpine, Wolfi,
Ubuntu, Rocky, Alma, CentOS, Fedora, Amazon Linux).

The databases are keyed by PURL for fast lookups and contain SPDX-validated
license expressions extracted from package copyright files (Ubuntu) or
package metadata (APK, RPM).

Strategy:
1. Check local cache first
2. Try to download from recent GitHub releases (checks up to 5 releases)
3. Cache the result locally for future use
"""

import gzip
import io
import json
import os
import re
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..metadata import NormalizedMetadata

# GitHub repository hosting the license databases
GITHUB_REPO = "sbomify/sbomify-action"
GITHUB_RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases"

# Number of recent releases to check when looking for a database
MAX_RELEASES_TO_CHECK = 5

# Default timeout for downloads
DEFAULT_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 120

# Cache directory (XDG compliant)
DEFAULT_CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "sbomify" / "license-db"

# Local generation is disabled by default (too slow for Ubuntu/Debian - takes hours)
# Set SBOMIFY_ENABLE_LICENSE_DB_GENERATION=true to enable local generation fallback
DISABLE_LOCAL_GENERATION = os.environ.get("SBOMIFY_ENABLE_LICENSE_DB_GENERATION", "").lower() not in (
    "1",
    "true",
    "yes",
)

# Supported distros and their database file patterns
SUPPORTED_DISTROS = {
    "alpine": {
        "type": "apk",
        "versions": ["3.13", "3.14", "3.15", "3.16", "3.17", "3.18", "3.19", "3.20", "3.21"],
    },
    "wolfi": {
        "type": "apk",
        "versions": ["rolling"],
    },
    "amazonlinux": {
        "type": "rpm",
        "versions": ["2", "2023"],
    },
    "centos": {
        "type": "rpm",
        "versions": ["stream8", "stream9"],
    },
    "debian": {
        "type": "deb",
        "versions": ["11", "12", "13"],
        "codenames": {"11": "bullseye", "12": "bookworm", "13": "trixie"},
    },
    "ubuntu": {
        "type": "deb",
        "versions": ["20.04", "22.04", "24.04"],
        "codenames": {"20.04": "focal", "22.04": "jammy", "24.04": "noble"},
    },
    "rocky": {
        "type": "rpm",
        "versions": ["8", "9"],
    },
    "almalinux": {
        "type": "rpm",
        "versions": ["8", "9"],
    },
    "fedora": {
        "type": "rpm",
        "versions": ["39", "40", "41", "42"],
    },
}

# In-memory cache of loaded databases
# Key: (distro, version) -> Dict of PURL -> license data
_db_cache: Dict[Tuple[str, str], Dict[str, Any]] = {}

# Cache for release assets across multiple releases
# Key: filename -> download_url (from the first release that has it)
_release_assets_cache: Optional[Dict[str, str]] = None

# Lock for database loading/generation to prevent race conditions
_db_lock = threading.Lock()


def clear_cache() -> None:
    """Clear the license database cache."""
    _db_cache.clear()
    global _release_assets_cache
    _release_assets_cache = None


def get_cache_dir() -> Path:
    """Get the cache directory, creating it if needed.

    Priority:
    1. SBOMIFY_CACHE_DIR environment variable (explicit cache location)
    2. XDG_CACHE_HOME/sbomify/license-db (XDG standard)
    3. ~/.cache/sbomify/license-db (fallback)
    """
    explicit_cache = os.environ.get("SBOMIFY_CACHE_DIR")
    if explicit_cache:
        cache_dir = Path(explicit_cache) / "license-db"
    else:
        cache_dir = DEFAULT_CACHE_DIR

    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


class LicenseDBSource:
    """
    Data source using pre-computed license databases.

    Downloads license databases from GitHub Releases on first use and
    caches them locally. Provides fast PURL-based lookups for package
    metadata including:
    - SPDX-validated license expressions
    - Package description
    - Supplier/maintainer information
    - Homepage URL
    - Download URL

    This is the PRIMARY source for Linux distro packages, replacing
    individual package repository lookups with pre-computed, validated data.

    Priority: 1 (top priority - pre-computed, validated data)
    Supports: pkg:apk/alpine/*, pkg:apk/wolfi/*, pkg:deb/ubuntu/*,
              pkg:rpm/rocky/*, pkg:rpm/almalinux/*, pkg:rpm/amazonlinux/*,
              pkg:rpm/centos/*, pkg:rpm/fedora/*
    """

    def __init__(self, cache_dir: Optional[Path] = None):
        """
        Initialize the license database source.

        Args:
            cache_dir: Optional custom cache directory
        """
        self._cache_dir = cache_dir or get_cache_dir()

    @property
    def name(self) -> str:
        return "license-db"

    @property
    def priority(self) -> int:
        # Top priority - pre-computed database with validated SPDX licenses
        # and full metadata (description, supplier, homepage, download_url)
        return 1

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL."""
        # Check package type
        if purl.type == "apk":
            namespace = (purl.namespace or "").lower()
            return namespace in ("alpine", "wolfi")
        elif purl.type == "deb":
            namespace = (purl.namespace or "").lower()
            return namespace in ("debian", "ubuntu")
        elif purl.type == "rpm":
            namespace = (purl.namespace or "").lower()
            return namespace in ("rocky", "almalinux", "amazonlinux", "centos", "fedora")
        return False

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch license metadata from the pre-computed database.

        Args:
            purl: Parsed PackageURL
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata with license info, or None if not found
        """
        # Determine distro and version from PURL
        distro, version = self._parse_distro_from_purl(purl)
        if not distro or not version:
            return None

        # Load the database
        db = self._load_database(distro, version, session)
        if not db:
            return None

        # Look up by PURL (try exact match first)
        purl_str = str(purl)
        pkg_data = db.get("packages", {}).get(purl_str)

        # If no exact match, try architecture-agnostic lookup
        # Licenses are the same across architectures (amd64, arm64, etc.)
        if not pkg_data:
            pkg_data = self._lookup_arch_agnostic(db, purl)

        # If still no match, try lookup by name only
        if not pkg_data:
            pkg_data = self._lookup_by_name(db, purl.name)

        if not pkg_data:
            logger.debug(f"Package {purl.name} not found in license database")
            return None

        # Extract license info - required
        spdx = pkg_data.get("spdx")
        if not spdx:
            return None

        # Build metadata with all available fields
        field_sources: dict = {}

        # License (required)
        licenses = [spdx]
        field_sources["licenses"] = self.name

        # Description
        description = pkg_data.get("description")
        if description:
            field_sources["description"] = self.name

        # Supplier
        supplier = pkg_data.get("supplier")
        if supplier:
            field_sources["supplier"] = self.name

        # Homepage
        homepage = pkg_data.get("homepage")
        if homepage:
            field_sources["homepage"] = self.name

        # Download URL
        download_url = pkg_data.get("download_url")
        if download_url:
            field_sources["download_url"] = self.name

        # Maintainer info
        maintainer_name = pkg_data.get("maintainer_name")
        maintainer_email = pkg_data.get("maintainer_email")
        if maintainer_name:
            field_sources["maintainer_name"] = self.name
        if maintainer_email:
            field_sources["maintainer_email"] = self.name

        # Note: CLE (lifecycle) data is now provided by the dedicated LifecycleSource
        # See: sbomify_action/_enrichment/sources/lifecycle.py

        return NormalizedMetadata(
            licenses=licenses,
            description=description,
            supplier=supplier,
            homepage=homepage,
            download_url=download_url,
            maintainer_name=maintainer_name,
            maintainer_email=maintainer_email,
            source=self.name,
            field_sources=field_sources,
        )

    def _normalize_version(self, distro: str, version: str) -> Optional[str]:
        """
        Normalize a version string to match supported versions.

        Handles point releases like:
        - Ubuntu: 24.04.1 -> 24.04
        - Alpine: 3.19.9 -> 3.19
        - Rocky/Alma: 9.4 -> 9
        - Fedora: 41 -> 41

        Args:
            distro: Distribution name
            version: Version string from PURL

        Returns:
            Normalized version matching SUPPORTED_DISTROS, or None
        """
        if distro not in SUPPORTED_DISTROS:
            return None

        supported_versions = SUPPORTED_DISTROS[distro]["versions"]

        # Direct match first
        if version in supported_versions:
            return version

        # Try progressively shorter version prefixes
        # e.g., "24.04.1" -> try "24.04", then "24"
        # e.g., "9.4" -> try "9"
        parts = version.split(".")
        for i in range(len(parts) - 1, 0, -1):
            prefix = ".".join(parts[:i])
            if prefix in supported_versions:
                return prefix

        return None

    def _parse_distro_from_purl(self, purl: PackageURL) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract distro and version from PURL.

        Args:
            purl: PackageURL to parse

        Returns:
            Tuple of (distro_name, version) or (None, None)
        """
        namespace = (purl.namespace or "").lower()
        qualifiers = purl.qualifiers or {}
        distro_qualifier = qualifiers.get("distro", "")

        distro = None
        version = None

        # Parse distro qualifier (e.g., "ubuntu-24.04.1", "rocky-9.4")
        if distro_qualifier:
            match = re.match(r"([a-z]+)-(.+)", distro_qualifier.lower())
            if match:
                distro = match.group(1)
                version = match.group(2)
            # For APK packages, distro qualifier is just version (e.g., "3.19.9")
            elif namespace in ("alpine", "wolfi") and re.match(r"^\d+\.\d+", distro_qualifier):
                distro = namespace
                version = distro_qualifier

        # Normalize version to match supported versions (e.g., 24.04.1 -> 24.04)
        if distro and version:
            normalized = self._normalize_version(distro, version)
            if normalized:
                return distro, normalized

        # Fall back to namespace and try to infer version
        if namespace in SUPPORTED_DISTROS:
            # Use latest supported version as default
            versions = SUPPORTED_DISTROS[namespace]["versions"]
            return namespace, versions[-1]  # Latest version

        return None, None

    def _load_database(self, distro: str, version: str, session: requests.Session) -> Optional[Dict[str, Any]]:
        """
        Load the license database for a distro/version.

        Strategy:
        1. Check in-memory cache (fast path, no lock)
        2. Acquire lock to prevent race conditions
        3. Double-check cache after acquiring lock
        4. Check local file cache
        5. Try to download from latest GitHub release
        6. Fallback: generate locally if download fails

        Args:
            distro: Distribution name (ubuntu, rocky, etc.)
            version: Distribution version
            session: requests.Session

        Returns:
            Loaded database dict or None
        """
        cache_key = (distro, version)

        # Fast path: check in-memory cache without lock
        if cache_key in _db_cache:
            return _db_cache[cache_key]

        # Acquire lock to prevent race conditions during download/generation
        with _db_lock:
            # Double-check cache after acquiring lock (another thread may have loaded it)
            if cache_key in _db_cache:
                return _db_cache[cache_key]

            # Check local file cache
            cache_file = self._cache_dir / f"{distro}-{version}.json.gz"
            if cache_file.exists():
                try:
                    db = self._load_from_file(cache_file)
                    _db_cache[cache_key] = db
                    logger.debug(f"Loaded license database from cache: {cache_file}")
                    return db
                except Exception as e:
                    logger.warning(f"Failed to load cached database {cache_file}: {e}")
                    cache_file.unlink(missing_ok=True)

            # Try to download from latest GitHub Release
            db = self._download_from_release(distro, version, session)
            if db:
                _db_cache[cache_key] = db
                # Save to local cache
                try:
                    self._save_to_file(cache_file, db)
                    logger.info(f"Cached license database: {cache_file}")
                except Exception as e:
                    logger.warning(f"Failed to save database to cache: {e}")
                return db

            # Fallback: generate locally
            if not DISABLE_LOCAL_GENERATION:
                logger.info(f"Database not found in release, generating locally for {distro}-{version}...")
                db = self._generate_locally(distro, version, cache_file)
                if db:
                    _db_cache[cache_key] = db
                    return db

            logger.debug(f"No license database available for {distro}-{version}")
            return None

    def _load_from_file(self, path: Path) -> Dict[str, Any]:
        """Load a gzipped JSON database from file."""
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)

    def _save_to_file(self, path: Path, db: Dict[str, Any]) -> None:
        """Save a database to gzipped JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(path, "wt", encoding="utf-8") as f:
            json.dump(db, f)

    def _download_from_release(self, distro: str, version: str, session: requests.Session) -> Optional[Dict[str, Any]]:
        """
        Download database from GitHub Releases, checking recent releases.

        Args:
            distro: Distribution name
            version: Distribution version
            session: requests.Session

        Returns:
            Loaded database dict or None
        """
        filename = f"{distro}-{version}.json.gz"

        # Get assets from recent releases
        assets = self._get_release_assets(session)
        if not assets:
            logger.debug("No license database assets found in any recent release")
            return None

        # Check if our file exists in any release
        download_url = assets.get(filename)
        if not download_url:
            logger.debug(f"License database not found in recent releases: {filename}")
            return None

        return self._download_asset(download_url, session)

    def _get_release_assets(self, session: requests.Session) -> Dict[str, str]:
        """
        Get assets from recent GitHub releases.

        Checks up to MAX_RELEASES_TO_CHECK releases, collecting all unique
        database files. If a file exists in multiple releases, the most
        recent version is used.

        Returns:
            Dict mapping filename -> download_url
        """
        global _release_assets_cache
        if _release_assets_cache is not None:
            return _release_assets_cache

        try:
            # Fetch recent releases (GitHub returns them newest first)
            response = session.get(
                GITHUB_RELEASES_API,
                params={"per_page": MAX_RELEASES_TO_CHECK},
                timeout=DEFAULT_TIMEOUT,
            )
            response.raise_for_status()

            releases = response.json()
            if not releases:
                logger.debug("No releases found yet")
                _release_assets_cache = {}
                return {}

            assets: Dict[str, str] = {}
            releases_checked = 0

            for release in releases:
                tag = release.get("tag_name", "unknown")
                release_assets = release.get("assets", [])

                for asset in release_assets:
                    name = asset.get("name", "")
                    url = asset.get("browser_download_url", "")
                    # Only add if not already found in a newer release
                    if name and url and name.endswith(".json.gz") and name not in assets:
                        assets[name] = url
                        logger.debug(f"Found {name} in release {tag}")

                releases_checked += 1

            _release_assets_cache = assets
            logger.debug(f"Found {len(assets)} license database(s) across {releases_checked} release(s)")
            return assets

        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                logger.debug("No releases found yet")
            else:
                logger.warning(f"Failed to fetch releases: {e}")
            _release_assets_cache = {}
            return {}

        except Exception as e:
            logger.warning(f"Failed to fetch releases: {e}")
            _release_assets_cache = {}
            return {}

    def _download_asset(self, url: str, session: requests.Session) -> Optional[Dict[str, Any]]:
        """Download and parse a release asset."""
        try:
            logger.info(f"Downloading license database: {url}")
            response = session.get(url, timeout=DOWNLOAD_TIMEOUT)
            response.raise_for_status()

            # Decompress and parse using BytesIO for reliability
            with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gz:
                return json.load(gz)

        except Exception as e:
            logger.warning(f"Failed to download license database: {e}")
            return None

    def _generate_locally(self, distro: str, version: str, output_path: Path) -> Optional[Dict[str, Any]]:
        """
        Generate the license database locally as a fallback.

        This imports and calls the generator functions directly.

        Args:
            distro: Distribution name
            version: Distribution version
            output_path: Where to save the generated database

        Returns:
            Loaded database dict or None
        """
        try:
            # Import generator functions
            from ..license_db_generator import (
                generate_alpine_db,
                generate_debian_db,
                generate_rpm_db,
                generate_ubuntu_db,
                generate_wolfi_db,
            )

            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)

            logger.info(f"Generating license database locally for {distro}-{version}...")

            if distro == "alpine":
                generate_alpine_db(version, output_path)
            elif distro == "wolfi":
                generate_wolfi_db(output_path)
            elif distro == "ubuntu":
                generate_ubuntu_db(version, output_path)
            elif distro == "debian":
                generate_debian_db(version, output_path)
            elif distro in ("rocky", "almalinux", "fedora", "amazonlinux", "centos"):
                generate_rpm_db(distro, version, output_path)
            else:
                logger.warning(f"Unknown distro for local generation: {distro}")
                return None

            # Load the generated database
            if output_path.exists():
                db = self._load_from_file(output_path)
                logger.info(f"Successfully generated license database: {output_path}")
                return db

        except Exception as e:
            logger.warning(f"Failed to generate license database locally: {e}")

        return None

    def _build_arch_agnostic_index(self, db: Dict[str, Any]) -> Dict[Tuple[str, str, str, str], list]:
        """
        Build an index for O(1) architecture-agnostic lookups.

        The index is keyed by (type, namespace, name, version) and stores
        a list of (qualifiers_without_arch, pkg_data) tuples.

        This is built once per database load and cached in the db dict.

        Args:
            db: Loaded database

        Returns:
            Index dict mapping (type, namespace, name, version) -> [(qualifiers, pkg_data), ...]
        """
        if "_arch_agnostic_index" in db:
            return db["_arch_agnostic_index"]

        index: Dict[Tuple[str, str, str, str], list] = {}
        packages = db.get("packages", {})

        for purl_str, pkg_data in packages.items():
            try:
                p = PackageURL.from_string(purl_str)
                key = (p.type, p.namespace or "", p.name, p.version or "")

                # Store qualifiers without arch for matching (using comprehension for clarity)
                qualifiers = {k: v for k, v in (p.qualifiers or {}).items() if k != "arch"}

                if key not in index:
                    index[key] = []
                index[key].append((qualifiers, pkg_data))

            except Exception as e:
                logger.debug(f"Failed to parse PURL for index: {purl_str}: {e}")
                continue

        db["_arch_agnostic_index"] = index
        logger.debug(f"Built arch-agnostic index with {len(index)} unique (type, ns, name, version) keys")
        return index

    def _lookup_arch_agnostic(self, db: Dict[str, Any], purl: PackageURL) -> Optional[Dict[str, Any]]:
        """
        Look up package ignoring architecture qualifier.

        Licenses are the same across architectures (amd64, arm64, i386, etc.),
        so we can match packages regardless of the arch qualifier.

        Uses an indexed lookup for O(1) performance instead of scanning
        all packages.

        Args:
            db: Loaded database
            purl: PackageURL to look up

        Returns:
            Package data dict or None
        """
        # Get arch qualifier - if not present, nothing to do (exact match already tried)
        input_arch = (purl.qualifiers or {}).get("arch")
        if not input_arch:
            return None

        # Create qualifiers dict without arch for comparison
        input_qualifiers = {k: v for k, v in (purl.qualifiers or {}).items() if k != "arch"}

        # Build/get the index for fast lookups
        index = self._build_arch_agnostic_index(db)

        # Look up by (type, namespace, name, version)
        key = (purl.type, purl.namespace or "", purl.name, purl.version or "")
        candidates = index.get(key)

        if not candidates:
            return None

        # Find a candidate with matching qualifiers (ignoring arch)
        for db_qualifiers, pkg_data in candidates:
            if db_qualifiers == input_qualifiers:
                logger.debug(f"Architecture-agnostic match: {purl.name} (input arch={input_arch})")
                return pkg_data

        return None

    def _lookup_by_name(self, db: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
        """
        Look up package by name when exact PURL match fails.

        Searches through all packages to find a name match.

        Args:
            db: Loaded database
            name: Package name to find

        Returns:
            Package data dict or None
        """
        packages = db.get("packages", {})

        # First pass: look for exact name match in the data
        for purl_str, pkg_data in packages.items():
            if pkg_data.get("name") == name:
                return pkg_data

        # Second pass: try to extract name from PURL keys
        for purl_str, pkg_data in packages.items():
            try:
                purl = PackageURL.from_string(purl_str)
                if purl.name == name:
                    return pkg_data
            except Exception as e:
                logger.debug(f"Failed to parse PURL during name lookup: {purl_str}: {e}")
                continue

        return None
