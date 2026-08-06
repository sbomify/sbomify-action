"""ClearlyDefined data source for package metadata (license and attribution)."""

import json
import re
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..exceptions import TransientSourceError
from ..license_utils import normalize_license_list
from ..metadata import NormalizedMetadata
from ..sanitization import normalize_vcs_url

CLEARLYDEFINED_API_BASE = "https://api.clearlydefined.io"
DEFAULT_TIMEOUT = 10  # seconds - short timeout, API can be slow/unreliable

# Mapping from PURL type to ClearlyDefined type
# NOTE: Only include types that ClearlyDefined reliably supports.
# Tested 2024-12: deb, apk, rpm are NOT reliably supported (timeouts, 404s).
# See: https://docs.clearlydefined.io/docs/curation/coordinates
PURL_TYPE_TO_CD_TYPE: Dict[str, str] = {
    "pypi": "pypi/pypi",
    "npm": "npm/npmjs",
    "cargo": "crate/cratesio",
    "maven": "maven/mavencentral",
    "gem": "gem/rubygems",
    "nuget": "nuget/nuget",
    "golang": "go/golang",
    # NOT SUPPORTED (unreliable):
    # "deb": Timeouts, not properly indexed
    # "apk": Not supported at all
    # "rpm": Timeouts, not properly indexed
}

# Simple in-memory cache
_cache: Dict[str, Optional[NormalizedMetadata]] = {}


def clear_cache() -> None:
    """Clear the ClearlyDefined metadata cache."""
    _cache.clear()


# Hosts whose URLs are actual repositories. ``sourceLocation.url`` is otherwise
# a download or registry link (Maven returns a sources jar, PyPI a project
# page), which is not a repository_url however plausible it looks.
_VCS_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "sr.ht")
_ARCHIVE_SUFFIXES = (".jar", ".zip", ".gz", ".tgz", ".whl", ".gem", ".crate", ".bz2", ".xz")


def _is_vcs_url(url: str) -> bool:
    """True when ``url`` points at a source repository rather than an artifact.

    Matches on the parsed hostname, not a substring of the whole URL: the
    latter accepts ``https://notgithub.com/x`` and
    ``https://example.com/?ref=github.com``, and this gates repository_url.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if PurePosixPath(parsed.path).suffix.lower() in _ARCHIVE_SUFFIXES:
        return False
    return any(host == vcs or host.endswith(f".{vcs}") for vcs in _VCS_HOSTS)


def _cleanest_party(parties: List[str]) -> Optional[str]:
    """Pick the most useful attribution party to use as the supplier.

    ClearlyDefined returns every copyright line its scanners found, so the list
    is usually several spellings of one holder -- for requests 2.32.3 it is
    "Copyright Kenneth Reitz" alongside three dated "copyright (c) 2012 by
    Kenneth Reitz" variants. Prefer an entry without a year, which is the
    canonical form, and fall back to the first entry so behaviour is stable
    when every line carries a date.
    """
    cleaned = [p.strip() for p in parties if p and p.strip()]
    if not cleaned:
        return None
    undated = [p for p in cleaned if not re.search(r"\b(19|20)\d{2}\b", p)]
    return (undated or cleaned)[0]


class ClearlyDefinedSource:
    """
    Data source for ClearlyDefined API.

    ClearlyDefined provides curated license and attribution data for
    open source packages across many ecosystems.

    Priority: 75 (medium-low - good for license data, slower API)
    Supports: pypi, npm, cargo, maven, gem, nuget, golang packages

    NOTE: OS packages (deb, apk, rpm) are NOT supported - ClearlyDefined
    does not reliably index these package types.
    """

    @property
    def name(self) -> str:
        return "clearlydefined.io"

    @property
    def priority(self) -> int:
        # Tier 3: Fallback sources (70-99) - Last resort, basic or rate-limited
        return 75

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL type."""
        return purl.type in PURL_TYPE_TO_CD_TYPE

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from ClearlyDefined API.

        Args:
            purl: Parsed PackageURL
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        cd_type = PURL_TYPE_TO_CD_TYPE.get(purl.type)
        if not cd_type:
            return None

        # Build the coordinate for ClearlyDefined API
        # Format: type/provider/namespace/name/revision
        # e.g., maven/mavencentral/org.apache.commons/commons-lang3/3.12.0
        version = purl.version or "-"
        namespace = purl.namespace or "-"
        cache_key = f"clearlydefined:{purl.type}:{namespace}:{purl.name}:{version}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (ClearlyDefined): {purl.name}")
            return _cache[cache_key]

        try:
            # Build coordinate: type/provider/namespace/name/version
            coordinate = f"{cd_type}/{namespace}/{purl.name}/{version}"
            url = f"{CLEARLYDEFINED_API_BASE}/definitions/{coordinate}"

            logger.debug(f"Fetching ClearlyDefined metadata for: {purl}")
            response = session.get(url, timeout=DEFAULT_TIMEOUT)

            metadata = None
            if response.status_code == 200:
                data = response.json()
                metadata = self._normalize_response(purl.name, data)
            elif response.status_code == 404:
                logger.debug(f"Package not found in ClearlyDefined: {purl}")
            elif response.status_code == 429 or response.status_code >= 500:
                # Throttled or upstream failure. Neither is evidence the
                # package has no metadata, so this must not be remembered as a
                # miss -- ClearlyDefined is rate limited per IP and CI runners
                # share one, so caching a 429 would suppress enrichment for
                # this package on every later run.
                raise TransientSourceError(f"HTTP {response.status_code} from {self.name}")
            else:
                logger.warning(f"Failed to fetch ClearlyDefined metadata for {purl}: HTTP {response.status_code}")

            # Cache result
            _cache[cache_key] = metadata
            return metadata

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching ClearlyDefined metadata for {purl}")
            raise TransientSourceError(f"Timeout from {self.name}") from None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching ClearlyDefined metadata for {purl}: {e}")
            raise TransientSourceError(f"RequestException from {self.name}") from None
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error for ClearlyDefined {purl}: {e}")
            _cache[cache_key] = None
            return None

    def _normalize_response(self, package_name: str, data: Dict[str, Any]) -> Optional[NormalizedMetadata]:
        """
        Normalize ClearlyDefined API response to NormalizedMetadata.

        Args:
            package_name: Name of the package
            data: Raw ClearlyDefined API response

        Returns:
            NormalizedMetadata with extracted fields, or None if no data
        """
        if not data:
            return None

        # Extract licensed info
        licensed = data.get("licensed", {})
        declared_license = licensed.get("declared")

        licenses: List[str] = []
        license_texts: Dict[str, str] = {}
        if declared_license and declared_license != "NOASSERTION":
            licenses, license_texts = normalize_license_list([declared_license])

        described = data.get("described", {})
        source_info = described.get("sourceLocation") or {}

        # Extract URLs
        homepage = described.get("projectWebsite")
        repository_url = None

        # ``sourceLocation.url`` is whatever the harvester resolved the source
        # to, which is not always a repository: Maven yields a sources-jar
        # download (search.maven.org/remotecontent?filepath=...jar) and PyPI a
        # project page. Only take it when it looks like a VCS location, so the
        # field is either a real repository or left for another source to fill.
        repo_url = source_info.get("url")
        if repo_url and _is_vcs_url(repo_url):
            repository_url = normalize_vcs_url(repo_url)

        # Extract supplier from the curated attribution parties.
        #
        # These live under ``licensed.facets.core.attribution.parties``. The
        # top-level ``licensed.attribution`` this used to read is absent from
        # every response the API actually returns, so supplier was always None
        # and ClearlyDefined's curated copyright data -- the one thing it
        # provides that the other sources do not -- was fetched and discarded.
        supplier = None
        attribution_parties = (
            licensed.get("facets", {}).get("core", {}).get("attribution", {}).get("parties")
            # Kept as a fallback in case the shape ever changes back.
            or licensed.get("attribution", {}).get("parties")
            or []
        )
        if attribution_parties:
            supplier = _cleanest_party(attribution_parties)

        # Build field_sources for attribution
        field_sources = {}
        if licenses:
            field_sources["licenses"] = self.name
        if supplier:
            field_sources["supplier"] = self.name
        if homepage:
            field_sources["homepage"] = self.name
        if repository_url:
            field_sources["repository_url"] = self.name

        metadata = NormalizedMetadata(
            # No description: ClearlyDefined definitions carry no such field.
            # ``described`` holds releaseDate, urls, hashes, files, tools,
            # sourceLocation and scores -- nothing summarising the package.
            # This is why this source can never satisfy the registry's
            # description-and-licenses-and-supplier early exit on its own.
            licenses=licenses,
            license_texts=license_texts,
            supplier=supplier,
            homepage=homepage,
            repository_url=repository_url,
            source=self.name,
            field_sources=field_sources,
        )

        if metadata.has_data():
            logger.debug(f"Successfully normalized ClearlyDefined metadata for {package_name}")
            return metadata
        return None
