"""ClearlyDefined data source for package metadata (license, homepage, repository).

Requests go through clearly-cached (https://github.com/sbomify/clearly-cached),
a caching, normalising front end for the ClearlyDefined definitions API. It
retries the transient failures that make ~40% of cold upstream requests look
like "this package has no metadata", collapses concurrent misses onto a single
fetch, and returns a ~0.4KB projection instead of a definition that can run to
190KB. Point `SBOMIFY_CLEARLY_CACHED_URL` at another instance (or at a local
container) to use your own.
"""

import os
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse

import requests
from packageurl import PackageURL

from sbomify_action.http_client import get_default_headers
from sbomify_action.logging_config import logger

from ..exceptions import TransientSourceError
from ..license_utils import normalize_license_list
from ..metadata import NormalizedMetadata
from ..sanitization import normalize_vcs_url

DEFAULT_API_BASE = "https://clearly-cached.sbomify.com"
API_BASE_ENV_VAR = "SBOMIFY_CLEARLY_CACHED_URL"

# (connect, read). The service retries upstream within a 25s deadline, so a cold
# coordinate can legitimately take that long; the short connect timeout keeps an
# unreachable service from costing 30s per package.
DEFAULT_TIMEOUT = (5, 30)

# Mapping from PURL type to ClearlyDefined type/provider coordinate prefix.
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

# Consecutive transient failures before this source stops being consulted for
# the rest of the process. A cold coordinate can cost the full upstream deadline
# and yield nothing, so a run against a struggling service would otherwise spend
# ~25s per package on a source that is only a fallback. The fetch continues
# server-side after we hang up, so what is skipped here is picked up cheaply by
# the next run rather than lost.
TRANSIENT_FAILURE_LIMIT = 5

# Simple in-memory cache
_cache: Dict[str, Optional[NormalizedMetadata]] = {}
_consecutive_failures = 0
_circuit_open = False


def clear_cache() -> None:
    """Clear the ClearlyDefined metadata cache and re-arm the circuit breaker."""
    global _consecutive_failures, _circuit_open
    _cache.clear()
    _consecutive_failures = 0
    _circuit_open = False


def _record_transient_failure(purl: PackageURL) -> None:
    """Count a transient failure and trip the breaker once the limit is reached."""
    global _consecutive_failures, _circuit_open
    _consecutive_failures += 1
    if _consecutive_failures >= TRANSIENT_FAILURE_LIMIT and not _circuit_open:
        _circuit_open = True
        logger.warning(
            f"Skipping ClearlyDefined for the rest of this run: "
            f"{_consecutive_failures} consecutive failures (last: {purl}). "
            f"Other enrichment sources are unaffected."
        )


def _record_success() -> None:
    """A definite answer - including a 404 - clears the failure streak."""
    global _consecutive_failures
    _consecutive_failures = 0


def get_api_base() -> str:
    """Return the clearly-cached base URL, honouring the environment override."""
    return (os.environ.get(API_BASE_ENV_VAR) or DEFAULT_API_BASE).rstrip("/")


def _as_str(value: Any) -> Optional[str]:
    """Return value if it is a non-empty string, else None."""
    return value if isinstance(value, str) and value else None


# The fields read out of a projection, and what each must be when present.
# Only the fields actually read are listed: `parties` and `score` are ignored,
# so a bad type in either says nothing about whether the licence can be
# trusted, and failing the whole projection over one would lose enrichment for
# no reason. `harvested` is validated separately, in _is_harvested.
_PROJECTION_TYPES: Dict[str, type] = {
    "declared": str,
    "homepage": str,
    "source_url": str,
}


def _reject_malformed(purl: PackageURL, data: Any) -> None:
    """Raise unless `data` is a projection whose fields have the right types.

    A field of the wrong type says the payload is not one we can read, which
    says nothing about the package. That has to be distinguished from a
    well-formed projection whose fields are simply empty - `{"declared": null,
    "parties": [], ..., "harvested": true}` is a real answer, meaning
    ClearlyDefined looked and found no licence, and is a definitive miss.

    The distinction matters because the registry persists a definitive miss for
    the miss TTL. Coercing a bad type to None would put a garbled response and
    a genuine absence into the same bucket, and let one malformed body suppress
    a package's enrichment for a day.
    """
    if not isinstance(data, dict) or not data:
        raise TransientSourceError(f"Projection for {purl} is not an object")
    for key, expected in _PROJECTION_TYPES.items():
        value = data.get(key)
        if value is not None and not isinstance(value, expected):
            raise TransientSourceError(
                f"Projection for {purl} has {key}={type(value).__name__}, expected {expected.__name__}"
            )


# Hosts whose URLs are actual repositories. ``source_url`` is otherwise a
# download or registry link (Maven returns a sources jar, PyPI a project page),
# which is not a repository_url however plausible it looks.
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


class ClearlyDefinedSource:
    """
    Data source for ClearlyDefined, served via clearly-cached.

    ClearlyDefined provides curated license data for open source packages
    across many ecosystems, plus a homepage and source location where it has
    one. Its copyright parties are not used - see _normalize_response.

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

    @property
    def provides(self) -> frozenset[str]:
        """Licences, and occasionally a homepage or repository URL.

        Measured rather than guessed: of 400 cached responses sampled, 400
        carried `licenses`, four a `homepage` and three a `repository_url`.
        Copyright parties are deliberately not used -- see
        _normalize_response -- so `supplier` is not among them, and this
        source has never returned a description.

        Declaring it lets the registry skip this source when a licence is
        already in hand. It used to be consulted whenever `description` or
        `supplier` was missing, neither of which it can supply: across a
        251-project run that filled the cache with 1,178 entries, 1,020 of
        them holding real licence data, while contributing zero fields to
        the finished SBOMs.
        """
        return frozenset({"licenses", "license_texts", "homepage", "repository_url"})

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL type."""
        return purl.type in PURL_TYPE_TO_CD_TYPE

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from clearly-cached.

        Args:
            purl: Parsed PackageURL
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None if the coordinate genuinely
            has no data.

        Raises:
            TransientSourceError: the service said nothing about this package -
                it stalled, refused, or has not harvested the coordinate yet.
                Never a definitive answer, so the registry does not persist it.
        """
        cd_type = PURL_TYPE_TO_CD_TYPE.get(purl.type)
        if not cd_type:
            return None

        if _circuit_open:
            # Transient, not a miss: the packages skipped here are unexamined,
            # not empty, and returning None would persist them as empty.
            raise TransientSourceError(f"{self.name} skipped after {TRANSIENT_FAILURE_LIMIT} consecutive failures")

        # Build the coordinate for the definitions endpoint
        # Format: type/provider/namespace/name/revision ("-" for an absent namespace)
        # e.g., maven/mavencentral/org.apache.commons/commons-lang3/3.12.0
        version = purl.version or "-"
        namespace = purl.namespace or "-"
        cache_key = f"clearlydefined:{purl.type}:{namespace}:{purl.name}:{version}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (ClearlyDefined): {purl.name}")
            return _cache[cache_key]

        try:
            # Each of namespace/name/revision is one path segment, so anything
            # inside them must be escaped - a Go namespace like
            # "github.com/gorilla" would otherwise split into two segments and
            # miss the coordinate entirely.
            coordinate = "/".join(quote(part, safe="") for part in (namespace, purl.name, version))
            url = f"{get_api_base()}/v1/definitions/{cd_type}/{coordinate}"

            logger.debug(f"Fetching ClearlyDefined metadata for: {purl}")
            # Send the User-Agent explicitly rather than relying on the caller's
            # session: clearly-cached is ours, and its logs should say who is
            # asking even when a bare session is passed in.
            response = session.get(url, timeout=DEFAULT_TIMEOUT, headers=get_default_headers())

            if response.status_code == 429 or response.status_code >= 500:
                # Throttled, or the upstream stalled past the service's
                # deadline. Neither is evidence the package has no metadata.
                _record_transient_failure(purl)
                raise TransientSourceError(f"HTTP {response.status_code} from {self.name}")

            _record_success()

            metadata = None
            if response.status_code == 200:
                data = response.json()
                try:
                    if not self._is_harvested(purl, data):
                        # Not examined yet, so there is nothing to record. This
                        # is the distinction clearly-cached exists to expose:
                        # ClearlyDefined never 404s, and an unharvested
                        # coordinate returns an empty definition that is
                        # indistinguishable from a package with genuinely no
                        # licence. Caching it as a miss would hold that answer
                        # past the point it changes.
                        raise TransientSourceError(f"{purl} not yet harvested by {self.name}")
                    _reject_malformed(purl, data)
                except TransientSourceError:
                    # Counts towards the breaker like any other non-answer: a
                    # service returning bodies we cannot read is a service
                    # worth backing off from.
                    _record_transient_failure(purl)
                    raise
                metadata = self._normalize_response(purl, data)
            elif response.status_code == 404:
                logger.debug(f"Package not found in ClearlyDefined: {purl}")
            else:
                logger.warning(f"Failed to fetch ClearlyDefined metadata for {purl}: HTTP {response.status_code}")

            # Cache result
            _cache[cache_key] = metadata
            return metadata

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching ClearlyDefined metadata for {purl}")
            _record_transient_failure(purl)
            raise TransientSourceError(f"Timeout from {self.name}") from None
        except ValueError as e:
            # A body that is not JSON is a CDN error page, not an answer about
            # the package.
            logger.warning(f"JSON decode error for ClearlyDefined {purl}: {e}")
            _record_transient_failure(purl)
            raise TransientSourceError(f"Malformed response from {self.name}") from None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching ClearlyDefined metadata for {purl}: {e}")
            _record_transient_failure(purl)
            raise TransientSourceError(f"RequestException from {self.name}") from None

    def _is_harvested(self, purl: PackageURL, data: Any) -> bool:
        """False when the coordinate has not been examined by ClearlyDefined yet.

        The flag is validated as a boolean rather than tested for truthiness.
        A malformed value - the string "false" is the obvious way to get this
        wrong - would otherwise read as harvested and let an empty definition
        be recorded as "this package has no licence", which is the one
        conclusion this check exists to prevent. Anything that is not a
        boolean is treated as unharvested, so a projection we cannot read
        costs a re-fetch rather than a wrong answer.
        """
        if not isinstance(data, dict):
            return True  # Not a projection at all; _normalize_response rejects it.
        harvested = data.get("harvested", True)
        if harvested is True:
            return True
        if harvested is False:
            logger.debug(f"Not yet harvested by ClearlyDefined: {purl}")
        else:
            logger.warning(f"Non-boolean 'harvested' from {self.name} for {purl}: {harvested!r}")
        return False

    def _normalize_response(self, purl: PackageURL, data: Dict[str, Any]) -> Optional[NormalizedMetadata]:
        """
        Normalize a clearly-cached projection to NormalizedMetadata.

        The projection is flat, unlike the upstream definition:

            {"declared": "Apache-2.0", "parties": [...], "homepage": null,
             "source_url": null, "harvested": true, "score": 73}

        Args:
            purl: Parsed PackageURL (for logging)
            data: Projection returned by clearly-cached

        Callers must run _reject_malformed first, so everything below is
        already known to be the right type; _as_str still normalises an empty
        string to None.

        Returns:
            NormalizedMetadata with extracted fields, or None when the
            projection is well-formed but carries nothing - a real answer,
            meaning ClearlyDefined looked and found nothing.
        """
        declared_license = _as_str(data.get("declared"))

        licenses: List[str] = []
        license_texts: Dict[str, str] = {}
        if declared_license and declared_license != "NOASSERTION":
            licenses, license_texts = normalize_license_list([declared_license])

        homepage = _as_str(data.get("homepage"))

        # ``source_url`` is whatever the harvester resolved the source to, which
        # is not always a repository: Maven yields a sources-jar download and
        # PyPI a project page. Only take it when it looks like a VCS location,
        # so the field is either a real repository or left for another source.
        source_url = _as_str(data.get("source_url"))
        repository_url = None
        if source_url and _is_vcs_url(source_url):
            repository_url = normalize_vcs_url(source_url)

        # `parties` is deliberately not read. It is every copyright line the
        # scanners found across the package's files, so a notice from vendored
        # code outranks nothing, and picking one of them named the wrong entity
        # often enough to matter: sqlalchemy got clipboard.js's author, numpy
        # got meson's, charset-normalizer got the literal string "COPYRIGHT (c)
        # FOOBAR", pydantic got "Copyright (c) 2017", which names nobody.
        #
        # Preferring an undated line made that worse rather than better -
        # "(c), Good News" for django and "(c) N Revealed" for attrs were
        # chosen precisely because they carry no year, over a dated line naming
        # the right holder.
        #
        # supplier feeds NTIA conformance, so a wrong value is not a smaller
        # version of a right one: it puts a false claim in the SBOM, where an
        # absent field merely leaves a gap another source can fill. The licence
        # is taken - it was accurate on all 76 coordinates sampled - and the
        # parties are not.

        # Build field_sources for attribution
        field_sources = {}
        if licenses:
            field_sources["licenses"] = self.name
        if homepage:
            field_sources["homepage"] = self.name
        if repository_url:
            field_sources["repository_url"] = self.name

        metadata = NormalizedMetadata(
            # No description: ClearlyDefined definitions carry no such field,
            # and the projection carries no more than the definition did. This
            # is why this source can never satisfy the registry's
            # description-and-licenses-and-supplier early exit on its own.
            licenses=licenses,
            license_texts=license_texts,
            supplier=None,
            homepage=homepage,
            repository_url=repository_url,
            source=self.name,
            field_sources=field_sources,
        )

        if metadata.has_data():
            logger.debug(f"Successfully normalized ClearlyDefined metadata for {purl.name}")
            return metadata
        return None
