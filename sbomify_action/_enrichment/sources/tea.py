"""TEA (Transparency Exchange API) enrichment source.

Queries TEA servers for product metadata and CLE (Common Lifecycle Enumeration)
data using TEI auto-discovery from PURL type.

Each PURL type maps to a known TEA domain (e.g. ``pypi`` → ``pypi.sbomify.com``).
The source discovers the TEA server via ``.well-known/tea`` and fetches CLE
lifecycle data.

``TEA_BASE_URL`` env var overrides auto-discovery for all PURL types.

Provides:
- Release date, end-of-support, end-of-life from CLE events
- License information from CLE ``released`` events

Priority 43 (Tier 2 aggregator).
"""

import hashlib
import ipaddress
import os
from urllib.parse import urlparse

import requests
from libtea import TeaClient
from libtea.exceptions import TeaError, TeaNotFoundError
from libtea.models import CLEEventType
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..metadata import NormalizedMetadata

# PURL type → TEA domain for .well-known/tea discovery.
# Expand as sbomify indexes more ecosystems.
PURL_TYPE_TO_TEA_DOMAIN: dict[str, str] = {
    "pypi": "pypi.sbomify.com",
}

_cache: dict[str, NormalizedMetadata | None] = {}
_client_cache: dict[str, TeaClient] = {}
_discovery_failures: dict[str, int] = {}

_MAX_DISCOVERY_RETRIES = 2

DEFAULT_TIMEOUT = 15


_BLOCKED_HOSTNAMES = frozenset({"localhost", "metadata.google.internal", "kubernetes.default.svc"})


def _is_safe_url(url: str) -> bool:
    """Check that a URL does not point to private/internal addresses."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        if hostname.lower() in _BLOCKED_HOSTNAMES:
            return False
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
                return False
        except ValueError:
            pass  # Not an IP literal; DNS-based SSRF (e.g. nip.io) is not checked here
        return True
    except Exception:
        return False


def clear_cache() -> None:
    """Clear the module-level caches (closes cached clients)."""
    for client in _client_cache.values():
        if hasattr(client, "close"):
            try:
                client.close()
            except Exception:
                pass
    _cache.clear()
    _client_cache.clear()
    _discovery_failures.clear()


def _get_client(purl_type: str) -> TeaClient | None:
    """Get or create a cached TeaClient for the given PURL type."""
    token = os.getenv("TEA_TOKEN")
    base_url_override = os.getenv("TEA_BASE_URL")

    if base_url_override:
        if not _is_safe_url(base_url_override):
            logger.warning(f"TEA_BASE_URL rejected (private/internal address): {base_url_override}")
            return None
        cache_key = f"base_url:{base_url_override}:token:{hashlib.sha256((token or '').encode()).hexdigest()[:16]}"
        if cache_key not in _client_cache:
            _client_cache[cache_key] = TeaClient(base_url_override, token=token, timeout=DEFAULT_TIMEOUT)
        return _client_cache[cache_key]

    domain = PURL_TYPE_TO_TEA_DOMAIN.get(purl_type)
    if not domain:
        return None

    cache_key = f"domain:{domain}:token:{hashlib.sha256((token or '').encode()).hexdigest()[:16]}"
    if cache_key not in _client_cache:
        if _discovery_failures.get(cache_key, 0) >= _MAX_DISCOVERY_RETRIES:
            return None
        try:
            _client_cache[cache_key] = TeaClient.from_well_known(domain, token=token, timeout=DEFAULT_TIMEOUT)
        except Exception as exc:
            _discovery_failures[cache_key] = _discovery_failures.get(cache_key, 0) + 1
            logger.warning(
                f"TEA well-known discovery failed for {domain} "
                f"(attempt {_discovery_failures[cache_key]}/{_MAX_DISCOVERY_RETRIES}): {exc}"
            )
            return None
    return _client_cache[cache_key]


def _purl_to_search_value(purl: PackageURL) -> str:
    """Convert a PackageURL to a canonical string (no qualifiers/subpath)."""
    return PackageURL(type=purl.type, namespace=purl.namespace, name=purl.name, version=purl.version).to_string()


class TeaSource:
    """Enrichment source that discovers TEA servers and fetches CLE data.

    Note: The ``session`` parameter in ``fetch()`` is accepted for protocol
    compliance but unused. libtea manages its own HTTP transport with separate
    SSRF protections, authentication, and retry logic. TEA requests will not
    carry the shared session's User-Agent or proxy configuration.
    """

    @property
    def name(self) -> str:
        return "tea"

    @property
    def priority(self) -> int:
        return 43

    @property
    def provides_cle(self) -> bool:
        return True

    def supports(self, purl: PackageURL) -> bool:
        """Supported when PURL type has a known TEA domain or a safe TEA_BASE_URL is set."""
        if purl.type in PURL_TYPE_TO_TEA_DOMAIN:
            return True
        base_url = os.getenv("TEA_BASE_URL")
        return bool(base_url) and _is_safe_url(base_url)

    def fetch(self, purl: PackageURL, session: requests.Session) -> NormalizedMetadata | None:
        """Discover TEA server from PURL type and fetch metadata."""
        purl_str = _purl_to_search_value(purl)
        token = os.getenv("TEA_TOKEN") or ""
        base_url = os.getenv("TEA_BASE_URL") or ""
        env_hash = hashlib.sha256(f"{base_url}:{token}".encode()).hexdigest()[:16]
        cache_key = f"tea:{purl_str}:{env_hash}"

        if cache_key in _cache:
            logger.debug(f"Cache hit (tea): {purl_str}")
            return _cache[cache_key]

        try:
            metadata = self._fetch_from_tea(purl, purl_str)
            _cache[cache_key] = metadata
            return metadata
        except Exception as exc:
            logger.warning(f"TEA enrichment failed for {purl_str}: {exc}")
            _cache[cache_key] = None
            return None

    def _fetch_from_tea(self, purl: PackageURL, purl_str: str) -> NormalizedMetadata | None:
        """Discover server and fetch metadata."""
        client = _get_client(purl.type)
        if not client:
            return None

        # Search for product releases matching this PURL
        response = client.search_product_releases(id_type="PURL", id_value=purl_str, page_size=1)
        if not response.results:
            logger.debug(f"No TEA product releases found for: {purl_str}")
            return None

        release = response.results[0]
        logger.debug(f"Found TEA product release: {release.product_name} {release.version} ({release.uuid})")

        field_sources: dict[str, str] = {}

        # Extract release date
        cle_release_date: str | None = None
        if release.release_date:
            cle_release_date = release.release_date.isoformat()
            field_sources["cle_release_date"] = self.name

        # Fetch CLE lifecycle data
        cle_eos: str | None = None
        cle_eol: str | None = None
        license_expr: str | None = None
        try:
            cle = client.get_product_release_cle(release.uuid)
            for event in cle.events:
                if event.type == CLEEventType.END_OF_SUPPORT and not cle_eos:
                    cle_eos = event.effective.isoformat()
                    field_sources["cle_eos"] = self.name
                elif event.type == CLEEventType.END_OF_LIFE and not cle_eol:
                    cle_eol = event.effective.isoformat()
                    field_sources["cle_eol"] = self.name
                elif event.type == CLEEventType.RELEASED and event.license and not license_expr:
                    license_expr = event.license
                    field_sources["licenses"] = self.name
        except TeaNotFoundError:
            logger.debug(f"No CLE data for release {release.uuid}")
        except TeaError as exc:
            logger.debug(f"CLE lookup failed for {release.uuid}: {exc}")

        licenses = [license_expr] if license_expr else []

        metadata = NormalizedMetadata(
            licenses=licenses,
            cle_release_date=cle_release_date,
            cle_eos=cle_eos,
            cle_eol=cle_eol,
            source=self.name,
            field_sources=field_sources,
        )

        if metadata.has_data():
            logger.debug(f"Successfully enriched from TEA: {purl_str}")
            return metadata
        return None
