"""TEA (Transparency Exchange API) enrichment source.

Queries TEA servers for product metadata and CLE (Common Lifecycle Enumeration)
data using TEI auto-discovery from PURL type.

Each PURL type maps to a known TEA domain (e.g. ``pypi`` → ``pypi.sbomify.com``).
The source builds a TEI URN, discovers the TEA server via ``.well-known/tea``,
and fetches CLE lifecycle data.

``TEA_BASE_URL`` env var overrides auto-discovery for all PURL types.

Provides:
- Release date, end-of-support, end-of-life from CLE events
- License information from CLE ``released`` events
- Product name as supplier context

Priority 45 (Tier 2 aggregator).
"""

import os

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

DEFAULT_TIMEOUT = 15


def clear_cache() -> None:
    """Clear the module-level cache."""
    _cache.clear()


def _build_tei(purl: PackageURL, domain: str) -> str:
    """Build a TEI URN from a PURL and domain.

    Format: ``urn:tei:purl:{domain}:{purl_string}``
    """
    purl_str = _purl_to_search_value(purl)
    return f"urn:tei:purl:{domain}:{purl_str}"


def _purl_to_search_value(purl: PackageURL) -> str:
    """Convert a PackageURL to a canonical string (no qualifiers/subpath)."""
    parts = [f"pkg:{purl.type}/"]
    if purl.namespace:
        parts.append(f"{purl.namespace}/")
    parts.append(purl.name)
    if purl.version:
        parts.append(f"@{purl.version}")
    return "".join(parts)


class TeaSource:
    """Enrichment source that discovers TEA servers and fetches CLE data."""

    @property
    def name(self) -> str:
        return "tea"

    @property
    def priority(self) -> int:
        return 45

    def supports(self, purl: PackageURL) -> bool:
        """Supported when PURL type has a known TEA domain or TEA_BASE_URL is set."""
        return purl.type in PURL_TYPE_TO_TEA_DOMAIN or bool(os.getenv("TEA_BASE_URL"))

    def fetch(self, purl: PackageURL, session: requests.Session) -> NormalizedMetadata | None:
        """Discover TEA server from PURL type and fetch metadata."""
        purl_str = _purl_to_search_value(purl)
        cache_key = f"tea:{purl_str}"

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
        """Build TEI, discover server, and fetch metadata."""
        token = os.getenv("TEA_TOKEN")
        base_url_override = os.getenv("TEA_BASE_URL")

        try:
            if base_url_override:
                # Direct override — skip discovery
                client = TeaClient(base_url_override, token=token, timeout=DEFAULT_TIMEOUT)
            else:
                # Auto-discover from PURL type
                domain = PURL_TYPE_TO_TEA_DOMAIN.get(purl.type)
                if not domain:
                    return None
                tei = _build_tei(purl, domain)
                logger.debug(f"TEI discovery: {tei}")
                client = TeaClient.from_well_known(domain, token=token, timeout=DEFAULT_TIMEOUT)

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

            # Extract product name as supplier
            supplier: str | None = release.product_name
            if supplier:
                field_sources["supplier"] = self.name

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
                supplier=supplier,
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

        except TeaNotFoundError:
            logger.debug(f"PURL not found on TEA server: {purl_str}")
            return None
        except TeaError as exc:
            logger.warning(f"TEA server error for {purl_str}: {exc}")
            return None
