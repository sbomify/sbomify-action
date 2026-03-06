"""Tests for the TEA enrichment source."""

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from packageurl import PackageURL

from sbomify_action._enrichment.sources.tea import (
    PURL_TYPE_TO_TEA_DOMAIN,
    TeaSource,
    _purl_to_search_value,
    clear_cache,
)


class TestTeaSourceProperties(unittest.TestCase):
    """Test TeaSource name and priority."""

    def test_name(self):
        assert TeaSource().name == "tea"

    def test_priority(self):
        assert TeaSource().priority == 45


class TestTeaSourceSupports(unittest.TestCase):
    """Test supports based on PURL type mapping and env var override."""

    def test_supports_mapped_purl_type(self):
        source = TeaSource()
        purl = PackageURL.from_string("pkg:pypi/requests@2.31.0")
        with patch.dict("os.environ", {}, clear=True):
            assert source.supports(purl) is True

    def test_does_not_support_unmapped_type_without_env(self):
        source = TeaSource()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0")
        with patch.dict("os.environ", {}, clear=True):
            assert source.supports(purl) is False

    def test_supports_any_type_with_base_url_override(self):
        source = TeaSource()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0")
        with patch.dict("os.environ", {"TEA_BASE_URL": "https://tea.example.com/v1"}):
            assert source.supports(purl) is True

    def test_supports_all_mapped_types(self):
        source = TeaSource()
        with patch.dict("os.environ", {}, clear=True):
            for purl_type in PURL_TYPE_TO_TEA_DOMAIN:
                purl = PackageURL(type=purl_type, name="test", version="1.0")
                assert source.supports(purl) is True, f"Should support {purl_type}"


class TestPurlToSearchValue(unittest.TestCase):
    """Test PURL string formatting for TEA search."""

    def test_simple_purl(self):
        purl = PackageURL.from_string("pkg:pypi/requests@2.31.0")
        assert _purl_to_search_value(purl) == "pkg:pypi/requests@2.31.0"

    def test_namespaced_purl(self):
        purl = PackageURL.from_string("pkg:maven/org.apache/commons-lang@3.12")
        assert _purl_to_search_value(purl) == "pkg:maven/org.apache/commons-lang@3.12"

    def test_purl_without_version(self):
        purl = PackageURL.from_string("pkg:pypi/requests")
        assert _purl_to_search_value(purl) == "pkg:pypi/requests"

    def test_purl_strips_qualifiers(self):
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.1?arch=amd64")
        assert _purl_to_search_value(purl) == "pkg:deb/debian/bash@5.1"


class TestTeaSourceFetch(unittest.TestCase):
    """Test fetch behavior with mocked TeaClient."""

    def setUp(self):
        clear_cache()
        self.source = TeaSource()
        self.session = MagicMock()
        self.purl = PackageURL.from_string("pkg:pypi/requests@2.31.0")

    def tearDown(self):
        clear_cache()

    @patch.dict("os.environ", {}, clear=True)
    @patch("sbomify_action._enrichment.sources.tea.TeaClient", autospec=True)
    def test_fetch_auto_discovery(self, mock_client_cls):
        """Fetch uses from_well_known with domain from PURL type mapping."""
        from libtea.models import (
            CLE,
            CLEEvent,
            CLEEventType,
            Identifier,
            PaginatedProductReleaseResponse,
            ProductRelease,
        )

        now = datetime.now(timezone.utc)
        release = ProductRelease(
            uuid="pr-uuid",
            product="prod-uuid",
            product_name="requests",
            version="2.31.0",
            created_date=now,
            release_date=now,
            identifiers=(Identifier(id_type="PURL", id_value="pkg:pypi/requests@2.31.0"),),
            components=(),
        )

        mock_client = MagicMock()
        mock_client_cls.from_well_known.return_value = mock_client
        mock_client.search_product_releases.return_value = PaginatedProductReleaseResponse(
            timestamp=now,
            page_start_index=0,
            page_size=1,
            total_results=1,
            results=(release,),
        )
        mock_client.get_product_release_cle.return_value = CLE(
            events=(
                CLEEvent(
                    id=1,
                    type=CLEEventType.RELEASED,
                    effective=now,
                    published=now,
                    version="2.31.0",
                    license="Apache-2.0",
                ),
                CLEEvent(
                    id=2,
                    type=CLEEventType.END_OF_SUPPORT,
                    effective=datetime(2025, 12, 31, tzinfo=timezone.utc),
                    published=now,
                ),
                CLEEvent(
                    id=3,
                    type=CLEEventType.END_OF_LIFE,
                    effective=datetime(2026, 6, 30, tzinfo=timezone.utc),
                    published=now,
                ),
            ),
            definitions=None,
        )

        metadata = self.source.fetch(self.purl, self.session)

        # Verify discovery used the mapped domain
        mock_client_cls.from_well_known.assert_called_once_with("pypi.sbomify.com", token=None, timeout=15)

        assert metadata is not None
        assert metadata.source == "tea"
        assert metadata.supplier == "requests"
        assert metadata.licenses == ["Apache-2.0"]
        assert metadata.cle_release_date == now.isoformat()
        assert metadata.cle_eos == "2025-12-31T00:00:00+00:00"
        assert metadata.cle_eol == "2026-06-30T00:00:00+00:00"
        assert metadata.field_sources["licenses"] == "tea"
        assert metadata.field_sources["cle_eos"] == "tea"
        assert metadata.field_sources["cle_eol"] == "tea"

    @patch.dict("os.environ", {"TEA_BASE_URL": "https://tea.example.com/v1"})
    @patch("sbomify_action._enrichment.sources.tea.TeaClient", autospec=True)
    def test_fetch_base_url_override(self, mock_client_cls):
        """TEA_BASE_URL overrides auto-discovery."""
        from libtea.models import PaginatedProductReleaseResponse

        now = datetime.now(timezone.utc)
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.search_product_releases.return_value = PaginatedProductReleaseResponse(
            timestamp=now,
            page_start_index=0,
            page_size=1,
            total_results=0,
            results=(),
        )

        # Use an unmapped type — should still work with TEA_BASE_URL
        purl = PackageURL.from_string("pkg:cargo/serde@1.0")
        self.source.fetch(purl, self.session)

        # Should use direct URL, not from_well_known
        mock_client_cls.assert_called_once_with("https://tea.example.com/v1", token=None, timeout=15)
        mock_client_cls.from_well_known.assert_not_called()

    @patch.dict("os.environ", {"TEA_BASE_URL": "https://tea.example.com/v1", "TEA_TOKEN": "secret"})
    @patch("sbomify_action._enrichment.sources.tea.TeaClient", autospec=True)
    def test_fetch_base_url_with_token(self, mock_client_cls):
        """TEA_BASE_URL + TEA_TOKEN are passed together."""
        from libtea.models import PaginatedProductReleaseResponse

        now = datetime.now(timezone.utc)
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.search_product_releases.return_value = PaginatedProductReleaseResponse(
            timestamp=now,
            page_start_index=0,
            page_size=1,
            total_results=0,
            results=(),
        )

        self.source.fetch(self.purl, self.session)
        mock_client_cls.assert_called_once_with("https://tea.example.com/v1", token="secret", timeout=15)

    @patch.dict("os.environ", {}, clear=True)
    @patch("sbomify_action._enrichment.sources.tea.TeaClient", autospec=True)
    def test_fetch_no_cle(self, mock_client_cls):
        """Fetch returns basic metadata when CLE is not available."""
        from libtea.exceptions import TeaNotFoundError
        from libtea.models import (
            PaginatedProductReleaseResponse,
            ProductRelease,
        )

        now = datetime.now(timezone.utc)
        release = ProductRelease(
            uuid="pr-uuid",
            product="prod-uuid",
            product_name="requests",
            version="2.31.0",
            created_date=now,
            release_date=now,
            identifiers=(),
            components=(),
        )

        mock_client = MagicMock()
        mock_client_cls.from_well_known.return_value = mock_client
        mock_client.search_product_releases.return_value = PaginatedProductReleaseResponse(
            timestamp=now,
            page_start_index=0,
            page_size=1,
            total_results=1,
            results=(release,),
        )
        mock_client.get_product_release_cle.side_effect = TeaNotFoundError("No CLE")

        metadata = self.source.fetch(self.purl, self.session)

        assert metadata is not None
        assert metadata.supplier == "requests"
        assert metadata.cle_release_date is not None
        assert metadata.cle_eos is None
        assert metadata.cle_eol is None
        assert metadata.licenses == []

    @patch.dict("os.environ", {}, clear=True)
    @patch("sbomify_action._enrichment.sources.tea.TeaClient", autospec=True)
    def test_fetch_not_found(self, mock_client_cls):
        """Fetch returns None when PURL is not on TEA server."""
        from libtea.models import PaginatedProductReleaseResponse

        now = datetime.now(timezone.utc)
        mock_client = MagicMock()
        mock_client_cls.from_well_known.return_value = mock_client
        mock_client.search_product_releases.return_value = PaginatedProductReleaseResponse(
            timestamp=now,
            page_start_index=0,
            page_size=1,
            total_results=0,
            results=(),
        )

        metadata = self.source.fetch(self.purl, self.session)
        assert metadata is None

    @patch.dict("os.environ", {}, clear=True)
    @patch("sbomify_action._enrichment.sources.tea.TeaClient", autospec=True)
    def test_fetch_connection_error(self, mock_client_cls):
        """Fetch returns None on connection error."""
        from libtea.exceptions import TeaConnectionError

        mock_client_cls.from_well_known.side_effect = TeaConnectionError("Connection refused")

        metadata = self.source.fetch(self.purl, self.session)
        assert metadata is None

    @patch.dict("os.environ", {}, clear=True)
    @patch("sbomify_action._enrichment.sources.tea.TeaClient", autospec=True)
    def test_fetch_caches_result(self, mock_client_cls):
        """Second fetch for same PURL should use cache."""
        from libtea.models import PaginatedProductReleaseResponse

        now = datetime.now(timezone.utc)
        mock_client = MagicMock()
        mock_client_cls.from_well_known.return_value = mock_client
        mock_client.search_product_releases.return_value = PaginatedProductReleaseResponse(
            timestamp=now,
            page_start_index=0,
            page_size=1,
            total_results=0,
            results=(),
        )

        self.source.fetch(self.purl, self.session)
        self.source.fetch(self.purl, self.session)

        # from_well_known should only be called once (client is cached)
        assert mock_client_cls.from_well_known.call_count == 1
        # search should also only be called once (metadata result is cached)
        assert mock_client.search_product_releases.call_count == 1

    @patch.dict("os.environ", {}, clear=True)
    @patch("sbomify_action._enrichment.sources.tea.TeaClient", autospec=True)
    def test_client_reused_across_purls(self, mock_client_cls):
        """Same domain reuses the cached TeaClient for different PURLs."""
        from libtea.models import PaginatedProductReleaseResponse

        now = datetime.now(timezone.utc)
        mock_client = MagicMock()
        mock_client_cls.from_well_known.return_value = mock_client
        mock_client.search_product_releases.return_value = PaginatedProductReleaseResponse(
            timestamp=now,
            page_start_index=0,
            page_size=1,
            total_results=0,
            results=(),
        )

        purl1 = PackageURL.from_string("pkg:pypi/requests@2.31.0")
        purl2 = PackageURL.from_string("pkg:pypi/flask@3.0.0")
        self.source.fetch(purl1, self.session)
        self.source.fetch(purl2, self.session)

        # Client created once, but search called twice (different PURLs)
        assert mock_client_cls.from_well_known.call_count == 1
        assert mock_client.search_product_releases.call_count == 2

    @patch.dict("os.environ", {}, clear=True)
    def test_fetch_unmapped_type_returns_none(self):
        """Fetch returns None for unmapped PURL type without TEA_BASE_URL."""
        purl = PackageURL.from_string("pkg:cargo/serde@1.0")
        metadata = self.source.fetch(purl, self.session)
        assert metadata is None

    @patch.dict("os.environ", {"TEA_TOKEN": "secret-token"})
    @patch("sbomify_action._enrichment.sources.tea.TeaClient", autospec=True)
    def test_fetch_passes_token(self, mock_client_cls):
        """TEA_TOKEN env var is passed to client."""
        from libtea.models import PaginatedProductReleaseResponse

        now = datetime.now(timezone.utc)
        mock_client = MagicMock()
        mock_client_cls.from_well_known.return_value = mock_client
        mock_client.search_product_releases.return_value = PaginatedProductReleaseResponse(
            timestamp=now,
            page_start_index=0,
            page_size=1,
            total_results=0,
            results=(),
        )

        self.source.fetch(self.purl, self.session)
        mock_client_cls.from_well_known.assert_called_once_with("pypi.sbomify.com", token="secret-token", timeout=15)


class TestTeaInRegistry(unittest.TestCase):
    """Test that TeaSource is registered in the default registry."""

    def test_tea_in_default_registry(self):
        from sbomify_action._enrichment.enricher import create_default_registry

        registry = create_default_registry()
        source_names = [s.name for s in registry._sources]
        assert "tea" in source_names

    def test_clear_all_caches_includes_tea(self):
        """clear_all_caches should not raise (tea cache is included)."""
        from sbomify_action._enrichment.enricher import clear_all_caches

        clear_all_caches()
