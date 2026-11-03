"""Tests for the Debian Sources data source."""

import json
from unittest.mock import Mock

import pytest
import requests
from packageurl import PackageURL

from sbomify_action._enrichment.exceptions import TransientSourceError
from sbomify_action._enrichment.sources.debian import (
    DEBIAN_SOURCES_BASE,
    DebianSource,
    clear_cache,
)


class TestDebianSourceBasics:
    """Test basic DebianSource functionality."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_source_name(self):
        """Test that source name is correct."""
        source = DebianSource()
        assert source.name == "sources.debian.org"

    def test_source_priority(self):
        """Test that priority is 10 (Tier 1: Native sources)."""
        source = DebianSource()
        assert source.priority == 10  # Tier 1: Native sources

    def test_supports_debian_deb_packages(self):
        """Test that source supports pkg:deb/debian/* packages."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        assert source.supports(purl) is True

    def test_does_not_support_ubuntu_packages(self):
        """Test that source does not support Ubuntu packages."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.2")
        assert source.supports(purl) is False

    def test_does_not_support_pypi_packages(self):
        """Test that source does not support PyPI packages."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")
        assert source.supports(purl) is False

    def test_does_not_support_rpm_packages(self):
        """Test that source does not support RPM packages."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:rpm/fedora/bash@5.2")
        assert source.supports(purl) is False

    def test_does_not_support_deb_without_namespace(self):
        """Test that source requires namespace to be 'debian'."""
        source = DebianSource()
        purl = PackageURL(type="deb", name="bash", version="5.2")
        assert source.supports(purl) is False


class TestDebianSourceFetch:
    """Test DebianSource fetch functionality."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_fetch_success(self):
        """Test successful metadata fetch from Debian Sources API."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {
                "vcs": "Git https://salsa.debian.org/debian/bash.git",
                "description": "GNU Bourne Again SHell",
            },
            "version": "5.2-1",
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.source == "sources.debian.org"
        assert metadata.supplier == "Debian Project"
        assert metadata.homepage == "https://tracker.debian.org/pkg/bash"
        assert "sources.debian.org/src/bash" in metadata.registry_url
        assert metadata.repository_url == "git+https://salsa.debian.org/debian/bash.git"

    def test_fetch_with_description(self):
        """Test that description is extracted from API response."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/coreutils@9.1")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {
                "long_description": "GNU core utilities provide basic file, shell and text manipulation utilities.",
            },
            "version": "9.1-1",
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.description == "GNU core utilities provide basic file, shell and text manipulation utilities."

    def test_fetch_with_short_description_fallback(self):
        """Test that short description is used when long_description is absent."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {
                "description": "GNU Bourne Again SHell",  # Short description
            },
            "version": "5.2-1",
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.description == "GNU Bourne Again SHell"

    def test_fetch_not_found_exact_version(self):
        """Test handling of 404 for exact version with fallback to latest."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2.15-2")

        mock_session = Mock()
        # First call (exact version) returns 404, second call (latest) returns 200
        mock_404_response = Mock()
        mock_404_response.status_code = 404

        mock_200_response = Mock()
        mock_200_response.status_code = 200
        mock_200_response.json.return_value = {
            "pkg_infos": {},
            "version": "5.2-3",
        }

        mock_session.get.side_effect = [mock_404_response, mock_200_response]

        metadata = source.fetch(purl, mock_session)

        # Should have fallen back to latest
        assert metadata is not None
        assert metadata.supplier == "Debian Project"
        assert mock_session.get.call_count == 2

    def test_fetch_not_found_both_versions(self):
        """Test handling when both exact and latest versions return 404."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/nonexistent@1.0")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is None
        # Should have tried both exact and latest
        assert mock_session.get.call_count == 2

    def test_fetch_timeout(self):
        """Test handling of request timeout."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_session.get.side_effect = requests.exceptions.Timeout("Connection timeout")

        with pytest.raises(TransientSourceError):
            source.fetch(purl, mock_session)

    def test_fetch_connection_error(self):
        """Test handling of connection error."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_session.get.side_effect = requests.exceptions.ConnectionError("Connection failed")

        with pytest.raises(TransientSourceError):
            source.fetch(purl, mock_session)

    def test_fetch_json_decode_error(self):
        """Test handling of JSON decode error."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is None


class TestDebianSourceCaching:
    """Test DebianSource caching functionality."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_cache_hit(self):
        """Test that subsequent calls use cache."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {},
            "version": "5.2-1",
        }
        mock_session.get.return_value = mock_response

        # First call
        metadata1 = source.fetch(purl, mock_session)
        # Second call should use cache
        metadata2 = source.fetch(purl, mock_session)

        assert metadata1 is not None
        assert metadata2 is not None
        assert metadata1.supplier == metadata2.supplier
        # Should only call API once
        assert mock_session.get.call_count == 1

    def test_cache_negative_result(self):
        """Test that negative results (404) are cached."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/nonexistent@1.0")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response

        # First call
        metadata1 = source.fetch(purl, mock_session)
        # Second call should use cache
        metadata2 = source.fetch(purl, mock_session)

        assert metadata1 is None
        assert metadata2 is None
        # Should have called API for exact + latest on first call only
        assert mock_session.get.call_count == 2

    def test_cache_by_version(self):
        """Test that cache is version-specific."""
        source = DebianSource()
        purl_v1 = PackageURL.from_string("pkg:deb/debian/bash@5.1")
        purl_v2 = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {},
            "version": "5.2-1",
        }
        mock_session.get.return_value = mock_response

        # Fetch different versions
        source.fetch(purl_v1, mock_session)
        source.fetch(purl_v2, mock_session)

        # Should have called API for each version (one call each since 200 returned)
        assert mock_session.get.call_count == 2

    def test_clear_cache(self):
        """Test that clear_cache clears the cache."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {},
            "version": "5.2-1",
        }
        mock_session.get.return_value = mock_response

        # First call
        source.fetch(purl, mock_session)
        assert mock_session.get.call_count == 1

        # Clear cache
        clear_cache()

        # Second call should hit API again
        source.fetch(purl, mock_session)
        assert mock_session.get.call_count == 2


class TestDebianSourceVCSParsing:
    """Test VCS URL parsing from pkg_infos."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_vcs_git_with_type_prefix(self):
        """Test parsing VCS field with 'Git https://...' format."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {
                "vcs": "Git https://salsa.debian.org/debian/bash.git",
            },
            "version": "5.2-1",
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata.repository_url == "git+https://salsa.debian.org/debian/bash.git"

    def test_vcs_plain_url(self):
        """Test parsing VCS field with plain URL."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {
                "vcs": "https://salsa.debian.org/debian/bash.git",
            },
            "version": "5.2-1",
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata.repository_url == "git+https://salsa.debian.org/debian/bash.git"

    def test_vcs_git_protocol(self):
        """Test parsing VCS field with git:// protocol."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {
                "vcs": "git://git.debian.org/debian/bash.git",
            },
            "version": "5.2-1",
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata.repository_url == "git://git.debian.org/debian/bash.git"

    def test_vcs_dict_format_url_key(self):
        """Test parsing VCS field as dict with 'url' key."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {
                "vcs": {
                    "url": "https://salsa.debian.org/debian/bash.git",
                    "browser": "https://salsa.debian.org/debian/bash",
                },
            },
            "version": "5.2-1",
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata.repository_url == "git+https://salsa.debian.org/debian/bash.git"

    def test_vcs_dict_format_browser_key(self):
        """Test parsing VCS field as dict with only 'browser' key."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {
                "vcs": {
                    "browser": "https://salsa.debian.org/debian/bash",
                },
            },
            "version": "5.2-1",
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata.repository_url == "git+https://salsa.debian.org/debian/bash"

    def test_vcs_empty(self):
        """Test handling when VCS field is empty."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {},
            "version": "5.2-1",
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata.repository_url is None


class TestDebianSourceFieldSources:
    """Test field_sources tracking."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_field_sources_populated(self):
        """Test that field_sources tracks which fields came from this source."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {
                "vcs": "Git https://salsa.debian.org/debian/bash.git",
                "description": "GNU Bourne Again SHell",
            },
            "version": "5.2-1",
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert "supplier" in metadata.field_sources
        assert metadata.field_sources["supplier"] == "sources.debian.org"
        assert "homepage" in metadata.field_sources
        assert metadata.field_sources["homepage"] == "sources.debian.org"
        assert "registry_url" in metadata.field_sources
        assert metadata.field_sources["registry_url"] == "sources.debian.org"
        assert "repository_url" in metadata.field_sources
        assert metadata.field_sources["repository_url"] == "sources.debian.org"
        assert "description" in metadata.field_sources
        assert metadata.field_sources["description"] == "sources.debian.org"


class TestDebianSourceVersionHandling:
    """Test version handling including 'latest' fallback."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_version_in_registry_url(self):
        """Test that registry_url includes the version."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2-1")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {},
            "version": "5.2-1",
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert "5.2-1" in metadata.registry_url

    def test_latest_version_uses_actual_version(self):
        """Test that when using 'latest', the actual version from response is used in registry_url."""
        source = DebianSource()
        # PURL without version
        purl = PackageURL(type="deb", namespace="debian", name="bash")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {},
            "version": "5.2-3",  # Actual latest version from API
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        # Should use actual version from API response
        assert "5.2-3" in metadata.registry_url

    def test_fallback_to_latest_preserves_metadata(self):
        """Test that fallback to latest still provides useful metadata."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2.15-2+nonexistent")

        mock_session = Mock()

        # First call (exact version) returns 404
        mock_404 = Mock()
        mock_404.status_code = 404

        # Second call (latest) returns 200 with metadata
        mock_200 = Mock()
        mock_200.status_code = 200
        mock_200.json.return_value = {
            "pkg_infos": {
                "description": "GNU Bourne Again SHell",
                "vcs": "Git https://salsa.debian.org/debian/bash.git",
            },
            "version": "5.2-3",
        }

        mock_session.get.side_effect = [mock_404, mock_200]

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.description == "GNU Bourne Again SHell"
        assert metadata.repository_url == "git+https://salsa.debian.org/debian/bash.git"
        assert metadata.supplier == "Debian Project"


class TestDebianSourceAPIUrls:
    """Test that correct API URLs are constructed."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_exact_version_url(self):
        """Test that exact version URL is correct."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2-1")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"pkg_infos": {}, "version": "5.2-1"}
        mock_session.get.return_value = mock_response

        source.fetch(purl, mock_session)

        # Check the URL that was called
        call_args = mock_session.get.call_args
        url = call_args[0][0]
        assert url == f"{DEBIAN_SOURCES_BASE}/api/info/package/bash/5.2-1/"

    def test_latest_fallback_url(self):
        """Test that fallback to 'latest' uses correct URL."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2-nonexistent")

        mock_session = Mock()
        mock_404 = Mock()
        mock_404.status_code = 404
        mock_200 = Mock()
        mock_200.status_code = 200
        mock_200.json.return_value = {"pkg_infos": {}, "version": "5.2-3"}

        mock_session.get.side_effect = [mock_404, mock_200]

        source.fetch(purl, mock_session)

        # Check both URLs that were called
        calls = mock_session.get.call_args_list
        assert len(calls) == 2
        assert calls[0][0][0] == f"{DEBIAN_SOURCES_BASE}/api/info/package/bash/5.2-nonexistent/"
        assert calls[1][0][0] == f"{DEBIAN_SOURCES_BASE}/api/info/package/bash/latest/"


class TestDebianSourceIntegration:
    """Integration tests for DebianSource with the enrichment pipeline."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_metadata_has_data(self):
        """Test that returned metadata has_data() returns True."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pkg_infos": {"description": "Test"},
            "version": "5.2-1",
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.has_data() is True

    def test_source_registered_in_default_registry(self):
        """Test that DebianSource is registered in the default registry."""
        from sbomify_action._enrichment.enricher import create_default_registry

        registry = create_default_registry()
        sources = registry.list_sources()

        # Check that DebianSource is registered
        source_names = [s["name"] for s in sources]
        assert "sources.debian.org" in source_names

        # Check priority
        debian_source = next(s for s in sources if s["name"] == "sources.debian.org")
        assert debian_source["priority"] == 10
