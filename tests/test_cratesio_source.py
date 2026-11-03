"""Tests for the CratesIOSource enrichment data source."""

import json
from unittest.mock import Mock

import pytest
import requests
from packageurl import PackageURL

from sbomify_action._enrichment.exceptions import TransientSourceError
from sbomify_action._enrichment.sources.cratesio import CratesIOSource, clear_cache


@pytest.fixture(autouse=True)
def clear_cache_before_test():
    """Clear the cache before each test to ensure isolation."""
    clear_cache()
    yield
    clear_cache()


@pytest.fixture
def mock_session():
    """Create a mock requests session."""
    return Mock(spec=requests.Session)


class TestCratesIOSourceBasics:
    """Test basic properties of CratesIOSource."""

    def test_source_name(self):
        """Test that the source name is correct."""
        source = CratesIOSource()
        assert source.name == "crates.io"

    def test_source_priority(self):
        """Test that the source has Tier 1 priority."""
        source = CratesIOSource()
        assert source.priority == 10  # Tier 1: Native sources

    def test_supports_cargo_packages(self):
        """Test that CratesIOSource supports cargo packages."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0.228")
        assert source.supports(purl) is True

    def test_supports_cargo_without_version(self):
        """Test that CratesIOSource supports cargo packages without version."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/tokio")
        assert source.supports(purl) is True

    def test_does_not_support_pypi(self):
        """Test that CratesIOSource does not support PyPI packages."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:pypi/requests@2.31.0")
        assert source.supports(purl) is False

    def test_does_not_support_npm(self):
        """Test that CratesIOSource does not support npm packages."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:npm/lodash@4.17.21")
        assert source.supports(purl) is False

    def test_does_not_support_deb(self):
        """Test that CratesIOSource does not support deb packages."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        assert source.supports(purl) is False


class TestCratesIOSourceFetch:
    """Test fetch functionality of CratesIOSource."""

    def test_fetch_success_with_version(self, mock_session):
        """Test successful metadata fetch with version specified."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0.228")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": {
                "id": 1748414,
                "crate": "serde",
                "num": "1.0.228",
                "description": "A generic serialization/deserialization framework",
                "license": "MIT OR Apache-2.0",
                "homepage": "https://serde.rs",
                "documentation": "https://docs.rs/serde",
                "repository": "https://github.com/serde-rs/serde",
                "published_by": {
                    "id": 3618,
                    "login": "dtolnay",
                    "name": "David Tolnay",
                    "url": "https://github.com/dtolnay",
                },
            },
            "crate": {
                "id": "serde",
                "name": "serde",
                "description": "A generic serialization/deserialization framework",
            },
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.description == "A generic serialization/deserialization framework"
        # SPDX expressions are kept as-is (e.g., "MIT OR Apache-2.0")
        assert len(metadata.licenses) == 1
        assert "MIT" in metadata.licenses[0]
        assert "Apache-2.0" in metadata.licenses[0]
        assert metadata.supplier == "crates.io"
        assert metadata.maintainer_name == "David Tolnay"
        assert metadata.homepage == "https://serde.rs"
        assert metadata.documentation_url == "https://docs.rs/serde"
        assert "github.com/serde-rs/serde" in metadata.repository_url
        assert metadata.registry_url == "https://crates.io/crates/serde"
        assert metadata.source == "crates.io"

        # Verify API was called with version-specific URL
        mock_session.get.assert_called_once()
        call_url = mock_session.get.call_args[0][0]
        assert "/serde/1.0.228" in call_url

    def test_fetch_success_without_version(self, mock_session):
        """Test successful metadata fetch without version (crate endpoint)."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/tokio")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "crate": {
                "id": "tokio",
                "name": "tokio",
                "description": "An event-driven, non-blocking I/O platform",
                "homepage": "https://tokio.rs",
                "documentation": None,
                "repository": "https://github.com/tokio-rs/tokio",
            },
            "versions": [],  # Crate endpoint returns version list, not version details
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.description == "An event-driven, non-blocking I/O platform"
        assert metadata.homepage == "https://tokio.rs"
        assert "github.com/tokio-rs/tokio" in metadata.repository_url
        # No license without version-specific endpoint
        assert metadata.licenses == []
        # Supplier is always the distribution platform
        assert metadata.supplier == "crates.io"

        # Verify API was called with crate URL (no version)
        mock_session.get.assert_called_once()
        call_url = mock_session.get.call_args[0][0]
        assert call_url.endswith("/tokio")

    def test_fetch_not_found(self, mock_session):
        """Test handling of 404 response."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/nonexistent-crate-12345@1.0.0")

        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_fetch_server_error(self, mock_session):
        """Test handling of server error response."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0.0")

        mock_response = Mock()
        mock_response.status_code = 500
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_fetch_timeout(self, mock_session):
        """Test handling of timeout."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0.0")

        mock_session.get.side_effect = requests.exceptions.Timeout()

        with pytest.raises(TransientSourceError):
            source.fetch(purl, mock_session)

    def test_fetch_connection_error(self, mock_session):
        """Test handling of connection error."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0.0")

        mock_session.get.side_effect = requests.exceptions.ConnectionError()

        with pytest.raises(TransientSourceError):
            source.fetch(purl, mock_session)

    def test_fetch_json_decode_error(self, mock_session):
        """Test handling of JSON decode error."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is None


class TestCratesIOSourceLicenseParsing:
    """Test license parsing in CratesIOSource."""

    def test_single_license(self, mock_session):
        """Test parsing a single license."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/rand@0.8.5")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": {
                "license": "MIT",
                "description": "Random number generators",
            },
            "crate": {},
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.licenses == ["MIT"]

    def test_dual_license_or(self, mock_session):
        """Test parsing dual MIT OR Apache-2.0 license.

        SPDX expressions like 'MIT OR Apache-2.0' are kept as-is by normalize_license_list
        since they are valid SPDX expressions.
        """
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": {
                "license": "MIT OR Apache-2.0",
                "description": "Serialization framework",
            },
            "crate": {},
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        # SPDX expressions are preserved as-is
        assert len(metadata.licenses) == 1
        assert metadata.licenses[0] == "MIT OR Apache-2.0"

    def test_no_license_field(self, mock_session):
        """Test handling when license field is missing."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/old-crate@0.1.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": {
                "description": "An old crate without license field",
                # No license field
            },
            "crate": {},
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.licenses == []


class TestCratesIOSourceCaching:
    """Test caching behavior of CratesIOSource."""

    def test_cache_hit(self, mock_session):
        """Test that repeated requests use cache."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0.228")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": {
                "description": "A generic serialization/deserialization framework",
                "license": "MIT OR Apache-2.0",
            },
            "crate": {},
        }
        mock_session.get.return_value = mock_response

        # First fetch
        metadata1 = source.fetch(purl, mock_session)
        # Second fetch (should use cache)
        metadata2 = source.fetch(purl, mock_session)

        assert metadata1 is not None
        assert metadata2 is not None
        assert metadata1.description == metadata2.description
        # API should only be called once
        assert mock_session.get.call_count == 1

    def test_cache_miss_different_versions(self, mock_session):
        """Test that different versions are cached separately."""
        source = CratesIOSource()
        purl1 = PackageURL.from_string("pkg:cargo/serde@1.0.227")
        purl2 = PackageURL.from_string("pkg:cargo/serde@1.0.228")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": {
                "description": "A generic serialization/deserialization framework",
                "license": "MIT OR Apache-2.0",
            },
            "crate": {},
        }
        mock_session.get.return_value = mock_response

        # Fetch different versions
        source.fetch(purl1, mock_session)
        source.fetch(purl2, mock_session)

        # API should be called twice (different cache keys)
        assert mock_session.get.call_count == 2

    def test_cache_cleared(self, mock_session):
        """Test that clear_cache() works."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0.228")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": {
                "description": "A generic serialization/deserialization framework",
                "license": "MIT OR Apache-2.0",
            },
            "crate": {},
        }
        mock_session.get.return_value = mock_response

        # First fetch
        source.fetch(purl, mock_session)
        # Clear cache
        clear_cache()
        # Second fetch (should not use cache)
        source.fetch(purl, mock_session)

        # API should be called twice
        assert mock_session.get.call_count == 2

    def test_cache_404_response(self, mock_session):
        """Test that 404 responses are cached."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/nonexistent@1.0.0")

        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response

        # First fetch
        metadata1 = source.fetch(purl, mock_session)
        # Second fetch (should use cache)
        metadata2 = source.fetch(purl, mock_session)

        assert metadata1 is None
        assert metadata2 is None
        # API should only be called once
        assert mock_session.get.call_count == 1


class TestCratesIOSourceFieldSources:
    """Test field_sources attribution in CratesIOSource."""

    def test_field_sources_populated(self, mock_session):
        """Test that field_sources is populated correctly."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0.228")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": {
                "description": "A generic serialization/deserialization framework",
                "license": "MIT OR Apache-2.0",
                "homepage": "https://serde.rs",
                "documentation": "https://docs.rs/serde",
                "repository": "https://github.com/serde-rs/serde",
                "published_by": {
                    "name": "David Tolnay",
                },
            },
            "crate": {},
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.field_sources.get("description") == "crates.io"
        assert metadata.field_sources.get("licenses") == "crates.io"
        assert metadata.field_sources.get("supplier") == "crates.io"
        assert metadata.field_sources.get("homepage") == "crates.io"
        assert metadata.field_sources.get("repository_url") == "crates.io"
        assert metadata.field_sources.get("documentation_url") == "crates.io"

    def test_field_sources_partial(self, mock_session):
        """Test that field_sources only includes fields that are present."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/minimal@1.0.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": {
                "description": "A minimal crate",
                # No license, no homepage, no repo
            },
            "crate": {},
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.field_sources.get("description") == "crates.io"
        assert "licenses" not in metadata.field_sources
        # Supplier is always present (distribution platform)
        assert metadata.field_sources.get("supplier") == "crates.io"
        assert "homepage" not in metadata.field_sources


class TestCratesIOSourceRepositoryNormalization:
    """Test repository URL normalization in CratesIOSource."""

    def test_github_url_normalized(self, mock_session):
        """Test that GitHub URLs are normalized to git+ format."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": {
                "repository": "https://github.com/serde-rs/serde",
            },
            "crate": {},
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        # normalize_vcs_url should add git+ prefix
        assert metadata.repository_url.startswith("git+")
        assert "github.com/serde-rs/serde" in metadata.repository_url

    def test_no_repository_url(self, mock_session):
        """Test handling when repository is not provided."""
        source = CratesIOSource()
        purl = PackageURL.from_string("pkg:cargo/no-repo@1.0.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": {
                "description": "A crate without a repository",
            },
            "crate": {},
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.repository_url is None


class TestCratesIOSourceIntegration:
    """Integration-style tests for CratesIOSource with the registry."""

    def test_registered_in_default_registry(self):
        """Test that CratesIOSource is in the default registry."""
        from sbomify_action._enrichment.enricher import create_default_registry

        registry = create_default_registry()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0.0")

        sources = registry.get_sources_for(purl)

        # CratesIOSource should be in the list
        source_names = [s.name for s in sources]
        assert "crates.io" in source_names

        # CratesIOSource should be first (highest priority for cargo)
        crates_source = next(s for s in sources if s.name == "crates.io")
        assert crates_source.priority == 10

    def test_priority_over_depsdev(self):
        """Test that CratesIOSource has priority over DepsDevSource for cargo."""
        from sbomify_action._enrichment.enricher import create_default_registry

        registry = create_default_registry()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0.0")

        sources = registry.get_sources_for(purl)

        # Find both sources
        source_dict = {s.name: s for s in sources}
        assert "crates.io" in source_dict
        assert "deps.dev" in source_dict

        # crates.io should have lower priority number (= higher priority)
        assert source_dict["crates.io"].priority < source_dict["deps.dev"].priority
