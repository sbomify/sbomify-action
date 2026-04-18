"""
Tests for the SBOM enrichment module with plugin-based architecture.

Tests the enrichment pipeline and data sources.
"""

import json
from unittest.mock import Mock, patch

import pytest
import requests
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from packageurl import PackageURL
from spdx_tools.spdx.model import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
)

from sbomify_action._enrichment.enricher import Enricher, clear_all_caches, create_default_registry
from sbomify_action._enrichment.metadata import NormalizedMetadata
from sbomify_action._enrichment.registry import SourceRegistry
from sbomify_action._enrichment.sources.debian import DebianSource
from sbomify_action._enrichment.sources.ecosystems import EcosystemsSource
from sbomify_action._enrichment.sources.pubdev import PubDevSource
from sbomify_action._enrichment.sources.purl import (
    OS_PACKAGE_TYPES,
    PACKAGE_TRACKER_URLS,
    PURLSource,
)
from sbomify_action._enrichment.sources.pypi import PyPISource
from sbomify_action._enrichment.sources.repology import RepologySource
from sbomify_action._enrichment.utils import parse_author_string
from sbomify_action.enrichment import (
    ALL_LOCKFILE_NAMES,
    NAMESPACE_TO_SUPPLIER,
    _add_enrichment_source_comment,
    _add_enrichment_source_property,
    _apply_metadata_to_cyclonedx_component,
    _apply_metadata_to_spdx_package,
    _enrich_lockfile_components,
    _enrich_os_component,
    _is_lockfile_component,
    _is_lockfile_package,
    clear_cache,
    enrich_sbom,
)
from sbomify_action.generation import (
    GO_LOCK_FILES,
    JAVASCRIPT_LOCK_FILES,
    PYTHON_LOCK_FILES,
    RUBY_LOCK_FILES,
    RUST_LOCK_FILES,
)

# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def clear_caches():
    """Clear all caches before each test."""
    clear_cache()
    yield


@pytest.fixture
def sample_normalized_metadata():
    """Sample NormalizedMetadata for testing."""
    return NormalizedMetadata(
        description="A high-level Python web framework",
        licenses=["BSD-3-Clause"],
        supplier="Django Software Foundation",
        homepage="https://www.djangoproject.com/",
        repository_url="https://github.com/django/django",
        registry_url="https://pypi.org/project/django/",
        maintainer_name="Django Software Foundation",
        source="test",
    )


@pytest.fixture
def mock_session():
    """Create a mock requests session."""
    return Mock(spec=requests.Session)


# =============================================================================
# Test NormalizedMetadata
# =============================================================================


class TestNormalizedMetadata:
    """Test the NormalizedMetadata dataclass."""

    def test_has_data_with_description(self):
        """Test has_data returns True when description is present."""
        metadata = NormalizedMetadata(description="Test description")
        assert metadata.has_data() is True

    def test_has_data_with_licenses(self):
        """Test has_data returns True when licenses are present."""
        metadata = NormalizedMetadata(licenses=["MIT"])
        assert metadata.has_data() is True

    def test_has_data_with_supplier(self):
        """Test has_data returns True when supplier is present."""
        metadata = NormalizedMetadata(supplier="Test Org")
        assert metadata.has_data() is True

    def test_has_data_empty(self):
        """Test has_data returns False when no data is present."""
        metadata = NormalizedMetadata()
        assert metadata.has_data() is False

    def test_merge_fills_missing_fields(self):
        """Test that merge fills in missing fields from other metadata."""
        meta1 = NormalizedMetadata(description="First", source="source1")
        meta2 = NormalizedMetadata(licenses=["MIT"], homepage="https://example.com", source="source2")

        merged = meta1.merge(meta2)

        assert merged.description == "First"  # From meta1
        assert merged.licenses == ["MIT"]  # From meta2
        assert merged.homepage == "https://example.com"  # From meta2
        assert merged.source == "source1"  # Primary source

    def test_merge_preserves_existing_values(self):
        """Test that merge preserves existing values."""
        meta1 = NormalizedMetadata(description="First", licenses=["Apache-2.0"], source="source1")
        meta2 = NormalizedMetadata(description="Second", licenses=["MIT"], source="source2")

        merged = meta1.merge(meta2)

        assert merged.description == "First"  # Preserved
        assert merged.licenses == ["Apache-2.0"]  # Preserved

    def test_merge_unions_hash_algorithms(self):
        """hashes is a dict keyed by algorithm, not a list — merging must
        preserve algorithms from both sources. Self wins on conflict."""
        meta1 = NormalizedMetadata(hashes={"sha256": "a" * 64}, source="pypi")
        meta2 = NormalizedMetadata(
            hashes={"sha256": "b" * 64, "blake2b-256": "c" * 64, "md5": "d" * 32},
            source="ecosyste.ms",
        )

        merged = meta1.merge(meta2)

        assert merged.hashes == {
            "sha256": "a" * 64,  # self wins on conflicting algorithm
            "blake2b-256": "c" * 64,  # new algorithm preserved
            "md5": "d" * 32,
        }
        # Source attribution records the contributing source when we
        # actually added keys from `other`.
        assert merged.field_sources.get("hashes") == "ecosyste.ms"

    def test_merge_hashes_no_other_keys_leaves_source_untouched(self):
        """When `other` contributes no new hash algorithms, we should not
        fabricate a hashes source attribution for `other`."""
        meta1 = NormalizedMetadata(hashes={"sha256": "a" * 64}, source="pypi")
        meta2 = NormalizedMetadata(hashes={"sha256": "b" * 64}, source="ecosyste.ms")

        merged = meta1.merge(meta2)

        assert merged.hashes == {"sha256": "a" * 64}
        assert "hashes" not in merged.field_sources


# =============================================================================
# Test PURLSource
# =============================================================================


class TestPURLSource:
    """Test the PURLSource data source."""

    def test_source_properties(self):
        """Test source name and priority."""
        source = PURLSource()
        assert source.name == "purl"
        assert source.priority == 70  # Tier 3: Fallback sources

    def test_supports_deb_packages(self):
        """Test that PURLSource supports deb packages."""
        source = PURLSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        assert source.supports(purl) is True

    def test_supports_rpm_packages(self):
        """Test that PURLSource supports rpm packages."""
        source = PURLSource()
        purl = PackageURL.from_string("pkg:rpm/fedora/bash@5.2")
        assert source.supports(purl) is True

    def test_supports_apk_packages(self):
        """Test that PURLSource supports apk packages."""
        source = PURLSource()
        purl = PackageURL.from_string("pkg:apk/alpine/bash@5.2")
        assert source.supports(purl) is True

    def test_does_not_support_pypi(self):
        """Test that PURLSource does not support pypi packages."""
        source = PURLSource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")
        assert source.supports(purl) is False

    def test_fetch_debian_package(self, mock_session):
        """Test fetching metadata for a Debian package."""
        source = PURLSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.supplier == "Debian Project"
        assert metadata.homepage == "https://tracker.debian.org/pkg/bash"
        assert metadata.source == "purl"

    def test_fetch_ubuntu_package(self, mock_session):
        """Test fetching metadata for an Ubuntu package."""
        source = PURLSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.2")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.supplier == "Canonical Ltd"
        assert "launchpad.net" in metadata.homepage

    def test_fetch_alpine_package(self, mock_session):
        """Test fetching metadata for an Alpine package."""
        source = PURLSource()
        purl = PackageURL.from_string("pkg:apk/alpine/bash@5.2")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.supplier == "Alpine Linux"
        assert "alpinelinux.org" in metadata.homepage

    def test_fetch_unknown_namespace(self, mock_session):
        """Test fetching metadata for unknown namespace falls back to title case."""
        source = PURLSource()
        purl = PackageURL.from_string("pkg:deb/customdistro/bash@5.2")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.supplier == "Customdistro Project"

    def test_constants_defined(self):
        """Test that PURL enrichment constants are properly defined."""
        assert "deb" in OS_PACKAGE_TYPES
        assert "rpm" in OS_PACKAGE_TYPES
        assert "apk" in OS_PACKAGE_TYPES
        assert "debian" in NAMESPACE_TO_SUPPLIER
        assert "deb" in PACKAGE_TRACKER_URLS


# =============================================================================
# Test PyPISource
# =============================================================================


class TestPyPISource:
    """Test the PyPISource data source."""

    def test_source_properties(self):
        """Test source name and priority."""
        source = PyPISource()
        assert source.name == "pypi.org"
        assert source.priority == 10  # Tier 1: Native sources

    def test_supports_pypi_packages(self):
        """Test that PyPISource supports pypi packages."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")
        assert source.supports(purl) is True

    def test_does_not_support_deb(self):
        """Test that PyPISource does not support deb packages."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        assert source.supports(purl) is False

    def test_fetch_success(self, mock_session):
        """Test successful metadata fetch from PyPI."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "summary": "A high-level Python web framework",
                "home_page": "https://www.djangoproject.com/",
                "license": "BSD-3-Clause",
                "author": "Django Software Foundation",
                "project_urls": {
                    "Source": "https://github.com/django/django",
                },
            }
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.description == "A high-level Python web framework"
        assert metadata.homepage == "https://www.djangoproject.com/"
        assert "BSD-3-Clause" in metadata.licenses
        # Supplier is the distribution platform, not the author
        assert metadata.supplier == "Python Package Index (PyPI)"
        assert metadata.maintainer_name == "Django Software Foundation"
        assert metadata.repository_url == "git+https://github.com/django/django"

    def test_fetch_not_found(self, mock_session):
        """Test handling of 404 response."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/nonexistent@1.0")

        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_fetch_timeout(self, mock_session):
        """Test handling of timeout."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")

        mock_session.get.side_effect = requests.exceptions.Timeout()

        metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_fetch_author_from_email_field(self, mock_session):
        """Test extraction of author name from author_email when author is empty.

        This tests the parse_author_string integration - packages like uri-template
        have empty author but author_email contains "Name <email>" format.
        """
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/uri-template@1.3.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "summary": "RFC 6570 URI Template Processor",
                "home_page": "https://gitlab.linss.com/open-source/python/uri-template",
                "license": "MIT",
                "author": "",  # Empty author!
                "author_email": "Peter Linss <peter.linss@gmail.com>",  # Name in email field
                "maintainer": "",
                "maintainer_email": "",
            }
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        # Supplier is always the distribution platform
        assert metadata.supplier == "Python Package Index (PyPI)"
        # Author name extracted from email field is preserved in maintainer_name
        assert metadata.maintainer_name == "Peter Linss", (
            f"Expected 'Peter Linss' extracted from author_email, got: {metadata.maintainer_name}"
        )

    def test_fetch_author_from_maintainer_email_field(self, mock_session):
        """Test extraction of author name from maintainer_email when all other fields empty."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/test-package@1.0.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "summary": "Test package",
                "license": "MIT",
                "author": "",
                "author_email": "",
                "maintainer": "",
                "maintainer_email": "Jane Doe <jane@example.com>",  # Only maintainer_email has name
            }
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        # Supplier is always the distribution platform
        assert metadata.supplier == "Python Package Index (PyPI)"
        # Author name extracted from maintainer_email is preserved in maintainer_name
        assert metadata.maintainer_name == "Jane Doe", (
            f"Expected 'Jane Doe' extracted from maintainer_email, got: {metadata.maintainer_name}"
        )

    def test_fetch_prefers_direct_author_over_email(self, mock_session):
        """Test that direct author field is preferred over parsing email field."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/test-package@1.0.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "summary": "Test package",
                "license": "MIT",
                "author": "Direct Author",  # Has direct author
                "author_email": "Different Person <other@example.com>",  # Different in email
            }
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        # Supplier is always the distribution platform
        assert metadata.supplier == "Python Package Index (PyPI)"
        # Direct author is preferred for maintainer_name
        assert metadata.maintainer_name == "Direct Author", (
            f"Expected 'Direct Author' from author field, got: {metadata.maintainer_name}"
        )

    # ---------- Per-file hash + yanked + release-date coverage --------------

    def test_fetch_populates_hashes_from_digests(self, mock_session):
        """PyPI `digests` block is extracted into NormalizedMetadata.hashes."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1.3")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {"summary": "A framework", "license": "BSD-3-Clause"},
            "urls": [
                {
                    "filename": "Django-5.1.3-py3-none-any.whl",
                    "digests": {"md5": "d" * 32, "sha256": "a" * 64},
                    "upload_time_iso_8601": "2024-11-05T05:24:21Z",
                    "yanked": False,
                }
            ],
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.distribution_filename == "Django-5.1.3-py3-none-any.whl"
        assert metadata.hashes == {"md5": "d" * 32, "sha256": "a" * 64}
        assert metadata.cle_release_date == "2024-11-05"
        assert metadata.cle_eol is None  # Not yanked

    def test_fetch_prefers_wheel_over_sdist_for_hashes(self, mock_session):
        """When multiple dists are available, wheel wins and its digests come through."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/foo@1.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {"summary": "Foo", "license": "MIT"},
            "urls": [
                {"filename": "foo-1.0.tar.gz", "digests": {"sha256": "b" * 64}},
                {
                    "filename": "foo-1.0-py3-none-any.whl",
                    "digests": {"sha256": "a" * 64},
                    "upload_time_iso_8601": "2024-05-01T12:00:00Z",
                },
            ],
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata.distribution_filename == "foo-1.0-py3-none-any.whl"
        assert metadata.hashes == {"sha256": "a" * 64}
        assert metadata.cle_release_date == "2024-05-01"

    def test_fetch_yanked_version_populates_eol(self, mock_session):
        """Yanked release → cle_eol at upload time."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/bad-release@9.9.9")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {"summary": "Oops", "license": "MIT", "yanked": True},
            "urls": [
                {
                    "filename": "bad_release-9.9.9-py3-none-any.whl",
                    "digests": {"sha256": "c" * 64},
                    "upload_time_iso_8601": "2023-07-04T08:15:30Z",
                    "yanked": True,
                }
            ],
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata.cle_eol == "2023-07-04"

    def test_fetch_yanked_flag_only_on_dist(self, mock_session):
        """Fallback: yanked on the per-file entry also triggers EOL."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/foo@1.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {"summary": "foo", "license": "MIT"},  # info.yanked absent
            "urls": [
                {
                    "filename": "foo-1.0.whl",
                    "digests": {"sha256": "a" * 64},
                    "upload_time_iso_8601": "2022-01-01T00:00:00Z",
                    "yanked": True,  # file-level yanked
                }
            ],
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata.cle_eol == "2022-01-01"

    def test_fetch_yanked_without_upload_time_leaves_eol_unset(self, mock_session):
        """A yanked release with no upload timestamp leaves cle_eol unset.

        Falling back to today's date would make output non-deterministic and
        emit a misleading "yanked just now" signal to downstream consumers.
        """
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/foo@1.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {"summary": "foo", "license": "MIT", "yanked": True},
            "urls": [{"filename": "foo-1.0.whl"}],  # no upload_time
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)
        assert metadata.cle_eol is None

    def test_fetch_yanked_with_reason_string_treated_as_yanked(self, mock_session):
        """Per PEP 691, `yanked` can be either a bool or a non-empty reason string."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/foo@1.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {"summary": "foo", "license": "MIT", "yanked": "Security advisory X"},
            "urls": [
                {
                    "filename": "foo-1.0.whl",
                    "digests": {"sha256": "a" * 64},
                    "upload_time_iso_8601": "2021-03-03T00:00:00Z",
                }
            ],
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)
        assert metadata.cle_eol == "2021-03-03"

    def test_fetch_yanked_empty_string_not_yanked(self, mock_session):
        """Empty-string / whitespace-only yanked is not a truthy PEP 691 signal."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/foo@1.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {"summary": "foo", "license": "MIT", "yanked": "   "},
            "urls": [
                {
                    "filename": "foo-1.0.whl",
                    "digests": {"sha256": "a" * 64},
                    "upload_time_iso_8601": "2021-03-03T00:00:00Z",
                }
            ],
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)
        assert metadata.cle_eol is None

    # Direct unit tests for the module-level is_pep691_yanked helper.
    # Kept close to the fetch-level tests so the two contracts stay in sync.

    @pytest.mark.parametrize(
        "value,expected",
        [
            (True, True),
            (False, False),
            (None, False),
            ("", False),
            ("   ", False),
            # Unicode whitespace reasons — Python str.strip() removes all
            # Unicode whitespace, so a whitespace-only reason stays falsy.
            ("\t", False),
            ("\u00a0", False),  # non-breaking space
            ("Security advisory X", True),
            # Non-ASCII reason strings are valid per PEP 691 §4.1.
            ("Sicherheitsl\u00fccke", True),
            ({"reason": "x"}, False),
            ([True], False),
            (1, False),  # isinstance(True, int) but bool check runs first
            (0, False),
            (0.5, False),
        ],
    )
    def test_is_pep691_yanked_contract(self, value, expected):
        from sbomify_action._enrichment.sources.pypi import is_pep691_yanked

        assert is_pep691_yanked(value) is expected, f"is_pep691_yanked({value!r}) expected {expected!r}"

    @pytest.mark.parametrize("bad_yanked", [{"reason": "x"}, [True], 1, 0.5, 0])
    def test_fetch_yanked_non_bool_non_string_ignored(self, mock_session, bad_yanked):
        """Malformed yanked types (dict / list / number) must not trigger yank.

        Defence-in-depth against attacker-controlled / cached responses.
        """
        from sbomify_action._enrichment.sources import pypi as pypi_module

        pypi_module._cache.clear()  # isolate from other parametric runs
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/foo@1.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {"summary": "foo", "license": "MIT", "yanked": bad_yanked},
            "urls": [
                {
                    "filename": "foo-1.0.whl",
                    "upload_time_iso_8601": "2020-01-01T00:00:00Z",
                }
            ],
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)
        assert metadata.cle_eol is None, f"bad yanked={bad_yanked!r} unexpectedly set cle_eol"

    def test_fetch_version_specific_endpoint_when_purl_has_version(self, mock_session):
        """URL should be /pypi/{name}/{version}/json when PURL carries a version."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1.3")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"summary": "x"}, "urls": []}
        mock_session.get.return_value = mock_response

        source.fetch(purl, mock_session)

        called_url = mock_session.get.call_args[0][0]
        assert called_url.endswith("/pypi/django/5.1.3/json")

    def test_fetch_latest_endpoint_when_purl_has_no_version(self, mock_session):
        """URL should be /pypi/{name}/json when PURL has no version."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/django")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"summary": "x"}, "urls": []}
        mock_session.get.return_value = mock_response

        source.fetch(purl, mock_session)

        called_url = mock_session.get.call_args[0][0]
        assert called_url.endswith("/pypi/django/json")

    # --- Security: path traversal via PURL version ----------------------------

    def test_fetch_rejects_path_traversal_in_version(self, mock_session):
        """An SBOM-crafted PURL like pkg:pypi/foo@%2E%2E/admin must not cause
        the Action to fetch https://pypi.org/admin/json. Verify the fetch is
        refused outright and no HTTP call is made."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/foo@%2E%2E/%2E%2E/admin")

        metadata = source.fetch(purl, mock_session)

        assert metadata is None
        assert not mock_session.get.called, "request must not be sent for traversal PURLs"

    def test_fetch_rejects_forward_slash_in_version(self, mock_session):
        """Explicit '/' in version also triggers the safety refusal."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/foo@1.0/admin")

        metadata = source.fetch(purl, mock_session)

        assert metadata is None
        assert not mock_session.get.called

    def test_fetch_rejects_path_traversal_in_name(self, mock_session):
        """Traversal tokens in the PURL name are refused symmetrically."""
        from sbomify_action._enrichment.sources import pypi as pypi_module

        pypi_module._cache.clear()
        source = PyPISource()

        class _Shim:
            """Use a lightweight shim exposing the attribute surface the
            fetch() method relies on. `PackageURL.from_string` actually
            preserves `..` in the name field (verified empirically) — so
            a real PURL would do, too — but the shim keeps the unit test
            independent of how the third-party parser may normalise in
            the future."""

            name = ".."
            version = "1.0"

        metadata = source.fetch(_Shim(), mock_session)  # type: ignore[arg-type]

        assert metadata is None
        assert not mock_session.get.called

    def test_fetch_encodes_special_characters_in_purl_components(self, mock_session):
        """Safe special characters survive but are percent-encoded in the URL,
        so `requests` cannot normalise them into path traversal."""
        from sbomify_action._enrichment.sources import pypi as pypi_module

        pypi_module._cache.clear()
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/some%20pkg@1.0%2B0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"summary": "x"}, "urls": []}
        mock_session.get.return_value = mock_response

        source.fetch(purl, mock_session)

        called_url = mock_session.get.call_args[0][0]
        # Space is percent-encoded as %20; raw space never reaches the URL;
        # the '+' version marker is preserved as its percent-encoded form;
        # and no raw path separators leak through.
        assert "some%20pkg" in called_url, f"expected encoded space in {called_url!r}"
        assert " " not in called_url, f"raw space should never reach the URL: {called_url!r}"
        assert ".." not in called_url
        assert "/pypi/" in called_url

    def test_fetch_versioned_404_falls_back_to_latest(self, mock_session):
        """If the version-specific endpoint 404s but the package exists, the
        source retries the latest-only URL so we still get base metadata."""
        from sbomify_action._enrichment.sources import pypi as pypi_module

        pypi_module._cache.clear()
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/foo@99.99.99")

        versioned = Mock()
        versioned.status_code = 404
        latest = Mock()
        latest.status_code = 200
        latest.json.return_value = {
            "info": {"summary": "foo (latest)", "license": "MIT"},
            "urls": [
                {
                    "filename": "foo-1.0-py3-none-any.whl",
                    "digests": {"sha256": "a" * 64},
                    "upload_time_iso_8601": "2024-01-01T00:00:00Z",
                }
            ],
        }
        mock_session.get.side_effect = [versioned, latest]

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.description == "foo (latest)"
        assert mock_session.get.call_count == 2
        # Fallback must have reached the non-versioned URL
        assert mock_session.get.call_args_list[1][0][0].endswith("/pypi/foo/json")

    def test_versioned_404_reuses_warm_latest_cache(self, mock_session):
        """When the name-only latest cache slot is already populated from a
        prior fallback, a second component whose pinned version 404s must
        short-circuit to the cached value without a second HTTP call.

        Pins down the fix for the 404 amplification vulnerability: a
        regression that dropped the cache-hit short-circuit would force
        ``mock_session.get.call_count == 2`` and fail this test.
        """
        from sbomify_action._enrichment.sources import pypi as pypi_module

        pypi_module._cache.clear()
        # Pre-warm the name-only cache slot, as a prior 404 fallback would.
        pre_cached = NormalizedMetadata(description="cached foo", source="pypi.org")
        pypi_module._cache[f"pypi:foo{pypi_module._LATEST_CACHE_SUFFIX}"] = pre_cached

        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/foo@99.99.99")
        versioned = Mock()
        versioned.status_code = 404
        mock_session.get.return_value = versioned

        metadata = source.fetch(purl, mock_session)

        assert metadata is pre_cached
        assert mock_session.get.call_count == 1, "versioned 404 with a warm latest cache must NOT issue a second GET"

    def test_versioned_404_transient_error_not_cached(self, mock_session):
        """When the version-specific endpoint 404s and the latest-endpoint
        retry returns a transient 5xx, the source must NOT cache None for
        the name-only key — a subsequent component in the same run should
        still get a chance to re-fetch when PyPI recovers.
        """
        from sbomify_action._enrichment.sources import pypi as pypi_module

        pypi_module._cache.clear()
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/foo@99.99.99")

        versioned = Mock()
        versioned.status_code = 404
        transient = Mock()
        transient.status_code = 503
        mock_session.get.side_effect = [versioned, transient]

        metadata = source.fetch(purl, mock_session)

        assert metadata is None
        assert f"pypi:foo{pypi_module._LATEST_CACHE_SUFFIX}" not in pypi_module._cache, (
            "transient 5xx must not be cached — retries can still succeed later"
        )

    def test_fetch_malformed_digests_ignored(self, mock_session):
        """Non-string hash values in the digests block do not blow up."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/foo@1.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {"summary": "foo", "license": "MIT"},
            "urls": [
                {
                    "filename": "foo-1.0.whl",
                    "digests": {
                        "sha256": "a" * 64,  # good
                        "md5": "",  # rejected (empty)
                        "blake2b": None,  # rejected (not str)
                        "sha512": "  ",  # rejected (whitespace-only)
                    },
                }
            ],
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)
        assert metadata.hashes == {"sha256": "a" * 64}


# =============================================================================
# Test parse_author_string utility
# =============================================================================
# Test PubDevSource
# =============================================================================


class TestPubDevSource:
    """Test the PubDevSource data source."""

    def test_source_properties(self):
        """Test source name and priority."""
        source = PubDevSource()
        assert source.name == "pub.dev"
        assert source.priority == 10  # Tier 1: Native sources

    def test_supports_pub_packages(self):
        """Test that PubDevSource supports pub packages."""
        source = PubDevSource()
        purl = PackageURL.from_string("pkg:pub/http@1.2.0")
        assert source.supports(purl) is True

    def test_does_not_support_pypi(self):
        """Test that PubDevSource does not support pypi packages."""
        source = PubDevSource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")
        assert source.supports(purl) is False

    def test_does_not_support_npm(self):
        """Test that PubDevSource does not support npm packages."""
        source = PubDevSource()
        purl = PackageURL.from_string("pkg:npm/lodash@4.17.21")
        assert source.supports(purl) is False

    def test_fetch_success(self, mock_session):
        """Test successful metadata fetch from pub.dev."""
        source = PubDevSource()
        purl = PackageURL.from_string("pkg:pub/http@1.2.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "name": "http",
            "publisher": {"publisherId": "dart.dev"},
            "latest": {
                "version": "1.2.0",
                "pubspec": {
                    "name": "http",
                    "description": "A composable, Future-based library for making HTTP requests.",
                    "version": "1.2.0",
                    "homepage": "https://github.com/dart-lang/http",
                    "repository": "https://github.com/dart-lang/http",
                    "issue_tracker": "https://github.com/dart-lang/http/issues",
                },
            },
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.description == "A composable, Future-based library for making HTTP requests."
        assert metadata.homepage == "https://github.com/dart-lang/http"
        assert metadata.repository_url == "git+https://github.com/dart-lang/http"
        assert metadata.issue_tracker_url == "https://github.com/dart-lang/http/issues"
        # Supplier is the distribution platform
        assert metadata.supplier == "pub.dev"
        # Publisher ID is preserved in maintainer_name
        assert metadata.maintainer_name == "dart.dev"
        assert metadata.registry_url == "https://pub.dev/packages/http"
        assert metadata.source == "pub.dev"

    def test_fetch_with_author(self, mock_session):
        """Test metadata fetch with author field instead of publisher."""
        source = PubDevSource()
        purl = PackageURL.from_string("pkg:pub/old_package@0.5.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "name": "old_package",
            "latest": {
                "version": "0.5.0",
                "pubspec": {
                    "name": "old_package",
                    "description": "An older package with author field",
                    "author": "John Doe <john@example.com>",
                },
            },
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.maintainer_name == "John Doe"
        assert metadata.maintainer_email == "john@example.com"
        # Supplier is always the distribution platform
        assert metadata.supplier == "pub.dev"

    def test_fetch_with_authors_list(self, mock_session):
        """Test metadata fetch with authors list field."""
        source = PubDevSource()
        purl = PackageURL.from_string("pkg:pub/multi_author@1.0.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "name": "multi_author",
            "latest": {
                "version": "1.0.0",
                "pubspec": {
                    "name": "multi_author",
                    "description": "Package with multiple authors",
                    "authors": ["Alice <alice@example.com>", "Bob <bob@example.com>"],
                },
            },
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.maintainer_name == "Alice"
        assert metadata.maintainer_email == "alice@example.com"

    def test_fetch_not_found(self, mock_session):
        """Test handling of 404 response."""
        source = PubDevSource()
        purl = PackageURL.from_string("pkg:pub/nonexistent@1.0")

        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_fetch_timeout(self, mock_session):
        """Test handling of timeout."""
        source = PubDevSource()
        purl = PackageURL.from_string("pkg:pub/http@1.2.0")

        mock_session.get.side_effect = requests.exceptions.Timeout()

        metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_fetch_cache_functionality(self, mock_session):
        """Test that pub.dev responses are cached."""
        source = PubDevSource()
        purl = PackageURL.from_string("pkg:pub/http@1.2.0")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "name": "http",
            "latest": {
                "version": "1.2.0",
                "pubspec": {
                    "name": "http",
                    "description": "HTTP library",
                },
            },
        }
        mock_session.get.return_value = mock_response

        # First call
        result1 = source.fetch(purl, mock_session)
        # Second call (should use cache)
        result2 = source.fetch(purl, mock_session)

        assert result1 is not None
        assert result2 is not None
        # Should only call API once due to caching
        assert mock_session.get.call_count == 1


# =============================================================================
# Test RepologySource
# =============================================================================


class TestRepologySource:
    """Test the RepologySource data source."""

    def test_source_properties(self):
        """Test source name and priority."""
        source = RepologySource()
        assert source.name == "repology.org"
        assert source.priority == 90  # Tier 3: Fallback sources

    def test_supports_deb_packages(self):
        """Test that RepologySource supports deb packages."""
        source = RepologySource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        assert source.supports(purl) is True

    def test_supports_rpm_packages(self):
        """Test that RepologySource supports rpm packages."""
        source = RepologySource()
        purl = PackageURL.from_string("pkg:rpm/fedora/bash@5.2")
        assert source.supports(purl) is True

    def test_does_not_support_pypi(self):
        """Test that RepologySource does not support pypi packages."""
        source = RepologySource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")
        assert source.supports(purl) is False

    def test_fetch_success(self, mock_session):
        """Test successful metadata fetch from Repology."""
        source = RepologySource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "repo": "debian_12",
                "summary": "GNU Bourne Again SHell",
                "www": "https://www.gnu.org/software/bash/",
                "licenses": ["GPL-3.0+"],
            }
        ]
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.description == "GNU Bourne Again SHell"
        assert metadata.homepage == "https://www.gnu.org/software/bash/"
        assert "GPL-3.0+" in metadata.licenses

    def test_fetch_not_found(self, mock_session):
        """Test handling of 404 response."""
        source = RepologySource()
        purl = PackageURL.from_string("pkg:deb/debian/nonexistent@1.0")

        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_fetch_rate_limit(self, mock_session):
        """Test handling of rate limit response."""
        source = RepologySource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_response = Mock()
        mock_response.status_code = 429
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is None


# =============================================================================
# Test SourceRegistry
# =============================================================================


class TestSourceRegistry:
    """Test the SourceRegistry."""

    def test_register_source(self):
        """Test registering a source."""
        registry = SourceRegistry()
        source = PURLSource()

        registry.register(source)

        assert len(registry.list_sources()) == 1

    def test_get_sources_for_purl(self):
        """Test getting applicable sources for a PURL."""
        registry = SourceRegistry()
        registry.register(PyPISource())
        registry.register(PURLSource())

        purl = PackageURL.from_string("pkg:pypi/django@5.1")
        sources = registry.get_sources_for(purl)

        # Only PyPISource should match
        assert len(sources) == 1
        assert sources[0].name == "pypi.org"

    def test_sources_sorted_by_priority(self):
        """Test that sources are returned sorted by priority."""
        registry = SourceRegistry()
        registry.register(RepologySource())  # Priority 100
        registry.register(PyPISource())  # Priority 10
        registry.register(PURLSource())  # Priority 60

        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        sources = registry.get_sources_for(purl)

        # PURLSource (60) should come before RepologySource (100)
        priorities = [s.priority for s in sources]
        assert priorities == sorted(priorities)


# =============================================================================
# Test Enricher
# =============================================================================


class TestEnricher:
    """Test the Enricher class."""

    def test_default_registry_has_all_sources(self):
        """Test that default registry has all expected sources."""
        registry = create_default_registry()
        sources = registry.list_sources()
        source_names = [s["name"] for s in sources]

        assert "pypi.org" in source_names
        assert "pub.dev" in source_names
        assert "sources.debian.org" in source_names
        assert "purl" in source_names
        assert "repology.org" in source_names

    def test_enricher_context_manager(self):
        """Test Enricher as context manager."""
        with Enricher() as enricher:
            assert enricher.registry is not None

    def test_fetch_metadata_pypi(self):
        """Test fetching metadata for a PyPI package."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "summary": "Test package",
                "license": "MIT",
                "author": "Test Author",
            }
        }

        with patch("requests.Session.get", return_value=mock_response):
            with Enricher() as enricher:
                metadata = enricher.fetch_metadata("pkg:pypi/testpkg@1.0")

                assert metadata is not None
                assert metadata.description == "Test package"


# =============================================================================
# Test Apply Metadata Functions
# =============================================================================


class TestApplyMetadata:
    """Test applying NormalizedMetadata to SBOM components."""

    def test_apply_to_cyclonedx_component(self, sample_normalized_metadata):
        """Test applying metadata to a CycloneDX component."""
        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)

        added_fields = _apply_metadata_to_cyclonedx_component(component, sample_normalized_metadata)

        assert component.description == "A high-level Python web framework"
        assert component.publisher == "Django Software Foundation"
        assert len(component.licenses) > 0
        assert "description" in added_fields

    def test_apply_to_cyclonedx_preserves_existing(self, sample_normalized_metadata):
        """Test that existing values are not overwritten."""
        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)
        component.description = "Existing description"

        _apply_metadata_to_cyclonedx_component(component, sample_normalized_metadata)

        assert component.description == "Existing description"

    def test_apply_to_spdx_package(self, sample_normalized_metadata):
        """Test applying metadata to an SPDX package."""
        package = Package(
            spdx_id="SPDXRef-django",
            name="django",
            download_location="NOASSERTION",
        )

        added_fields = _apply_metadata_to_spdx_package(package, sample_normalized_metadata)

        assert package.description == "A high-level Python web framework"
        assert package.homepage == "https://www.djangoproject.com/"
        assert "description" in added_fields

    def test_apply_empty_metadata(self):
        """Test applying empty metadata does nothing."""
        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)

        added_fields = _apply_metadata_to_cyclonedx_component(component, NormalizedMetadata())

        assert added_fields == []
        assert component.description is None


# =============================================================================
# Test OS Component Enrichment
# =============================================================================


class TestOSComponentEnrichment:
    """Test enriching operating-system type components."""

    def test_enrich_debian_os(self):
        """Test enriching a Debian OS component with publisher and CLE."""
        component = Component(name="debian", version="12", type=ComponentType.OPERATING_SYSTEM)

        added_fields = _enrich_os_component(component)

        assert component.publisher == "Debian Project"
        assert "publisher" in " ".join(added_fields)

        # Check lifecycle milestone properties
        props = {p.name: p.value for p in component.properties}
        assert props.get("cdx:lifecycle:milestone:generalAvailability") == "2023-06-10"
        assert props.get("cdx:lifecycle:milestone:endOfSupport") == "2026-06-10"
        assert props.get("cdx:lifecycle:milestone:endOfLife") == "2028-06-30"

    def test_enrich_debian_os_with_point_release(self):
        """Test enriching Debian with point release version (12.12 -> 12)."""
        component = Component(name="debian", version="12.12", type=ComponentType.OPERATING_SYSTEM)

        _enrich_os_component(component)

        # Should still get Debian 12 lifecycle data
        props = {p.name: p.value for p in component.properties}
        assert props.get("cdx:lifecycle:milestone:endOfLife") == "2028-06-30"

    def test_enrich_ubuntu_os(self):
        """Test enriching an Ubuntu OS component."""
        component = Component(name="ubuntu", version="22.04", type=ComponentType.OPERATING_SYSTEM)

        _enrich_os_component(component)

        assert component.publisher == "Canonical Ltd"

        # Check lifecycle milestone properties
        props = {p.name: p.value for p in component.properties}
        assert props.get("cdx:lifecycle:milestone:generalAvailability") == "2022-04"
        assert props.get("cdx:lifecycle:milestone:endOfSupport") == "2027-06"
        assert props.get("cdx:lifecycle:milestone:endOfLife") == "2032-04"

    def test_enrich_alpine_os(self):
        """Test enriching an Alpine OS component."""
        component = Component(name="alpine", version="3.19", type=ComponentType.OPERATING_SYSTEM)

        _enrich_os_component(component)

        assert component.publisher == "Alpine Linux"

        # Check lifecycle milestone properties
        props = {p.name: p.value for p in component.properties}
        assert props.get("cdx:lifecycle:milestone:generalAvailability") == "2023-12-07"
        assert props.get("cdx:lifecycle:milestone:endOfLife") == "2025-11-01"

    def test_enrich_unknown_os(self):
        """Test that unknown OS gets no CLE data."""
        component = Component(name="unknownos", version="1.0", type=ComponentType.OPERATING_SYSTEM)

        _enrich_os_component(component)

        assert component.publisher is None
        # No CLE properties for unknown OS
        assert component.properties is None or len(component.properties) == 0

    def test_enrich_non_os_type(self):
        """Test that non-OS types are not enriched."""
        component = Component(name="debian", version="12", type=ComponentType.LIBRARY)

        added_fields = _enrich_os_component(component)

        assert added_fields == []


# =============================================================================
# Test Lockfile Handling
# =============================================================================


class TestLockfileHandling:
    """Test lockfile component detection and enrichment."""

    def test_all_lockfile_names_defined(self):
        """Test that ALL_LOCKFILE_NAMES includes all lockfile types."""
        assert "requirements.txt" in ALL_LOCKFILE_NAMES
        assert "uv.lock" in ALL_LOCKFILE_NAMES
        assert "package-lock.json" in ALL_LOCKFILE_NAMES
        assert "Cargo.lock" in ALL_LOCKFILE_NAMES

    def test_is_lockfile_component_true(self):
        """Test detecting lockfile components."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [{"type": "application", "name": "uv.lock"}],
        }
        bom = Bom.from_json(bom_json)
        component = list(bom.components)[0]

        assert _is_lockfile_component(component) is True

    def test_is_lockfile_component_false_with_purl(self):
        """Test that components with PURL are not lockfiles."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [{"type": "application", "name": "uv.lock", "purl": "pkg:pypi/uvlock@1.0"}],
        }
        bom = Bom.from_json(bom_json)
        component = list(bom.components)[0]

        assert _is_lockfile_component(component) is False

    def test_is_lockfile_component_false_for_library(self):
        """Test that library components are not lockfiles."""
        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)

        assert _is_lockfile_component(component) is False

    def test_enrich_lockfile_components(self):
        """Test enriching lockfile components with descriptions."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {"type": "application", "name": "uv.lock"},
                {"type": "library", "name": "django", "version": "5.1", "purl": "pkg:pypi/django@5.1"},
            ],
        }
        bom = Bom.from_json(bom_json)

        enriched = _enrich_lockfile_components(bom)

        assert enriched == 1
        for comp in bom.components:
            if comp.name == "uv.lock":
                assert comp.description == "Python uv lockfile"


# =============================================================================
# Test Enrichment Source Tracking
# =============================================================================


class TestEnrichmentSourceTracking:
    """Test enrichment source property/comment tracking."""

    def test_add_enrichment_source_property(self):
        """Test adding enrichment source property to CycloneDX component."""
        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)

        _add_enrichment_source_property(component, "pypi.org")

        props = [p for p in component.properties if p.name == "sbomify:enrichment:source"]
        assert len(props) == 1
        assert props[0].value == "pypi.org"

    def test_add_enrichment_source_property_no_duplicate(self):
        """Test that duplicate properties are not added."""
        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)

        _add_enrichment_source_property(component, "pypi.org")
        _add_enrichment_source_property(component, "pypi.org")

        props = [p for p in component.properties if p.name == "sbomify:enrichment:source"]
        assert len(props) == 1

    def test_add_enrichment_source_comment(self):
        """Test adding enrichment source comment to SPDX package."""
        package = Package(spdx_id="SPDXRef-test", name="test", download_location="NOASSERTION")

        _add_enrichment_source_comment(package, "pypi.org")

        assert "Enriched by sbomify from pypi.org" in package.comment


# =============================================================================
# Test End-to-End Enrichment
# =============================================================================


class TestEndToEndEnrichment:
    """Test end-to-end SBOM enrichment."""

    def test_enrich_cyclonedx_sbom(self, tmp_path):
        """Test enriching a CycloneDX SBOM end-to-end."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {"timestamp": "2024-01-01T00:00:00Z"},
            "components": [
                {
                    "type": "library",
                    "name": "django",
                    "version": "5.1",
                    "purl": "pkg:pypi/django@5.1",
                    "bom-ref": "pkg-django",
                }
            ],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        # Mock PyPI response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "summary": "Django web framework",
                "license": "BSD-3-Clause",
                "author": "Django Software Foundation",
            }
        }

        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(input_file), str(output_file), validate=False)

        assert output_file.exists()
        with open(output_file) as f:
            result = json.load(f)

        assert result["components"][0]["description"] == "Django web framework"
        # Publisher is the package author (maintainer_name), not distribution platform
        assert result["components"][0]["publisher"] == "Django Software Foundation"

    def test_enrich_spdx_sbom(self, tmp_path):
        """Test enriching an SPDX SBOM end-to-end."""
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-sbom",
            "creationInfo": {
                "created": "2024-01-01T00:00:00Z",
                "creators": ["Tool: test"],
                "licenseListVersion": "3.21",
            },
            "dataLicense": "CC0-1.0",
            "documentNamespace": "https://example.com/test-sbom",
            "packages": [
                {
                    "SPDXID": "SPDXRef-django",
                    "name": "django",
                    "versionInfo": "5.1",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/django@5.1",
                        }
                    ],
                }
            ],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        # Mock PyPI response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "summary": "Django web framework",
                "license": "BSD-3-Clause",
                "author": "Django Software Foundation",
                "home_page": "https://www.djangoproject.com/",
            }
        }

        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(input_file), str(output_file), validate=False)

        assert output_file.exists()
        with open(output_file) as f:
            result = json.load(f)

        pkg = result["packages"][0]
        assert pkg["description"] == "Django web framework"
        assert pkg["homepage"] == "https://www.djangoproject.com/"

    def test_enrich_os_packages_with_purl_fallback(self, tmp_path):
        """Test that OS packages are enriched via PURL when native sources fail."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {"timestamp": "2024-01-01T00:00:00Z"},
            "components": [
                {
                    "type": "library",
                    "name": "bash",
                    "version": "5.2",
                    "purl": "pkg:deb/ubuntu/bash@5.2",  # Ubuntu uses PURL fallback
                    "bom-ref": "pkg-bash",
                }
            ],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        # Mock all API responses to 404 - only PURL extraction should work
        mock_response = Mock()
        mock_response.status_code = 404

        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(input_file), str(output_file), validate=False)

        with open(output_file) as f:
            result = json.load(f)

        component = result["components"][0]
        assert component["publisher"] == "Canonical Ltd"
        # Check for enrichment source property
        # May include "lifecycle" (for distro CLE) and/or "purl" (for publisher)
        props = {p["name"]: p["value"] for p in component.get("properties", [])}
        source = props.get("sbomify:enrichment:source", "")
        assert "purl" in source or "lifecycle" in source


# =============================================================================
# Test Error Handling
# =============================================================================


class TestErrorHandling:
    """Test error handling in enrichment."""

    def test_file_not_found(self, tmp_path):
        """Test handling of missing input file."""
        with pytest.raises(FileNotFoundError):
            enrich_sbom(str(tmp_path / "nonexistent.json"), str(tmp_path / "out.json"))

    def test_invalid_json(self, tmp_path):
        """Test handling of invalid JSON."""
        input_file = tmp_path / "invalid.json"
        input_file.write_text("not valid json")

        with pytest.raises(ValueError, match="Invalid JSON"):
            enrich_sbom(str(input_file), str(tmp_path / "out.json"))

    def test_unsupported_format(self, tmp_path):
        """Test handling of unsupported SBOM format."""
        input_file = tmp_path / "unknown.json"
        input_file.write_text(json.dumps({"unknown": "format"}))

        with pytest.raises(ValueError, match="Neither CycloneDX nor SPDX"):
            enrich_sbom(str(input_file), str(tmp_path / "out.json"))

    def test_missing_spec_version(self, tmp_path):
        """Test handling of missing specVersion in CycloneDX."""
        input_file = tmp_path / "missing_version.json"
        input_file.write_text(json.dumps({"bomFormat": "CycloneDX"}))

        with pytest.raises(Exception, match="specVersion"):
            enrich_sbom(str(input_file), str(tmp_path / "out.json"))


# =============================================================================
# Test SPDX License Handling
# =============================================================================


class TestSPDXLicenseHandling:
    """Test SPDX license field enrichment."""

    def test_spdx_license_declared_with_single_license(self):
        """Test that license_declared is properly set for a single license."""
        metadata = NormalizedMetadata(licenses=["BSD-3-Clause"], source="test")
        package = Package(
            spdx_id="SPDXRef-django",
            name="django",
            download_location="NOASSERTION",
            version="5.1",
        )

        added_fields = _apply_metadata_to_spdx_package(package, metadata)

        assert package.license_declared is not None
        assert "BSD-3-Clause" in str(package.license_declared)
        assert "license_declared" in " ".join(added_fields)

    def test_spdx_license_declared_with_multiple_licenses(self):
        """Test that license_declared handles multiple licenses with OR operator."""
        metadata = NormalizedMetadata(licenses=["MIT", "Apache-2.0"], source="test")
        package = Package(
            spdx_id="SPDXRef-test",
            name="test",
            download_location="NOASSERTION",
            version="1.0",
        )

        _apply_metadata_to_spdx_package(package, metadata)

        assert package.license_declared is not None
        license_str = str(package.license_declared)
        assert "MIT" in license_str
        assert "Apache-2.0" in license_str
        assert "OR" in license_str

    def test_spdx_license_declared_not_override_existing(self):
        """Test that existing license_declared is not overridden."""
        from spdx_tools.spdx.parser.jsonlikedict.license_expression_parser import LicenseExpressionParser

        metadata = NormalizedMetadata(licenses=["MIT"], source="test")
        package = Package(
            spdx_id="SPDXRef-test",
            name="test",
            download_location="NOASSERTION",
            version="1.0",
        )

        # Set existing license
        license_parser = LicenseExpressionParser()
        existing_license = license_parser.parse_license_expression("GPL-3.0-or-later")
        package.license_declared = existing_license

        added_fields = _apply_metadata_to_spdx_package(package, metadata)

        # Verify existing license was preserved
        assert "GPL-3.0" in str(package.license_declared)
        assert "MIT" not in str(package.license_declared)
        # License should not be in added fields since we didn't add it
        assert not any("license" in field for field in added_fields)


# =============================================================================
# Test Schema Version End-to-End
# =============================================================================


class TestSchemaVersionEndToEnd:
    """Test end-to-end enrichment for different schema versions."""

    @pytest.fixture
    def mock_pypi_response(self):
        """Mock PyPI API response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "summary": "Test package description",
                "license": "MIT",
                "author": "Test Author",
                "home_page": "https://example.com",
            }
        }
        return mock_response

    def test_cyclonedx_15_enrichment(self, tmp_path, mock_pypi_response):
        """Test enriching a CycloneDX 1.5 SBOM."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "version": 1,
            "metadata": {"timestamp": "2024-01-01T00:00:00Z"},
            "components": [{"type": "library", "name": "django", "version": "5.1", "purl": "pkg:pypi/django@5.1"}],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        with patch("requests.Session.get", return_value=mock_pypi_response):
            enrich_sbom(str(input_file), str(output_file), validate=False)

        with open(output_file) as f:
            result = json.load(f)

        assert result["specVersion"] == "1.5"
        assert result["components"][0]["description"] == "Test package description"

    def test_cyclonedx_16_enrichment(self, tmp_path, mock_pypi_response):
        """Test enriching a CycloneDX 1.6 SBOM."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "version": 1,
            "metadata": {"timestamp": "2024-01-01T00:00:00Z"},
            "components": [
                {"type": "library", "name": "requests", "version": "2.32.0", "purl": "pkg:pypi/requests@2.32.0"}
            ],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        with patch("requests.Session.get", return_value=mock_pypi_response):
            enrich_sbom(str(input_file), str(output_file), validate=False)

        with open(output_file) as f:
            result = json.load(f)

        assert result["specVersion"] == "1.6"
        assert result["components"][0]["description"] == "Test package description"

    def test_spdx_22_enrichment(self, tmp_path, mock_pypi_response):
        """Test enriching an SPDX 2.2 SBOM."""
        sbom_data = {
            "spdxVersion": "SPDX-2.2",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-doc-22",
            "documentNamespace": "https://test.com/spdx22",
            "creationInfo": {
                "created": "2024-01-01T00:00:00Z",
                "creators": ["Tool: test-tool"],
                "licenseListVersion": "3.21",
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-django",
                    "name": "django",
                    "versionInfo": "5.1",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/django@5.1",
                        }
                    ],
                }
            ],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        with patch("requests.Session.get", return_value=mock_pypi_response):
            enrich_sbom(str(input_file), str(output_file), validate=False)

        with open(output_file) as f:
            result = json.load(f)

        assert result["spdxVersion"] == "SPDX-2.2"
        assert result["packages"][0]["description"] == "Test package description"

    def test_spdx_23_enrichment(self, tmp_path, mock_pypi_response):
        """Test enriching an SPDX 2.3 SBOM."""
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-doc-23",
            "documentNamespace": "https://test.com/spdx23",
            "creationInfo": {
                "created": "2024-01-01T00:00:00Z",
                "creators": ["Tool: test-tool"],
                "licenseListVersion": "3.21",
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-requests",
                    "name": "requests",
                    "versionInfo": "2.32.0",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/requests@2.32.0",
                        }
                    ],
                }
            ],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        with patch("requests.Session.get", return_value=mock_pypi_response):
            enrich_sbom(str(input_file), str(output_file), validate=False)

        with open(output_file) as f:
            result = json.load(f)

        assert result["spdxVersion"] == "SPDX-2.3"
        assert result["packages"][0]["description"] == "Test package description"


# =============================================================================
# Test Cache and API Behavior
# =============================================================================


class TestCacheAndAPIBehavior:
    """Test caching and API error handling behavior."""

    def test_pypi_cache_functionality(self, mock_session):
        """Test that PyPI responses are cached."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"summary": "Django", "author": "DSF"}}
        mock_session.get.return_value = mock_response

        # First call
        result1 = source.fetch(purl, mock_session)
        # Second call (should use cache)
        result2 = source.fetch(purl, mock_session)

        assert result1 is not None
        assert result2 is not None
        # Should only call API once due to caching
        assert mock_session.get.call_count == 1

    def test_api_404_response(self, mock_session):
        """Test handling of 404 API responses."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/nonexistent@1.0")

        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_api_429_rate_limit(self, mock_session, caplog):
        """Test handling of rate limit responses."""
        source = RepologySource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_response = Mock()
        mock_response.status_code = 429
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is None
        assert "rate limit" in caplog.text.lower()

    def test_api_timeout(self, mock_session):
        """Test handling of API timeouts."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")

        mock_session.get.side_effect = requests.exceptions.Timeout()

        metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_api_connection_error(self, mock_session):
        """Test handling of connection errors."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")

        mock_session.get.side_effect = requests.exceptions.ConnectionError()

        metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_clear_all_caches(self, mock_session):
        """Test clearing all source caches."""
        source = PyPISource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"summary": "Django", "author": "DSF"}}
        mock_session.get.return_value = mock_response

        # Populate cache
        source.fetch(purl, mock_session)
        assert mock_session.get.call_count == 1

        # Clear caches
        clear_all_caches()

        # Fetch again - should call API again
        source.fetch(purl, mock_session)
        assert mock_session.get.call_count == 2


# =============================================================================
# Test Enrichment Edge Cases
# =============================================================================


class TestEnrichmentEdgeCases:
    """Test edge cases in enrichment."""

    def test_enrich_component_with_none_metadata(self):
        """Test enriching component when metadata is None."""
        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)

        added_fields = _apply_metadata_to_cyclonedx_component(component, NormalizedMetadata())

        assert added_fields == []
        assert component.description is None

    def test_enrich_spdx_package_with_none_metadata(self):
        """Test enriching SPDX package when metadata is None."""
        package = Package(
            spdx_id="SPDXRef-test",
            name="test",
            download_location="NOASSERTION",
        )

        added_fields = _apply_metadata_to_spdx_package(package, NormalizedMetadata())

        assert added_fields == []
        assert package.description is None

    def test_enrich_component_single_license(self):
        """Test enriching component with a single license."""
        metadata = NormalizedMetadata(licenses=["MIT"], source="test")
        component = Component(name="test", version="1.0", type=ComponentType.LIBRARY)

        _apply_metadata_to_cyclonedx_component(component, metadata)

        assert len(component.licenses) > 0

    def test_enrich_spdx_originator_from_maintainer(self):
        """Test enriching SPDX originator from maintainer_name."""
        metadata = NormalizedMetadata(maintainer_name="Test Maintainer", source="test")
        package = Package(
            spdx_id="SPDXRef-test",
            name="test",
            download_location="NOASSERTION",
        )

        _apply_metadata_to_spdx_package(package, metadata)

        # Should set originator from maintainer
        assert package.originator is not None
        assert package.originator.name == "Test Maintainer"

    def test_enrich_component_preserves_existing_description(self):
        """Test that existing description is preserved."""
        metadata = NormalizedMetadata(description="New description", source="test")
        component = Component(name="test", version="1.0", type=ComponentType.LIBRARY)
        component.description = "Existing description"

        _apply_metadata_to_cyclonedx_component(component, metadata)

        assert component.description == "Existing description"

    def test_enrich_component_external_references(self, sample_normalized_metadata):
        """Test that external references are added."""
        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)

        _apply_metadata_to_cyclonedx_component(component, sample_normalized_metadata)

        # Should have external references for homepage and repository
        assert len(component.external_references) > 0


# =============================================================================
# Test PURL Enrichment Integration
# =============================================================================


class TestPURLEnrichmentIntegration:
    """Test PURL-based enrichment integration."""

    def test_enrich_debian_sbom_end_to_end(self, tmp_path):
        """Test end-to-end enrichment of Debian packages."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
            "version": 1,
            "metadata": {"timestamp": "2024-01-01T00:00:00Z"},
            "components": [
                {
                    "type": "library",
                    "name": "bash",
                    "version": "5.2",
                    "purl": "pkg:deb/debian/bash@5.2",
                }
            ],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        # Mock API to 404 - only PURL extraction should work
        mock_response = Mock()
        mock_response.status_code = 404

        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(input_file), str(output_file), validate=False)

        with open(output_file) as f:
            result = json.load(f)

        component = result["components"][0]
        assert component["publisher"] == "Debian Project"

    def test_enrich_mixed_sbom_pypi_and_debian(self, tmp_path):
        """Test enriching SBOM with both PyPI and Debian packages."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:44444444-4444-4444-4444-444444444444",
            "version": 1,
            "metadata": {"timestamp": "2024-01-01T00:00:00Z"},
            "components": [
                {"type": "library", "name": "django", "version": "5.1", "purl": "pkg:pypi/django@5.1"},
                {"type": "library", "name": "bash", "version": "5.2", "purl": "pkg:deb/debian/bash@5.2"},
            ],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        def mock_get(url, **kwargs):
            mock_response = Mock()
            if "pypi.org" in url:
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "info": {
                        "summary": "Django web framework",
                        "author": "Django Software Foundation",
                    }
                }
            else:
                mock_response.status_code = 404
            return mock_response

        with patch("requests.Session.get", side_effect=mock_get):
            enrich_sbom(str(input_file), str(output_file), validate=False)

        with open(output_file) as f:
            result = json.load(f)

        components = {c["name"]: c for c in result["components"]}

        # PyPI package should have description
        assert components["django"]["description"] == "Django web framework"
        # Debian package should have publisher from PURL
        assert components["bash"]["publisher"] == "Debian Project"


# =============================================================================
# Test Lockfile Filtering Extended
# =============================================================================


class TestLockfileFilteringExtended:
    """Extended tests for lockfile handling."""

    def test_all_lockfile_names_matches_all_constants(self):
        """Test that ALL_LOCKFILE_NAMES includes files from all language categories."""
        # Check Python
        for f in PYTHON_LOCK_FILES:
            assert f in ALL_LOCKFILE_NAMES

        # Check JavaScript
        for f in JAVASCRIPT_LOCK_FILES:
            assert f in ALL_LOCKFILE_NAMES

        # Check Rust
        for f in RUST_LOCK_FILES:
            assert f in ALL_LOCKFILE_NAMES

        # Check Ruby
        for f in RUBY_LOCK_FILES:
            assert f in ALL_LOCKFILE_NAMES

        # Check Go
        for f in GO_LOCK_FILES:
            assert f in ALL_LOCKFILE_NAMES

    def test_is_lockfile_package_spdx_true(self):
        """Test detecting lockfile packages in SPDX."""
        package = Package(
            spdx_id="SPDXRef-requirements",
            name="requirements.txt",
            download_location="NOASSERTION",
        )

        assert _is_lockfile_package(package) is True

    def test_is_lockfile_package_spdx_false_with_purl(self):
        """Test that SPDX packages with PURL are not lockfiles."""
        package = Package(
            spdx_id="SPDXRef-requirements",
            name="requirements.txt",
            download_location="NOASSERTION",
        )
        package.external_references = [
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator="pkg:pypi/requirements@1.0",
            )
        ]

        assert _is_lockfile_package(package) is False

    def test_is_lockfile_package_spdx_false_for_regular_package(self):
        """Test that regular packages are not lockfiles."""
        package = Package(
            spdx_id="SPDXRef-django",
            name="django",
            download_location="NOASSERTION",
        )

        assert _is_lockfile_package(package) is False

    def test_is_lockfile_package_spdx_with_full_path(self):
        """Test that lockfile packages with full paths are detected.

        Trivy generates SPDX with full paths like /github/workspace/uv.lock.
        The detection should extract the basename to match against known lockfiles.
        """
        # Full path should be detected as lockfile
        package = Package(
            spdx_id="SPDXRef-uv-lock",
            name="/github/workspace/uv.lock",
            download_location="NOASSERTION",
        )
        assert _is_lockfile_package(package) is True

        # Various path formats
        package = Package(
            spdx_id="SPDXRef-requirements",
            name="/app/requirements.txt",
            download_location="NOASSERTION",
        )
        assert _is_lockfile_package(package) is True

        # Deep nested path
        package = Package(
            spdx_id="SPDXRef-poetry",
            name="/home/runner/work/project/src/poetry.lock",
            download_location="NOASSERTION",
        )
        assert _is_lockfile_package(package) is True

    def test_is_lockfile_package_spdx_full_path_not_lockfile(self):
        """Test that full paths to non-lockfile files are not detected."""
        # Full path to a regular file
        package = Package(
            spdx_id="SPDXRef-app",
            name="/github/workspace/app.py",
            download_location="NOASSERTION",
        )
        assert _is_lockfile_package(package) is False

        # Path that contains lockfile name but isn't a lockfile
        package = Package(
            spdx_id="SPDXRef-backup",
            name="/backup/old/requirements.txt.bak",
            download_location="NOASSERTION",
        )
        assert _is_lockfile_package(package) is False

    def test_enrich_lockfile_spdx_end_to_end(self, tmp_path):
        """Test enriching lockfile packages in SPDX document end-to-end."""
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "dataLicense": "CC0-1.0",
            "documentNamespace": "https://example.com/test-lockfile",
            "creationInfo": {
                "created": "2024-01-01T00:00:00Z",
                "creators": ["Tool: test"],
                "licenseListVersion": "3.21",
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-uv-lock",
                    "name": "uv.lock",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                },
                {
                    "SPDXID": "SPDXRef-django",
                    "name": "django",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                },
            ],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        with patch("requests.Session.get") as mock_get:
            mock_get.return_value = Mock(status_code=404)
            enrich_sbom(str(input_file), str(output_file), validate=False)

        with open(output_file) as f:
            result = json.load(f)

        uv_pkg = next(p for p in result["packages"] if p["name"] == "uv.lock")
        assert "uv lockfile" in uv_pkg["description"].lower()

    def test_enrich_lockfile_spdx_with_full_path(self, tmp_path):
        """Test enriching lockfile packages with full paths (Trivy-generated SPDX).

        Trivy generates SPDX with full paths like /github/workspace/uv.lock.
        This test verifies that:
        1. The lockfile is detected despite the full path
        2. The description is looked up correctly using the basename
        """
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "dataLicense": "CC0-1.0",
            "documentNamespace": "https://example.com/test-fullpath-lockfile",
            "creationInfo": {
                "created": "2024-01-01T00:00:00Z",
                "creators": ["Tool: trivy-0.67.2"],
                "licenseListVersion": "3.21",
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-main",
                    "name": "Python Stack",
                    "versionInfo": "1.0.0",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "supplier": "Organization: Acme Corp",
                },
                {
                    "SPDXID": "SPDXRef-uv-lock",
                    "name": "/github/workspace/uv.lock",  # Full path like Trivy generates
                    "downloadLocation": "NONE",
                    "filesAnalyzed": False,
                },
                {
                    "SPDXID": "SPDXRef-django",
                    "name": "django",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                },
            ],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        with patch("requests.Session.get") as mock_get:
            mock_get.return_value = Mock(status_code=404)
            enrich_sbom(str(input_file), str(output_file), validate=False)

        with open(output_file) as f:
            result = json.load(f)

        # Find the lockfile package (still has full path name)
        uv_pkg = next(p for p in result["packages"] if "uv.lock" in p["name"])

        # Verify the lockfile was enriched despite the full path
        assert uv_pkg["description"] is not None, "Lockfile should have description"
        assert "uv" in uv_pkg["description"].lower(), "Description should mention uv"
        assert "lockfile" in uv_pkg["description"].lower(), "Description should mention lockfile"

        # Verify version was inherited (lockfiles get version from root)
        assert uv_pkg.get("versionInfo") is not None, "Lockfile should have version"

    def test_enrich_lockfile_with_description(self):
        """Test that lockfiles get descriptive descriptions."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {"type": "application", "name": "package-lock.json"},
                {"type": "application", "name": "Cargo.lock"},
                {"type": "application", "name": "Gemfile.lock"},
            ],
        }
        bom = Bom.from_json(bom_json)

        _enrich_lockfile_components(bom)

        descriptions = {c.name: c.description for c in bom.components}
        # Check that each lockfile got a description (format may vary)
        assert descriptions["package-lock.json"] is not None
        assert "lockfile" in descriptions["package-lock.json"].lower()
        assert descriptions["Cargo.lock"] is not None
        assert "rust" in descriptions["Cargo.lock"].lower()
        assert descriptions["Gemfile.lock"] is not None
        assert "ruby" in descriptions["Gemfile.lock"].lower()


# =============================================================================
# Test DebianSource
# =============================================================================


class TestDebianSource:
    """Test the DebianSource data source."""

    def test_source_properties(self):
        """Test source name and priority."""
        source = DebianSource()
        assert source.name == "sources.debian.org"
        assert source.priority == 10  # Tier 1: Native sources

    def test_supports_debian_packages(self):
        """Test that DebianSource supports debian packages."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        assert source.supports(purl) is True

    def test_does_not_support_ubuntu(self):
        """Test that DebianSource does not support Ubuntu packages."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.2")
        assert source.supports(purl) is False

    def test_does_not_support_pypi(self):
        """Test that DebianSource does not support pypi packages."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")
        assert source.supports(purl) is False

    def test_fetch_success(self, mock_session):
        """Test successful metadata fetch from Debian sources."""
        source = DebianSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "package": "bash",
            "copyright": {
                "license": "GPL-3+",
                "copyright": "Copyright (C) Free Software Foundation",
            },
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        # Should return metadata or None based on implementation
        # The key is that it doesn't crash
        assert metadata is None or isinstance(metadata, NormalizedMetadata)


# =============================================================================
# Test EcosystemsSource
# =============================================================================


class TestEcosystemsSource:
    """Test the EcosystemsSource data source."""

    def test_source_properties(self):
        """Test source name and priority."""
        source = EcosystemsSource()
        assert source.name == "ecosyste.ms"
        assert source.priority == 45  # Tier 2: Primary aggregators

    def test_supports_pypi(self):
        """Test that EcosystemsSource supports pypi packages."""
        source = EcosystemsSource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")
        assert source.supports(purl) is True

    def test_supports_npm(self):
        """Test that EcosystemsSource supports npm packages."""
        source = EcosystemsSource()
        purl = PackageURL.from_string("pkg:npm/lodash@4.17.21")
        assert source.supports(purl) is True

    def test_does_not_support_deb(self):
        """Test that EcosystemsSource does not support deb packages."""
        source = EcosystemsSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        assert source.supports(purl) is False


# =============================================================================
# Test ClearlyDefinedSource
# =============================================================================


class TestClearlyDefinedSource:
    """Test the ClearlyDefinedSource data source."""

    def test_source_properties(self):
        """Test source name and priority."""
        from sbomify_action._enrichment.sources.clearlydefined import ClearlyDefinedSource

        source = ClearlyDefinedSource()
        assert source.name == "clearlydefined.io"
        assert source.priority == 75  # Tier 3: Fallback sources

    def test_supports_pypi(self):
        """Test that ClearlyDefinedSource supports pypi packages."""
        from sbomify_action._enrichment.sources.clearlydefined import ClearlyDefinedSource

        source = ClearlyDefinedSource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")
        assert source.supports(purl) is True

    def test_supports_npm(self):
        """Test that ClearlyDefinedSource supports npm packages."""
        from sbomify_action._enrichment.sources.clearlydefined import ClearlyDefinedSource

        source = ClearlyDefinedSource()
        purl = PackageURL.from_string("pkg:npm/lodash@4.17.21")
        assert source.supports(purl) is True

    def test_does_not_support_deb(self):
        """Test that ClearlyDefinedSource does not support deb packages."""
        from sbomify_action._enrichment.sources.clearlydefined import ClearlyDefinedSource

        source = ClearlyDefinedSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        assert source.supports(purl) is False

    def test_fetch_success(self, mock_session):
        """Test successful metadata fetch from ClearlyDefined."""
        from sbomify_action._enrichment.sources.clearlydefined import ClearlyDefinedSource

        source = ClearlyDefinedSource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "licensed": {
                "declared": "BSD-3-Clause",
                "facets": {
                    "core": {"attribution": {"parties": ["Django Software Foundation"]}},
                },
            },
            "described": {
                "projectWebsite": "https://www.djangoproject.com/",
                "releaseDate": "2024-01-01",
            },
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        # Should return metadata or None based on implementation
        assert metadata is None or isinstance(metadata, NormalizedMetadata)

    def test_fetch_not_found(self, mock_session):
        """Test handling of 404 response."""
        from sbomify_action._enrichment.sources.clearlydefined import ClearlyDefinedSource

        source = ClearlyDefinedSource()
        purl = PackageURL.from_string("pkg:pypi/nonexistent@1.0")

        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is None


# =============================================================================
# Test DepsDevSource
# =============================================================================


class TestVcsUrlNormalization:
    """Test VCS URL normalization (now in sanitization module)."""

    def test_normalize_ssh_shorthand_to_git_https(self):
        """Test that SSH shorthand URLs (git@host:path) are normalized to git+https://host/path."""
        from sbomify_action._enrichment.sanitization import normalize_vcs_url

        url = "git@github.com:user/repo.git"
        result = normalize_vcs_url(url)
        assert result == "git+https://github.com/user/repo.git"

    def test_normalize_scm_git_ssh_to_git_https(self):
        """Test that scm:git:git@... URLs are normalized to git+https://."""
        from sbomify_action._enrichment.sanitization import normalize_vcs_url

        url = "scm:git:git@github.com:user/repo.git"
        result = normalize_vcs_url(url)
        assert result == "git+https://github.com/user/repo.git"

    def test_normalize_scm_git_protocol_strips_prefix(self):
        """Test that scm:git:git://... strips the scm:git: prefix but keeps git://."""
        from sbomify_action._enrichment.sanitization import normalize_vcs_url

        url = "scm:git:git://github.com/user/repo.git"
        result = normalize_vcs_url(url)
        # git:// is already a valid SPDX VCS scheme, don't change protocol
        assert result == "git://github.com/user/repo.git"

    def test_normalize_scm_git_https_to_git_https(self):
        """Test that scm:git:https://... URLs are normalized to git+https://."""
        from sbomify_action._enrichment.sanitization import normalize_vcs_url

        url = "scm:git:https://github.com/user/repo.git"
        result = normalize_vcs_url(url)
        assert result == "git+https://github.com/user/repo.git"

    def test_normalize_scm_git_http_to_git_http(self):
        """Test that scm:git:http://... URLs are normalized to git+http://."""
        from sbomify_action._enrichment.sanitization import normalize_vcs_url

        url = "scm:git:http://github.com/user/repo.git"
        result = normalize_vcs_url(url)
        assert result == "git+http://github.com/user/repo.git"

    def test_normalize_git_protocol_unchanged(self):
        """Test that git:// URLs are left unchanged (already valid SPDX VCS scheme)."""
        from sbomify_action._enrichment.sanitization import normalize_vcs_url

        url = "git://github.com/user/repo.git"
        result = normalize_vcs_url(url)
        # git:// is the git protocol (port 9418), already valid - don't change it
        assert result == "git://github.com/user/repo.git"

    def test_normalize_known_git_host_https(self):
        """Test that https:// URLs from known git hosts are normalized."""
        from sbomify_action._enrichment.sanitization import normalize_vcs_url

        # GitHub is a known git host, so we can safely add git+ prefix
        url = "https://github.com/user/repo.git"
        result = normalize_vcs_url(url)
        assert result == "git+https://github.com/user/repo.git"

    def test_normalize_unknown_host_unchanged(self):
        """Test that https:// URLs from unknown hosts are NOT modified."""
        from sbomify_action._enrichment.sanitization import normalize_vcs_url

        # Unknown domain - could be Mercurial, SVN, or just a website
        url = "https://example.com/some/repo"
        result = normalize_vcs_url(url)
        assert result == "https://example.com/some/repo"

    def test_normalize_empty_string(self):
        """Test that empty strings are returned unchanged."""
        from sbomify_action._enrichment.sanitization import normalize_vcs_url

        assert normalize_vcs_url("") == ""

    def test_normalize_gitlab_ssh(self):
        """Test normalization of GitLab SSH URLs."""
        from sbomify_action._enrichment.sanitization import normalize_vcs_url

        url = "git@gitlab.com:group/project.git"
        result = normalize_vcs_url(url)
        assert result == "git+https://gitlab.com/group/project.git"

    def test_normalize_bitbucket_ssh(self):
        """Test normalization of Bitbucket SSH URLs."""
        from sbomify_action._enrichment.sanitization import normalize_vcs_url

        url = "git@bitbucket.org:user/repo.git"
        result = normalize_vcs_url(url)
        assert result == "git+https://bitbucket.org/user/repo.git"


class TestDepsDevSource:
    """Test the DepsDevSource data source."""

    def test_source_properties(self):
        """Test source name and priority."""
        from sbomify_action._enrichment.sources.depsdev import DepsDevSource

        source = DepsDevSource()
        assert source.name == "deps.dev"
        assert source.priority == 40  # Tier 2: Primary aggregators

    def test_supports_pypi(self):
        """Test that DepsDevSource supports pypi packages."""
        from sbomify_action._enrichment.sources.depsdev import DepsDevSource

        source = DepsDevSource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")
        assert source.supports(purl) is True

    def test_supports_npm(self):
        """Test that DepsDevSource supports npm packages."""
        from sbomify_action._enrichment.sources.depsdev import DepsDevSource

        source = DepsDevSource()
        purl = PackageURL.from_string("pkg:npm/lodash@4.17.21")
        assert source.supports(purl) is True

    def test_does_not_support_deb(self):
        """Test that DepsDevSource does not support deb packages."""
        from sbomify_action._enrichment.sources.depsdev import DepsDevSource

        source = DepsDevSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        assert source.supports(purl) is False

    def test_fetch_success(self, mock_session):
        """Test successful metadata fetch from deps.dev."""
        from sbomify_action._enrichment.sources.depsdev import DepsDevSource

        source = DepsDevSource()
        purl = PackageURL.from_string("pkg:pypi/django@5.1")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": {
                "description": "Django web framework",
                "licenses": ["BSD-3-Clause"],
                "links": {"homepage": "https://www.djangoproject.com/"},
            }
        }
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        # Should return metadata or None based on implementation
        assert metadata is None or isinstance(metadata, NormalizedMetadata)

    def test_fetch_not_found(self, mock_session):
        """Test handling of 404 response."""
        from sbomify_action._enrichment.sources.depsdev import DepsDevSource

        source = DepsDevSource()
        purl = PackageURL.from_string("pkg:pypi/nonexistent@1.0")

        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response

        metadata = source.fetch(purl, mock_session)

        assert metadata is None


# =============================================================================
# Test Utility Functions
# =============================================================================


class TestParseAuthorString:
    """Test the parse_author_string utility function."""

    def test_parse_name_and_email(self):
        """Test parsing 'Name <email>' format."""
        name, email = parse_author_string("John Doe <john@example.com>")
        assert name == "John Doe"
        assert email == "john@example.com"

    def test_parse_name_only(self):
        """Test parsing name without email."""
        name, email = parse_author_string("John Doe")
        assert name == "John Doe"
        assert email is None

    def test_parse_email_only(self):
        """Test parsing email only (no name before angle bracket)."""
        name, email = parse_author_string("<john@example.com>")
        assert name is None
        assert email == "john@example.com"

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        name, email = parse_author_string("")
        assert name is None
        assert email is None

    def test_parse_none(self):
        """Test parsing None value."""
        name, email = parse_author_string(None)
        assert name is None
        assert email is None

    def test_parse_whitespace_handling(self):
        """Test that whitespace is properly stripped."""
        name, email = parse_author_string("  John Doe   <  john@example.com  >  ")
        assert name == "John Doe"
        assert email == "john@example.com"

    def test_parse_complex_name(self):
        """Test parsing name with multiple parts."""
        name, email = parse_author_string("Dr. Jane Smith Jr. <jane.smith@example.org>")
        assert name == "Dr. Jane Smith Jr."
        assert email == "jane.smith@example.org"


# =============================================================================
# Test Field Sources Tracking
# =============================================================================


class TestFieldSourcesTracking:
    """Test that field sources are properly tracked in metadata."""

    def test_metadata_field_sources(self):
        """Test that field_sources tracks where each field came from."""
        metadata = NormalizedMetadata(
            description="Test",
            licenses=["MIT"],
            source="pypi.org",
            field_sources={
                "description": "pypi.org",
                "licenses": "pypi.org",
            },
        )

        assert metadata.field_sources["description"] == "pypi.org"
        assert metadata.field_sources["licenses"] == "pypi.org"

    def test_merge_preserves_field_sources(self):
        """Test that merge preserves field_sources from both metadata."""
        meta1 = NormalizedMetadata(description="First", source="source1", field_sources={"description": "source1"})
        meta2 = NormalizedMetadata(licenses=["MIT"], source="source2", field_sources={"licenses": "source2"})

        merged = meta1.merge(meta2)

        # Both field sources should be preserved
        assert merged.field_sources.get("description") == "source1"
        assert merged.field_sources.get("licenses") == "source2"


# =============================================================================
# Test No Components With PURLs
# =============================================================================


class TestNoComponentsWithPURLs:
    """Test behavior when SBOM has no components with PURLs."""

    def test_cyclonedx_no_purls(self, tmp_path):
        """Test enriching CycloneDX SBOM with no PURLs."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:55555555-5555-5555-5555-555555555555",
            "version": 1,
            "metadata": {"timestamp": "2024-01-01T00:00:00Z"},
            "components": [
                {"type": "library", "name": "unknown-lib", "version": "1.0"},
            ],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        with patch("requests.Session.get") as mock_get:
            enrich_sbom(str(input_file), str(output_file), validate=False)

        # Should not call any API since no PURLs
        mock_get.assert_not_called()

        # Output should still exist
        assert output_file.exists()

    def test_spdx_no_purls(self, tmp_path):
        """Test enriching SPDX SBOM with no PURLs."""
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-no-purls",
            "documentNamespace": "https://example.com/test",
            "dataLicense": "CC0-1.0",
            "creationInfo": {
                "created": "2024-01-01T00:00:00Z",
                "creators": ["Tool: test"],
                "licenseListVersion": "3.21",
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-unknown",
                    "name": "unknown-lib",
                    "versionInfo": "1.0",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                }
            ],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        with patch("requests.Session.get") as mock_get:
            enrich_sbom(str(input_file), str(output_file), validate=False)

        # Should not call any API since no PURLs
        mock_get.assert_not_called()

        assert output_file.exists()


# =============================================================================
# Test Validation After Enrichment
# =============================================================================


class TestEnrichmentValidation:
    """Test validation logic after enrichment."""

    def test_enrich_sbom_validates_output_by_default(self, tmp_path):
        """Test that enrich_sbom validates output when validate=True (default)."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:66666666-6666-6666-6666-666666666666",
            "version": 1,
            "metadata": {"timestamp": "2024-01-01T00:00:00Z"},
            "components": [],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        with patch("requests.Session.get"):
            # Should succeed - validation is enabled by default
            enrich_sbom(str(input_file), str(output_file))

        assert output_file.exists()

    def test_enrich_sbom_validation_failure_raises_error(self, tmp_path):
        """Test that validation failure raises SBOMValidationError."""
        from sbomify_action.exceptions import SBOMValidationError

        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:77777777-7777-7777-7777-777777777777",
            "version": 1,
            "metadata": {"timestamp": "2024-01-01T00:00:00Z"},
            "components": [],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        with patch("requests.Session.get"):
            with patch("sbomify_action.enrichment.validate_sbom_file_auto") as mock_validate:
                # Mock validation failure
                mock_result = Mock()
                mock_result.valid = False
                mock_result.error_message = "Schema validation failed"
                mock_validate.return_value = mock_result

                with pytest.raises(SBOMValidationError) as exc_info:
                    enrich_sbom(str(input_file), str(output_file), validate=True)

                assert "Enriched SBOM failed validation" in str(exc_info.value)
                assert "Schema validation failed" in str(exc_info.value)

    def test_enrich_sbom_skips_validation_when_disabled(self, tmp_path):
        """Test that validation is skipped when validate=False."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:88888888-8888-8888-8888-888888888888",
            "version": 1,
            "metadata": {"timestamp": "2024-01-01T00:00:00Z"},
            "components": [],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        with patch("requests.Session.get"):
            with patch("sbomify_action.enrichment.validate_sbom_file_auto") as mock_validate:
                enrich_sbom(str(input_file), str(output_file), validate=False)

                # Validation should not be called
                mock_validate.assert_not_called()

        assert output_file.exists()

    def test_enrich_sbom_spdx_validates_output(self, tmp_path):
        """Test that SPDX enrichment also validates output."""
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-validation",
            "documentNamespace": "https://example.com/test-validation",
            "dataLicense": "CC0-1.0",
            "creationInfo": {
                "created": "2024-01-01T00:00:00Z",
                "creators": ["Tool: test"],
                "licenseListVersion": "3.21",
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-main",
                    "name": "test-pkg",
                    "versionInfo": "1.0",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                }
            ],
        }

        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(sbom_data))

        with patch("requests.Session.get"):
            # Should succeed with validation
            enrich_sbom(str(input_file), str(output_file), validate=True)

        assert output_file.exists()


# =============================================================================
# Test LicenseDBSource Architecture-Agnostic Lookup
# =============================================================================


class TestLicenseDBSourceArchAgnostic:
    """Test the LicenseDBSource architecture-agnostic PURL lookup."""

    @pytest.fixture
    def license_db_source(self, tmp_path):
        """Create a LicenseDBSource with a temporary cache directory."""
        from sbomify_action._enrichment.sources.license_db import LicenseDBSource

        return LicenseDBSource(cache_dir=tmp_path)

    @pytest.fixture
    def sample_db(self):
        """Create a sample license database for testing."""
        return {
            "metadata": {
                "distro": "debian",
                "version": "12",
                "package_count": 3,
            },
            "packages": {
                "pkg:deb/debian/apt@2.6.1?arch=amd64&distro=debian-12": {
                    "name": "apt",
                    "spdx": "GPL-2.0-only",
                    "supplier": "APT Development Team",
                },
                "pkg:deb/debian/bash@5.2.15?arch=amd64&distro=debian-12": {
                    "name": "bash",
                    "spdx": "GPL-3.0-or-later",
                    "supplier": "Bash Maintainers",
                },
                "pkg:deb/debian/coreutils@9.1?arch=amd64&distro=debian-12": {
                    "name": "coreutils",
                    "spdx": "GPL-3.0-only",
                    "supplier": "GNU Project",
                },
            },
        }

    def test_arch_agnostic_lookup_arm64_matches_amd64(self, license_db_source, sample_db):
        """Test that arm64 PURL matches amd64 database entry."""
        # Input is arm64, database has amd64
        purl = PackageURL.from_string("pkg:deb/debian/apt@2.6.1?arch=arm64&distro=debian-12")

        result = license_db_source._lookup_arch_agnostic(sample_db, purl)

        assert result is not None
        assert result["name"] == "apt"
        assert result["spdx"] == "GPL-2.0-only"

    def test_arch_agnostic_lookup_i386_matches_amd64(self, license_db_source, sample_db):
        """Test that i386 PURL matches amd64 database entry."""
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2.15?arch=i386&distro=debian-12")

        result = license_db_source._lookup_arch_agnostic(sample_db, purl)

        assert result is not None
        assert result["name"] == "bash"
        assert result["spdx"] == "GPL-3.0-or-later"

    def test_arch_agnostic_lookup_no_match_different_version(self, license_db_source, sample_db):
        """Test that different version does not match."""
        # Version 9.2 not in database (only 9.1)
        purl = PackageURL.from_string("pkg:deb/debian/coreutils@9.2?arch=arm64&distro=debian-12")

        result = license_db_source._lookup_arch_agnostic(sample_db, purl)

        assert result is None

    def test_arch_agnostic_lookup_no_match_different_distro(self, license_db_source, sample_db):
        """Test that different distro qualifier does not match."""
        # distro=debian-11 not in database (only debian-12)
        purl = PackageURL.from_string("pkg:deb/debian/apt@2.6.1?arch=arm64&distro=debian-11")

        result = license_db_source._lookup_arch_agnostic(sample_db, purl)

        assert result is None

    def test_arch_agnostic_lookup_no_arch_qualifier_returns_none(self, license_db_source, sample_db):
        """Test that PURL without arch qualifier returns None (exact match already tried)."""
        # No arch qualifier - should return None since exact match is tried first
        purl = PackageURL.from_string("pkg:deb/debian/apt@2.6.1?distro=debian-12")

        result = license_db_source._lookup_arch_agnostic(sample_db, purl)

        assert result is None

    def test_arch_agnostic_lookup_builds_index_once(self, license_db_source, sample_db):
        """Test that the index is built only once and cached."""
        purl1 = PackageURL.from_string("pkg:deb/debian/apt@2.6.1?arch=arm64&distro=debian-12")
        purl2 = PackageURL.from_string("pkg:deb/debian/bash@5.2.15?arch=arm64&distro=debian-12")

        # First lookup builds the index
        license_db_source._lookup_arch_agnostic(sample_db, purl1)
        assert "_arch_agnostic_index" in sample_db

        # Second lookup uses cached index
        result = license_db_source._lookup_arch_agnostic(sample_db, purl2)
        assert result is not None
        assert result["name"] == "bash"

    def test_arch_agnostic_index_structure(self, license_db_source, sample_db):
        """Test that the index has correct structure."""
        index = license_db_source._build_arch_agnostic_index(sample_db)

        # Should have 3 unique keys (one per package)
        assert len(index) == 3

        # Check apt entry
        apt_key = ("deb", "debian", "apt", "2.6.1")
        assert apt_key in index
        assert len(index[apt_key]) == 1

        # Qualifiers should not include arch
        qualifiers, pkg_data = index[apt_key][0]
        assert "arch" not in qualifiers
        assert "distro" in qualifiers
        assert qualifiers["distro"] == "debian-12"


class TestBSIEnrichmentFields:
    """Tests for BSI TR-03183-2 enrichment: manufacturer + filename."""

    def test_manufacturer_set_with_email(self):
        """Manufacturer should be set when maintainer has name + email."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(
            maintainer_name="Django Software Foundation",
            maintainer_email="foundation@djangoproject.com",
        )

        added = _apply_metadata_to_cyclonedx_component(component, metadata)

        assert "manufacturer" in added
        assert component.manufacturer is not None
        assert component.manufacturer.name == "Django Software Foundation"
        contacts = list(component.manufacturer.contacts)
        assert len(contacts) == 1
        assert contacts[0].email == "foundation@djangoproject.com"

    def test_manufacturer_not_set_without_email(self):
        """Manufacturer should NOT be set without email (BSI needs contact info)."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(maintainer_name="Django Foundation")

        added = _apply_metadata_to_cyclonedx_component(component, metadata)

        assert "manufacturer" not in added
        assert component.manufacturer is None

    def test_filename_property_added(self):
        """BSI filename property should be added from distribution_filename."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(distribution_filename="Django-5.1-py3-none-any.whl")

        added = _apply_metadata_to_cyclonedx_component(component, metadata)

        assert "filename" in added
        filenames = [p for p in component.properties if p.name == "bsi:component:filename"]
        assert len(filenames) == 1
        assert filenames[0].value == "Django-5.1-py3-none-any.whl"

    def test_filename_not_duplicated(self):
        """Filename should not be added twice across enrichment runs."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(distribution_filename="Django-5.1-py3-none-any.whl")

        _apply_metadata_to_cyclonedx_component(component, metadata)
        _apply_metadata_to_cyclonedx_component(component, metadata)  # second run

        filenames = [p for p in component.properties if p.name == "bsi:component:filename"]
        assert len(filenames) == 1

    # --- BSI §5.2.2 derived boolean properties -----------------------------------

    def test_bsi_wheel_library_derives_archive_non_executable_structured(self):
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(distribution_filename="Django-5.1-py3-none-any.whl")
        _apply_metadata_to_cyclonedx_component(component, metadata)
        props = {p.name: p.value for p in component.properties}
        assert props["bsi:component:archive"] == "archive"
        assert props["bsi:component:executable"] == "non-executable"
        assert props["bsi:component:structured"] == "structured"

    def test_bsi_exe_application_derives_executable_no_archive(self):
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="myapp", version="1.0", type=ComponentType.APPLICATION)
        metadata = NormalizedMetadata(distribution_filename="myapp-1.0.exe")
        _apply_metadata_to_cyclonedx_component(component, metadata)
        props = {p.name: p.value for p in component.properties}
        assert props["bsi:component:executable"] == "executable"
        assert props["bsi:component:archive"] == "no archive"
        assert props["bsi:component:structured"] == "structured"

    def test_bsi_container_type_defaults(self):
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="myimg", version="1.0", type=ComponentType.CONTAINER)
        metadata = NormalizedMetadata()  # no filename — fall through to type-based default
        _apply_metadata_to_cyclonedx_component(component, metadata)
        props = {p.name: p.value for p in component.properties}
        assert props["bsi:component:archive"] == "archive"
        assert props["bsi:component:executable"] == "executable"
        assert props["bsi:component:structured"] == "structured"

    def test_bsi_operator_supplied_values_win(self):
        """Pre-existing BSI properties must not be overwritten by the helper."""
        from cyclonedx.model import Property

        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)
        component.properties.add(Property(name="bsi:component:archive", value="no archive"))
        component.properties.add(Property(name="bsi:component:executable", value="executable"))
        metadata = NormalizedMetadata(distribution_filename="Django-5.1-py3-none-any.whl")
        _apply_metadata_to_cyclonedx_component(component, metadata)
        props = [(p.name, p.value) for p in component.properties]
        # Only one of each; the operator's values survive
        assert ("bsi:component:archive", "no archive") in props
        assert ("bsi:component:executable", "executable") in props
        assert ("bsi:component:archive", "archive") not in props

    def test_bsi_unknown_filename_no_derivation(self):
        """When we cannot derive anything confidently we emit nothing."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_bsi_derived_properties

        component = Component(name="?", version="0", type=ComponentType.DEVICE)
        metadata = NormalizedMetadata()
        added = _apply_bsi_derived_properties(component, metadata)
        assert added == []

    def test_bsi_plain_library_no_filename_skipped(self):
        """A plain library with no filename has no unambiguous signal and
        must not get made-up values."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_bsi_derived_properties

        component = Component(name="foo", version="1.0", type=ComponentType.LIBRARY)
        added = _apply_bsi_derived_properties(component, NormalizedMetadata())
        assert added == []

    @pytest.mark.parametrize(
        "filename,expected_archive,expected_exec",
        [
            ("foo-1.0.tar.gz", "archive", "non-executable"),
            ("foo-1.0.tgz", "archive", "non-executable"),
            ("foo-1.0.tar.bz2", "archive", "non-executable"),
            ("foo-1.0.tar.xz", "archive", "non-executable"),
            ("foo-1.0.zip", "archive", "non-executable"),
            ("foo.jar", "archive", "non-executable"),
            ("foo.war", "archive", "non-executable"),
            ("foo.deb", "archive", "non-executable"),
            ("foo.rpm", "archive", "non-executable"),
            ("foo.gem", "archive", "non-executable"),
            ("foo.crate", "archive", "non-executable"),
            ("myapp.exe", "no archive", "executable"),
            ("runner.bin", "no archive", "executable"),
            ("libfoo.so", "no archive", "executable"),
            ("libfoo.dylib", "no archive", "executable"),
            ("plugin.dll", "no archive", "executable"),
        ],
    )
    def test_bsi_filename_extensions_derive_correctly(self, filename, expected_archive, expected_exec):
        """Each recognised archive / executable filename extension maps to
        the expected BSI boolean-style property values."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="anything", version="0", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(distribution_filename=filename)
        _apply_metadata_to_cyclonedx_component(component, metadata)
        props = {p.name: p.value for p in component.properties}
        assert props.get("bsi:component:archive") == expected_archive, filename
        assert props.get("bsi:component:executable") == expected_exec, filename
        assert props.get("bsi:component:structured") == "structured", filename

    @pytest.mark.parametrize(
        "type_,expected_archive,expected_exec",
        [
            (ComponentType.APPLICATION, "no archive", "executable"),
            (ComponentType.CONTAINER, "archive", "executable"),
            (ComponentType.FIRMWARE, "archive", "executable"),
            (ComponentType.OPERATING_SYSTEM, "no archive", "executable"),
        ],
    )
    def test_bsi_type_only_derivation(self, type_, expected_archive, expected_exec):
        """Strongly-typed components with no filename derive boolean-style
        properties from the component type alone."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="x", version="1.0", type=type_)
        _apply_metadata_to_cyclonedx_component(component, NormalizedMetadata())
        props = {p.name: p.value for p in component.properties}
        assert props.get("bsi:component:archive") == expected_archive, type_
        assert props.get("bsi:component:executable") == expected_exec, type_
        assert props.get("bsi:component:structured") == "structured"

    def test_bsi_case_insensitive_filename_extension(self):
        """Uppercase filename extensions match the same way as lowercase."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="x", version="1.0", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(distribution_filename="FOO-1.0.WHL")
        _apply_metadata_to_cyclonedx_component(component, metadata)
        props = {p.name: p.value for p in component.properties}
        assert props["bsi:component:archive"] == "archive"

    # --- P1 #3: per-component hashes ---------------------------------------------

    def test_component_hashes_applied_from_pypi_digests(self):
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(
            distribution_filename="Django-5.1-py3-none-any.whl",
            hashes={
                "md5": "d" * 32,
                "sha256": "a" * 64,
                "blake2b-256": "b" * 64,
            },
        )
        _apply_metadata_to_cyclonedx_component(component, metadata)
        alg_names = {str(h.alg) for h in component.hashes}
        assert any("SHA_256" in n for n in alg_names)
        assert any("MD5" in n for n in alg_names)
        assert any("BLAKE2B_256" in n for n in alg_names)

    def test_component_hashes_not_duplicated(self):
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(hashes={"sha256": "a" * 64})
        _apply_metadata_to_cyclonedx_component(component, metadata)
        _apply_metadata_to_cyclonedx_component(component, metadata)
        hashes = list(component.hashes)
        assert len(hashes) == 1
        assert str(hashes[0].content) == "a" * 64

    def test_component_hashes_unknown_algorithm_ignored(self):
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(hashes={"rot13": "a" * 32})
        _apply_metadata_to_cyclonedx_component(component, metadata)
        assert len(list(component.hashes)) == 0

    def test_spdx_checksums_applied(self):
        from spdx_tools.spdx.model import Package, SpdxNoAssertion

        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_spdx_package

        package = Package(
            name="django",
            spdx_id="SPDXRef-Package-django",
            download_location=SpdxNoAssertion(),
        )
        metadata = NormalizedMetadata(hashes={"sha256": "a" * 64, "md5": "d" * 32})
        _apply_metadata_to_spdx_package(package, metadata)
        assert len(package.checksums) == 2
        algs = {c.algorithm.name for c in package.checksums}
        assert "SHA256" in algs
        assert "MD5" in algs

    @pytest.mark.parametrize(
        "alg_key,cdx_suffix,hex_len",
        [
            ("md5", "MD5", 32),
            ("sha1", "SHA_1", 40),
            ("sha-1", "SHA_1", 40),
            ("sha256", "SHA_256", 64),
            ("sha-256", "SHA_256", 64),
            ("sha384", "SHA_384", 96),
            ("sha-384", "SHA_384", 96),
            ("sha512", "SHA_512", 128),
            ("sha-512", "SHA_512", 128),
            ("sha3-256", "SHA3_256", 64),
            ("sha3-384", "SHA3_384", 96),
            ("sha3-512", "SHA3_512", 128),
            ("blake2b-256", "BLAKE2B_256", 64),
            ("blake2b-384", "BLAKE2B_384", 96),
            ("blake2b-512", "BLAKE2B_512", 128),
            ("blake3", "BLAKE3", 64),  # no fixed length enforced, 64 is the common default
        ],
    )
    def test_cyclonedx_every_mapped_hash_algorithm_emits(self, alg_key, cdx_suffix, hex_len):
        """Every key in _CYCLONEDX_HASH_ALGORITHMS produces the expected enum,
        and hex-length validation accepts the correct length for each algorithm."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="x", version="1", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(hashes={alg_key: "a" * hex_len})
        _apply_metadata_to_cyclonedx_component(component, metadata)
        hashes = list(component.hashes)
        assert len(hashes) == 1, f"no hash emitted for {alg_key!r}"
        assert str(hashes[0].alg).endswith(cdx_suffix), (
            f"{alg_key!r} mapped to {hashes[0].alg!r}, expected suffix {cdx_suffix}"
        )

    @pytest.mark.parametrize(
        "alg_key,spdx_name,hex_len",
        [
            ("md5", "MD5", 32),
            ("sha1", "SHA1", 40),
            ("sha-1", "SHA1", 40),
            ("sha224", "SHA224", 56),
            ("sha-224", "SHA224", 56),
            ("sha256", "SHA256", 64),
            ("sha-256", "SHA256", 64),
            ("sha384", "SHA384", 96),
            ("sha-384", "SHA384", 96),
            ("sha512", "SHA512", 128),
            ("sha-512", "SHA512", 128),
            ("sha3-256", "SHA3_256", 64),
            ("sha3-384", "SHA3_384", 96),
            ("sha3-512", "SHA3_512", 128),
            ("blake2b-256", "BLAKE2B_256", 64),
            ("blake2b-384", "BLAKE2B_384", 96),
            ("blake2b-512", "BLAKE2B_512", 128),
            ("blake3", "BLAKE3", 64),
        ],
    )
    def test_spdx_every_mapped_hash_algorithm_emits(self, alg_key, spdx_name, hex_len):
        """Every key in _SPDX_CHECKSUM_ALGORITHMS maps to its enum value,
        including the SPDX-only SHA-224 entry that the CDX enum lacks."""
        from spdx_tools.spdx.model import Package, SpdxNoAssertion

        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_spdx_package

        package = Package(name="x", spdx_id="SPDXRef-x", download_location=SpdxNoAssertion())
        metadata = NormalizedMetadata(hashes={alg_key: "a" * hex_len})
        _apply_metadata_to_spdx_package(package, metadata)
        assert len(package.checksums) == 1
        assert package.checksums[0].algorithm.name == spdx_name

    def test_cyclonedx_hash_wrong_length_rejected(self):
        """A SHA-256 hex-value of the wrong length is rejected rather than
        written into the SBOM. Defence against malformed sources."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="x", version="1", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(hashes={"sha256": "a" * 40})  # SHA-1 length, wrong
        _apply_metadata_to_cyclonedx_component(component, metadata)
        assert len(list(component.hashes)) == 0

    def test_cyclonedx_hash_non_hex_characters_rejected(self):
        """Non-hex characters in the hash content are rejected."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="x", version="1", type=ComponentType.LIBRARY)
        # Script-injection attempt that happens to be 64 chars
        payload = "<script>alert(1)</script>abcdef" + "0" * 34
        metadata = NormalizedMetadata(hashes={"sha256": payload})
        _apply_metadata_to_cyclonedx_component(component, metadata)
        assert len(list(component.hashes)) == 0

    def test_spdx_hash_wrong_length_rejected(self):
        """SPDX parity: a SHA-256 value of the wrong length is rejected
        rather than written into the package checksums."""
        from spdx_tools.spdx.model import Package, SpdxNoAssertion

        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_spdx_package

        package = Package(name="x", spdx_id="SPDXRef-x", download_location=SpdxNoAssertion())
        metadata = NormalizedMetadata(hashes={"sha256": "a" * 40})  # wrong length
        _apply_metadata_to_spdx_package(package, metadata)
        assert len(package.checksums) == 0

    def test_spdx_hash_non_hex_characters_rejected(self):
        """SPDX parity: non-hex content rejected symmetrically with the CDX path.

        Payload is exactly 64 characters (valid SHA-256 length) but every
        character is outside ``[0-9a-f]`` so it isolates the regex branch —
        a bug that dropped the length check would still fail this test.
        """
        from spdx_tools.spdx.model import Package, SpdxNoAssertion

        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_spdx_package

        package = Package(name="x", spdx_id="SPDXRef-x", download_location=SpdxNoAssertion())
        payload = "g" * 64  # length-valid but never hex
        metadata = NormalizedMetadata(hashes={"sha256": payload})
        _apply_metadata_to_spdx_package(package, metadata)
        assert len(package.checksums) == 0

    def test_spdx_checksums_not_duplicated(self):
        """Repeated enrichment runs don't duplicate the same checksum entry."""
        from spdx_tools.spdx.model import Package, SpdxNoAssertion

        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_spdx_package

        package = Package(name="django", spdx_id="SPDXRef-Package-django", download_location=SpdxNoAssertion())
        metadata = NormalizedMetadata(hashes={"sha256": "a" * 64})
        _apply_metadata_to_spdx_package(package, metadata)
        _apply_metadata_to_spdx_package(package, metadata)
        assert len(package.checksums) == 1

    def test_spdx_checksums_unknown_algorithm_ignored(self):
        """Unknown SPDX algorithm names are silently skipped."""
        from spdx_tools.spdx.model import Package, SpdxNoAssertion

        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_spdx_package

        package = Package(name="x", spdx_id="SPDXRef-x", download_location=SpdxNoAssertion())
        metadata = NormalizedMetadata(hashes={"rot13": "abc", "sha256": "a" * 64})
        _apply_metadata_to_spdx_package(package, metadata)
        algs = {c.algorithm.name for c in package.checksums}
        assert algs == {"SHA256"}

    def test_cyclonedx_sha512_hash_emitted(self):
        """SHA-512 (BSI TR-03183-2's preferred hash) makes it through."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="x", version="1", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(hashes={"sha512": "f" * 128})
        _apply_metadata_to_cyclonedx_component(component, metadata)
        hashes = list(component.hashes)
        assert len(hashes) == 1
        assert str(hashes[0].alg).endswith("SHA_512")
        assert str(hashes[0].content) == "f" * 128

    def test_cyclonedx_hash_whitespace_trimmed_and_lowercased(self):
        """Algorithm keys and hex content are normalised."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="x", version="1", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(hashes={"SHA256": "  " + "a" * 64 + "  "})
        _apply_metadata_to_cyclonedx_component(component, metadata)
        hashes = list(component.hashes)
        assert len(hashes) == 1
        # Content written is stripped + lowercased (we stored as-lower already)
        assert str(hashes[0].content) == "a" * 64

    def test_cyclonedx_empty_hash_value_rejected(self):
        """Empty / whitespace-only hex values don't produce Hash objects."""
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="x", version="1", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(hashes={"sha256": "   "})
        _apply_metadata_to_cyclonedx_component(component, metadata)
        assert len(list(component.hashes)) == 0

    # --- P2 #6: enriched licences marked as BSI "original/declared" --------------

    def test_enriched_license_marked_declared(self):
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _apply_metadata_to_cyclonedx_component

        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)
        metadata = NormalizedMetadata(licenses=["BSD-3-Clause"])
        _apply_metadata_to_cyclonedx_component(component, metadata)
        licences = list(component.licenses)
        assert len(licences) == 1
        # CycloneDX LicenseExpression exposes the enum via .acknowledgement
        ack = getattr(licences[0], "acknowledgement", None)
        assert ack is not None
        assert str(ack.value) == "declared"


class TestNormalizedMetadataDistributionFilename:
    """Tests for distribution_filename in NormalizedMetadata."""

    def test_has_data_with_distribution_filename(self):
        from sbomify_action._enrichment.metadata import NormalizedMetadata

        meta = NormalizedMetadata(distribution_filename="pkg-1.0.whl")
        assert meta.has_data() is True

    def test_has_data_with_maintainer_email(self):
        from sbomify_action._enrichment.metadata import NormalizedMetadata

        meta = NormalizedMetadata(maintainer_email="dev@example.com")
        assert meta.has_data() is True

    def test_merge_preserves_distribution_filename(self):
        from sbomify_action._enrichment.metadata import NormalizedMetadata

        a = NormalizedMetadata(distribution_filename="a.whl", source="src-a")
        b = NormalizedMetadata(distribution_filename="b.whl", source="src-b")
        merged = a.merge(b)
        assert merged.distribution_filename == "a.whl"  # first takes precedence
