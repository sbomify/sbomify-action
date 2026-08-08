"""
Tests for the lifecycle enrichment module.

Tests cover:
- DISTRO_LIFECYCLE data structure and helper functions
- PACKAGE_LIFECYCLE data structure and matching
- LifecycleSource DataSource implementation
- Version cycle extraction
- PURL matching for various package types
"""

from unittest.mock import Mock

import pytest
from packageurl import PackageURL

from sbomify_action._enrichment.lifecycle_data import (
    DISTRO_LIFECYCLE,
    PACKAGE_LIFECYCLE,
    extract_version_cycle,
    get_distro_lifecycle,
    get_package_lifecycle,
    get_package_lifecycle_entry,
)
from sbomify_action._enrichment.sources.lifecycle import (
    LifecycleSource,
    clear_cache,
)

# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def clear_lifecycle_cache():
    """Clear lifecycle cache before each test."""
    clear_cache()
    yield


@pytest.fixture
def mock_session():
    """Create a mock requests session."""
    return Mock()


# =============================================================================
# Test DISTRO_LIFECYCLE Data
# =============================================================================


class TestDistroLifecycleData:
    """Test DISTRO_LIFECYCLE data structure."""

    def test_distro_lifecycle_contains_expected_distros(self):
        """Test that all expected distros are in DISTRO_LIFECYCLE."""
        expected_distros = [
            "wolfi",
            "alpine",
            "rocky",
            "almalinux",
            "amazonlinux",
            "centos",
            "fedora",
            "ubuntu",
            "debian",
        ]
        for distro in expected_distros:
            assert distro in DISTRO_LIFECYCLE, f"Missing distro: {distro}"

    def test_alpine_versions_present(self):
        """Test Alpine versions are present."""
        alpine = DISTRO_LIFECYCLE["alpine"]
        expected_versions = ["3.13", "3.14", "3.15", "3.16", "3.17", "3.18", "3.19", "3.20", "3.21"]
        for version in expected_versions:
            assert version in alpine, f"Missing Alpine version: {version}"

    def test_ubuntu_versions_present(self):
        """Test Ubuntu versions are present."""
        ubuntu = DISTRO_LIFECYCLE["ubuntu"]
        expected_versions = ["20.04", "22.04", "24.04"]
        for version in expected_versions:
            assert version in ubuntu, f"Missing Ubuntu version: {version}"

    def test_distro_lifecycle_dates_format(self):
        """Test that lifecycle dates have correct format."""
        for distro_name, versions in DISTRO_LIFECYCLE.items():
            for version, dates in versions.items():
                # Check required keys exist
                assert "release_date" in dates or dates.get("release_date") is None
                assert "end_of_support" in dates or dates.get("end_of_support") is None
                assert "end_of_life" in dates or dates.get("end_of_life") is None

    def test_wolfi_rolling_release(self):
        """Test Wolfi rolling release has None dates."""
        wolfi = DISTRO_LIFECYCLE["wolfi"]["rolling"]
        assert wolfi["release_date"] is None
        assert wolfi["end_of_support"] is None
        assert wolfi["end_of_life"] is None

    def test_alpine_has_lifecycle_dates(self):
        """Test Alpine 3.20 has lifecycle dates."""
        alpine_320 = DISTRO_LIFECYCLE["alpine"]["3.20"]
        assert alpine_320["release_date"] == "2024-05-22"
        assert alpine_320["end_of_support"] == "2026-04-01"
        assert alpine_320["end_of_life"] == "2026-04-01"


class TestGetDistroLifecycle:
    """Test get_distro_lifecycle helper function."""

    def test_get_ubuntu_lifecycle(self):
        """Test getting Ubuntu 24.04 lifecycle."""
        lifecycle = get_distro_lifecycle("ubuntu", "24.04")
        assert lifecycle is not None
        assert lifecycle["release_date"] == "2024-04"
        assert lifecycle["end_of_support"] == "2029-05"
        assert lifecycle["end_of_life"] == "2034-04"

    def test_get_alpine_lifecycle(self):
        """Test getting Alpine 3.21 lifecycle."""
        lifecycle = get_distro_lifecycle("alpine", "3.21")
        assert lifecycle is not None
        assert lifecycle["release_date"] == "2024-12-05"

    def test_get_unknown_distro_returns_none(self):
        """Test that unknown distro returns None."""
        lifecycle = get_distro_lifecycle("unknown", "1.0")
        assert lifecycle is None

    def test_get_unknown_version_returns_none(self):
        """Test that unknown version returns None."""
        lifecycle = get_distro_lifecycle("ubuntu", "99.99")
        assert lifecycle is None

    def test_case_insensitive_distro(self):
        """Test that distro lookup is case-insensitive."""
        lifecycle = get_distro_lifecycle("UBUNTU", "24.04")
        assert lifecycle is not None

    def test_get_debian_lifecycle(self):
        """Test getting Debian 12 lifecycle."""
        lifecycle = get_distro_lifecycle("debian", "12")
        assert lifecycle is not None
        assert lifecycle["release_date"] == "2023-06-10"
        assert lifecycle["end_of_support"] == "2026-06-11"
        assert lifecycle["end_of_life"] == "2028-06-30"

    def test_get_debian_version_normalization(self):
        """Test Debian version normalization (12.12 -> 12)."""
        lifecycle = get_distro_lifecycle("debian", "12.12")
        assert lifecycle is not None
        assert lifecycle["end_of_life"] == "2028-06-30"

    def test_get_debian_11(self):
        """Test getting Debian 11 lifecycle."""
        lifecycle = get_distro_lifecycle("debian", "11")
        assert lifecycle is not None
        assert lifecycle["end_of_life"] == "2026-08-31"

    def test_get_debian_13(self):
        """Test getting Debian 13 (trixie) lifecycle."""
        lifecycle = get_distro_lifecycle("debian", "13")
        assert lifecycle is not None
        assert lifecycle["release_date"] == "2025-08-09"
        assert lifecycle["end_of_support"] == "2028-08-09"
        assert lifecycle["end_of_life"] == "2030-06-30"

    def test_get_almalinux_via_alma_name(self):
        """Test that 'alma' name maps to 'almalinux' lifecycle."""
        lifecycle = get_distro_lifecycle("alma", "9")
        assert lifecycle is not None
        assert lifecycle["end_of_life"] == "2032-05-31"

    def test_get_amazonlinux_via_amazon_name(self):
        """Test that 'amazon' name maps to 'amazonlinux' lifecycle."""
        lifecycle = get_distro_lifecycle("amazon", "2023")
        assert lifecycle is not None
        # AWS publishes two distinct phases: standard support to 2027-06-30,
        # then maintenance (security-only) to 2029-06-30.
        assert lifecycle["end_of_support"] == "2027-06-30"
        assert lifecycle["end_of_life"] == "2029-06-30"

    def test_get_amazonlinux_complex_version(self):
        """Test Amazon Linux with complex version string like '2023.10.20260105 (Amazon Linux)'."""
        lifecycle = get_distro_lifecycle("amazon", "2023.10.20260105 (Amazon Linux)")
        assert lifecycle is not None
        assert lifecycle["end_of_life"] == "2029-06-30"

    def test_get_almalinux_with_point_release(self):
        """Test AlmaLinux with point release version like '9.7'."""
        lifecycle = get_distro_lifecycle("alma", "9.7")
        assert lifecycle is not None
        assert lifecycle["end_of_life"] == "2032-05-31"


# =============================================================================
# Test PACKAGE_LIFECYCLE Data
# =============================================================================


class TestPackageLifecycleData:
    """Test PACKAGE_LIFECYCLE data structure."""

    def test_package_lifecycle_contains_expected_packages(self):
        """Test that all expected packages are in PACKAGE_LIFECYCLE."""
        expected_packages = ["python", "django", "rails", "laravel", "php", "golang", "rust", "react", "vue"]
        for pkg in expected_packages:
            assert pkg in PACKAGE_LIFECYCLE, f"Missing package: {pkg}"

    def test_python_has_expected_cycles(self):
        """Test Python has expected version cycles."""
        python = PACKAGE_LIFECYCLE["python"]
        cycles = python["cycles"]
        expected_cycles = ["2.7", "3.10", "3.11", "3.12", "3.13", "3.14"]
        for cycle in expected_cycles:
            assert cycle in cycles, f"Missing Python cycle: {cycle}"

    def test_python_312_lifecycle(self):
        """Test Python 3.12 lifecycle dates."""
        python_312 = PACKAGE_LIFECYCLE["python"]["cycles"]["3.12"]
        assert python_312["release_date"] == "2023-10-02"
        assert python_312["end_of_support"] == "2025-04-02"
        assert python_312["end_of_life"] == "2028-10-31"

    def test_django_has_purl_types(self):
        """Test Django is limited to pypi PURL type."""
        django = PACKAGE_LIFECYCLE["django"]
        assert django["purl_types"] == ["pypi"]

    def test_rails_has_gem_purl_type(self):
        """Test Rails is limited to gem PURL type."""
        rails = PACKAGE_LIFECYCLE["rails"]
        assert rails["purl_types"] == ["gem"]

    def test_laravel_has_composer_purl_type(self):
        """Test Laravel is limited to composer PURL type."""
        laravel = PACKAGE_LIFECYCLE["laravel"]
        assert laravel["purl_types"] == ["composer"]

    def test_react_has_npm_purl_type(self):
        """Test React is limited to npm PURL type."""
        react = PACKAGE_LIFECYCLE["react"]
        assert react["purl_types"] == ["npm"]

    def test_vue_has_npm_purl_type(self):
        """Test Vue is limited to npm PURL type."""
        vue = PACKAGE_LIFECYCLE["vue"]
        assert vue["purl_types"] == ["npm"]

    def test_php_matches_all_purl_types(self):
        """Test PHP matches all PURL types (None)."""
        php = PACKAGE_LIFECYCLE["php"]
        assert php["purl_types"] is None

    def test_php_has_expected_cycles(self):
        """Test PHP has expected version cycles."""
        php = PACKAGE_LIFECYCLE["php"]
        cycles = php["cycles"]
        expected_cycles = ["7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"]
        for cycle in expected_cycles:
            assert cycle in cycles, f"Missing PHP cycle: {cycle}"

    def test_php_84_lifecycle(self):
        """Test PHP 8.4 lifecycle dates."""
        php_84 = PACKAGE_LIFECYCLE["php"]["cycles"]["8.4"]
        assert php_84["release_date"] == "2024-11-21"
        assert php_84["end_of_support"] == "2026-12-31"
        assert php_84["end_of_life"] == "2028-12-31"

    def test_php_74_eol(self):
        """Test PHP 7.4 (unsupported) has only EOL date."""
        php_74 = PACKAGE_LIFECYCLE["php"]["cycles"]["7.4"]
        assert php_74["release_date"] == "2019-11-28"
        assert php_74["end_of_support"] is None  # Unsupported branches don't have EOS
        assert php_74["end_of_life"] == "2022-11-28"

    def test_golang_matches_all_purl_types(self):
        """Test Go matches all PURL types (None)."""
        golang = PACKAGE_LIFECYCLE["golang"]
        assert golang["purl_types"] is None

    def test_golang_has_expected_cycles(self):
        """Test Go has expected version cycles."""
        golang = PACKAGE_LIFECYCLE["golang"]
        cycles = golang["cycles"]
        expected_cycles = ["1.22", "1.23", "1.24", "1.25"]
        for cycle in expected_cycles:
            assert cycle in cycles, f"Missing Go cycle: {cycle}"

    def test_golang_123_lifecycle(self):
        """Test Go 1.23 lifecycle dates."""
        go_123 = PACKAGE_LIFECYCLE["golang"]["cycles"]["1.23"]
        assert go_123["release_date"] == "2024-08-13"
        assert go_123["end_of_support"] == "2025-08-12"
        assert go_123["end_of_life"] == "2025-08-12"

    def test_rust_matches_all_purl_types(self):
        """Test Rust matches all PURL types (None)."""
        rust = PACKAGE_LIFECYCLE["rust"]
        assert rust["purl_types"] is None

    def test_rust_has_expected_cycles(self):
        """Test Rust has expected version cycles."""
        rust = PACKAGE_LIFECYCLE["rust"]
        cycles = rust["cycles"]
        expected_cycles = ["1.90", "1.91", "1.92"]
        for cycle in expected_cycles:
            assert cycle in cycles, f"Missing Rust cycle: {cycle}"

    def test_rust_191_lifecycle(self):
        """Test Rust 1.91 lifecycle dates."""
        rust_191 = PACKAGE_LIFECYCLE["rust"]["cycles"]["1.91"]
        assert rust_191["release_date"] == "2025-10-30"
        assert rust_191["end_of_support"] == "2025-12-11"
        assert rust_191["end_of_life"] == "2025-12-11"

    def test_python_matches_all_purl_types(self):
        """Test Python matches all PURL types (None)."""
        python = PACKAGE_LIFECYCLE["python"]
        assert python["purl_types"] is None

    def test_python_name_patterns(self):
        """Test Python name patterns include expected variations."""
        python = PACKAGE_LIFECYCLE["python"]
        patterns = python["name_patterns"]
        assert "python" in patterns
        assert "python3" in patterns
        assert "python3.*" in patterns

    def test_react_no_eol_dates(self):
        """Test React versions have no fixed EOL dates."""
        react_19 = PACKAGE_LIFECYCLE["react"]["cycles"]["19"]
        assert react_19["end_of_support"] is None
        assert react_19["end_of_life"] is None
        assert react_19["release_date"] == "2024-12-05"

    def test_vue_2_eol(self):
        """Test Vue 2 has EOL date."""
        vue_2 = PACKAGE_LIFECYCLE["vue"]["cycles"]["2"]
        assert vue_2["end_of_life"] == "2023-12-31"

    def test_laravel_quarter_dates(self):
        """Test that quarter-precision dates survive when upstream publishes them.

        Laravel publishes "Q3 2027" for Laravel 13's bug-fix window but a firm
        date for its security window, so the two fields carry different
        precisions.
        """
        laravel_13 = PACKAGE_LIFECYCLE["laravel"]["cycles"]["13"]
        assert laravel_13["release_date"] == "2026-03-17"
        assert laravel_13["end_of_support"] == "2027-Q3"
        assert laravel_13["end_of_life"] == "2028-03-17"


# =============================================================================
# Test Version Cycle Extraction
# =============================================================================


class TestVersionCycleExtraction:
    """Test extract_version_cycle function."""

    def test_extract_major_minor_from_full_version(self):
        """Test extracting major.minor from 3.12.7."""
        cycle = extract_version_cycle("3.12.7")
        assert cycle == "3.12"

    def test_extract_major_minor_from_two_part_version(self):
        """Test extracting major.minor from 3.12."""
        cycle = extract_version_cycle("3.12")
        assert cycle == "3.12"

    def test_extract_major_only(self):
        """Test extracting major version only."""
        cycle = extract_version_cycle("19.0.1", version_extract="major")
        assert cycle == "19"

    def test_extract_from_v_prefix(self):
        """Test extracting from version with v prefix."""
        cycle = extract_version_cycle("v3.12.7")
        assert cycle == "3.12"

    def test_extract_from_single_number(self):
        """Test extracting from single number version."""
        cycle = extract_version_cycle("19", version_extract="major.minor")
        assert cycle == "19"

    def test_extract_handles_rc_suffix(self):
        """Test extracting handles -rc1 suffix."""
        cycle = extract_version_cycle("3.14.0-rc1")
        assert cycle == "3.14"

    def test_extract_empty_version(self):
        """Test extracting from empty string returns None."""
        cycle = extract_version_cycle("")
        assert cycle is None

    def test_extract_none_version(self):
        """Test extracting from None returns None."""
        cycle = extract_version_cycle(None)
        assert cycle is None


# =============================================================================
# Test Package Lifecycle Entry Lookup
# =============================================================================


class TestGetPackageLifecycleEntry:
    """Test get_package_lifecycle_entry function."""

    def test_find_python_entry(self):
        """Test finding Python lifecycle entry."""
        entry = get_package_lifecycle_entry("python")
        assert entry is not None
        assert "python" in entry.get("name_patterns", [])

    def test_find_python3_entry(self):
        """Test finding entry for python3."""
        entry = get_package_lifecycle_entry("python3")
        assert entry is not None

    def test_find_python312_entry(self):
        """Test finding entry for python3.12 (glob pattern)."""
        entry = get_package_lifecycle_entry("python3.12")
        assert entry is not None

    def test_find_django_entry(self):
        """Test finding Django lifecycle entry."""
        entry = get_package_lifecycle_entry("django")
        assert entry is not None
        assert entry.get("purl_types") == ["pypi"]

    def test_find_rails_entry(self):
        """Test finding Rails lifecycle entry."""
        entry = get_package_lifecycle_entry("rails")
        assert entry is not None
        assert entry.get("purl_types") == ["gem"]

    def test_case_insensitive_lookup(self):
        """Test that lookup is case-insensitive."""
        entry = get_package_lifecycle_entry("Django")
        assert entry is not None

    def test_unknown_package_returns_none(self):
        """Test that unknown package returns None."""
        entry = get_package_lifecycle_entry("unknownpackage")
        assert entry is None


# =============================================================================
# Test Get Package Lifecycle
# =============================================================================


class TestGetPackageLifecycle:
    """Test get_package_lifecycle function."""

    def test_get_python_312_lifecycle(self):
        """Test getting Python 3.12 lifecycle."""
        lifecycle = get_package_lifecycle("python", "3.12.7")
        assert lifecycle is not None
        assert lifecycle["release_date"] == "2023-10-02"
        assert lifecycle["end_of_support"] == "2025-04-02"
        assert lifecycle["end_of_life"] == "2028-10-31"

    def test_get_django_42_lifecycle(self):
        """Test getting Django 4.2 lifecycle."""
        lifecycle = get_package_lifecycle("django", "4.2.9", purl_type="pypi")
        assert lifecycle is not None
        assert lifecycle["end_of_life"] == "2026-04-07"

    def test_django_wrong_purl_type_returns_none(self):
        """Test Django with wrong PURL type returns None."""
        lifecycle = get_package_lifecycle("django", "4.2.9", purl_type="npm")
        assert lifecycle is None

    def test_get_react_19_lifecycle(self):
        """Test getting React 19 lifecycle."""
        lifecycle = get_package_lifecycle("react", "19.0.1", purl_type="npm")
        assert lifecycle is not None
        assert lifecycle["release_date"] == "2024-12-05"
        assert lifecycle["end_of_support"] is None

    def test_get_laravel_major_version(self):
        """Test Laravel uses major version extraction."""
        lifecycle = get_package_lifecycle("laravel", "12.5.3", purl_type="composer")
        assert lifecycle is not None
        assert lifecycle["release_date"] == "2025-02-24"

    def test_unknown_cycle_returns_none(self):
        """Test unknown cycle returns None."""
        lifecycle = get_package_lifecycle("python", "2.5.0")
        assert lifecycle is None

    def test_python_matches_any_purl_type(self):
        """Test Python matches any PURL type."""
        lifecycle_pypi = get_package_lifecycle("python3", "3.12.1", purl_type="pypi")
        lifecycle_deb = get_package_lifecycle("python3", "3.12.1", purl_type="deb")
        lifecycle_rpm = get_package_lifecycle("python3", "3.12.1", purl_type="rpm")

        assert lifecycle_pypi is not None
        assert lifecycle_deb is not None
        assert lifecycle_rpm is not None

    def test_get_php_84_lifecycle(self):
        """Test getting PHP 8.4 lifecycle."""
        lifecycle = get_package_lifecycle("php", "8.4.1")
        assert lifecycle is not None
        assert lifecycle["release_date"] == "2024-11-21"
        assert lifecycle["end_of_support"] == "2026-12-31"
        assert lifecycle["end_of_life"] == "2028-12-31"

    def test_php_matches_any_purl_type(self):
        """Test PHP matches any PURL type."""
        lifecycle_composer = get_package_lifecycle("php", "8.4.1", purl_type="composer")
        lifecycle_deb = get_package_lifecycle("php", "8.4.1", purl_type="deb")
        lifecycle_apk = get_package_lifecycle("php", "8.4.1", purl_type="apk")

        assert lifecycle_composer is not None
        assert lifecycle_deb is not None
        assert lifecycle_apk is not None

    def test_get_golang_123_lifecycle(self):
        """Test getting Go 1.23 lifecycle."""
        lifecycle = get_package_lifecycle("go", "1.23.4")
        assert lifecycle is not None
        assert lifecycle["release_date"] == "2024-08-13"
        assert lifecycle["end_of_support"] == "2025-08-12"
        assert lifecycle["end_of_life"] == "2025-08-12"

    def test_golang_matches_any_purl_type(self):
        """Test Go matches any PURL type."""
        lifecycle_golang = get_package_lifecycle("golang", "1.23.1", purl_type="golang")
        lifecycle_apk = get_package_lifecycle("go", "1.23.1", purl_type="apk")
        lifecycle_deb = get_package_lifecycle("go", "1.23.1", purl_type="deb")

        assert lifecycle_golang is not None
        assert lifecycle_apk is not None
        assert lifecycle_deb is not None

    def test_get_rust_191_lifecycle(self):
        """Test getting Rust 1.91 lifecycle."""
        lifecycle = get_package_lifecycle("rust", "1.91.0")
        assert lifecycle is not None
        assert lifecycle["release_date"] == "2025-10-30"
        assert lifecycle["end_of_support"] == "2025-12-11"
        assert lifecycle["end_of_life"] == "2025-12-11"

    def test_rust_matches_any_purl_type(self):
        """Test Rust matches any PURL type."""
        lifecycle_cargo = get_package_lifecycle("rust", "1.91.0", purl_type="cargo")
        lifecycle_deb = get_package_lifecycle("rustc", "1.91.0", purl_type="deb")
        lifecycle_apk = get_package_lifecycle("cargo", "1.91.0", purl_type="apk")

        assert lifecycle_cargo is not None
        assert lifecycle_deb is not None
        assert lifecycle_apk is not None


# =============================================================================
# Test LifecycleSource DataSource
# =============================================================================


class TestLifecycleSource:
    """Test LifecycleSource DataSource implementation."""

    def test_source_properties(self):
        """Test source name and priority."""
        source = LifecycleSource()
        assert source.name == "sbomify-lifecycle-db"
        assert source.priority == 5  # High priority for local data

    def test_supports_python_pypi(self):
        """Test that LifecycleSource supports Python from PyPI."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:pypi/python@3.12.1")
        assert source.supports(purl) is True

    def test_supports_python_deb(self):
        """Test that LifecycleSource supports Python from deb."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/python3@3.12.1")
        assert source.supports(purl) is True

    def test_supports_python_rpm(self):
        """Test that LifecycleSource supports Python from rpm."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:rpm/fedora/python3@3.12.1")
        assert source.supports(purl) is True

    def test_supports_python3_with_version_suffix(self):
        """Test that LifecycleSource supports python3.12 packages."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:apk/alpine/python3.12@3.12.1")
        assert source.supports(purl) is True

    def test_supports_django(self):
        """Test that LifecycleSource supports Django."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:pypi/django@4.2.9")
        assert source.supports(purl) is True

    def test_does_not_support_django_from_npm(self):
        """Test that LifecycleSource does not support Django from npm."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:npm/django@4.2.9")
        assert source.supports(purl) is False

    def test_supports_rails(self):
        """Test that LifecycleSource supports Rails."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:gem/rails@8.0.1")
        assert source.supports(purl) is True

    def test_supports_react(self):
        """Test that LifecycleSource supports React."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:npm/react@19.0.1")
        assert source.supports(purl) is True

    def test_supports_vue(self):
        """Test that LifecycleSource supports Vue."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:npm/vue@3.4.1")
        assert source.supports(purl) is True

    def test_supports_php(self):
        """Test that LifecycleSource supports PHP."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:apk/alpine/php@8.4.1")
        assert source.supports(purl) is True

    def test_supports_php_from_deb(self):
        """Test that LifecycleSource supports PHP from deb."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/php@8.3.6")
        assert source.supports(purl) is True

    def test_supports_golang(self):
        """Test that LifecycleSource supports Go."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:golang/golang@1.23.4")
        assert source.supports(purl) is True

    def test_supports_go_from_apk(self):
        """Test that LifecycleSource supports Go from apk."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:apk/alpine/go@1.23.4")
        assert source.supports(purl) is True

    def test_supports_rust(self):
        """Test that LifecycleSource supports Rust."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:cargo/rust@1.91.0")
        assert source.supports(purl) is True

    def test_supports_rustc_from_deb(self):
        """Test that LifecycleSource supports rustc from deb."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/debian/rustc@1.91.0")
        assert source.supports(purl) is True

    def test_supports_cargo(self):
        """Test that LifecycleSource supports cargo (Rust package manager)."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/cargo@1.91.0")
        assert source.supports(purl) is True

    def test_does_not_support_unknown_package(self):
        """Test that LifecycleSource does not support unknown packages."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:pypi/requests@2.31.0")
        assert source.supports(purl) is False

    def test_fetch_python_312(self, mock_session):
        """Test fetching Python 3.12 lifecycle."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:pypi/python@3.12.7")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_release_date == "2023-10-02"
        assert metadata.cle_eos == "2025-04-02"
        assert metadata.cle_eol == "2028-10-31"
        assert metadata.source == "sbomify-lifecycle-db"

    def test_fetch_django_42(self, mock_session):
        """Test fetching Django 4.2 lifecycle."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:pypi/django@4.2.9")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_eos == "2023-12-04"
        assert metadata.cle_eol == "2026-04-07"

    def test_fetch_react_19(self, mock_session):
        """Test fetching React 19 lifecycle (no EOL dates)."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:npm/react@19.0.0")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_release_date == "2024-12-05"
        # React doesn't have fixed EOL dates
        assert metadata.cle_eos is None
        assert metadata.cle_eol is None

    def test_fetch_unknown_version_returns_none(self, mock_session):
        """Test fetching unknown Python version returns None."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:pypi/python@2.5.0")

        metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_fetch_unknown_package_returns_none(self, mock_session):
        """Test fetching unknown package returns None."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:pypi/requests@2.31.0")

        metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_fetch_no_version_returns_none(self, mock_session):
        """Test fetching package without version returns None."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:pypi/python")

        metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_fetch_caches_results(self, mock_session):
        """Test that fetch results are cached."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:pypi/python@3.12.7")

        # First call
        metadata1 = source.fetch(purl, mock_session)
        # Second call (should be cached)
        metadata2 = source.fetch(purl, mock_session)

        assert metadata1 is not None
        assert metadata2 is not None
        # Both should reference the same cached object
        assert metadata1 is metadata2

    def test_fetch_field_sources_tracked(self, mock_session):
        """Test that field sources are properly tracked."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:pypi/django@4.2.9")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.field_sources.get("cle_eos") == "sbomify-lifecycle-db"
        assert metadata.field_sources.get("cle_eol") == "sbomify-lifecycle-db"

    def test_fetch_python_from_deb(self, mock_session):
        """Test fetching Python lifecycle from deb package."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/python3@3.12.3")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_eol == "2028-10-31"

    def test_fetch_laravel_major_version(self, mock_session):
        """Test fetching Laravel with major version extraction."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:composer/laravel/framework@12.1.0")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_release_date == "2025-02-24"

    def test_fetch_php_84(self, mock_session):
        """Test fetching PHP 8.4 lifecycle."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:apk/alpine/php@8.4.1")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_release_date == "2024-11-21"
        assert metadata.cle_eos == "2026-12-31"
        assert metadata.cle_eol == "2028-12-31"

    def test_fetch_php_from_deb(self, mock_session):
        """Test fetching PHP lifecycle from deb package."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/php@8.3.6")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_eol == "2027-12-31"

    def test_fetch_golang_123(self, mock_session):
        """Test fetching Go 1.23 lifecycle."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:golang/go@1.23.4")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_release_date == "2024-08-13"
        assert metadata.cle_eos == "2025-08-12"
        assert metadata.cle_eol == "2025-08-12"

    def test_fetch_golang_from_apk(self, mock_session):
        """Test fetching Go lifecycle from apk package."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:apk/alpine/go@1.24.1")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_release_date == "2025-02-11"
        # Go supports a release until two newer ones exist, so 1.24 ended when
        # 1.26 shipped.
        assert metadata.cle_eos == "2026-02-10"
        assert metadata.cle_eol == "2026-02-10"

    def test_fetch_golang_current_has_no_eol(self, mock_session):
        """A Go release that is still supported carries no EOS/EOL."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:apk/alpine/go@1.26.0")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_release_date == "2026-02-10"
        assert metadata.cle_eos is None
        assert metadata.cle_eol is None

    def test_fetch_rust_191(self, mock_session):
        """Test fetching Rust 1.91 lifecycle."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:cargo/rust@1.91.0")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_release_date == "2025-10-30"
        assert metadata.cle_eos == "2025-12-11"
        assert metadata.cle_eol == "2025-12-11"

    def test_fetch_rustc_from_deb(self, mock_session):
        """Test fetching Rust lifecycle from deb rustc package."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/debian/rustc@1.92.0")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_release_date == "2025-12-11"
        # Rust supports only the latest stable, so 1.92 ended when 1.93 shipped.
        assert metadata.cle_eos == "2026-01-22"
        assert metadata.cle_eol == "2026-01-22"

    def test_fetch_rust_current_has_no_eol(self, mock_session):
        """The current Rust stable carries no EOS/EOL."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:cargo/rust@1.97.0")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_release_date == "2026-07-09"
        assert metadata.cle_eos is None
        assert metadata.cle_eol is None


# =============================================================================
# Test Clear Cache
# =============================================================================


class TestClearCache:
    """Test cache clearing functionality."""

    def test_clear_cache_resets_state(self, mock_session):
        """Test that clear_cache resets the cache."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:pypi/python@3.12.7")

        # Populate cache
        source.fetch(purl, mock_session)

        # Clear cache
        clear_cache()

        # Fetch again - should work (not test for identity, just functionality)
        metadata = source.fetch(purl, mock_session)
        assert metadata is not None


# =============================================================================
# Test Integration with Enricher Registry
# =============================================================================


class TestLifecycleSourceRegistration:
    """Test that LifecycleSource is properly registered."""

    def test_lifecycle_source_in_default_registry(self):
        """Test LifecycleSource is registered in default registry."""
        from sbomify_action._enrichment.enricher import create_default_registry

        registry = create_default_registry()
        sources = registry.list_sources()
        source_names = [s["name"] for s in sources]

        assert "sbomify-lifecycle-db" in source_names

    def test_lifecycle_source_priority(self):
        """Test LifecycleSource has correct priority."""
        from sbomify_action._enrichment.enricher import create_default_registry

        registry = create_default_registry()
        sources = registry.list_sources()

        lifecycle_source = next((s for s in sources if s["name"] == "sbomify-lifecycle-db"), None)
        assert lifecycle_source is not None
        assert lifecycle_source["priority"] == 5


# =============================================================================
# Test Edge Cases
# =============================================================================


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_python27_eol(self, mock_session):
        """Test Python 2.7 EOL is correctly reported."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:pypi/python@2.7.18")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_eos == "2020-01-01"
        assert metadata.cle_eol == "2020-04-20"

    def test_vue2_eol(self, mock_session):
        """Test Vue 2 EOL is correctly reported."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:npm/vue@2.7.14")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_eol == "2023-12-31"

    def test_rails_70_eol(self, mock_session):
        """Test Rails 7.0 EOL is correctly reported."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:gem/rails@7.0.8")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_eol == "2025-10-29"

    def test_cpython_alias(self, mock_session):
        """Test cpython alias is matched."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:generic/cpython@3.12.1")

        # Should be supported due to name pattern
        assert source.supports(purl) is True

        metadata = source.fetch(purl, mock_session)
        assert metadata is not None

    def test_railties_alias(self, mock_session):
        """Test railties (Rails component) is matched."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:gem/railties@8.0.1")

        assert source.supports(purl) is True

        metadata = source.fetch(purl, mock_session)
        assert metadata is not None
        assert metadata.cle_eol == "2026-11-07"

    def test_php74_eol(self, mock_session):
        """Test PHP 7.4 EOL is correctly reported (unsupported branch)."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:apk/alpine/php@7.4.33")

        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.cle_release_date == "2019-11-28"
        assert metadata.cle_eos is None  # Unsupported branches don't publish EOS
        assert metadata.cle_eol == "2022-11-28"

    def test_php_cli_variant(self, mock_session):
        """Test php-cli variant is matched."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/debian/php-cli@8.3.6")

        assert source.supports(purl) is True

        metadata = source.fetch(purl, mock_session)
        assert metadata is not None
        assert metadata.cle_eol == "2027-12-31"

    def test_alpine_php83_variant(self, mock_session):
        """Test Alpine php83 package naming is matched."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:apk/alpine/php83@8.3.6")

        assert source.supports(purl) is True

        metadata = source.fetch(purl, mock_session)
        assert metadata is not None
        assert metadata.cle_eol == "2027-12-31"

    def test_libpython_stdlib(self, mock_session):
        """Test Debian libpython stdlib package is matched."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/debian/libpython3.12-stdlib@3.12.1")

        assert source.supports(purl) is True

        metadata = source.fetch(purl, mock_session)
        assert metadata is not None
        assert metadata.cle_eol == "2028-10-31"

    def test_golang_versioned_debian(self, mock_session):
        """Test Debian versioned golang package is matched."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/debian/golang-1.23-go@1.23.4")

        assert source.supports(purl) is True

        metadata = source.fetch(purl, mock_session)
        assert metadata is not None

    def test_libstd_rust_stdlib(self, mock_session):
        """Test Debian libstd-rust stdlib package is matched."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/debian/libstd-rust-1.91@1.91.0")

        assert source.supports(purl) is True

        metadata = source.fetch(purl, mock_session)
        assert metadata is not None

    def test_react_dom_alias(self, mock_session):
        """Test react-dom alias is matched."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:npm/react-dom@19.0.0")

        assert source.supports(purl) is True

        metadata = source.fetch(purl, mock_session)
        assert metadata is not None
        assert metadata.cle_release_date == "2024-12-05"

    def test_rails_activesupport_alias(self, mock_session):
        """Test Rails activesupport gem is matched."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:gem/activesupport@8.0.1")

        assert source.supports(purl) is True

        metadata = source.fetch(purl, mock_session)
        assert metadata is not None
        assert metadata.cle_eol == "2026-11-07"


# =============================================================================
# Test Non-Tracked Packages Return None
# =============================================================================


class TestNonTrackedPackages:
    """Test that non-tracked OS packages return None (no distro lifecycle fallback)."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock session for testing."""
        return Mock()

    def test_ubuntu_curl_not_supported(self, mock_session):
        """Test that curl on Ubuntu is not supported (we don't track curl)."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/curl@8.5.0-2ubuntu10.6")

        # curl is not tracked - we only track specific runtimes/frameworks
        assert source.supports(purl) is False

        metadata = source.fetch(purl, mock_session)
        assert metadata is None

    def test_alpine_nginx_not_supported(self, mock_session):
        """Test that nginx on Alpine is not supported (we don't track nginx)."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:apk/alpine/nginx@1.27.0-r0")

        assert source.supports(purl) is False

        metadata = source.fetch(purl, mock_session)
        assert metadata is None

    def test_rocky_openssl_not_supported(self, mock_session):
        """Test that openssl on Rocky is not supported (we don't track openssl)."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/openssl@3.0.7")

        assert source.supports(purl) is False

        metadata = source.fetch(purl, mock_session)
        assert metadata is None

    def test_python_on_ubuntu_is_supported(self, mock_session):
        """Test that Python on Ubuntu IS supported (we track Python)."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/python3@3.12.3-1")

        assert source.supports(purl) is True

        metadata = source.fetch(purl, mock_session)
        assert metadata is not None
        assert metadata.cle_eol == "2028-10-31"

    def test_php_on_debian_is_supported(self, mock_session):
        """Test that PHP on Debian IS supported (we track PHP)."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/debian/php@8.3.6")

        assert source.supports(purl) is True

        metadata = source.fetch(purl, mock_session)
        assert metadata is not None
        assert metadata.cle_eol == "2027-12-31"

    def test_unknown_package_returns_none(self, mock_session):
        """Test that unknown packages return None."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:deb/someunknowndistro/curl@8.0.0")

        assert source.supports(purl) is False

        metadata = source.fetch(purl, mock_session)
        assert metadata is None

    def test_wolfi_busybox_not_supported(self, mock_session):
        """Test that busybox on Wolfi is not supported (we don't track busybox)."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:apk/wolfi/busybox@1.36.1-r6")

        assert source.supports(purl) is False

        metadata = source.fetch(purl, mock_session)
        assert metadata is None

    def test_amazonlinux_awscli_not_supported(self, mock_session):
        """Test that aws-cli on Amazon Linux is not supported (we don't track aws-cli)."""
        source = LifecycleSource()
        purl = PackageURL.from_string("pkg:rpm/amzn/aws-cli@2.15.0")

        assert source.supports(purl) is False

        metadata = source.fetch(purl, mock_session)
        assert metadata is None
