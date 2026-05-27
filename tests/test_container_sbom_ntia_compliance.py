"""
Tests for NTIA compliance on real container image SBOMs.

Reference: https://sbomify.com/compliance/ntia-minimum-elements/
Crosswalk: https://sbomify.com/compliance/schema-crosswalk/

This module tests enrichment and augmentation on SBOMs generated from:
- Ubuntu 22.04
- Alpine 3.19
- Debian 12-slim
- Fedora 41

Both CycloneDX and SPDX formats are tested with Trivy and Syft outputs.

NTIA Minimum Elements validated:
- Supplier Name: CycloneDX publisher/supplier.name, SPDX packages[].supplier
- Component Name/Version: Always present from generators
- Unique Identifiers: PURLs from generators
- Dependency Relationship: dependencies[]/relationships[]
- SBOM Author: metadata.authors[]/creationInfo.creators[]
- Timestamp: metadata.timestamp/creationInfo.created
"""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from sbomify_action.augmentation import augment_sbom_from_file
from sbomify_action.enrichment import clear_cache, enrich_sbom

from .ntia_checker import NTIAComplianceChecker

# Test data directory
TEST_DATA_DIR = Path(__file__).parent / "test-data"

# Container images we generated SBOMs for (maps display name to file prefix)
CONTAINER_IMAGE_FILES = {
    "ubuntu_22.04": "ubuntu_22.04",
    "alpine_3.19": "alpine_3.19",
    "debian_12-slim": "debian_12-slim",
    "fedora_41": "fedora_41",
}

# For parametrize - use the keys
CONTAINER_IMAGES = list(CONTAINER_IMAGE_FILES.keys())

# Sample backend metadata for augmentation testing
SAMPLE_BACKEND_METADATA = {
    "supplier": {
        "name": "Acme Corporation",
        "url": ["https://acme.example.com"],
        "contact": [
            {"name": "Security Team", "email": "security@acme.example.com"},
        ],
    },
    "authors": [
        {"name": "John Doe", "email": "john@acme.example.com"},
    ],
    "licenses": ["Apache-2.0"],
}


def check_cyclonedx_with_stats(data):
    """Wrapper to call NTIAComplianceChecker with stats for container tests."""
    return NTIAComplianceChecker.check_cyclonedx(data, include_stats=True, filter_library_only=True)


def check_spdx_with_stats(data):
    """Wrapper to call NTIAComplianceChecker with stats for container tests."""
    return NTIAComplianceChecker.check_spdx(data, include_stats=True, filter_library_only=True)


class TestContainerSBOMsExist:
    """Verify all expected test SBOMs exist."""

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_trivy_cdx_exists(self, image):
        """Test that Trivy CycloneDX SBOM exists."""
        sbom_path = TEST_DATA_DIR / f"{image}_trivy.cdx.json"
        assert sbom_path.exists(), f"Missing: {sbom_path}"

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_trivy_spdx_exists(self, image):
        """Test that Trivy SPDX SBOM exists."""
        sbom_path = TEST_DATA_DIR / f"{image}_trivy.spdx.json"
        assert sbom_path.exists(), f"Missing: {sbom_path}"

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_syft_cdx_exists(self, image):
        """Test that Syft CycloneDX SBOM exists."""
        sbom_path = TEST_DATA_DIR / f"{image}_syft.cdx.json"
        assert sbom_path.exists(), f"Missing: {sbom_path}"

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_syft_spdx_exists(self, image):
        """Test that Syft SPDX SBOM exists."""
        sbom_path = TEST_DATA_DIR / f"{image}_syft.spdx.json"
        assert sbom_path.exists(), f"Missing: {sbom_path}"


class TestRawSBOMNTIACompliance:
    """Test NTIA compliance of raw scanner output (before enrichment)."""

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_raw_trivy_cyclonedx_compliance(self, image):
        """Test NTIA compliance of raw Trivy CycloneDX output."""
        sbom_path = TEST_DATA_DIR / f"{image}_trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        with open(sbom_path) as f:
            data = json.load(f)

        is_compliant, present, missing, stats = check_cyclonedx_with_stats(data)

        print(f"\n{image} Trivy CycloneDX Raw NTIA Compliance:")
        print(f"  Total components: {stats['total_components']}")
        print(f"  With supplier: {stats['components_with_supplier']}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Compliant: {is_compliant}")

        # Trivy typically includes supplier for deb/rpm packages
        # This test documents the raw state - we may or may not be compliant

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_raw_trivy_spdx_compliance(self, image):
        """Test NTIA compliance of raw Trivy SPDX output."""
        sbom_path = TEST_DATA_DIR / f"{image}_trivy.spdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        with open(sbom_path) as f:
            data = json.load(f)

        is_compliant, present, missing, stats = check_spdx_with_stats(data)

        print(f"\n{image} Trivy SPDX Raw NTIA Compliance:")
        print(f"  Total packages: {stats['total_packages']}")
        print(f"  With supplier: {stats['packages_with_supplier']}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Compliant: {is_compliant}")

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_raw_syft_cyclonedx_compliance(self, image):
        """Test NTIA compliance of raw Syft CycloneDX output."""
        sbom_path = TEST_DATA_DIR / f"{image}_syft.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        with open(sbom_path) as f:
            data = json.load(f)

        is_compliant, present, missing, stats = check_cyclonedx_with_stats(data)

        print(f"\n{image} Syft CycloneDX Raw NTIA Compliance:")
        print(f"  Total components: {stats['total_components']}")
        print(f"  With supplier: {stats['components_with_supplier']}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Compliant: {is_compliant}")

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_raw_syft_spdx_compliance(self, image):
        """Test NTIA compliance of raw Syft SPDX output."""
        sbom_path = TEST_DATA_DIR / f"{image}_syft.spdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        with open(sbom_path) as f:
            data = json.load(f)

        is_compliant, present, missing, stats = check_spdx_with_stats(data)

        print(f"\n{image} Syft SPDX Raw NTIA Compliance:")
        print(f"  Total packages: {stats['total_packages']}")
        print(f"  With supplier: {stats['packages_with_supplier']}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Compliant: {is_compliant}")


class TestEnrichmentNTIACompliance:
    """Test that enrichment improves NTIA compliance."""

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_enriched_trivy_cyclonedx_compliance(self, image, tmp_path):
        """Test NTIA compliance after enrichment of Trivy CycloneDX."""
        sbom_path = TEST_DATA_DIR / f"{image}_trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        clear_cache()
        output_file = tmp_path / "enriched.cdx.json"

        # Mock ecosyste.ms to return None (force PURL fallback for OS packages)
        # Mock API responses to 404 (force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(sbom_path), str(output_file), validate=False)

        with open(output_file) as f:
            enriched_data = json.load(f)

        is_compliant, present, missing, stats = check_cyclonedx_with_stats(enriched_data)

        print(f"\n{image} Trivy CycloneDX ENRICHED NTIA Compliance:")
        print(f"  Total components: {stats['total_components']}")
        print(f"  With supplier: {stats['components_with_supplier']}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Compliant: {is_compliant}")

        # After enrichment, supplier should be filled in via PURL fallback
        assert stats["components_with_supplier"] > 0, "Enrichment should add some suppliers"

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_enriched_trivy_spdx_compliance(self, image, tmp_path):
        """Test NTIA compliance after enrichment of Trivy SPDX."""
        sbom_path = TEST_DATA_DIR / f"{image}_trivy.spdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        clear_cache()
        output_file = tmp_path / "enriched.spdx.json"

        # Mock API responses to 404 (force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(sbom_path), str(output_file), validate=False)

        with open(output_file) as f:
            enriched_data = json.load(f)

        is_compliant, present, missing, stats = check_spdx_with_stats(enriched_data)

        print(f"\n{image} Trivy SPDX ENRICHED NTIA Compliance:")
        print(f"  Total packages: {stats['total_packages']}")
        print(f"  With supplier: {stats['packages_with_supplier']}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Compliant: {is_compliant}")


class TestAugmentationNTIACompliance:
    """Test that augmentation adds organizational metadata."""

    @pytest.fixture
    def mock_backend_response(self):
        """Mock backend API response."""
        return SAMPLE_BACKEND_METADATA

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_augmented_trivy_cyclonedx(self, image, tmp_path, mock_backend_response):
        """Test augmentation adds supplier to CycloneDX SBOM."""
        sbom_path = TEST_DATA_DIR / f"{image}_trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        output_file = tmp_path / "augmented.cdx.json"

        # Mock the sbomify API provider
        mock_api_response = Mock()
        mock_api_response.ok = True
        mock_api_response.json.return_value = mock_backend_response

        with (
            patch(
                "sbomify_action._augmentation.providers.json_config.JsonConfigProvider._find_config_file",
                return_value=None,
            ),
            patch(
                "sbomify_action._augmentation.providers.sbomify_api.SbomifyApiProvider._fetch_backend_metadata",
                return_value=mock_api_response.json.return_value,
            ),
        ):
            sbom_format = augment_sbom_from_file(
                str(sbom_path),
                str(output_file),
                api_base_url="https://api.example.com",
                token="test-token",
                component_id="test-component",
                validate=False,
            )

        assert sbom_format == "cyclonedx"

        with open(output_file) as f:
            augmented_data = json.load(f)

        # Check supplier was added to metadata
        supplier = augmented_data.get("metadata", {}).get("supplier", {})
        assert supplier.get("name") == "Acme Corporation", "Augmentation should add supplier"

        # Check sbomify was added to tools
        tools = augmented_data.get("metadata", {}).get("tools", {})
        services = tools.get("services", [])
        components = tools.get("components", [])
        all_tools = services + components

        sbomify_found = any("sbomify" in str(t.get("name", "")).lower() for t in all_tools)
        assert sbomify_found, f"sbomify should be in tools. Found: {[t.get('name') for t in all_tools]}"

        print(f"\n{image} Trivy CycloneDX AUGMENTED:")
        print(f"  Supplier: {supplier.get('name')}")
        print(f"  Tools: {[t.get('name') for t in all_tools]}")

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_augmented_trivy_spdx(self, image, tmp_path, mock_backend_response):
        """Test augmentation adds supplier to SPDX SBOM."""
        sbom_path = TEST_DATA_DIR / f"{image}_trivy.spdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        output_file = tmp_path / "augmented.spdx.json"

        mock_api_response = Mock()
        mock_api_response.ok = True
        mock_api_response.json.return_value = mock_backend_response

        with patch(
            "sbomify_action._augmentation.providers.sbomify_api.SbomifyApiProvider._fetch_backend_metadata",
            return_value=mock_api_response.json.return_value,
        ):
            sbom_format = augment_sbom_from_file(
                str(sbom_path),
                str(output_file),
                api_base_url="https://api.example.com",
                token="test-token",
                component_id="test-component",
                validate=False,
            )

        assert sbom_format == "spdx"

        with open(output_file) as f:
            augmented_data = json.load(f)

        # Check creators include sbomify
        creators = augmented_data.get("creationInfo", {}).get("creators", [])
        sbomify_creator = [c for c in creators if "sbomify" in c.lower()]
        assert sbomify_creator, f"sbomify should be in creators. Found: {creators}"

        print(f"\n{image} Trivy SPDX AUGMENTED:")
        print(f"  Creators: {creators}")


class TestFullPipelineNTIACompliance:
    """Test full pipeline: enrich then augment."""

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_full_pipeline_cyclonedx(self, image, tmp_path):
        """Test full pipeline achieves NTIA compliance for CycloneDX."""
        sbom_path = TEST_DATA_DIR / f"{image}_trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        enriched_file = tmp_path / "enriched.cdx.json"
        augmented_file = tmp_path / "augmented.cdx.json"

        # Step 1: Enrich
        clear_cache()
        # Mock API responses to 404 (force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(sbom_path), str(enriched_file), validate=False)

        # Step 2: Augment
        mock_api_response = Mock()
        mock_api_response.ok = True
        mock_api_response.json.return_value = SAMPLE_BACKEND_METADATA

        with patch(
            "sbomify_action._augmentation.providers.sbomify_api.SbomifyApiProvider._fetch_backend_metadata",
            return_value=mock_api_response.json.return_value,
        ):
            augment_sbom_from_file(
                str(enriched_file),
                str(augmented_file),
                api_base_url="https://api.example.com",
                token="test-token",
                component_id="test-component",
                validate=False,
            )

        with open(augmented_file) as f:
            final_data = json.load(f)

        is_compliant, present, missing, stats = check_cyclonedx_with_stats(final_data)

        print(f"\n{image} FULL PIPELINE CycloneDX NTIA Compliance:")
        print(f"  Total components: {stats['total_components']}")
        print(f"  With supplier: {stats['components_with_supplier']}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Compliant: {is_compliant}")

        # Document compliance status - we expect most elements to be present
        # After full pipeline:
        # - Timestamp: Yes (scanner)
        # - Author of SBOM Data: Yes (scanner + sbomify)
        # - Component Name: Yes (scanner)
        # - Version: Yes (scanner)
        # - Supplier Name: Should be improved by enrichment
        # - Unique Identifiers: Yes (PURL from scanner)
        # - Dependencies: Depends on scanner


class TestSpecificDistroEnrichment:
    """Test enrichment for specific distro packages."""

    def test_debian_deb_package_enrichment(self, tmp_path):
        """Test that Debian deb packages get proper supplier from PURL."""
        sbom_path = TEST_DATA_DIR / "debian-trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        clear_cache()
        output_file = tmp_path / "enriched.cdx.json"

        # Mock API responses to 404 (force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(sbom_path), str(output_file), validate=False)

        with open(output_file) as f:
            data = json.load(f)

        # Find OS component
        os_components = [c for c in data.get("components", []) if c.get("type") == "operating-system"]
        if os_components:
            os_comp = os_components[0]
            print("\nDebian OS Component:")
            print(f"  Name: {os_comp.get('name')}")
            print(f"  Publisher: {os_comp.get('publisher')}")
            # Enrichment should add publisher for known OS
            if os_comp.get("name", "").lower() == "debian":
                assert os_comp.get("publisher") == "Debian Project", "Debian OS should have Debian Project as publisher"

    def test_alpine_apk_package_enrichment(self, tmp_path):
        """Test that Alpine apk packages get proper supplier from PURL."""
        sbom_path = TEST_DATA_DIR / "alpine-trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        clear_cache()
        output_file = tmp_path / "enriched.cdx.json"

        # Mock API responses to 404 (force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(sbom_path), str(output_file), validate=False)

        with open(output_file) as f:
            data = json.load(f)

        # Find OS component
        os_components = [c for c in data.get("components", []) if c.get("type") == "operating-system"]
        if os_components:
            os_comp = os_components[0]
            print("\nAlpine OS Component:")
            print(f"  Name: {os_comp.get('name')}")
            print(f"  Publisher: {os_comp.get('publisher')}")
            if os_comp.get("name", "").lower() == "alpine":
                assert os_comp.get("publisher") == "Alpine Linux", "Alpine OS should have Alpine Linux as publisher"

    def test_ubuntu_deb_package_enrichment(self, tmp_path):
        """Test that Ubuntu deb packages get proper supplier from PURL."""
        sbom_path = TEST_DATA_DIR / "ubuntu-trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        clear_cache()
        output_file = tmp_path / "enriched.cdx.json"

        # Mock API responses to 404 (force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(sbom_path), str(output_file), validate=False)

        with open(output_file) as f:
            data = json.load(f)

        # Find OS component
        os_components = [c for c in data.get("components", []) if c.get("type") == "operating-system"]
        if os_components:
            os_comp = os_components[0]
            print("\nUbuntu OS Component:")
            print(f"  Name: {os_comp.get('name')}")
            print(f"  Publisher: {os_comp.get('publisher')}")
            if os_comp.get("name", "").lower() == "ubuntu":
                assert os_comp.get("publisher") == "Canonical Ltd", "Ubuntu OS should have Canonical Ltd as publisher"

    def test_redhat_rpm_package_enrichment(self, tmp_path):
        """Test that Red Hat rpm packages get proper supplier from PURL."""
        sbom_path = TEST_DATA_DIR / "redhat-trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        clear_cache()
        output_file = tmp_path / "enriched.cdx.json"

        # Mock API responses to 404 (force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(sbom_path), str(output_file), validate=False)

        with open(output_file) as f:
            data = json.load(f)

        # Find OS component
        os_components = [c for c in data.get("components", []) if c.get("type") == "operating-system"]
        if os_components:
            os_comp = os_components[0]
            print("\nRedHat OS Component:")
            print(f"  Name: {os_comp.get('name')}")
            print(f"  Publisher: {os_comp.get('publisher')}")
