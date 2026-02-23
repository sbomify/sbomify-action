"""
Tests for the new augmentation module with proper library usage.
"""

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from cyclonedx.model.bom import Bom
from spdx_tools.spdx.model import Actor, ActorType

from sbomify_action.augmentation import (
    augment_cyclonedx_sbom,
    augment_sbom_from_file,
    augment_spdx_sbom,
    fetch_augmentation_metadata,
)


class TestLicenseHandling:
    """Test handling of three license types from backend API."""

    @pytest.fixture
    def sample_backend_metadata_with_mixed_licenses(self):
        """Backend metadata with all three license types."""
        return {
            "supplier": {
                "name": "Test Corp",
                "url": ["https://test.com"],
                "contact": [{"name": "Test Contact", "email": "contact@test.com"}],
            },
            "authors": [{"name": "Test Author", "email": "author@test.com"}],
            "licenses": [
                "MIT",  # Type 1: Simple SPDX license string
                "Apache-2.0 OR GPL-3.0",  # Type 2: License expression string
                {  # Type 3: Custom license object
                    "name": "Custom Proprietary License",
                    "url": "https://test.com/license",
                    "text": "Custom license text here",
                },
            ],
        }

    @pytest.fixture
    def sample_cyclonedx_bom(self):
        """Sample CycloneDX BOM for testing."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:12345678-1234-5678-1234-567812345678",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0",
                },
            },
            "components": [],
        }
        return Bom.from_json(bom_json)

    def test_cyclonedx_augmentation_with_mixed_licenses(
        self, sample_cyclonedx_bom, sample_backend_metadata_with_mixed_licenses
    ):
        """Test that CycloneDX augmentation handles all three license types."""
        # Augment the BOM
        enriched_bom = augment_cyclonedx_sbom(
            bom=sample_cyclonedx_bom,
            augmentation_data=sample_backend_metadata_with_mixed_licenses,
            override_sbom_metadata=False,
        )

        # Verify licenses were combined into ONE expression (per CycloneDX spec)
        # When multiple licenses are present, they must be combined into a single LicenseExpression
        assert len(enriched_bom.metadata.licenses) == 1

        # Convert to JSON to verify structure using proper serialization
        from cyclonedx.model.license import LicenseExpression
        from cyclonedx.output.json import JsonV1Dot6

        outputter = JsonV1Dot6(enriched_bom)
        bom_json_str = outputter.output_as_string()
        bom_json = json.loads(bom_json_str)
        licenses = bom_json["metadata"]["licenses"]

        # Verify we have one license expression
        assert len(licenses) == 1
        assert "expression" in licenses[0]

        # The expression should combine all three licenses with OR (treating as alternatives)
        # This is correct for dual/multi-licensing: user can choose any of the offered licenses
        expression = licenses[0]["expression"]
        assert "MIT" in expression
        assert "Apache-2.0 OR GPL-3.0" in expression
        assert "Custom Proprietary License" in expression
        assert " OR " in expression

        # Verify the licenses are alternatives, not all required
        # Should be: "MIT OR Apache-2.0 OR GPL-3.0 OR Custom Proprietary License"
        # NOT: "MIT AND (Apache-2.0 OR GPL-3.0) AND Custom Proprietary License"

        # Verify it's a valid LicenseExpression object
        license_obj = list(enriched_bom.metadata.licenses)[0]
        assert isinstance(license_obj, LicenseExpression)

    def test_cyclonedx_supplier_augmentation(self, sample_cyclonedx_bom, sample_backend_metadata_with_mixed_licenses):
        """Test that supplier information is properly augmented."""
        enriched_bom = augment_cyclonedx_sbom(
            bom=sample_cyclonedx_bom,
            augmentation_data=sample_backend_metadata_with_mixed_licenses,
            override_sbom_metadata=False,
        )

        # Verify supplier
        assert enriched_bom.metadata.supplier is not None
        assert enriched_bom.metadata.supplier.name == "Test Corp"
        assert len(enriched_bom.metadata.supplier.urls) > 0
        assert len(enriched_bom.metadata.supplier.contacts) == 1

    def test_cyclonedx_authors_augmentation(self, sample_cyclonedx_bom, sample_backend_metadata_with_mixed_licenses):
        """Test that authors are properly augmented."""
        enriched_bom = augment_cyclonedx_sbom(
            bom=sample_cyclonedx_bom,
            augmentation_data=sample_backend_metadata_with_mixed_licenses,
            override_sbom_metadata=False,
        )

        # Verify authors
        assert len(enriched_bom.metadata.authors) == 1
        author = list(enriched_bom.metadata.authors)[0]
        assert author.name == "Test Author"
        assert author.email == "author@test.com"

    def test_component_overrides(self, sample_cyclonedx_bom, sample_backend_metadata_with_mixed_licenses):
        """Test that component name and version overrides work."""
        enriched_bom = augment_cyclonedx_sbom(
            bom=sample_cyclonedx_bom,
            augmentation_data=sample_backend_metadata_with_mixed_licenses,
            override_sbom_metadata=False,
            component_name="overridden-name",
            component_version="2.0.0",
        )

        # Verify overrides
        assert enriched_bom.metadata.component.name == "overridden-name"
        assert enriched_bom.metadata.component.version == "2.0.0"

    @patch("sbomify_action._augmentation.providers.json_config.JsonConfigProvider._find_config_file")
    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_fetch_augmentation_metadata(self, mock_get, mock_find_config, sample_backend_metadata_with_mixed_licenses):
        """Test fetching metadata from providers (sbomify API)."""
        # Disable json-config provider to isolate sbomify API test
        mock_find_config.return_value = None

        # Setup mock
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = sample_backend_metadata_with_mixed_licenses
        mock_get.return_value = mock_response

        # Fetch metadata
        result = fetch_augmentation_metadata(
            api_base_url="https://api.test.com",
            token="test-token",
            component_id="test-component-123",
        )

        # Verify API call
        mock_get.assert_called_once()
        assert result["supplier"] == sample_backend_metadata_with_mixed_licenses["supplier"]
        assert result["authors"] == sample_backend_metadata_with_mixed_licenses["authors"]

    @patch("sbomify_action._augmentation.providers.json_config.JsonConfigProvider._find_config_file")
    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_augment_sbom_from_file_cyclonedx(
        self, mock_get, mock_find_config, sample_cyclonedx_bom, sample_backend_metadata_with_mixed_licenses
    ):
        """Test augmenting SBOM from file (CycloneDX)."""
        # Disable json-config provider to isolate sbomify API test
        mock_find_config.return_value = None

        # Setup mock
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = sample_backend_metadata_with_mixed_licenses
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create input file
            input_file = Path(tmpdir) / "input.json"
            output_file = Path(tmpdir) / "output.json"

            from cyclonedx.output.json import JsonV1Dot6

            outputter = JsonV1Dot6(sample_cyclonedx_bom)
            with open(input_file, "w") as f:
                f.write(outputter.output_as_string())

            # Augment
            format_result = augment_sbom_from_file(
                input_file=str(input_file),
                output_file=str(output_file),
                api_base_url="https://api.test.com",
                token="test-token",
                component_id="test-component-123",
            )

            # Verify
            assert format_result == "cyclonedx"
            assert output_file.exists()

            # Load and verify output
            with open(output_file, "r") as f:
                output_data = json.load(f)

            assert output_data["bomFormat"] == "CycloneDX"
            assert "supplier" in output_data["metadata"]
            assert output_data["metadata"]["supplier"]["name"] == "Test Corp"


class TestVersionCompatibility:
    """Test compatibility with different SBOM versions."""

    @pytest.fixture
    def cyclonedx_15_bom(self):
        """CycloneDX 1.5 BOM."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app-15",
                    "version": "1.5.0",
                },
            },
            "components": [],
        }
        return Bom.from_json(bom_json)

    @pytest.fixture
    def cyclonedx_16_bom(self):
        """CycloneDX 1.6 BOM."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app-16",
                    "version": "1.6.0",
                },
            },
            "components": [],
        }
        return Bom.from_json(bom_json)

    def test_cyclonedx_15_augmentation(self, cyclonedx_15_bom):
        """Test augmentation works with CycloneDX 1.5."""
        backend_data = {
            "supplier": {"name": "Test Supplier 1.5"},
            "authors": [{"name": "Author 1.5"}],
            "licenses": ["MIT"],
        }

        enriched_bom = augment_cyclonedx_sbom(
            bom=cyclonedx_15_bom,
            augmentation_data=backend_data,
        )

        # Verify augmentation worked
        assert enriched_bom.metadata.supplier.name == "Test Supplier 1.5"

    def test_cyclonedx_16_augmentation(self, cyclonedx_16_bom):
        """Test augmentation works with CycloneDX 1.6."""
        backend_data = {
            "supplier": {"name": "Test Supplier 1.6"},
            "authors": [{"name": "Author 1.6"}],
            "licenses": ["Apache-2.0"],
        }

        enriched_bom = augment_cyclonedx_sbom(
            bom=cyclonedx_16_bom,
            augmentation_data=backend_data,
        )

        # Verify augmentation worked
        assert enriched_bom.metadata.supplier.name == "Test Supplier 1.6"


class TestSPDXAugmentation:
    """Test SPDX augmentation functionality."""

    @pytest.fixture
    def spdx_document(self):
        """Create a sample SPDX document."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            ActorType,
            CreationInfo,
            Document,
            Package,
        )

        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-doc",
            document_namespace="https://test.com/test-doc",
            creators=[Actor(ActorType.TOOL, "test-tool")],
            created=datetime(2024, 1, 1),
        )

        package = Package(
            spdx_id="SPDXRef-main", name="test-app", download_location="https://example.com", version="1.0.0"
        )

        return Document(creation_info=creation_info, packages=[package])

    def test_spdx_supplier_augmentation(self, spdx_document):
        """Test SPDX supplier augmentation."""
        backend_data = {
            "supplier": {
                "name": "SPDX Test Corp",
                "url": ["https://spdxtest.com"],
            },
            "authors": [],
            "licenses": [],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Verify supplier was added to creators
        org_creators = [c for c in enriched_doc.creation_info.creators if c.actor_type == ActorType.ORGANIZATION]
        assert len(org_creators) > 0
        assert any("SPDX Test Corp" in c.name for c in org_creators)

        # Verify packages have supplier
        assert enriched_doc.packages[0].supplier is not None
        assert "SPDX Test Corp" in enriched_doc.packages[0].supplier.name

    def test_spdx_authors_augmentation(self, spdx_document):
        """Test SPDX authors augmentation."""
        backend_data = {
            "supplier": {},
            "authors": [{"name": "SPDX Author", "email": "author@spdx.com"}],
            "licenses": [],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Verify author was added to creators
        person_creators = [c for c in enriched_doc.creation_info.creators if c.actor_type == ActorType.PERSON]
        assert len(person_creators) > 0
        assert any("SPDX Author" in c.name for c in person_creators)

        # Verify packages have originator
        assert enriched_doc.packages[0].originator is not None
        assert "SPDX Author" in enriched_doc.packages[0].originator.name

    def test_spdx_component_overrides(self, spdx_document):
        """Test SPDX component name and version overrides."""
        backend_data = {
            "supplier": {},
            "authors": [],
            # No licenses key to avoid the empty list issue
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
            component_name="overridden-spdx-name",
            component_version="2.0.0-spdx",
        )

        # Verify document name was overridden (SPDX stores name in creation_info)
        assert enriched_doc.creation_info.name == "overridden-spdx-name"

        # Verify package name and version were overridden
        assert enriched_doc.packages[0].name == "overridden-spdx-name"
        assert enriched_doc.packages[0].version == "2.0.0-spdx"

    @patch("sbomify_action._augmentation.providers.json_config.JsonConfigProvider._find_config_file")
    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_augment_sbom_from_file_spdx(self, mock_get, mock_find_config, spdx_document):
        """Test augmenting SPDX SBOM from file."""
        # Disable json-config provider to isolate sbomify API test
        mock_find_config.return_value = None

        backend_data = {
            "supplier": {"name": "SPDX Supplier"},
            "authors": [{"name": "SPDX Author"}],
            "licenses": ["MIT"],
        }

        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = backend_data
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

            input_file = Path(tmpdir) / "input_spdx.json"
            output_file = Path(tmpdir) / "output_spdx.json"

            # Write input
            spdx_write_file(spdx_document, str(input_file), validate=False)

            # Augment
            format_result = augment_sbom_from_file(
                input_file=str(input_file),
                output_file=str(output_file),
                api_base_url="https://api.test.com",
                token="test-token",
                component_id="test-component-spdx",
            )

            # Verify
            assert format_result == "spdx"
            assert output_file.exists()

            # Load and verify output
            from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file

            output_doc = spdx_parse_file(str(output_file))

            # Verify supplier was added
            org_creators = [c for c in output_doc.creation_info.creators if c.actor_type == ActorType.ORGANIZATION]
            assert any("SPDX Supplier" in c.name for c in org_creators)

    def test_spdx_homepage_preservation(self, spdx_document):
        """Test that existing homepage is preserved."""
        # Set existing homepage
        spdx_document.packages[0].homepage = "https://existing.com"

        backend_data = {
            "supplier": {
                "name": "Test Supplier",
                "url": ["https://supplier.com"],
            },
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
            override_sbom_metadata=False,
        )

        # Homepage should be preserved (not overridden)
        assert enriched_doc.packages[0].homepage == "https://existing.com"

    def test_spdx_homepage_added_when_missing(self, spdx_document):
        """Test that homepage is added from supplier URL when missing."""
        backend_data = {
            "supplier": {
                "name": "Test Supplier",
                "url": ["https://supplier.com"],
            },
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Homepage should be added from supplier URL
        assert enriched_doc.packages[0].homepage == "https://supplier.com"

    def test_spdx_originator_preservation(self, spdx_document):
        """Test that existing originator is preserved."""
        from spdx_tools.spdx.model import ActorType

        # Set existing originator
        spdx_document.packages[0].originator = Actor(ActorType.PERSON, "Existing Originator")

        backend_data = {
            "authors": [{"name": "Backend Author"}],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
            override_sbom_metadata=False,
        )

        # Originator should be preserved
        assert "Existing Originator" in enriched_doc.packages[0].originator.name

    def test_spdx_duplicate_external_refs_avoided(self, spdx_document):
        """Test that duplicate external references are not added."""
        from spdx_tools.spdx.model import ExternalPackageRef, ExternalPackageRefCategory

        # Add an existing external ref
        existing_ref = ExternalPackageRef(
            category=ExternalPackageRefCategory.OTHER,
            reference_type="website",
            locator="https://supplier.com",
            comment="Existing",
        )
        spdx_document.packages[0].external_references.append(existing_ref)

        backend_data = {
            "supplier": {
                "name": "Test Supplier",
                "url": ["https://supplier.com"],  # Same URL
            },
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Should not have duplicate - still only 1 ref
        refs_with_url = [
            ref for ref in enriched_doc.packages[0].external_references if ref.locator == "https://supplier.com"
        ]
        assert len(refs_with_url) == 1

    def test_spdx_preserves_existing_creators(self, spdx_document):
        """Test that existing creators are preserved."""
        from spdx_tools.spdx.model import ActorType

        # Add an existing creator
        existing_creator = Actor(ActorType.PERSON, "Original Creator")
        spdx_document.creation_info.creators.append(existing_creator)

        backend_data = {
            "supplier": {"name": "New Supplier"},
            "authors": [{"name": "New Author"}],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Original creator should still be present
        creator_names = [c.name for c in enriched_doc.creation_info.creators]
        assert "Original Creator" in " ".join(creator_names)

    def test_spdx_license_handling(self, spdx_document):
        """Test SPDX license handling with mixed types."""
        backend_data = {
            "licenses": [
                "MIT",
                "Apache-2.0 OR GPL-3.0",
                {"name": "Custom SPDX License", "url": "https://custom.com/license", "text": "Custom license text"},
            ],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Verify license_declared was set with the full expression
        package = enriched_doc.packages[0]
        assert package.license_declared is not None
        license_declared_str = str(package.license_declared)
        assert "MIT" in license_declared_str
        # Custom licenses are converted to LicenseRef format
        assert "LicenseRef" in license_declared_str

        # Verify ExtractedLicensingInfo objects were added to document
        assert len(enriched_doc.extracted_licensing_info) > 0
        custom_license = enriched_doc.extracted_licensing_info[0]
        assert custom_license.license_id.startswith("LicenseRef-")
        assert custom_license.extracted_text == "Custom license text"
        assert custom_license.license_name == "Custom SPDX License"
        assert "https://custom.com/license" in custom_license.cross_references

    def test_spdx_supplier_with_multiple_urls(self, spdx_document):
        """Test SPDX handling of supplier with multiple URLs."""
        backend_data = {
            "supplier": {
                "name": "Multi URL Supplier",
                "url": ["https://main.com", "https://support.com"],
            },
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Verify external references were added
        package = enriched_doc.packages[0]
        ref_locators = [ref.locator for ref in package.external_references]
        assert "https://main.com" in ref_locators
        assert "https://support.com" in ref_locators

    def test_spdx_extracted_licensing_info_multiple_custom_licenses(self, spdx_document):
        """Test that multiple custom licenses create unique ExtractedLicensingInfo objects."""
        backend_data = {
            "licenses": [
                {"name": "Custom License 1", "url": "https://custom1.com", "text": "License 1 text"},
                {"name": "Custom License 2", "url": "https://custom2.com", "text": "License 2 text"},
                "MIT",  # Standard license
            ],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Should have 2 ExtractedLicensingInfo objects (for the 2 custom licenses)
        assert len(enriched_doc.extracted_licensing_info) == 2

        # Verify each custom license has proper fields
        license_ids = [lic.license_id for lic in enriched_doc.extracted_licensing_info]
        assert "LicenseRef-Custom-License-1" in license_ids
        assert "LicenseRef-Custom-License-2" in license_ids

        # Verify license_declared includes all licenses
        package = enriched_doc.packages[0]
        license_declared_str = str(package.license_declared)
        assert "MIT" in license_declared_str
        assert "LicenseRef-Custom-License-1" in license_declared_str
        assert "LicenseRef-Custom-License-2" in license_declared_str
        assert " OR " in license_declared_str

    def test_spdx_extracted_licensing_info_without_text(self, spdx_document):
        """Test that custom licenses without text field still work."""
        backend_data = {
            "licenses": [
                {"name": "Custom License No Text", "url": "https://custom.com"},
            ],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Should have 1 ExtractedLicensingInfo object
        assert len(enriched_doc.extracted_licensing_info) == 1
        custom_license = enriched_doc.extracted_licensing_info[0]

        # Should have default text when not provided
        assert custom_license.extracted_text == "License text not provided"
        assert custom_license.license_name == "Custom License No Text"

    def test_spdx_license_declared_override_behavior(self, spdx_document):
        """Test that license_declared respects override_sbom_metadata flag."""
        # Set existing license_declared (need to use the parser to create an Expression object)
        from spdx_tools.spdx.parser.jsonlikedict.license_expression_parser import LicenseExpressionParser

        license_parser = LicenseExpressionParser()
        existing_license = license_parser.parse_license_expression("GPL-3.0")
        spdx_document.packages[0].license_declared = existing_license

        backend_data = {
            "licenses": ["MIT"],
        }

        # Without override - should add to comment
        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
            override_sbom_metadata=False,
        )

        # Original license should be preserved (parser normalizes GPL-3.0 to GPL-3.0-only)
        assert "GPL-3.0" in str(enriched_doc.packages[0].license_declared)
        # Backend license should be in comment
        assert "MIT" in enriched_doc.packages[0].license_comment

        # With override - should replace
        spdx_document.packages[0].license_declared = existing_license
        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
            override_sbom_metadata=True,
        )

        # Should be replaced with backend license
        assert "MIT" in str(enriched_doc.packages[0].license_declared)


class TestManufacturerHandling:
    """Test manufacturer data handling across CycloneDX versions and SPDX."""

    @pytest.fixture
    def manufacturer_data(self):
        """Sample manufacturer data from backend."""
        return {
            "manufacturer": {
                "name": "Acme Manufacturing Inc",
                "url": ["https://acme-mfg.com", "https://acme-support.com"],
                "contacts": [{"name": "Mfg Contact", "email": "contact@acme-mfg.com", "phone": "+1-555-0100"}],
            }
        }

    @pytest.fixture
    def cyclonedx_14_bom(self):
        """CycloneDX 1.4 BOM (uses metadata.manufacture)."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:44444444-4444-4444-4444-444444444444",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app-14",
                    "version": "1.4.0",
                },
            },
            "components": [],
        }
        return Bom.from_json(bom_json)

    @pytest.fixture
    def cyclonedx_15_bom(self):
        """CycloneDX 1.5 BOM (uses metadata.manufacture)."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:55555555-5555-5555-5555-555555555555",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app-15",
                    "version": "1.5.0",
                },
            },
            "components": [],
        }
        return Bom.from_json(bom_json)

    @pytest.fixture
    def cyclonedx_16_bom(self):
        """CycloneDX 1.6 BOM (uses metadata.component.manufacturer)."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:66666666-6666-6666-6666-666666666666",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app-16",
                    "version": "1.6.0",
                },
            },
            "components": [],
        }
        return Bom.from_json(bom_json)

    @pytest.fixture
    def spdx_document(self):
        """Create a sample SPDX document for manufacturer tests."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            Actor,
            ActorType,
            CreationInfo,
            Document,
            Package,
        )

        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-doc-mfg",
            document_namespace="https://test.com/test-doc-mfg",
            creators=[Actor(ActorType.TOOL, "test-tool")],
            created=datetime(2024, 1, 1),
        )

        package = Package(
            spdx_id="SPDXRef-main", name="test-app-mfg", download_location="https://example.com", version="1.0.0"
        )

        return Document(creation_info=creation_info, packages=[package])

    def test_cyclonedx_14_manufacturer_sets_manufacture(self, cyclonedx_14_bom, manufacturer_data):
        """Test that CycloneDX 1.4 sets metadata.manufacture (no 'r')."""
        enriched_bom = augment_cyclonedx_sbom(
            bom=cyclonedx_14_bom,
            augmentation_data=manufacturer_data,
            spec_version="1.4",
        )

        # Verify metadata.manufacture is set (not metadata.manufacturer)
        assert enriched_bom.metadata.manufacture is not None
        assert enriched_bom.metadata.manufacture.name == "Acme Manufacturing Inc"
        assert len(enriched_bom.metadata.manufacture.urls) == 2
        assert len(enriched_bom.metadata.manufacture.contacts) == 1

    def test_cyclonedx_15_manufacturer_sets_manufacture(self, cyclonedx_15_bom, manufacturer_data):
        """Test that CycloneDX 1.5 sets metadata.manufacture (no 'r')."""
        enriched_bom = augment_cyclonedx_sbom(
            bom=cyclonedx_15_bom,
            augmentation_data=manufacturer_data,
            spec_version="1.5",
        )

        # Verify metadata.manufacture is set (not metadata.manufacturer)
        assert enriched_bom.metadata.manufacture is not None
        assert enriched_bom.metadata.manufacture.name == "Acme Manufacturing Inc"
        assert len(enriched_bom.metadata.manufacture.urls) == 2

    def test_cyclonedx_16_manufacturer_sets_component_manufacturer(self, cyclonedx_16_bom, manufacturer_data):
        """Test that CycloneDX 1.6 sets metadata.component.manufacturer (with 'r')."""
        enriched_bom = augment_cyclonedx_sbom(
            bom=cyclonedx_16_bom,
            augmentation_data=manufacturer_data,
            spec_version="1.6",
        )

        # Verify metadata.component.manufacturer is set
        assert enriched_bom.metadata.component is not None
        assert enriched_bom.metadata.component.manufacturer is not None
        assert enriched_bom.metadata.component.manufacturer.name == "Acme Manufacturing Inc"
        assert len(enriched_bom.metadata.component.manufacturer.urls) == 2
        assert len(enriched_bom.metadata.component.manufacturer.contacts) == 1

    def test_cyclonedx_17_manufacturer_sets_component_manufacturer(self, manufacturer_data):
        """Test that CycloneDX 1.7 sets metadata.component.manufacturer (with 'r')."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "serialNumber": "urn:uuid:77777777-7777-7777-7777-777777777777",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app-17",
                    "version": "1.7.0",
                },
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        enriched_bom = augment_cyclonedx_sbom(
            bom=bom,
            augmentation_data=manufacturer_data,
            spec_version="1.7",
        )

        # Verify metadata.component.manufacturer is set
        assert enriched_bom.metadata.component.manufacturer is not None
        assert enriched_bom.metadata.component.manufacturer.name == "Acme Manufacturing Inc"

    def test_cyclonedx_manufacturer_preserves_existing(self, cyclonedx_14_bom, manufacturer_data):
        """Test that existing manufacture is fully preserved when not overriding (CDX 1.4)."""
        from cyclonedx.model.bom import OrganizationalEntity

        # Set existing manufacture
        cyclonedx_14_bom.metadata.manufacture = OrganizationalEntity(
            name="Existing Manufacturer",
            urls=["https://existing-mfg.com"],
        )

        enriched_bom = augment_cyclonedx_sbom(
            bom=cyclonedx_14_bom,
            augmentation_data=manufacturer_data,
            override_sbom_metadata=False,
            spec_version="1.4",
        )

        # Existing manufacture should be completely preserved (fill-only-if-missing)
        assert enriched_bom.metadata.manufacture.name == "Existing Manufacturer"
        urls = {str(url) for url in enriched_bom.metadata.manufacture.urls}
        assert urls == {"https://existing-mfg.com"}
        # Backend URLs should NOT be added
        assert "https://acme-mfg.com" not in urls

    def test_cyclonedx_manufacturer_override_replaces_existing(self, cyclonedx_16_bom, manufacturer_data):
        """Test that existing manufacturer is replaced when override=True (CDX 1.6)."""
        from cyclonedx.model.bom import OrganizationalEntity

        # Set existing manufacturer on component
        cyclonedx_16_bom.metadata.component.manufacturer = OrganizationalEntity(
            name="Old Manufacturer",
            urls=["https://old-mfg.com"],
        )

        enriched_bom = augment_cyclonedx_sbom(
            bom=cyclonedx_16_bom,
            augmentation_data=manufacturer_data,
            override_sbom_metadata=True,
            spec_version="1.6",
        )

        # Should be replaced with backend manufacturer
        assert enriched_bom.metadata.component.manufacturer.name == "Acme Manufacturing Inc"

    def test_spdx_manufacturer_sets_originator(self, spdx_document, manufacturer_data):
        """Test that SPDX manufacturer sets originator (organization type)."""
        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=manufacturer_data,
        )

        # Verify manufacturer was added to creators
        org_creators = [c for c in enriched_doc.creation_info.creators if c.actor_type == ActorType.ORGANIZATION]
        assert any("Acme Manufacturing Inc" in c.name for c in org_creators)

        # Verify originator is set to manufacturer
        assert enriched_doc.packages[0].originator is not None
        assert enriched_doc.packages[0].originator.actor_type == ActorType.ORGANIZATION
        assert "Acme Manufacturing Inc" in enriched_doc.packages[0].originator.name

    def test_spdx_manufacturer_takes_precedence_over_authors(self, spdx_document):
        """Test that manufacturer takes precedence over authors for originator."""
        backend_data = {
            "manufacturer": {
                "name": "Manufacturer Corp",
                "url": ["https://mfg.com"],
            },
            "authors": [{"name": "Author Person", "email": "author@example.com"}],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Originator should be manufacturer (organization), not author (person)
        assert enriched_doc.packages[0].originator is not None
        assert enriched_doc.packages[0].originator.actor_type == ActorType.ORGANIZATION
        assert "Manufacturer Corp" in enriched_doc.packages[0].originator.name
        # Should NOT be the author
        assert "Author Person" not in enriched_doc.packages[0].originator.name

    def test_spdx_manufacturer_urls_as_external_refs(self, spdx_document, manufacturer_data):
        """Test that manufacturer URLs are added as external references."""
        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=manufacturer_data,
        )

        # Verify external references were added
        package = enriched_doc.packages[0]
        ref_locators = [ref.locator for ref in package.external_references]
        assert "https://acme-mfg.com" in ref_locators
        assert "https://acme-support.com" in ref_locators

        # Verify comment indicates manufacturer
        mfg_refs = [ref for ref in package.external_references if "acme-mfg.com" in ref.locator]
        assert len(mfg_refs) > 0
        assert "Manufacturer" in mfg_refs[0].comment

    def test_spdx_originator_preserved_when_not_overriding(self, spdx_document, manufacturer_data):
        """Test that existing originator is preserved when not overriding."""
        # Set existing originator
        spdx_document.packages[0].originator = Actor(ActorType.PERSON, "Existing Originator")

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=manufacturer_data,
            override_sbom_metadata=False,
        )

        # Originator should be preserved
        assert "Existing Originator" in enriched_doc.packages[0].originator.name

    def test_spdx_originator_replaced_when_overriding(self, spdx_document, manufacturer_data):
        """Test that existing originator is replaced when override=True."""
        # Set existing originator
        spdx_document.packages[0].originator = Actor(ActorType.PERSON, "Old Originator")

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=manufacturer_data,
            override_sbom_metadata=True,
        )

        # Originator should be replaced with manufacturer
        assert "Acme Manufacturing Inc" in enriched_doc.packages[0].originator.name

    def test_cyclonedx_16_no_component_skips_manufacturer(self, manufacturer_data):
        """Test that CDX 1.6+ without root component skips manufacturer gracefully."""
        # Create a BOM without a root component
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:88888888-8888-8888-8888-888888888888",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                # No component defined
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Should not raise, just skip manufacturer
        enriched_bom = augment_cyclonedx_sbom(
            bom=bom,
            augmentation_data=manufacturer_data,
            spec_version="1.6",
        )

        # No root component, so nothing to set
        assert enriched_bom.metadata.component is None

    def test_cyclonedx_manufacturer_preserves_existing_contacts(self, cyclonedx_14_bom, manufacturer_data):
        """Test that existing manufacture contacts are preserved when not overriding."""
        from cyclonedx.model.bom import OrganizationalContact, OrganizationalEntity

        # Set existing manufacture with contacts
        existing_contact = OrganizationalContact(
            name="Existing Contact",
            email="existing@example.com",
            phone="+1-555-OLD",
        )
        cyclonedx_14_bom.metadata.manufacture = OrganizationalEntity(
            name="Existing Mfg",
            contacts=[existing_contact],
        )

        enriched_bom = augment_cyclonedx_sbom(
            bom=cyclonedx_14_bom,
            augmentation_data=manufacturer_data,
            override_sbom_metadata=False,
            spec_version="1.4",
        )

        # Existing contacts should be preserved, backend contacts NOT added
        contacts = list(enriched_bom.metadata.manufacture.contacts)
        assert len(contacts) == 1
        assert contacts[0].email == "existing@example.com"

    def test_cyclonedx_manufacturer_normalizes_single_url_to_list(self):
        """Test manufacturer URL normalization from single string to list."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:99999999-9999-9999-9999-999999999999",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0",
                },
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Single URL string instead of array
        manufacturer_data = {
            "manufacturer": {
                "name": "Single URL Mfg",
                "url": "https://single-url.com",  # Not an array
            }
        }

        enriched_bom = augment_cyclonedx_sbom(
            bom=bom,
            augmentation_data=manufacturer_data,
            spec_version="1.4",
        )

        # Should handle single URL string
        assert enriched_bom.metadata.manufacture is not None
        assert enriched_bom.metadata.manufacture.name == "Single URL Mfg"
        assert len(enriched_bom.metadata.manufacture.urls) == 1


class TestLockfileComponentDetection:
    """Test lockfile component detection for supplier propagation."""

    def test_lockfile_component_detected_by_name(self):
        """Test that lockfile components are detected by their filename."""
        from cyclonedx.model.component import Component, ComponentType

        from sbomify_action.augmentation import _is_lockfile_component

        # requirements.txt is a known lockfile
        component = Component(name="requirements.txt", type=ComponentType.APPLICATION)
        assert _is_lockfile_component(component) is True

        # uv.lock is a known lockfile
        component = Component(name="uv.lock", type=ComponentType.APPLICATION)
        assert _is_lockfile_component(component) is True

    def test_non_lockfile_not_detected(self):
        """Test that non-lockfile components are not detected."""
        from cyclonedx.model.component import Component, ComponentType

        from sbomify_action.augmentation import _is_lockfile_component

        # Regular application component
        component = Component(name="my-app", type=ComponentType.APPLICATION)
        assert _is_lockfile_component(component) is False

        # Non-application type
        component = Component(name="requirements.txt", type=ComponentType.LIBRARY)
        assert _is_lockfile_component(component) is False

    def test_component_with_purl_not_lockfile(self):
        """Test that component with PURL is not considered a lockfile."""
        from cyclonedx.model.component import Component, ComponentType
        from packageurl import PackageURL

        from sbomify_action.augmentation import _is_lockfile_component

        # Component with PURL is a real package, not a lockfile artifact
        component = Component(
            name="requirements.txt",
            type=ComponentType.APPLICATION,
            purl=PackageURL.from_string("pkg:pypi/requirements.txt@1.0.0"),
        )
        assert _is_lockfile_component(component) is False


class TestLockfilePackageDetection:
    """Test lockfile package detection for SPDX (augmentation module)."""

    def test_lockfile_package_detected_by_name(self):
        """Test that lockfile packages are detected by their filename."""
        from spdx_tools.spdx.model import Package

        from sbomify_action.augmentation import _is_lockfile_package

        # requirements.txt is a known lockfile
        package = Package(
            spdx_id="SPDXRef-requirements",
            name="requirements.txt",
            download_location="NOASSERTION",
        )
        assert _is_lockfile_package(package) is True

        # uv.lock is a known lockfile
        package = Package(
            spdx_id="SPDXRef-uv-lock",
            name="uv.lock",
            download_location="NOASSERTION",
        )
        assert _is_lockfile_package(package) is True

    def test_lockfile_package_detected_by_full_path(self):
        """Test that lockfile packages with full paths are detected.

        Trivy generates SPDX with full paths like /github/workspace/uv.lock.
        The detection should extract the basename to match against known lockfiles.
        """
        from spdx_tools.spdx.model import Package

        from sbomify_action.augmentation import _is_lockfile_package

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

    def test_non_lockfile_package_not_detected(self):
        """Test that regular packages are not detected as lockfiles."""
        from spdx_tools.spdx.model import Package

        from sbomify_action.augmentation import _is_lockfile_package

        # Regular package
        package = Package(
            spdx_id="SPDXRef-django",
            name="django",
            download_location="NOASSERTION",
        )
        assert _is_lockfile_package(package) is False

        # Full path that is not a lockfile
        package = Package(
            spdx_id="SPDXRef-app",
            name="/github/workspace/app.py",
            download_location="NOASSERTION",
        )
        assert _is_lockfile_package(package) is False


class TestErrorHandling:
    """Test error handling in augmentation."""

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_file_not_found_error(self, mock_get):
        """Test handling of missing input file."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"supplier": {}}
        mock_get.return_value = mock_response

        with pytest.raises(FileNotFoundError) as exc_info:
            augment_sbom_from_file(
                input_file="/nonexistent/file.json",
                output_file="/tmp/output.json",
                api_base_url="https://api.test.com",
                token="test-token",
                component_id="test-component",
            )

        assert "Input SBOM file not found" in str(exc_info.value)
        assert "/nonexistent/file.json" in str(exc_info.value)

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_invalid_json_error(self, mock_get):
        """Test handling of invalid JSON in input file."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"supplier": {}}
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "invalid.json"
            output_file = Path(tmpdir) / "output.json"

            # Write invalid JSON
            with open(input_file, "w") as f:
                f.write("{invalid json content")

            with pytest.raises(ValueError) as exc_info:
                augment_sbom_from_file(
                    input_file=str(input_file),
                    output_file=str(output_file),
                    api_base_url="https://api.test.com",
                    token="test-token",
                    component_id="test-component",
                )

            assert "Invalid JSON in SBOM file" in str(exc_info.value)

    @patch("sbomify_action._augmentation.providers.json_config.JsonConfigProvider._find_config_file")
    @patch.dict(os.environ, {}, clear=True)
    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_api_connection_error(self, mock_get, mock_find_config):
        """Test handling of API connection errors (provider returns None, not exception)."""
        import requests

        # Disable json-config provider to isolate API error test
        mock_find_config.return_value = None
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection failed")

        # With the provider architecture, API errors are caught and logged,
        # the provider returns None, and fetch_augmentation_metadata returns {}
        result = fetch_augmentation_metadata(
            api_base_url="https://api.test.com",
            token="test-token",
            component_id="test-component",
        )

        # Provider catches the error and returns None, which results in empty dict
        assert result == {}

    @patch("sbomify_action._augmentation.providers.json_config.JsonConfigProvider._find_config_file")
    @patch.dict(os.environ, {}, clear=True)
    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_api_timeout_error(self, mock_get, mock_find_config):
        """Test handling of API timeout errors (provider returns None, not exception)."""
        import requests

        # Disable json-config provider to isolate API error test
        mock_find_config.return_value = None
        mock_get.side_effect = requests.exceptions.Timeout("Timeout")

        # With the provider architecture, API errors are caught and logged
        result = fetch_augmentation_metadata(
            api_base_url="https://api.test.com",
            token="test-token",
            component_id="test-component",
        )

        # Provider catches the error and returns None, which results in empty dict
        assert result == {}

    @patch("sbomify_action._augmentation.providers.json_config.JsonConfigProvider._find_config_file")
    @patch.dict(os.environ, {}, clear=True)
    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_api_404_error(self, mock_get, mock_find_config):
        """Test handling of API 404 errors (provider returns None, not exception)."""
        # Disable json-config provider to isolate API error test
        mock_find_config.return_value = None

        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 404
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"detail": "Component not found"}
        mock_get.return_value = mock_response

        # With the provider architecture, API errors are caught and logged
        result = fetch_augmentation_metadata(
            api_base_url="https://api.test.com",
            token="test-token",
            component_id="nonexistent",
        )

        # Provider catches the error and returns None, which results in empty dict
        assert result == {}

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_missing_spec_version_error(self, mock_get):
        """Test handling of missing specVersion in CycloneDX SBOM."""
        from sbomify_action.exceptions import SBOMValidationError

        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"supplier": {}}
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "sbom.json"
            output_file = Path(tmpdir) / "output.json"

            # Write CycloneDX SBOM without specVersion
            sbom_data = {
                "bomFormat": "CycloneDX",
                # specVersion is intentionally missing
                "serialNumber": "urn:uuid:12345678-1234-5678-1234-567812345678",
                "version": 1,
                "metadata": {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "component": {
                        "type": "application",
                        "name": "test-app",
                        "version": "1.0.0",
                    },
                },
                "components": [],
            }

            with open(input_file, "w") as f:
                json.dump(sbom_data, f)

            with pytest.raises(SBOMValidationError) as exc_info:
                augment_sbom_from_file(
                    input_file=str(input_file),
                    output_file=str(output_file),
                    api_base_url="https://api.test.com",
                    token="test-token",
                    component_id="test-component",
                )

            assert "specVersion" in str(exc_info.value)
            assert "missing" in str(exc_info.value).lower()


class TestSupplierMerging:
    """Test supplier merging behavior."""

    @pytest.fixture
    def cyclonedx_bom_with_existing_supplier(self):
        """BOM that already has supplier info."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0",
                },
                "supplier": {
                    "name": "Existing Supplier",
                    "url": ["https://existing.com"],
                    "contact": [{"name": "Existing Contact", "email": "existing@example.com"}],
                },
            },
            "components": [],
        }
        return Bom.from_json(bom_json)

    def test_supplier_merge_preserves_existing(self, cyclonedx_bom_with_existing_supplier):
        """Test that existing supplier is preserved when override=False."""
        backend_data = {
            "supplier": {
                "name": "Backend Supplier",
                "url": ["https://backend.com"],
                "contact": [{"name": "Backend Contact", "email": "backend@example.com"}],
            },
            # No authors or licenses to avoid empty list issues
        }

        enriched_bom = augment_cyclonedx_sbom(
            bom=cyclonedx_bom_with_existing_supplier,
            augmentation_data=backend_data,
            override_sbom_metadata=False,
        )

        # Name should be preserved from existing
        assert enriched_bom.metadata.supplier.name == "Existing Supplier"

        # URLs should be merged
        urls = {str(url) for url in enriched_bom.metadata.supplier.urls}
        assert "https://existing.com" in urls
        assert "https://backend.com" in urls

        # Contacts should be merged
        assert len(enriched_bom.metadata.supplier.contacts) == 2

    def test_supplier_override_replaces_existing(self, cyclonedx_bom_with_existing_supplier):
        """Test that existing supplier is replaced when override=True."""
        backend_data = {
            "supplier": {
                "name": "Backend Supplier",
                "url": ["https://backend.com"],
                "contact": [{"name": "Backend Contact", "email": "backend@example.com"}],
            },
            # No authors or licenses
        }

        enriched_bom = augment_cyclonedx_sbom(
            bom=cyclonedx_bom_with_existing_supplier,
            augmentation_data=backend_data,
            override_sbom_metadata=True,
        )

        # Name should be replaced with backend
        assert enriched_bom.metadata.supplier.name == "Backend Supplier"


class TestToolMetadataVersions:
    """Test tool metadata handling across different CycloneDX versions."""

    def test_tool_metadata_cyclonedx_14(self):
        """Test tool metadata is correctly added for CycloneDX 1.4 (legacy format)."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
            "version": 1,
            "metadata": {},
            "components": [],
        }

        bom = Bom.from_json(bom_json)
        enriched_bom = augment_cyclonedx_sbom(bom, augmentation_data={}, spec_version="1.4")

        # For 1.4, sbomify should be added as a Tool in tools.tools (legacy format)
        tool_names = [tool.name for tool in enriched_bom.metadata.tools.tools]
        assert "sbomify action" in tool_names, "sbomify should be in tools.tools for CDX 1.4"

        # Verify vendor is set (Tool.vendor should be string per spec)
        sbomify_tool = next(t for t in enriched_bom.metadata.tools.tools if t.name == "sbomify action")
        assert sbomify_tool.vendor is not None
        assert sbomify_tool.vendor == "sbomify"
        assert isinstance(sbomify_tool.vendor, str), "Tool.vendor must be string, not OrganizationalEntity"

    def test_tool_metadata_cyclonedx_15(self):
        """Test tool metadata is correctly added for CycloneDX 1.5."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "version": 1,
            "metadata": {},
            "components": [],
        }

        bom = Bom.from_json(bom_json)
        enriched_bom = augment_cyclonedx_sbom(bom, augmentation_data={}, spec_version="1.5")

        # For 1.5+, sbomify should be added as a Service in tools.services (modern format)
        service_names = [service.name for service in enriched_bom.metadata.tools.services]
        assert "sbomify action" in service_names, "sbomify should be in tools.services for CDX 1.5+"

        # Verify group is set (equivalent to vendor in legacy format)
        sbomify_service = next(s for s in enriched_bom.metadata.tools.services if s.name == "sbomify action")
        assert sbomify_service.group is not None
        assert sbomify_service.group == "sbomify"

    def test_tool_metadata_cyclonedx_16(self):
        """Test tool metadata is correctly added for CycloneDX 1.6."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "version": 1,
            "metadata": {},
            "components": [],
        }

        bom = Bom.from_json(bom_json)
        enriched_bom = augment_cyclonedx_sbom(bom, augmentation_data={}, spec_version="1.6")

        # For 1.6+, sbomify should be added as a Service in tools.services (modern format)
        service_names = [service.name for service in enriched_bom.metadata.tools.services]
        assert "sbomify action" in service_names, "sbomify should be in tools.services for CDX 1.6+"

        # Verify external references
        sbomify_service = next(s for s in enriched_bom.metadata.tools.services if s.name == "sbomify action")
        assert len(sbomify_service.external_references) > 0

    def test_tool_metadata_avoids_duplicates(self):
        """Test that tool metadata doesn't create duplicates."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
            "version": 1,
            "metadata": {},
            "components": [],
        }

        bom = Bom.from_json(bom_json)

        # Augment twice
        enriched_bom = augment_cyclonedx_sbom(bom, augmentation_data={}, spec_version="1.6")
        enriched_bom = augment_cyclonedx_sbom(enriched_bom, augmentation_data={}, spec_version="1.6")

        # For 1.6+, sbomify is in services (modern format)
        service_names = [service.name for service in enriched_bom.metadata.tools.services]
        sbomify_count = service_names.count("sbomify action")
        assert sbomify_count == 1, "Should not have duplicate sbomify services"

    def test_tool_metadata_normalizes_services_with_string_providers(self):
        """Test that components and services remain in modern format (1.5+) without converting to legacy tools."""
        # This test verifies that for 1.5+, we keep the modern format (components/services)
        # and add sbomify as a service, not converting everything to legacy Tool format

        # Create a BOM programmatically with components that have group fields
        # (This is what SBOM generators like Trivy produce)
        from cyclonedx.model.bom import Bom
        from cyclonedx.model.component import Component, ComponentType
        from cyclonedx.model.service import Service

        bom = Bom()
        bom.spec_version = "1.6"  # Set spec version to 1.6

        # Add a component with group (standard way to specify tool vendor)
        component = Component(name="tool-component", version="1.0.0", type=ComponentType.APPLICATION)
        component.group = "example-org"
        bom.metadata.tools.components.add(component)

        # Add a component like Trivy produces (with group field)
        component2 = Component(name="trivy", version="0.67.2", type=ComponentType.APPLICATION)
        component2.group = "aquasecurity"
        bom.metadata.tools.components.add(component2)

        # Add a service
        service = Service(name="test-service", version="1.0.0")
        bom.metadata.tools.services.add(service)

        # This should not raise TypeError during augmentation or serialization
        enriched_bom = augment_cyclonedx_sbom(bom, augmentation_data={}, spec_version="1.6")

        # For 1.6+, components and services should NOT be converted to legacy tools
        # They should remain in modern format
        assert len(enriched_bom.metadata.tools.components) == 2, (
            "Components should remain in modern format for CDX 1.6+"
        )
        assert len(enriched_bom.metadata.tools.services) >= 2, (
            "Services should remain in modern format (original + sbomify) for CDX 1.6+"
        )

        # Verify sbomify was added as a service
        service_names = [s.name for s in enriched_bom.metadata.tools.services]
        assert "sbomify action" in service_names

        # Verify all components have string groups (equivalent to vendor)
        for comp in enriched_bom.metadata.tools.components:
            if comp.group is not None:
                assert isinstance(comp.group, str), (
                    f"Component '{comp.name}' group should be string, got {type(comp.group)}"
                )

        # Most importantly: verify we can serialize without errors
        from sbomify_action.serialization import serialize_cyclonedx_bom

        serialized = serialize_cyclonedx_bom(enriched_bom, "1.6")
        assert serialized is not None
        assert len(serialized) > 0


class TestLicenseRefSanitization:
    """Test SPDX LicenseRef sanitization."""

    def test_sanitize_basic_name(self):
        """Test sanitizing a simple license name."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        assert _sanitize_license_ref_id("Custom License") == "Custom-License"
        assert _sanitize_license_ref_id("MIT") == "MIT"
        assert _sanitize_license_ref_id("Apache-2.0") == "Apache-2.0"

    def test_sanitize_special_characters(self):
        """Test sanitization removes invalid characters."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        # Remove parentheses, brackets, etc.
        assert _sanitize_license_ref_id("License (v1.0)") == "License-v1.0"
        assert _sanitize_license_ref_id("License [Beta]") == "License-Beta"
        assert _sanitize_license_ref_id("License/Version") == "License-Version"
        assert _sanitize_license_ref_id("License\\Path") == "License-Path"

        # Remove other invalid chars
        assert _sanitize_license_ref_id("License@Company") == "LicenseCompany"
        assert _sanitize_license_ref_id("License#1") == "License1"
        assert _sanitize_license_ref_id("License$Money") == "LicenseMoney"

    def test_sanitize_multiple_spaces(self):
        """Test multiple spaces collapse to single hyphen."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        assert _sanitize_license_ref_id("Custom   License") == "Custom-License"
        assert _sanitize_license_ref_id("My  Custom  License") == "My-Custom-License"

    def test_sanitize_underscores_and_slashes(self):
        """Test underscores and slashes become hyphens."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        assert _sanitize_license_ref_id("Custom_License") == "Custom-License"
        assert _sanitize_license_ref_id("BSD/MIT") == "BSD-MIT"
        assert _sanitize_license_ref_id("Custom_License/v2") == "Custom-License-v2"

    def test_sanitize_consecutive_hyphens(self):
        """Test multiple consecutive hyphens collapse to one."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        assert _sanitize_license_ref_id("Custom---License") == "Custom-License"
        assert _sanitize_license_ref_id("A-.-.B") == "A-B"

    def test_sanitize_leading_trailing(self):
        """Test leading/trailing hyphens and periods are removed."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        assert _sanitize_license_ref_id("  Custom License  ") == "Custom-License"
        assert _sanitize_license_ref_id("-License-") == "License"
        assert _sanitize_license_ref_id(".License.") == "License"

    def test_sanitize_empty_name_raises(self):
        """Test empty or whitespace-only names raise ValueError."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        with pytest.raises(ValueError, match="cannot be empty"):
            _sanitize_license_ref_id("")

        with pytest.raises(ValueError, match="cannot be empty"):
            _sanitize_license_ref_id("   ")

    def test_sanitize_all_special_chars_raises(self):
        """Test name with only special characters raises ValueError."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        with pytest.raises(ValueError, match="cannot be sanitized"):
            _sanitize_license_ref_id("@#$%^&*()")

        with pytest.raises(ValueError, match="cannot be sanitized"):
            _sanitize_license_ref_id("---...")

    def test_sanitize_long_name_truncates(self):
        """Test very long names are truncated with hash."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        long_name = "A" * 100 + " Very Long License Name"
        result = _sanitize_license_ref_id(long_name)

        # Should be truncated to reasonable length
        assert len(result) <= 64
        # Should contain a hash for uniqueness
        assert "-" in result

    def test_convert_expression_with_collision_handling(self):
        """Test that duplicate custom licenses get unique refs."""
        from sbomify_action.augmentation import _convert_backend_licenses_to_spdx_expression

        # Two licenses that would sanitize to same thing
        licenses = [
            {"name": "Custom License"},
            {"name": "Custom-License"},  # Would sanitize to same as above
        ]

        expression, extracted_infos = _convert_backend_licenses_to_spdx_expression(licenses)

        # Should have two distinct LicenseRefs
        assert "LicenseRef-Custom-License" in expression
        assert "LicenseRef-Custom-License-2" in expression
        # Should have 2 ExtractedLicensingInfo objects
        assert len(extracted_infos) == 2

    def test_convert_expression_skips_invalid(self):
        """Test that invalid license names are skipped with warning."""
        from sbomify_action.augmentation import _convert_backend_licenses_to_spdx_expression

        licenses = [
            "MIT",
            {"name": "@@@"},  # Invalid - all special chars
            "Apache-2.0",
        ]

        expression, extracted_infos = _convert_backend_licenses_to_spdx_expression(licenses)

        # Should only have the valid licenses
        assert expression == "MIT OR Apache-2.0"
        # No extracted infos since invalid license was skipped
        assert len(extracted_infos) == 0

    def test_convert_expression_mixed_types(self):
        """Test conversion with mixed string and dict licenses."""
        from sbomify_action.augmentation import _convert_backend_licenses_to_spdx_expression

        licenses = [
            "MIT",
            {"name": "Proprietary License (Company X)"},
            "Apache-2.0",
        ]

        expression, extracted_infos = _convert_backend_licenses_to_spdx_expression(licenses)

        assert "MIT" in expression
        assert "LicenseRef-Proprietary-License-Company-X" in expression
        assert "Apache-2.0" in expression
        assert " OR " in expression
        # Should have 1 ExtractedLicensingInfo for the custom license
        assert len(extracted_infos) == 1
        assert extracted_infos[0].license_id == "LicenseRef-Proprietary-License-Company-X"


class TestAugmentationValidation:
    """Test validation logic after augmentation."""

    @pytest.fixture
    def sample_cyclonedx_bom(self):
        """Sample CycloneDX BOM for validation tests."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:99999999-9999-9999-9999-999999999999",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "validation-test-app",
                    "version": "1.0.0",
                },
            },
            "components": [],
        }
        return Bom.from_json(bom_json)

    @pytest.fixture
    def sample_spdx_document(self):
        """Create a sample SPDX document for validation tests."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            ActorType,
            CreationInfo,
            Document,
            Package,
        )

        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="validation-test-doc",
            document_namespace="https://test.com/validation-test-doc",
            creators=[Actor(ActorType.TOOL, "test-tool")],
            created=datetime(2024, 1, 1),
        )

        package = Package(
            spdx_id="SPDXRef-main",
            name="validation-test-app",
            download_location="https://example.com",
            version="1.0.0",
        )

        return Document(creation_info=creation_info, packages=[package])

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_augment_cyclonedx_validates_output_by_default(self, mock_get, sample_cyclonedx_bom):
        """Test that CycloneDX augmentation validates output by default."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"supplier": {"name": "Test Supplier"}}
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            from cyclonedx.output.json import JsonV1Dot6

            input_file = Path(tmpdir) / "input.json"
            output_file = Path(tmpdir) / "output.json"

            outputter = JsonV1Dot6(sample_cyclonedx_bom)
            with open(input_file, "w") as f:
                f.write(outputter.output_as_string())

            # Should succeed - validation is enabled by default
            format_result = augment_sbom_from_file(
                input_file=str(input_file),
                output_file=str(output_file),
                api_base_url="https://api.test.com",
                token="test-token",
                component_id="test-component",
            )

            assert format_result == "cyclonedx"
            assert output_file.exists()

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_augment_cyclonedx_validation_failure_raises_error(self, mock_get, sample_cyclonedx_bom):
        """Test that CycloneDX validation failure raises SBOMValidationError."""
        from sbomify_action.exceptions import SBOMValidationError

        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"supplier": {"name": "Test Supplier"}}
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            from cyclonedx.output.json import JsonV1Dot6

            input_file = Path(tmpdir) / "input.json"
            output_file = Path(tmpdir) / "output.json"

            outputter = JsonV1Dot6(sample_cyclonedx_bom)
            with open(input_file, "w") as f:
                f.write(outputter.output_as_string())

            with patch("sbomify_action.augmentation.validate_sbom_file_auto") as mock_validate:
                # Mock validation failure
                mock_result = Mock()
                mock_result.valid = False
                mock_result.error_message = "CycloneDX schema validation failed"
                mock_validate.return_value = mock_result

                with pytest.raises(SBOMValidationError) as exc_info:
                    augment_sbom_from_file(
                        input_file=str(input_file),
                        output_file=str(output_file),
                        api_base_url="https://api.test.com",
                        token="test-token",
                        component_id="test-component",
                        validate=True,
                    )

                assert "Augmented SBOM failed validation" in str(exc_info.value)

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_augment_cyclonedx_skips_validation_when_disabled(self, mock_get, sample_cyclonedx_bom):
        """Test that CycloneDX validation is skipped when validate=False."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"supplier": {"name": "Test Supplier"}}
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            from cyclonedx.output.json import JsonV1Dot6

            input_file = Path(tmpdir) / "input.json"
            output_file = Path(tmpdir) / "output.json"

            outputter = JsonV1Dot6(sample_cyclonedx_bom)
            with open(input_file, "w") as f:
                f.write(outputter.output_as_string())

            with patch("sbomify_action.augmentation.validate_sbom_file_auto") as mock_validate:
                augment_sbom_from_file(
                    input_file=str(input_file),
                    output_file=str(output_file),
                    api_base_url="https://api.test.com",
                    token="test-token",
                    component_id="test-component",
                    validate=False,
                )

                # Validation should not be called
                mock_validate.assert_not_called()

            assert output_file.exists()

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_augment_spdx_validates_output_by_default(self, mock_get, sample_spdx_document):
        """Test that SPDX augmentation validates output by default."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"supplier": {"name": "SPDX Supplier"}}
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

            input_file = Path(tmpdir) / "input_spdx.json"
            output_file = Path(tmpdir) / "output_spdx.json"

            spdx_write_file(sample_spdx_document, str(input_file), validate=False)

            # Should succeed - validation is enabled by default
            format_result = augment_sbom_from_file(
                input_file=str(input_file),
                output_file=str(output_file),
                api_base_url="https://api.test.com",
                token="test-token",
                component_id="test-component",
            )

            assert format_result == "spdx"
            assert output_file.exists()

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_augment_spdx_validation_failure_raises_error(self, mock_get, sample_spdx_document):
        """Test that SPDX validation failure raises SBOMValidationError."""
        from sbomify_action.exceptions import SBOMValidationError

        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"supplier": {"name": "SPDX Supplier"}}
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

            input_file = Path(tmpdir) / "input_spdx.json"
            output_file = Path(tmpdir) / "output_spdx.json"

            spdx_write_file(sample_spdx_document, str(input_file), validate=False)

            with patch("sbomify_action.augmentation.validate_sbom_file_auto") as mock_validate:
                # Mock validation failure
                mock_result = Mock()
                mock_result.valid = False
                mock_result.error_message = "SPDX schema validation failed"
                mock_validate.return_value = mock_result

                with pytest.raises(SBOMValidationError) as exc_info:
                    augment_sbom_from_file(
                        input_file=str(input_file),
                        output_file=str(output_file),
                        api_base_url="https://api.test.com",
                        token="test-token",
                        component_id="test-component",
                        validate=True,
                    )

                assert "Augmented SBOM failed validation" in str(exc_info.value)

    @patch("sbomify_action._augmentation.providers.sbomify_api.requests.get")
    def test_augment_spdx_skips_validation_when_disabled(self, mock_get, sample_spdx_document):
        """Test that SPDX validation is skipped when validate=False."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"supplier": {"name": "SPDX Supplier"}}
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

            input_file = Path(tmpdir) / "input_spdx.json"
            output_file = Path(tmpdir) / "output_spdx.json"

            spdx_write_file(sample_spdx_document, str(input_file), validate=False)

            with patch("sbomify_action.augmentation.validate_sbom_file_auto") as mock_validate:
                augment_sbom_from_file(
                    input_file=str(input_file),
                    output_file=str(output_file),
                    api_base_url="https://api.test.com",
                    token="test-token",
                    component_id="test-component",
                    validate=False,
                )

                # Validation should not be called
                mock_validate.assert_not_called()

            assert output_file.exists()


class TestPurlVersionUpdate:
    """Tests for PURL version update functionality when COMPONENT_VERSION is set."""

    def test_update_component_purl_version_cyclonedx(self):
        """Test that CycloneDX component PURL version is updated."""
        from cyclonedx.model.component import Component, ComponentType
        from packageurl import PackageURL

        from sbomify_action.augmentation import _update_component_purl_version

        # Create component with PURL
        component = Component(
            name="test-app",
            type=ComponentType.APPLICATION,
            version="1.0.0",
            purl=PackageURL.from_string("pkg:pypi/test-app@1.0.0"),
        )

        # Update PURL version
        result = _update_component_purl_version(component, "2.0.0")

        assert result is True
        assert component.purl is not None
        assert component.purl.version == "2.0.0"
        assert str(component.purl) == "pkg:pypi/test-app@2.0.0"

    def test_update_component_purl_version_no_purl(self):
        """Test that function returns False when component has no PURL."""
        from cyclonedx.model.component import Component, ComponentType

        from sbomify_action.augmentation import _update_component_purl_version

        # Create component without PURL
        component = Component(
            name="test-app",
            type=ComponentType.APPLICATION,
            version="1.0.0",
        )

        # Update should return False
        result = _update_component_purl_version(component, "2.0.0")

        assert result is False
        assert component.purl is None

    def test_update_component_purl_version_preserves_qualifiers(self):
        """Test that PURL qualifiers are preserved during version update."""
        from cyclonedx.model.component import Component, ComponentType
        from packageurl import PackageURL

        from sbomify_action.augmentation import _update_component_purl_version

        # Create component with PURL that has qualifiers
        component = Component(
            name="test-app",
            type=ComponentType.APPLICATION,
            version="1.0.0",
            purl=PackageURL.from_string("pkg:npm/%40scope/test-app@1.0.0?vcs_url=git%2Bhttps://github.com/test"),
        )

        # Update PURL version
        result = _update_component_purl_version(component, "2.0.0")

        assert result is True
        assert component.purl.version == "2.0.0"
        assert component.purl.namespace == "@scope"
        assert "vcs_url" in component.purl.qualifiers

    def test_update_spdx_package_purl_version(self):
        """Test that SPDX package PURL external reference is updated."""
        from spdx_tools.spdx.model import (
            ExternalPackageRef,
            ExternalPackageRefCategory,
            Package,
            SpdxNoAssertion,
        )

        from sbomify_action.augmentation import _update_spdx_package_purl_version

        # Create SPDX package with PURL external reference
        package = Package(
            spdx_id="SPDXRef-Package",
            name="test-app",
            version="1.0.0",
            download_location=SpdxNoAssertion(),
        )
        package.external_references.append(
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator="pkg:pypi/test-app@1.0.0",
            )
        )

        # Update PURL version
        result = _update_spdx_package_purl_version(package, "2.0.0")

        assert result is True
        purl_ref = next(ref for ref in package.external_references if ref.reference_type == "purl")
        assert purl_ref.locator == "pkg:pypi/test-app@2.0.0"

    def test_update_spdx_package_purl_version_no_purl(self):
        """Test that function returns False when package has no PURL external ref."""
        from spdx_tools.spdx.model import Package, SpdxNoAssertion

        from sbomify_action.augmentation import _update_spdx_package_purl_version

        # Create SPDX package without PURL external reference
        package = Package(
            spdx_id="SPDXRef-Package",
            name="test-app",
            version="1.0.0",
            download_location=SpdxNoAssertion(),
        )

        # Update should return False
        result = _update_spdx_package_purl_version(package, "2.0.0")

        assert result is False

    def test_cyclonedx_augmentation_updates_purl_version(self):
        """Test that CycloneDX augmentation updates PURL when component_version is set."""

        # Create BOM with component that has PURL
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:12345678-1234-5678-1234-567812345678",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0",
                    "purl": "pkg:pypi/test-app@1.0.0",
                },
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augment with version override
        enriched_bom = augment_cyclonedx_sbom(
            bom=bom,
            augmentation_data={},
            override_sbom_metadata=False,
            component_version="2.0.0",
        )

        # Verify both version and PURL are updated
        assert enriched_bom.metadata.component.version == "2.0.0"
        assert enriched_bom.metadata.component.purl is not None
        assert enriched_bom.metadata.component.purl.version == "2.0.0"
        assert str(enriched_bom.metadata.component.purl) == "pkg:pypi/test-app@2.0.0"

    def test_spdx_augmentation_updates_purl_version(self):
        """Test that SPDX augmentation updates PURL when component_version is set."""
        from spdx_tools.spdx.model import (
            CreationInfo,
            Document,
            ExternalPackageRef,
            ExternalPackageRefCategory,
            Package,
            SpdxNoAssertion,
        )

        # Create SPDX document with package that has PURL
        package = Package(
            spdx_id="SPDXRef-Package",
            name="test-app",
            version="1.0.0",
            download_location=SpdxNoAssertion(),
        )
        package.external_references.append(
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator="pkg:pypi/test-app@1.0.0",
            )
        )

        from datetime import datetime

        document = Document(
            creation_info=CreationInfo(
                spdx_version="SPDX-2.3",
                spdx_id="SPDXRef-DOCUMENT",
                name="test-document",
                document_namespace="https://example.com/test",
                creators=[Actor(ActorType.TOOL, "test-tool")],
                created=datetime.now(),
            ),
            packages=[package],
        )

        # Augment with version override
        enriched_doc = augment_spdx_sbom(
            document=document,
            augmentation_data={},
            component_version="2.0.0",
        )

        # Verify both version and PURL are updated
        main_package = enriched_doc.packages[0]
        assert main_package.version == "2.0.0"

        purl_ref = next(ref for ref in main_package.external_references if ref.reference_type == "purl")
        assert purl_ref.locator == "pkg:pypi/test-app@2.0.0"

    def test_cyclonedx_version_override_without_purl(self):
        """Test that CycloneDX version override works when component has no PURL."""
        # Create BOM with component that has no PURL
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:12345678-1234-5678-1234-567812345678",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0",
                    # No PURL
                },
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augment with version override
        enriched_bom = augment_cyclonedx_sbom(
            bom=bom,
            augmentation_data={},
            override_sbom_metadata=False,
            component_version="2.0.0",
        )

        # Verify version is updated and no PURL is added
        assert enriched_bom.metadata.component.version == "2.0.0"
        assert enriched_bom.metadata.component.purl is None


class TestSpdxJsonPurlVersionUpdate:
    """Tests for SPDX JSON PURL version update (used in main.py version override)."""

    def test_update_spdx_json_purl_version(self):
        """Test that SPDX package PURL is updated in JSON format."""
        from sbomify_action.cli.main import _update_spdx_json_purl_version

        # Create SPDX package JSON with PURL external reference
        package_json = {
            "SPDXID": "SPDXRef-Package",
            "name": "test-app",
            "versionInfo": "1.0.0",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/test-app@1.0.0",
                }
            ],
        }

        # Update PURL version
        result = _update_spdx_json_purl_version(package_json, "2.0.0")

        assert result is True
        assert package_json["externalRefs"][0]["referenceLocator"] == "pkg:pypi/test-app@2.0.0"

    def test_update_spdx_json_purl_version_no_purl(self):
        """Test that function returns False when package has no PURL external ref."""
        from sbomify_action.cli.main import _update_spdx_json_purl_version

        # Create SPDX package JSON without PURL external reference
        package_json = {
            "SPDXID": "SPDXRef-Package",
            "name": "test-app",
            "versionInfo": "1.0.0",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "vcs",
                    "referenceLocator": "https://github.com/test/test-app",
                }
            ],
        }

        # Update should return False
        result = _update_spdx_json_purl_version(package_json, "2.0.0")

        assert result is False

    def test_update_spdx_json_purl_version_no_external_refs(self):
        """Test that function returns False when package has no external refs."""
        from sbomify_action.cli.main import _update_spdx_json_purl_version

        # Create SPDX package JSON without external refs
        package_json = {
            "SPDXID": "SPDXRef-Package",
            "name": "test-app",
            "versionInfo": "1.0.0",
            "downloadLocation": "NOASSERTION",
        }

        # Update should return False
        result = _update_spdx_json_purl_version(package_json, "2.0.0")

        assert result is False

    def test_update_spdx_json_purl_version_preserves_other_refs(self):
        """Test that other external refs are preserved during PURL update."""
        from sbomify_action.cli.main import _update_spdx_json_purl_version

        # Create SPDX package JSON with multiple external references
        package_json = {
            "SPDXID": "SPDXRef-Package",
            "name": "test-app",
            "versionInfo": "1.0.0",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "vcs",
                    "referenceLocator": "https://github.com/test/test-app",
                },
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/test-app@1.0.0",
                },
            ],
        }

        # Update PURL version
        result = _update_spdx_json_purl_version(package_json, "2.0.0")

        assert result is True
        # VCS ref should be unchanged
        assert package_json["externalRefs"][0]["referenceLocator"] == "https://github.com/test/test-app"
        # PURL should be updated
        assert package_json["externalRefs"][1]["referenceLocator"] == "pkg:pypi/test-app@2.0.0"


@dataclass
class MockPurlConfig:
    """Mock config for PURL override tests.

    We use a minimal mock instead of the real Config class because
    _apply_sbom_purl_override() only accesses the component_purl field.
    This keeps tests focused and avoids requiring unrelated fields like
    token, component_id, etc. that would add noise without value.
    """

    component_purl: str


class TestComponentPurlOverride:
    """Tests for COMPONENT_PURL override functionality via _apply_sbom_purl_override."""

    def test_cyclonedx_set_purl_when_none_exists(self, tmp_path):
        """Test setting PURL on CycloneDX component that has no PURL."""
        from sbomify_action.cli.main import _apply_sbom_purl_override

        # Create a minimal CycloneDX SBOM without PURL
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {"component": {"name": "test-app", "version": "1.0.0", "type": "application"}},
            "components": [],
        }
        sbom_file = tmp_path / "test.cdx.json"
        sbom_file.write_text(json.dumps(sbom))

        _apply_sbom_purl_override(str(sbom_file), MockPurlConfig("pkg:pypi/test-app@1.0.0"))

        # Verify PURL was set
        result = json.loads(sbom_file.read_text())
        assert result["metadata"]["component"]["purl"] == "pkg:pypi/test-app@1.0.0"

    def test_cyclonedx_override_existing_purl(self, tmp_path):
        """Test overriding existing PURL on CycloneDX component."""
        from sbomify_action.cli.main import _apply_sbom_purl_override

        # Create CycloneDX SBOM with existing PURL
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {
                    "name": "test-app",
                    "version": "1.0.0",
                    "type": "application",
                    "purl": "pkg:pypi/old-purl@1.0.0",
                }
            },
            "components": [],
        }
        sbom_file = tmp_path / "test.cdx.json"
        sbom_file.write_text(json.dumps(sbom))

        _apply_sbom_purl_override(str(sbom_file), MockPurlConfig("pkg:npm/@scope/new-package@2.0.0"))

        # Verify PURL was overridden (may be in canonical %40 form or literal @ form)
        result = json.loads(sbom_file.read_text())
        purl = result["metadata"]["component"]["purl"]
        # Accept either form - both are valid PURLs
        assert purl in ["pkg:npm/@scope/new-package@2.0.0", "pkg:npm/%40scope/new-package@2.0.0"]

    def test_cyclonedx_invalid_purl_is_skipped(self, tmp_path):
        """Test that invalid PURL is skipped without crashing."""
        from sbomify_action.cli.main import _apply_sbom_purl_override

        # Create CycloneDX SBOM without PURL
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {"component": {"name": "test-app", "version": "1.0.0", "type": "application"}},
            "components": [],
        }
        sbom_file = tmp_path / "test.cdx.json"
        sbom_file.write_text(json.dumps(sbom))

        # Should not raise
        _apply_sbom_purl_override(str(sbom_file), MockPurlConfig("not-a-valid-purl"))

        # Verify PURL was not added (invalid PURL was skipped)
        result = json.loads(sbom_file.read_text())
        assert "purl" not in result["metadata"]["component"]

    def test_spdx_set_purl_when_none_exists(self, tmp_path):
        """Test adding PURL to SPDX package that has no PURL."""
        from sbomify_action.cli.main import _apply_sbom_purl_override

        # Create minimal SPDX SBOM without PURL
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-document",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package",
                    "name": "test-app",
                    "downloadLocation": "NOASSERTION",
                }
            ],
        }
        sbom_file = tmp_path / "test.spdx.json"
        sbom_file.write_text(json.dumps(sbom))

        _apply_sbom_purl_override(str(sbom_file), MockPurlConfig("pkg:pypi/test-app@1.0.0"))

        # Verify PURL was added
        result = json.loads(sbom_file.read_text())
        purl_refs = [r for r in result["packages"][0].get("externalRefs", []) if r["referenceType"] == "purl"]
        assert len(purl_refs) == 1
        assert purl_refs[0]["referenceLocator"] == "pkg:pypi/test-app@1.0.0"

    def test_spdx_override_existing_purl(self, tmp_path):
        """Test overriding existing PURL on SPDX package."""
        from sbomify_action.cli.main import _apply_sbom_purl_override

        # Create SPDX SBOM with existing PURL
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-document",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package",
                    "name": "test-app",
                    "downloadLocation": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/old-purl@1.0.0",
                        }
                    ],
                }
            ],
        }
        sbom_file = tmp_path / "test.spdx.json"
        sbom_file.write_text(json.dumps(sbom))

        _apply_sbom_purl_override(str(sbom_file), MockPurlConfig("pkg:npm/@scope/new-package@2.0.0"))

        # Verify PURL was overridden
        result = json.loads(sbom_file.read_text())
        purl_refs = [r for r in result["packages"][0]["externalRefs"] if r["referenceType"] == "purl"]
        assert len(purl_refs) == 1
        assert purl_refs[0]["referenceLocator"] == "pkg:npm/@scope/new-package@2.0.0"

    def test_spdx_invalid_purl_is_skipped(self, tmp_path):
        """Test that invalid PURL is skipped without crashing for SPDX."""
        from sbomify_action.cli.main import _apply_sbom_purl_override

        # Create minimal SPDX SBOM
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-document",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package",
                    "name": "test-app",
                    "downloadLocation": "NOASSERTION",
                }
            ],
        }
        sbom_file = tmp_path / "test.spdx.json"
        sbom_file.write_text(json.dumps(sbom))

        # Should not raise
        _apply_sbom_purl_override(str(sbom_file), MockPurlConfig("not-a-valid-purl"))

        # Verify no PURL was added (invalid PURL was skipped)
        result = json.loads(sbom_file.read_text())
        purl_refs = [r for r in result["packages"][0].get("externalRefs", []) if r.get("referenceType") == "purl"]
        assert len(purl_refs) == 0

    def test_cyclonedx_creates_component_if_not_exists(self, tmp_path):
        """Test that component is created when setting PURL and no component exists."""
        from sbomify_action.cli.main import _apply_sbom_purl_override

        # Create CycloneDX SBOM without metadata.component
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {},
            "components": [],
        }
        sbom_file = tmp_path / "test.cdx.json"
        sbom_file.write_text(json.dumps(sbom))

        _apply_sbom_purl_override(str(sbom_file), MockPurlConfig("pkg:pypi/new-app@1.0.0"))

        # Verify component was created with PURL
        result = json.loads(sbom_file.read_text())
        assert "component" in result["metadata"]
        assert result["metadata"]["component"]["purl"] == "pkg:pypi/new-app@1.0.0"


class TestPurlConstructionFromVCS:
    """Test PURL construction from VCS URL for NTIA compliance."""

    def test_construct_purl_from_github_url(self):
        """Test PURL construction from GitHub URL."""
        from sbomify_action.augmentation import _construct_purl_from_vcs

        purl = _construct_purl_from_vcs(
            "https://github.com/sbomify/sbomify",
            "356b558abc123",
        )
        assert purl == "pkg:github/sbomify/sbomify@356b558"

    def test_construct_purl_from_github_url_with_git_suffix(self):
        """Test PURL construction handles .git suffix."""
        from sbomify_action.augmentation import _construct_purl_from_vcs

        purl = _construct_purl_from_vcs(
            "https://github.com/owner/repo.git",
            "abc1234567890",
        )
        assert purl == "pkg:github/owner/repo@abc1234"

    def test_construct_purl_from_gitlab_url(self):
        """Test PURL construction from GitLab URL."""
        from sbomify_action.augmentation import _construct_purl_from_vcs

        purl = _construct_purl_from_vcs(
            "https://gitlab.com/mygroup/myproject",
            "deadbeef12345",
        )
        assert purl == "pkg:gitlab/mygroup/myproject@deadbee"

    def test_construct_purl_from_gitlab_nested_groups(self):
        """Test PURL construction handles GitLab nested groups."""
        from sbomify_action.augmentation import _construct_purl_from_vcs

        purl = _construct_purl_from_vcs(
            "https://gitlab.com/group/subgroup/project",
            "abc1234567890",
        )
        # Should use first part as namespace, last part as name
        assert purl == "pkg:gitlab/group/project@abc1234"

    def test_construct_purl_from_bitbucket_url(self):
        """Test PURL construction from Bitbucket URL."""
        from sbomify_action.augmentation import _construct_purl_from_vcs

        purl = _construct_purl_from_vcs(
            "https://bitbucket.org/team/project",
            "1234567890abc",
        )
        assert purl == "pkg:bitbucket/team/project@1234567"

    def test_construct_purl_without_commit_sha(self):
        """Test PURL construction when no commit SHA is available."""
        from sbomify_action.augmentation import _construct_purl_from_vcs

        purl = _construct_purl_from_vcs(
            "https://github.com/owner/repo",
            None,
        )
        assert purl == "pkg:github/owner/repo"

    def test_construct_purl_unknown_host_returns_none(self):
        """Test PURL construction returns None for unknown hosts."""
        from sbomify_action.augmentation import _construct_purl_from_vcs

        purl = _construct_purl_from_vcs(
            "https://unknown-git-host.example.com/owner/repo",
            "abc123",
        )
        assert purl is None

    def test_construct_purl_empty_url_returns_none(self):
        """Test PURL construction returns None for empty URL."""
        from sbomify_action.augmentation import _construct_purl_from_vcs

        purl = _construct_purl_from_vcs("", "abc123")
        assert purl is None

        purl = _construct_purl_from_vcs(None, "abc123")
        assert purl is None

    def test_spdx_augmentation_adds_purl_from_vcs(self):
        """Test that SPDX augmentation adds PURL from VCS info."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            CreationInfo,
            Document,
            Package,
            SpdxNoAssertion,
        )

        # Create SPDX document without PURL
        package = Package(
            spdx_id="SPDXRef-Package",
            name="test-app",
            version="1.0.0",
            download_location=SpdxNoAssertion(),
        )

        document = Document(
            creation_info=CreationInfo(
                spdx_version="SPDX-2.3",
                spdx_id="SPDXRef-DOCUMENT",
                name="test-document",
                document_namespace="https://example.com/test",
                creators=[Actor(ActorType.TOOL, "test-tool")],
                created=datetime.now(),
            ),
            packages=[package],
        )

        # Augment with VCS info
        augmentation_data = {
            "vcs_url": "https://github.com/sbomify/sbomify",
            "vcs_commit_sha": "356b558abc123def",
        }

        enriched_doc = augment_spdx_sbom(
            document=document,
            augmentation_data=augmentation_data,
        )

        # Verify PURL was added
        main_package = enriched_doc.packages[0]
        purl_refs = [ref for ref in main_package.external_references if ref.reference_type == "purl"]
        assert len(purl_refs) == 1
        assert purl_refs[0].locator == "pkg:github/sbomify/sbomify@356b558"

    def test_spdx_augmentation_does_not_overwrite_existing_purl(self):
        """Test that existing PURL is not overwritten."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            CreationInfo,
            Document,
            ExternalPackageRef,
            ExternalPackageRefCategory,
            Package,
            SpdxNoAssertion,
        )

        # Create SPDX document with existing PURL
        package = Package(
            spdx_id="SPDXRef-Package",
            name="test-app",
            version="1.0.0",
            download_location=SpdxNoAssertion(),
        )
        package.external_references.append(
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator="pkg:pypi/test-app@1.0.0",
            )
        )

        document = Document(
            creation_info=CreationInfo(
                spdx_version="SPDX-2.3",
                spdx_id="SPDXRef-DOCUMENT",
                name="test-document",
                document_namespace="https://example.com/test",
                creators=[Actor(ActorType.TOOL, "test-tool")],
                created=datetime.now(),
            ),
            packages=[package],
        )

        # Augment with VCS info (should not overwrite existing PURL)
        augmentation_data = {
            "vcs_url": "https://github.com/sbomify/sbomify",
            "vcs_commit_sha": "356b558abc123def",
        }

        enriched_doc = augment_spdx_sbom(
            document=document,
            augmentation_data=augmentation_data,
        )

        # Verify original PURL is preserved
        main_package = enriched_doc.packages[0]
        purl_refs = [ref for ref in main_package.external_references if ref.reference_type == "purl"]
        assert len(purl_refs) == 1
        assert purl_refs[0].locator == "pkg:pypi/test-app@1.0.0"  # Original preserved
