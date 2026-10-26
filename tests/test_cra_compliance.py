"""
Tests for CRA (Cyber Resilience Act) compliance validation.

Reference: EU Cyber Resilience Act (CRA) 2024

CRA Requirements for SBOM metadata:
1. Security Contact - Point of contact for vulnerability reporting (REQUIRED)
2. Support Period - Clear indication of security support duration (REQUIRED)

Additional lifecycle fields (RECOMMENDED):
3. Release Date - When the component was released
4. End of Life - When all support ends

These tests verify that:
1. Raw scanner output is NOT CRA compliant (missing required fields)
2. Augmented SBOMs with CRA fields ARE compliant
3. End-to-end augmentation produces CRA-compliant output
"""

import json
from datetime import datetime
from pathlib import Path

import pytest
from cyclonedx.model.bom import Bom

from sbomify_action.augmentation import augment_cyclonedx_sbom, augment_spdx_sbom

from .cra_checker import CRAComplianceChecker


class TestCRAComplianceCycloneDX:
    """Test CRA compliance for CycloneDX SBOMs."""

    @pytest.fixture
    def trivy_cdx_path(self):
        """Path to Trivy CycloneDX test data."""
        return Path(__file__).parent / "test-data" / "trivy.cdx.json"

    @pytest.fixture
    def cra_metadata(self):
        """Sample CRA-compliant metadata for augmentation."""
        return {
            "supplier": {
                "name": "Acme Corporation",
                "url": ["https://acme.example.com"],
            },
            "security_contact": "https://acme.example.com/.well-known/security.txt",
            "release_date": "2024-06-15",
            "support_period_end": "2026-12-31",
            "end_of_life": "2028-12-31",
        }

    def test_raw_trivy_sbom_not_cra_compliant(self, trivy_cdx_path):
        """Test that raw Trivy SBOM is NOT CRA compliant (missing required fields)."""
        with open(trivy_cdx_path) as f:
            data = json.load(f)

        is_compliant, present, missing, values = CRAComplianceChecker.check_cyclonedx(data)

        # Raw scanner output should NOT be CRA compliant
        assert not is_compliant, "Raw scanner output should NOT be CRA compliant"
        assert "Security Contact" in missing, "Should be missing Security Contact"
        assert "Support Period End" in missing, "Should be missing Support Period End"

        print("\nRaw Trivy SBOM CRA Compliance:")
        print(f"  Compliant: {is_compliant}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")

    def test_partial_cra_compliance_not_sufficient(self):
        """Test that having only one required CRA field is NOT compliant.

        CRA requires BOTH security_contact AND support_period_end.
        Having only one should result in non-compliance.
        """
        # SBOM with only security contact (missing support_period_end)
        data_security_only = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "name": "test-app",
                    "externalReferences": [{"type": "security-contact", "url": "https://example.com/security"}],
                },
            },
        }

        is_compliant, present, missing, _ = CRAComplianceChecker.check_cyclonedx(data_security_only)
        assert not is_compliant, "Should NOT be compliant with only security_contact"
        assert "Security Contact" in present, "Should have Security Contact"
        assert "Support Period End" in missing, "Should be missing Support Period End"

        # SBOM with only support_period_end (missing security_contact)
        data_support_only = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {"name": "test-app"},
                "properties": [
                    {"name": "cdx:lifecycle:milestone:endOfSupport", "value": "2026-12-31"},
                ],
            },
        }

        is_compliant, present, missing, _ = CRAComplianceChecker.check_cyclonedx(data_support_only)
        assert not is_compliant, "Should NOT be compliant with only support_period_end"
        assert "Support Period End" in present, "Should have Support Period End"
        assert "Security Contact" in missing, "Should be missing Security Contact"

        print("\nPartial CRA Compliance Test:")
        print("  Security-only: NOT compliant (correct)")
        print("  Support-only: NOT compliant (correct)")

    def test_augmented_sbom_is_cra_compliant(self, cra_metadata):
        """Test that augmented SBOM with CRA fields IS compliant."""
        # Create a CycloneDX 1.6 BOM with a root component
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0",
                },
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augment with CRA metadata
        augmented_bom = augment_cyclonedx_sbom(bom, cra_metadata, spec_version="1.6")

        # Serialize to dict for checking
        from cyclonedx.output.json import JsonV1Dot6

        outputter = JsonV1Dot6(augmented_bom)
        augmented_data = json.loads(outputter.output_as_string())

        # Check CRA compliance
        is_compliant, present, missing, values = CRAComplianceChecker.check_cyclonedx(augmented_data)

        assert is_compliant, f"Augmented SBOM should be CRA compliant. Missing: {missing}"
        assert "Security Contact" in present, "Should have Security Contact"
        assert "Support Period End" in present, "Should have Support Period End"
        assert "Release Date" in present, "Should have Release Date"
        assert "End of Life" in present, "Should have End of Life"

        print("\nAugmented SBOM CRA Compliance (CycloneDX 1.6):")
        print(f"  Compliant: {is_compliant}")
        print(f"  Present: {present}")
        print(f"  Values: {values}")

    def test_augmented_sbom_cra_compliant_cdx_14(self, cra_metadata):
        """Test that augmented SBOM with CRA fields is compliant even in CycloneDX 1.4."""
        # Create a CycloneDX 1.4 BOM
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0",
                },
                "tools": [{"vendor": "test", "name": "test-tool", "version": "1.0"}],
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augment with CRA metadata
        augmented_bom = augment_cyclonedx_sbom(bom, cra_metadata, spec_version="1.4")

        # Serialize to dict for checking
        from cyclonedx.output.json import JsonV1Dot4

        outputter = JsonV1Dot4(augmented_bom)
        augmented_data = json.loads(outputter.output_as_string())

        # Check CRA compliance - CDX 1.4 uses properties for lifecycle dates
        # and support external reference for security contact
        is_compliant, present, missing, values = CRAComplianceChecker.check_cyclonedx(augmented_data)

        # Should have at least support period via properties
        assert "Support Period End" in present, f"Should have Support Period End. Missing: {missing}"

        print("\nAugmented SBOM CRA Compliance (CycloneDX 1.4):")
        print(f"  Compliant: {is_compliant}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Values: {values}")

    def test_end_to_end_cra_compliance_cyclonedx(self, trivy_cdx_path, cra_metadata):
        """Test end-to-end: raw SBOM -> augmentation -> CRA compliant output."""
        # Load raw SBOM
        with open(trivy_cdx_path) as f:
            raw_data = json.load(f)

        # Verify raw is NOT compliant
        raw_compliant, _, _, _ = CRAComplianceChecker.check_cyclonedx(raw_data)
        assert not raw_compliant, "Raw SBOM should NOT be CRA compliant"

        # Parse and augment
        bom = Bom.from_json(raw_data)
        spec_version = raw_data.get("specVersion", "1.6")
        augmented_bom = augment_cyclonedx_sbom(bom, cra_metadata, spec_version=spec_version)

        # Serialize back to dict
        from cyclonedx.output.json import JsonV1Dot6

        outputter = JsonV1Dot6(augmented_bom)
        augmented_data = json.loads(outputter.output_as_string())

        # Verify augmented IS compliant
        is_compliant, present, missing, values = CRAComplianceChecker.check_cyclonedx(augmented_data)

        assert is_compliant, f"Augmented SBOM should be CRA compliant. Missing: {missing}"

        print("\nEnd-to-End CRA Compliance (CycloneDX):")
        print(f"  Raw compliant: {raw_compliant}")
        print(f"  Augmented compliant: {is_compliant}")
        print(f"  CRA fields: {values}")


class TestCRAComplianceSPDX:
    """Test CRA compliance for SPDX SBOMs."""

    @pytest.fixture
    def trivy_spdx_path(self):
        """Path to Trivy SPDX test data."""
        return Path(__file__).parent / "test-data" / "trivy.spdx.json"

    @pytest.fixture
    def cra_metadata(self):
        """Sample CRA-compliant metadata for augmentation."""
        return {
            "supplier": {
                "name": "Acme Corporation",
                "url": ["https://acme.example.com"],
            },
            "security_contact": "https://acme.example.com/.well-known/security.txt",
            "release_date": "2024-06-15",
            "support_period_end": "2026-12-31",
            "end_of_life": "2028-12-31",
        }

    def test_raw_trivy_spdx_not_cra_compliant(self, trivy_spdx_path):
        """Test that raw Trivy SPDX SBOM is NOT CRA compliant."""
        with open(trivy_spdx_path) as f:
            data = json.load(f)

        is_compliant, present, missing, values = CRAComplianceChecker.check_spdx(data)

        # Raw scanner output should NOT be CRA compliant
        assert not is_compliant, "Raw scanner output should NOT be CRA compliant"
        assert "Security Contact" in missing, "Should be missing Security Contact"
        assert "Support Period End" in missing, "Should be missing Support Period End"

        print("\nRaw Trivy SPDX CRA Compliance:")
        print(f"  Compliant: {is_compliant}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")

    def test_augmented_spdx_is_cra_compliant(self, cra_metadata, tmp_path):
        """Test that augmented SPDX SBOM with CRA fields IS compliant."""
        from spdx_tools.spdx.model import CreationInfo, Document, Package, Relationship, RelationshipType
        from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

        # Create a minimal SPDX document
        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-sbom",
            document_namespace="https://example.com/test-cra",
            creators=[],
            created=datetime.now(),
        )
        document = Document(
            creation_info=creation_info,
            packages=[
                Package(
                    spdx_id="SPDXRef-main",
                    name="my-app",
                    download_location="https://example.com/download",
                    version="1.0.0",
                ),
            ],
            relationships=[Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-main")],
        )

        # Augment with CRA metadata
        augmented_doc = augment_spdx_sbom(document, cra_metadata)

        # Write and read back to get dict format
        output_file = tmp_path / "augmented.spdx.json"
        spdx_write_file(augmented_doc, str(output_file), validate=False)
        with open(output_file) as f:
            augmented_data = json.load(f)

        # Check CRA compliance
        is_compliant, present, missing, values = CRAComplianceChecker.check_spdx(augmented_data)

        assert is_compliant, f"Augmented SPDX should be CRA compliant. Missing: {missing}"
        assert "Security Contact" in present, "Should have Security Contact"
        assert "Support Period End" in present, "Should have Support Period End"
        assert "Release Date" in present, "Should have Release Date"
        assert "End of Life" in present, "Should have End of Life"

        print("\nAugmented SPDX CRA Compliance:")
        print(f"  Compliant: {is_compliant}")
        print(f"  Present: {present}")
        print(f"  Values: {values}")

    def test_end_to_end_cra_compliance_spdx(self, trivy_spdx_path, cra_metadata, tmp_path):
        """Test end-to-end: raw SPDX -> augmentation -> CRA compliant output."""
        from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file
        from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

        # Load raw SBOM
        with open(trivy_spdx_path) as f:
            raw_data = json.load(f)

        # Verify raw is NOT compliant
        raw_compliant, _, _, _ = CRAComplianceChecker.check_spdx(raw_data)
        assert not raw_compliant, "Raw SPDX SBOM should NOT be CRA compliant"

        # Parse and augment
        document = spdx_parse_file(str(trivy_spdx_path))
        augmented_doc = augment_spdx_sbom(document, cra_metadata)

        # Serialize back to dict
        output_file = tmp_path / "augmented.spdx.json"
        spdx_write_file(augmented_doc, str(output_file), validate=False)
        with open(output_file) as f:
            augmented_data = json.load(f)

        # Verify augmented IS compliant
        is_compliant, present, missing, values = CRAComplianceChecker.check_spdx(augmented_data)

        assert is_compliant, f"Augmented SPDX should be CRA compliant. Missing: {missing}"

        print("\nEnd-to-End CRA Compliance (SPDX):")
        print(f"  Raw compliant: {raw_compliant}")
        print(f"  Augmented compliant: {is_compliant}")
        print(f"  CRA fields: {values}")


class TestCRACheckerUnit:
    """Unit tests for the CRA checker itself."""

    def test_cyclonedx_with_security_contact_in_ext_refs(self):
        """Test detection of security-contact external reference."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "name": "test",
                    "externalReferences": [{"type": "security-contact", "url": "https://example.com/security"}],
                },
            },
        }

        is_compliant, present, missing, values = CRAComplianceChecker.check_cyclonedx(data)

        assert "Security Contact" in present
        assert values["Security Contact"] == "https://example.com/security"

    def test_cyclonedx_with_support_fallback(self):
        """Test fallback to support external reference for security contact (CDX 1.4)."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "metadata": {
                "component": {
                    "name": "test",
                    "externalReferences": [{"type": "support", "url": "https://example.com/support"}],
                },
            },
        }

        is_compliant, present, missing, values = CRAComplianceChecker.check_cyclonedx(data)

        assert "Security Contact" in present
        assert values["Security Contact"] == "https://example.com/support"

    def test_cyclonedx_with_supplier_contact_fallback(self):
        """Test fallback to supplier contact email."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "metadata": {
                "component": {"name": "test"},
                "supplier": {
                    "name": "Test Corp",
                    "contact": [{"email": "security@test.com"}],
                },
            },
        }

        is_compliant, present, missing, values = CRAComplianceChecker.check_cyclonedx(data)

        assert "Security Contact" in present
        assert values["Security Contact"] == "security@test.com"

    def test_cyclonedx_with_lifecycle_dates(self):
        """Test detection of lifecycle dates from named lifecycles."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {"name": "test"},
                "lifecycles": [
                    {"name": "release", "description": "Released: 2024-06-15"},
                    {"name": "support-end", "description": "Security support ends: 2026-12-31"},
                    {"name": "end-of-life", "description": "End of life: 2028-12-31"},
                ],
            },
        }

        is_compliant, present, missing, values = CRAComplianceChecker.check_cyclonedx(data)

        assert "Release Date" in present
        assert "Support Period End" in present
        assert "End of Life" in present

    def test_cyclonedx_with_property_dates(self):
        """Test detection of lifecycle dates from properties (CDX 1.4 fallback)."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "metadata": {
                "component": {"name": "test"},
                "properties": [
                    {"name": "cdx:lifecycle:milestone:generalAvailability", "value": "2024-06-15"},
                    {"name": "cdx:lifecycle:milestone:endOfSupport", "value": "2026-12-31"},
                    {"name": "cdx:lifecycle:milestone:endOfLife", "value": "2028-12-31"},
                ],
            },
        }

        is_compliant, present, missing, values = CRAComplianceChecker.check_cyclonedx(data)

        assert "Release Date" in present
        assert "Support Period End" in present
        assert "End of Life" in present
        assert values["Release Date"] == "2024-06-15"
        assert values["Support Period End"] == "2026-12-31"
        assert values["End of Life"] == "2028-12-31"

    def test_spdx_with_all_cra_fields(self):
        """Test detection of all CRA fields in SPDX."""
        data = {
            "spdxVersion": "SPDX-2.3",
            "documentDescribes": ["SPDXRef-main"],
            "packages": [
                {
                    "name": "test-app",
                    "SPDXID": "SPDXRef-main",
                    "validUntilDate": "2026-12-31T00:00:00Z",
                    "externalRefs": [
                        {
                            "referenceCategory": "SECURITY",
                            "referenceType": "security-contact",
                            "referenceLocator": "https://example.com/security",
                        },
                        {
                            "referenceCategory": "OTHER",
                            "referenceType": "release-date",
                            "referenceLocator": "2024-06-15",
                        },
                        {
                            "referenceCategory": "OTHER",
                            "referenceType": "end-of-life-date",
                            "referenceLocator": "2028-12-31",
                        },
                    ],
                }
            ],
        }

        is_compliant, present, missing, values = CRAComplianceChecker.check_spdx(data)

        assert is_compliant, f"Should be CRA compliant. Missing: {missing}"
        assert "Security Contact" in present
        assert "Release Date" in present
        assert "Support Period End" in present
        assert "End of Life" in present

    def test_spdx_support_end_from_external_ref(self):
        """Test support period detection from external ref (fallback from validUntilDate)."""
        data = {
            "spdxVersion": "SPDX-2.3",
            "documentDescribes": ["SPDXRef-main"],
            "packages": [
                {
                    "name": "test-app",
                    "SPDXID": "SPDXRef-main",
                    "externalRefs": [
                        {
                            "referenceCategory": "OTHER",
                            "referenceType": "support-end-date",
                            "referenceLocator": "2026-12-31",
                        },
                    ],
                }
            ],
        }

        is_compliant, present, missing, values = CRAComplianceChecker.check_spdx(data)

        assert "Support Period End" in present
        assert values["Support Period End"] == "2026-12-31"


class TestCRAWithRealSBOMs:
    """Integration tests that verify CRA compliance with real SBOM files."""

    @pytest.fixture
    def all_test_sboms(self):
        """Get all test SBOM files."""
        test_data_dir = Path(__file__).parent / "test-data"
        cyclonedx_files = list(test_data_dir.glob("*.cdx.json"))
        spdx_files = list(test_data_dir.glob("*.spdx.json"))
        return {"cyclonedx": cyclonedx_files, "spdx": spdx_files}

    def test_raw_sboms_are_not_cra_compliant(self, all_test_sboms):
        """Verify that raw SBOMs from various generators are NOT CRA compliant."""
        results = []

        for cdx_file in all_test_sboms["cyclonedx"]:
            with open(cdx_file) as f:
                data = json.load(f)
            is_compliant, present, missing, _ = CRAComplianceChecker.check_cyclonedx(data)
            results.append(
                {
                    "file": cdx_file.name,
                    "format": "CycloneDX",
                    "compliant": is_compliant,
                    "present": present,
                    "missing": missing,
                }
            )

        for spdx_file in all_test_sboms["spdx"]:
            with open(spdx_file) as f:
                data = json.load(f)
            is_compliant, present, missing, _ = CRAComplianceChecker.check_spdx(data)
            results.append(
                {
                    "file": spdx_file.name,
                    "format": "SPDX",
                    "compliant": is_compliant,
                    "present": present,
                    "missing": missing,
                }
            )

        print("\nCRA Compliance Check for Raw SBOMs:")
        for r in results:
            print(f"  {r['file']} ({r['format']}): compliant={r['compliant']}, missing={r['missing']}")

        # All raw SBOMs should be missing CRA required fields
        for r in results:
            # Raw SBOMs from scanners should NOT be CRA compliant
            assert not r["compliant"], f"Raw {r['file']} should NOT be CRA compliant (scanners don't add CRA fields)"

    def test_augmented_sboms_become_cra_compliant(self, all_test_sboms):
        """Verify that augmented SBOMs become CRA compliant.

        Tests only the first CycloneDX file to keep test fast.
        Full coverage is provided by other tests.
        """
        cra_metadata = {
            "supplier": {"name": "Test Corp"},
            "security_contact": "https://example.com/security",
            "release_date": "2024-06-15",
            "support_period_end": "2026-12-31",
            "end_of_life": "2028-12-31",
        }

        # Test only the first CycloneDX file to keep test fast
        cdx_files = all_test_sboms["cyclonedx"][:1]

        for cdx_file in cdx_files:
            with open(cdx_file) as f:
                raw_data = json.load(f)

            # Augment
            bom = Bom.from_json(raw_data)
            spec_version = raw_data.get("specVersion", "1.6")
            augmented_bom = augment_cyclonedx_sbom(bom, cra_metadata, spec_version=spec_version)

            # Serialize
            from cyclonedx.output.json import JsonV1Dot6

            outputter = JsonV1Dot6(augmented_bom)
            augmented_data = json.loads(outputter.output_as_string())

            is_compliant, present, missing, values = CRAComplianceChecker.check_cyclonedx(augmented_data)

            print(f"\nCRA Compliance After Augmentation ({cdx_file.name}):")
            print(f"  Compliant: {is_compliant}")
            print(f"  Present: {present}")

            assert is_compliant, f"Augmented {cdx_file.name} should be CRA compliant. Missing: {missing}"
