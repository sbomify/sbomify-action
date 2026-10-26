"""
Tests for NTIA Minimum Elements compliance validation.

Reference: https://sbomify.com/compliance/ntia-minimum-elements/

NTIA Minimum Elements for SBOM (July 2021):
1. Supplier Name - Entity that created/distributed the component
2. Component Name - Designation assigned by original supplier
3. Version - Change state identifier
4. Other Unique Identifiers - PURLs, CPE, etc.
5. Dependency Relationship - How components relate
6. Author of SBOM Data - Entity that created the SBOM
7. Timestamp - Date/time SBOM was assembled

Field Mappings (per https://sbomify.com/compliance/schema-crosswalk/):

CycloneDX (all versions 1.3-1.7):
- Supplier Name: components[].publisher OR components[].supplier.name
- Component Name: components[].name
- Component Version: components[].version
- Unique Identifiers: components[].purl, components[].cpe
- Dependency Relationship: dependencies[].ref + dependencies[].dependsOn[]
- SBOM Author: metadata.authors[]
- Timestamp: metadata.timestamp

SPDX (2.2 and 2.3):
- Supplier Name: packages[].supplier
- Component Name: packages[].name
- Component Version: packages[].versionInfo
- Unique Identifiers: packages[].externalRefs[] (referenceType: purl, cpe22Type, cpe23Type)
- Dependency Relationship: relationships[] (DEPENDS_ON, CONTAINS)
- SBOM Author: creationInfo.creators[]
- Timestamp: creationInfo.created

CISA 2025 Additional Fields:
- Component Hash: CycloneDX components[].hashes[] / SPDX packages[].checksums[]
- License: CycloneDX components[].licenses[] / SPDX packages[].licenseDeclared
- Tool Name/Version: CycloneDX metadata.tools / SPDX creationInfo.creators[]
- Generation Context: CycloneDX metadata.lifecycles[].phase (1.5+) / SPDX creationInfo.creatorComment
"""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from cyclonedx.model.bom import Bom

from sbomify_action.enrichment import clear_cache, enrich_sbom

from .ntia_checker import ISO8601_REGEX, NTIAComplianceChecker


class TestNTIAComplianceCycloneDX:
    """Test NTIA compliance for CycloneDX SBOMs."""

    @pytest.fixture
    def trivy_cdx_path(self):
        """Path to Trivy CycloneDX test data."""
        return Path(__file__).parent / "test-data" / "trivy.cdx.json"

    @pytest.fixture
    def ecosystems_metadata(self):
        """Sample ecosyste.ms metadata for enrichment."""
        return {
            "pkg:pypi/django@5.1": {
                "description": "A high-level Python web framework",
                "homepage": "https://www.djangoproject.com/",
                "repository_url": "https://github.com/django/django",
                "registry_url": "https://pypi.org/project/django/",
                "normalized_licenses": ["BSD-3-Clause"],
                "maintainers": [{"name": "Django Software Foundation", "login": "django"}],
            },
            "pkg:pypi/asgiref@3.8.1": {
                "description": "ASGI specs, helper code, and adapters",
                "homepage": "https://github.com/django/asgiref",
                "normalized_licenses": ["BSD-3-Clause"],
                "maintainers": [{"name": "Django Software Foundation"}],
            },
            "pkg:pypi/sqlparse@0.5.1": {
                "description": "A non-validating SQL parser",
                "homepage": "https://github.com/andialbrecht/sqlparse",
                "normalized_licenses": ["BSD-3-Clause"],
                "maintainers": [{"name": "Andi Albrecht"}],
            },
        }

    def test_raw_trivy_sbom_missing_supplier(self, trivy_cdx_path):
        """Test that raw Trivy SBOM is missing supplier (NTIA requirement)."""
        with open(trivy_cdx_path) as f:
            data = json.load(f)

        # Filter out lockfile components (requirements.txt) for compliance check
        library_components = [c for c in data.get("components", []) if c.get("type") == "library"]

        # Raw scanner output should be missing supplier
        for component in library_components:
            assert component.get("publisher") is None, (
                f"Component {component['name']} should not have publisher in raw output"
            )
            assert component.get("supplier") is None, (
                f"Component {component['name']} should not have supplier in raw output"
            )

        # But should have other NTIA elements
        for component in library_components:
            assert component.get("name"), "Component should have name"
            assert component.get("version"), "Component should have version"
            assert component.get("purl"), "Component should have PURL"

        # Check timestamp and tools are present
        assert data.get("metadata", {}).get("timestamp"), "Should have timestamp"
        assert data.get("metadata", {}).get("tools"), "Should have tools"

    def test_enriched_sbom_has_supplier(self, trivy_cdx_path, ecosystems_metadata, tmp_path):
        """Test that enriched SBOM has supplier field populated (NTIA compliant).

        Uses PyPI API as native source for Python packages (new plugin architecture).
        """
        clear_cache()

        # Mock PyPI HTTP responses at the source level
        def mock_get(url, *args, **kwargs):
            mock_response = Mock()
            # Parse package name from URL
            if "pypi.org/pypi/" in url:
                pkg_name = url.split("/pypi/")[1].split("/")[0]
                purl_key = f"pkg:pypi/{pkg_name}@"
                # Find matching metadata
                for key, meta in ecosystems_metadata.items():
                    if purl_key in key or f"pkg:pypi/{pkg_name}@" in key:
                        mock_response.status_code = 200
                        mock_response.json.return_value = {
                            "info": {
                                "summary": meta.get("description"),
                                "home_page": meta.get("homepage"),
                                "license": meta.get("normalized_licenses", [""])[0]
                                if meta.get("normalized_licenses")
                                else "",
                                "author": meta.get("maintainers", [{}])[0].get("name")
                                if meta.get("maintainers")
                                else None,
                                "project_urls": {"Source": meta.get("repository_url")}
                                if meta.get("repository_url")
                                else None,
                            }
                        }
                        return mock_response
            mock_response.status_code = 404
            return mock_response

        with patch("requests.Session.get", side_effect=mock_get):
            output_file = tmp_path / "enriched.cdx.json"
            enrich_sbom(str(trivy_cdx_path), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        # Filter library components
        library_components = [c for c in enriched_data.get("components", []) if c.get("type") == "library"]

        # All library components should now have publisher
        for component in library_components:
            assert component.get("publisher"), f"Component {component['name']} should have publisher after enrichment"

        # Run NTIA compliance check
        is_compliant, present, missing = NTIAComplianceChecker.check_cyclonedx(enriched_data)

        print("\nNTIA Compliance Check Results:")
        print(f"  Present elements: {present}")
        print(f"  Missing elements: {missing}")

        # Supplier should now be present
        assert "Supplier Name" in present, "Supplier Name should be present after enrichment"

    def test_full_ntia_compliance_after_enrichment(self, trivy_cdx_path, ecosystems_metadata, tmp_path):
        """Test full NTIA compliance after enrichment.

        Uses PyPI API as native source for Python packages (new plugin architecture).
        """
        clear_cache()

        # Mock PyPI HTTP responses at the source level
        def mock_get(url, *args, **kwargs):
            mock_response = Mock()
            if "pypi.org/pypi/" in url:
                pkg_name = url.split("/pypi/")[1].split("/")[0]
                purl_key = f"pkg:pypi/{pkg_name}@"
                for key, meta in ecosystems_metadata.items():
                    if purl_key in key or f"pkg:pypi/{pkg_name}@" in key:
                        mock_response.status_code = 200
                        mock_response.json.return_value = {
                            "info": {
                                "summary": meta.get("description"),
                                "home_page": meta.get("homepage"),
                                "license": meta.get("normalized_licenses", [""])[0]
                                if meta.get("normalized_licenses")
                                else "",
                                "author": meta.get("maintainers", [{}])[0].get("name")
                                if meta.get("maintainers")
                                else None,
                                "project_urls": {"Source": meta.get("repository_url")}
                                if meta.get("repository_url")
                                else None,
                            }
                        }
                        return mock_response
            mock_response.status_code = 404
            return mock_response

        with patch("requests.Session.get", side_effect=mock_get):
            output_file = tmp_path / "enriched.cdx.json"
            enrich_sbom(str(trivy_cdx_path), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        is_compliant, present, missing = NTIAComplianceChecker.check_cyclonedx(enriched_data)

        print("\nNTIA Compliance Check After Enrichment:")
        print(f"  Compliant: {is_compliant}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")

        # Enrichment adds supplier, licenses, description, etc. but NOT authors
        # Full NTIA compliance requires augmentation to add authors
        assert "Timestamp" in present
        assert "Component Name" in present
        assert "Version" in present
        assert "Supplier Name" in present
        assert "Unique Identifiers" in present
        assert "Dependency Relationships" in present
        # Note: "Author of SBOM Data" requires metadata.authors which comes from augmentation, not enrichment


class TestNTIAComplianceSPDX:
    """Test NTIA compliance for SPDX SBOMs."""

    @pytest.fixture
    def trivy_spdx_path(self):
        """Path to Trivy SPDX test data."""
        return Path(__file__).parent / "test-data" / "trivy.spdx.json"

    @pytest.fixture
    def ecosystems_metadata(self):
        """Sample ecosyste.ms metadata for enrichment."""
        return {
            "pkg:pypi/django@5.1": {
                "description": "A high-level Python web framework",
                "homepage": "https://www.djangoproject.com/",
                "repository_url": "https://github.com/django/django",
                "registry_url": "https://pypi.org/project/django/",
                "normalized_licenses": ["BSD-3-Clause"],
                "maintainers": [{"name": "Django Software Foundation", "login": "django"}],
                "ecosystem": "PyPI",
            },
            "pkg:pypi/asgiref@3.8.1": {
                "description": "ASGI specs, helper code, and adapters",
                "homepage": "https://github.com/django/asgiref",
                "normalized_licenses": ["BSD-3-Clause"],
                "maintainers": [{"name": "Django Software Foundation"}],
                "ecosystem": "PyPI",
            },
            "pkg:pypi/sqlparse@0.5.1": {
                "description": "A non-validating SQL parser",
                "homepage": "https://github.com/andialbrecht/sqlparse",
                "normalized_licenses": ["BSD-3-Clause"],
                "maintainers": [{"name": "Andi Albrecht"}],
                "ecosystem": "PyPI",
            },
        }

    def test_raw_trivy_spdx_has_noassertion_supplier(self, trivy_spdx_path):
        """Test that raw Trivy SPDX SBOM has NOASSERTION for supplier."""
        with open(trivy_spdx_path) as f:
            data = json.load(f)

        # Filter out non-library packages
        library_packages = [p for p in data.get("packages", []) if p.get("primaryPackagePurpose") == "LIBRARY"]

        # Raw scanner output has NOASSERTION for supplier
        for package in library_packages:
            assert package.get("supplier") == "NOASSERTION", (
                f"Package {package['name']} should have NOASSERTION supplier in raw output"
            )

        # But should have other elements
        for package in library_packages:
            assert package.get("name"), "Package should have name"
            assert package.get("versionInfo"), "Package should have version"

    def test_enriched_spdx_has_originator_and_metadata(self, trivy_spdx_path, ecosystems_metadata, tmp_path):
        """Test that enriched SPDX SBOM has originator and other metadata populated.

        Note: SPDX supplier handling is complex - the spdx-tools library may preserve
        NOASSERTION if already set. We verify originator is populated (maps to NTIA
        Author requirement at the package level) and other fields are enriched.
        """
        clear_cache()

        # Mock PyPI response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "summary": "Test description",
                "home_page": "https://example.com",
                "license": "MIT",
                "author": "Test Author",
            }
        }

        output_file = tmp_path / "enriched.spdx.json"
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(trivy_spdx_path), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        # Filter library packages
        library_packages = [p for p in enriched_data.get("packages", []) if p.get("primaryPackagePurpose") == "LIBRARY"]

        # All library packages should now have originator (relates to supplier/author)
        for package in library_packages:
            originator = package.get("originator")
            assert originator and originator != "NOASSERTION", (
                f"Package {package['name']} should have valid originator after enrichment"
            )
            # Also check description was enriched
            assert package.get("description"), f"Package {package['name']} should have description after enrichment"
            # Also check homepage was enriched
            assert package.get("homepage"), f"Package {package['name']} should have homepage after enrichment"

        print("\nSPDX Enrichment Results:")
        for package in library_packages:
            print(f"  {package['name']}:")
            print(f"    originator = {package.get('originator')}")
            print(f"    description = {package.get('description')[:50] if package.get('description') else None}...")


class TestNTIAPURLFallback:
    """Test PURL-based enrichment for OS packages when ecosyste.ms has no data."""

    def test_debian_package_purl_fallback(self, tmp_path):
        """Test that Debian packages get supplier from PURL namespace."""
        clear_cache()

        # Create a Debian-based SBOM
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [
                {
                    "type": "operating-system",
                    "name": "debian",
                    "version": "12",
                    "bom-ref": "os-debian",
                },
                {
                    "type": "library",
                    "name": "bash",
                    "version": "5.2.15-2",
                    "purl": "pkg:deb/debian/bash@5.2.15-2?distro=debian-12",
                    "bom-ref": "pkg-bash",
                },
                {
                    "type": "library",
                    "name": "coreutils",
                    "version": "9.1-1",
                    "purl": "pkg:deb/debian/coreutils@9.1-1?distro=debian-12",
                    "bom-ref": "pkg-coreutils",
                },
            ],
            "dependencies": [
                {"ref": "os-debian", "dependsOn": ["pkg-bash", "pkg-coreutils"]},
                {"ref": "pkg-bash", "dependsOn": []},
                {"ref": "pkg-coreutils", "dependsOn": []},
            ],
        }

        input_file = tmp_path / "debian.cdx.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.cdx.json"

        # Mock API responses to 404 (simulating no data - force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(input_file), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        # Find OS component
        os_component = next(
            (c for c in enriched_data["components"] if c.get("type") == "operating-system"),
            None,
        )
        assert os_component is not None
        assert os_component.get("publisher") == "Debian Project", "OS component should have Debian Project as publisher"

        # Find library components
        library_components = [c for c in enriched_data["components"] if c.get("type") == "library"]

        for component in library_components:
            assert component.get("publisher") == "Debian Project", (
                f"Component {component['name']} should have Debian Project as publisher from PURL"
            )

        print("\nPURL Fallback Results (Debian):")
        for component in enriched_data["components"]:
            print(f"  {component['name']}: publisher = {component.get('publisher')}")

    def test_alpine_package_purl_fallback(self, tmp_path):
        """Test that Alpine packages get supplier from PURL namespace when other sources fail."""
        clear_cache()

        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [
                {
                    "type": "library",
                    "name": "busybox",
                    "version": "1.36.1-r15",
                    "purl": "pkg:apk/alpine/busybox@1.36.1-r15?distro=alpine-3.19",
                    "bom-ref": "pkg-busybox",
                },
            ],
            "dependencies": [{"ref": "pkg-busybox", "dependsOn": []}],
        }

        input_file = tmp_path / "alpine.cdx.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.cdx.json"

        # Mock API responses to 404 (simulating no data - force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with (
            patch("requests.Session.get", return_value=mock_response),
            # Also disable LicenseDB so PURL fallback is truly tested
            patch("sbomify_action._enrichment.sources.license_db.LicenseDBSource.fetch", return_value=None),
        ):
            enrich_sbom(str(input_file), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        component = enriched_data["components"][0]
        assert component.get("publisher") == "Alpine Linux", "Component should have Alpine Linux as publisher from PURL"

    def test_rpm_package_purl_fallback(self, tmp_path):
        """Test that RPM packages get supplier from PURL namespace."""
        clear_cache()

        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [
                {
                    "type": "library",
                    "name": "bash",
                    "version": "5.2.15-5.fc39",
                    "purl": "pkg:rpm/fedora/bash@5.2.15-5.fc39?distro=fedora-39",
                    "bom-ref": "pkg-bash",
                },
            ],
            "dependencies": [{"ref": "pkg-bash", "dependsOn": []}],
        }

        input_file = tmp_path / "fedora.cdx.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.cdx.json"

        # Mock API responses to 404 (simulating no data - force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(input_file), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        component = enriched_data["components"][0]
        assert component.get("publisher") == "Fedora Project", (
            "Component should have Fedora Project as publisher from PURL"
        )


class TestNTIAAugmentation:
    """Test that augmentation adds supplier and tool metadata."""

    @pytest.fixture
    def sample_backend_metadata(self):
        """Sample backend metadata for augmentation."""
        return {
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
            "licenses": ["MIT"],
        }

    def test_augmentation_adds_supplier_cyclonedx(self, sample_backend_metadata, tmp_path):
        """Test that augmentation adds supplier to CycloneDX SBOM."""
        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Create a minimal CycloneDX BOM with valid UUID
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:44444444-4444-4444-4444-444444444444",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [
                {
                    "type": "library",
                    "name": "my-lib",
                    "version": "1.0.0",
                    "purl": "pkg:pypi/my-lib@1.0.0",
                },
            ],
        }
        bom = Bom.from_json(bom_json)

        # Augment with backend metadata
        augmented_bom = augment_cyclonedx_sbom(bom, sample_backend_metadata, spec_version="1.6")

        # Check supplier was added
        assert augmented_bom.metadata.supplier is not None
        assert augmented_bom.metadata.supplier.name == "Acme Corporation"

        # Check sbomify was added as a tool/service (for 1.6, uses services)
        services = list(augmented_bom.metadata.tools.services) if augmented_bom.metadata.tools.services else []
        components = list(augmented_bom.metadata.tools.components) if augmented_bom.metadata.tools.components else []

        # sbomify should be added as service for 1.5+
        sbomify_found = any("sbomify" in s.name.lower() for s in services)
        if not sbomify_found:
            # Might be in components or tools for different versions
            sbomify_found = any("sbomify" in c.name.lower() for c in components)

        assert sbomify_found, (
            f"sbomify should be added to tools. Services: {[s.name for s in services]}, Components: {[c.name for c in components]}"
        )

        print("\nAugmentation Results (CycloneDX):")
        print(f"  Supplier: {augmented_bom.metadata.supplier.name}")
        print(f"  Tools/Services: {[s.name for s in services]}")

    def test_augmentation_adds_supplier_spdx(self, sample_backend_metadata, tmp_path):
        """Test that augmentation adds supplier to SPDX SBOM."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            ActorType,
            CreationInfo,
            Document,
            Package,
            Relationship,
            RelationshipType,
        )

        from sbomify_action.augmentation import augment_spdx_sbom

        # Create a minimal SPDX document
        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-sbom",
            document_namespace="https://example.com/test",
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

        # Augment with backend metadata
        augmented_doc = augment_spdx_sbom(document, sample_backend_metadata)

        # Check supplier was added to main package
        main_package = augmented_doc.packages[0]
        assert main_package.supplier is not None
        assert main_package.supplier.actor_type == ActorType.ORGANIZATION
        assert "Acme Corporation" in main_package.supplier.name

        # Check sbomify was added to creators
        creator_names = [str(c) for c in augmented_doc.creation_info.creators]
        sbomify_creator = next((c for c in creator_names if "sbomify" in c.lower()), None)
        assert sbomify_creator is not None, "sbomify should be added to creators"

        print("\nAugmentation Results (SPDX):")
        print(f"  Supplier: {main_package.supplier.name}")
        print(f"  Creators: {creator_names}")

    def test_augmentation_adds_lifecycle_phase_cyclonedx(self, sample_backend_metadata):
        """Test that augmentation adds lifecycle_phase to CycloneDX 1.5+ SBOM.

        CISA 2025 requires Generation Context (metadata.lifecycles[].phase).
        This is only available in CycloneDX 1.5+.
        """
        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Add lifecycle_phase to backend metadata
        backend_metadata_with_lifecycle = dict(sample_backend_metadata)
        backend_metadata_with_lifecycle["lifecycle_phase"] = "build"

        # Create a CycloneDX 1.6 BOM
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:55555555-5555-5555-5555-555555555555",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augment with lifecycle phase
        augmented_bom = augment_cyclonedx_sbom(bom, backend_metadata_with_lifecycle, spec_version="1.6")

        # Check lifecycle was added
        lifecycles = list(augmented_bom.metadata.lifecycles)
        assert len(lifecycles) == 1, "Should have one lifecycle"
        assert lifecycles[0].phase.value == "build", f"Lifecycle phase should be 'build', got {lifecycles[0].phase}"

        print("\nLifecycle Phase Augmentation Results (CycloneDX 1.6):")
        print(f"  Lifecycles: {lifecycles}")

    def test_augmentation_skips_lifecycle_phase_cyclonedx_14(self, sample_backend_metadata):
        """Test that lifecycle_phase is skipped for CycloneDX 1.4 (not supported in schema)."""
        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Add lifecycle_phase to backend metadata
        backend_metadata_with_lifecycle = dict(sample_backend_metadata)
        backend_metadata_with_lifecycle["lifecycle_phase"] = "build"

        # Create a CycloneDX 1.4 BOM
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:66666666-6666-6666-6666-666666666666",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": [{"vendor": "test", "name": "test-tool", "version": "1.0"}],
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augment with lifecycle phase - should skip for 1.4
        augmented_bom = augment_cyclonedx_sbom(bom, backend_metadata_with_lifecycle, spec_version="1.4")

        # Check lifecycle was NOT added (not supported in 1.4)
        lifecycles = list(augmented_bom.metadata.lifecycles)
        assert len(lifecycles) == 0, "Lifecycle should not be added for CycloneDX 1.4"

    def test_augmentation_adds_lifecycle_phase_spdx(self, sample_backend_metadata):
        """Test that augmentation adds lifecycle_phase to SPDX creator comment."""
        from datetime import datetime

        from spdx_tools.spdx.model import CreationInfo, Document, Package

        from sbomify_action.augmentation import augment_spdx_sbom

        # Add lifecycle_phase to backend metadata
        backend_metadata_with_lifecycle = dict(sample_backend_metadata)
        backend_metadata_with_lifecycle["lifecycle_phase"] = "post-build"

        # Create a minimal SPDX document
        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-sbom",
            document_namespace="https://example.com/test-lifecycle",
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
            relationships=[],
        )

        # Augment with lifecycle phase
        augmented_doc = augment_spdx_sbom(document, backend_metadata_with_lifecycle)

        # Check lifecycle was added to creator comment
        creator_comment = augmented_doc.creation_info.creator_comment
        assert creator_comment is not None, "Creator comment should be set"
        assert "Lifecycle phase: post-build" in creator_comment, (
            f"Creator comment should contain lifecycle phase. Got: {creator_comment}"
        )

        print("\nLifecycle Phase Augmentation Results (SPDX):")
        print(f"  Creator comment: {creator_comment}")

    def test_augmentation_adds_security_contact_cyclonedx(self, sample_backend_metadata):
        """Test that augmentation adds security_contact to CycloneDX 1.5+ SBOM.

        CRA requires a vulnerability contact for security disclosure.
        In CycloneDX 1.5+, this is added as security-contact external reference.
        """
        from cyclonedx.model import ExternalReferenceType

        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Add security_contact to backend metadata
        metadata_with_security = dict(sample_backend_metadata)
        metadata_with_security["security_contact"] = "https://example.com/.well-known/security.txt"

        # Create a CycloneDX 1.6 BOM with a component
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:77777777-7777-7777-7777-777777777777",
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

        # Augment with security contact
        augmented_bom = augment_cyclonedx_sbom(bom, metadata_with_security, spec_version="1.6")

        # Check security-contact external reference was added
        external_refs = list(augmented_bom.metadata.component.external_references)
        security_refs = [ref for ref in external_refs if ref.type == ExternalReferenceType.SECURITY_CONTACT]
        assert len(security_refs) == 1, "Should have one security-contact external reference"
        assert str(security_refs[0].url) == "https://example.com/.well-known/security.txt"

        print("\nSecurity Contact Augmentation Results (CycloneDX 1.6):")
        print(f"  Security contact: {security_refs[0].url}")

    def test_augmentation_adds_security_contact_cyclonedx_14_fallback(self, sample_backend_metadata):
        """Test that security_contact fallback works for CycloneDX 1.4."""
        from cyclonedx.model import ExternalReferenceType

        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Add security_contact URL (not email) to backend metadata
        metadata_with_security = dict(sample_backend_metadata)
        metadata_with_security["security_contact"] = "https://example.com/security"

        # Create a CycloneDX 1.4 BOM with a component
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:88888888-8888-8888-8888-888888888888",
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

        # Augment with security contact
        augmented_bom = augment_cyclonedx_sbom(bom, metadata_with_security, spec_version="1.4")

        # Check support external reference was added as fallback (security-contact not available in 1.4)
        external_refs = list(augmented_bom.metadata.component.external_references)
        support_refs = [ref for ref in external_refs if ref.type == ExternalReferenceType.SUPPORT]
        assert len(support_refs) == 1, "Should have one support external reference as fallback"
        assert str(support_refs[0].url) == "https://example.com/security"

        print("\nSecurity Contact Fallback Results (CycloneDX 1.4):")
        print(f"  Support URL (fallback): {support_refs[0].url}")

    def test_augmentation_adds_security_contact_spdx(self, sample_backend_metadata):
        """Test that augmentation adds security_contact to SPDX."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            CreationInfo,
            Document,
            ExternalPackageRefCategory,
            Package,
            Relationship,
            RelationshipType,
        )

        from sbomify_action.augmentation import augment_spdx_sbom

        # Add security_contact to backend metadata
        metadata_with_security = dict(sample_backend_metadata)
        metadata_with_security["security_contact"] = "https://example.com/security"

        # Create a minimal SPDX document
        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-sbom",
            document_namespace="https://example.com/test-security",
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

        # Augment with security contact
        augmented_doc = augment_spdx_sbom(document, metadata_with_security)

        # Check security contact was added as external reference
        main_package = augmented_doc.packages[0]
        security_refs = [ref for ref in main_package.external_references if ref.reference_type == "security-contact"]
        assert len(security_refs) == 1, "Should have one security-contact external reference"
        assert security_refs[0].category == ExternalPackageRefCategory.SECURITY
        assert security_refs[0].locator == "https://example.com/security"

        print("\nSecurity Contact Augmentation Results (SPDX):")
        print(f"  Security contact: {security_refs[0].locator}")

    def test_augmentation_adds_support_period_end_cyclonedx(self, sample_backend_metadata):
        """Test that augmentation adds support_period_end to CycloneDX 1.5+ SBOM.

        CRA requires support period information.
        In CycloneDX 1.5+, this is added as both a named lifecycle and property.
        """
        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Add support_period_end to backend metadata
        metadata_with_support = dict(sample_backend_metadata)
        metadata_with_support["support_period_end"] = "2028-12-31"

        # Create a CycloneDX 1.6 BOM
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:99999999-9999-9999-9999-999999999999",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augment with support period
        augmented_bom = augment_cyclonedx_sbom(bom, metadata_with_support, spec_version="1.6")

        # Check property was added (using official CycloneDX property taxonomy)
        props = list(augmented_bom.metadata.properties)
        support_props = [p for p in props if p.name == "cdx:lifecycle:milestone:endOfSupport"]
        assert len(support_props) == 1, "Should have one cdx:lifecycle:milestone:endOfSupport property"
        assert support_props[0].value == "2028-12-31"

        print("\nSupport Period End Augmentation Results (CycloneDX 1.6):")
        print(f"  Property: {support_props[0].name}={support_props[0].value}")

    def test_augmentation_adds_support_period_end_cyclonedx_14(self, sample_backend_metadata):
        """Test that support_period_end works for CycloneDX 1.4 (property only)."""
        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Add support_period_end to backend metadata
        metadata_with_support = dict(sample_backend_metadata)
        metadata_with_support["support_period_end"] = "2028-12-31"

        # Create a CycloneDX 1.4 BOM
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": [{"vendor": "test", "name": "test-tool", "version": "1.0"}],
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augment with support period
        augmented_bom = augment_cyclonedx_sbom(bom, metadata_with_support, spec_version="1.4")

        # Check property was added (using official CycloneDX property taxonomy)
        props = list(augmented_bom.metadata.properties)
        support_props = [p for p in props if p.name == "cdx:lifecycle:milestone:endOfSupport"]
        assert len(support_props) == 1, "Should have one cdx:lifecycle:milestone:endOfSupport property"
        assert support_props[0].value == "2028-12-31"

        print("\nSupport Period End Results (CycloneDX 1.4):")
        print(f"  Property: {support_props[0].name}={support_props[0].value}")

    def test_augmentation_adds_support_period_end_spdx(self, sample_backend_metadata):
        """Test that augmentation adds support_period_end to SPDX."""
        from datetime import datetime

        from spdx_tools.spdx.model import CreationInfo, Document, Package, Relationship, RelationshipType

        from sbomify_action.augmentation import augment_spdx_sbom

        # Add support_period_end to backend metadata
        metadata_with_support = dict(sample_backend_metadata)
        metadata_with_support["support_period_end"] = "2028-12-31"

        # Create a minimal SPDX document
        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-sbom",
            document_namespace="https://example.com/test-support",
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

        # Augment with support period
        augmented_doc = augment_spdx_sbom(document, metadata_with_support)

        # Check external reference was added
        main_package = augmented_doc.packages[0]
        support_refs = [ref for ref in main_package.external_references if ref.reference_type == "support-end-date"]
        assert len(support_refs) == 1, "Should have one support-end-date external reference"
        assert support_refs[0].locator == "2028-12-31"

        print("\nSupport Period End Augmentation Results (SPDX):")
        print(f"  Support end date: {support_refs[0].locator}")

    def test_augmentation_adds_release_date_cyclonedx(self, sample_backend_metadata):
        """Test that augmentation adds release_date to CycloneDX 1.5+ SBOM.

        Release date is added as both a named lifecycle and property.
        """
        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Add release_date to backend metadata
        metadata_with_release = dict(sample_backend_metadata)
        metadata_with_release["release_date"] = "2024-06-15"

        # Create a CycloneDX 1.6 BOM
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augment with release date
        augmented_bom = augment_cyclonedx_sbom(bom, metadata_with_release, spec_version="1.6")

        # Check property was added (using official CycloneDX property taxonomy)
        props = list(augmented_bom.metadata.properties)
        release_props = [p for p in props if p.name == "cdx:lifecycle:milestone:generalAvailability"]
        assert len(release_props) == 1, "Should have one cdx:lifecycle:milestone:generalAvailability property"
        assert release_props[0].value == "2024-06-15"

        print("\nRelease Date Augmentation Results (CycloneDX 1.6):")
        print(f"  Property: {release_props[0].name}={release_props[0].value}")

    def test_augmentation_adds_end_of_life_cyclonedx(self, sample_backend_metadata):
        """Test that augmentation adds end_of_life to CycloneDX 1.5+ SBOM.

        End of life date is added as both a named lifecycle and property.
        """
        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Add end_of_life to backend metadata
        metadata_with_eol = dict(sample_backend_metadata)
        metadata_with_eol["end_of_life"] = "2028-12-31"

        # Create a CycloneDX 1.6 BOM
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:cccccccc-cccc-cccc-cccc-cccccccccccc",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augment with end of life
        augmented_bom = augment_cyclonedx_sbom(bom, metadata_with_eol, spec_version="1.6")

        # Check property was added (using official CycloneDX property taxonomy)
        props = list(augmented_bom.metadata.properties)
        eol_props = [p for p in props if p.name == "cdx:lifecycle:milestone:endOfLife"]
        assert len(eol_props) == 1, "Should have one cdx:lifecycle:milestone:endOfLife property"
        assert eol_props[0].value == "2028-12-31"

        print("\nEnd of Life Augmentation Results (CycloneDX 1.6):")
        print(f"  Property: {eol_props[0].name}={eol_props[0].value}")

    def test_augmentation_adds_release_date_cyclonedx_14(self, sample_backend_metadata):
        """Test that release_date works for CycloneDX 1.4 (property only)."""
        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Add release_date to backend metadata
        metadata_with_release = dict(sample_backend_metadata)
        metadata_with_release["release_date"] = "2024-06-15"

        # Create a CycloneDX 1.4 BOM
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:dddddddd-dddd-dddd-dddd-dddddddddddd",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": [{"vendor": "test", "name": "test-tool", "version": "1.0"}],
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augment with release date
        augmented_bom = augment_cyclonedx_sbom(bom, metadata_with_release, spec_version="1.4")

        # Check property was added (using official CycloneDX property taxonomy)
        props = list(augmented_bom.metadata.properties)
        release_props = [p for p in props if p.name == "cdx:lifecycle:milestone:generalAvailability"]
        assert len(release_props) == 1, "Should have one cdx:lifecycle:milestone:generalAvailability property"
        assert release_props[0].value == "2024-06-15"

        print("\nRelease Date Results (CycloneDX 1.4):")
        print(f"  Property: {release_props[0].name}={release_props[0].value}")

    def test_augmentation_adds_release_date_spdx(self, sample_backend_metadata):
        """Test that augmentation adds release_date to SPDX."""
        from datetime import datetime

        from spdx_tools.spdx.model import CreationInfo, Document, Package, Relationship, RelationshipType

        from sbomify_action.augmentation import augment_spdx_sbom

        # Add release_date to backend metadata
        metadata_with_release = dict(sample_backend_metadata)
        metadata_with_release["release_date"] = "2024-06-15"

        # Create a minimal SPDX document
        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-sbom",
            document_namespace="https://example.com/test-release",
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

        # Augment with release date
        augmented_doc = augment_spdx_sbom(document, metadata_with_release)

        # Check external reference was added
        main_package = augmented_doc.packages[0]
        release_refs = [ref for ref in main_package.external_references if ref.reference_type == "release-date"]
        assert len(release_refs) == 1, "Should have one release-date external reference"
        assert release_refs[0].locator == "2024-06-15"

        print("\nRelease Date Augmentation Results (SPDX):")
        print(f"  Release date: {release_refs[0].locator}")

    def test_augmentation_adds_end_of_life_spdx(self, sample_backend_metadata):
        """Test that augmentation adds end_of_life to SPDX."""
        from datetime import datetime

        from spdx_tools.spdx.model import CreationInfo, Document, Package, Relationship, RelationshipType

        from sbomify_action.augmentation import augment_spdx_sbom

        # Add end_of_life to backend metadata
        metadata_with_eol = dict(sample_backend_metadata)
        metadata_with_eol["end_of_life"] = "2028-12-31"

        # Create a minimal SPDX document
        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-sbom",
            document_namespace="https://example.com/test-eol",
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

        # Augment with end of life
        augmented_doc = augment_spdx_sbom(document, metadata_with_eol)

        # Check external reference was added
        main_package = augmented_doc.packages[0]
        eol_refs = [ref for ref in main_package.external_references if ref.reference_type == "end-of-life-date"]
        assert len(eol_refs) == 1, "Should have one end-of-life-date external reference"
        assert eol_refs[0].locator == "2028-12-31"

        print("\nEnd of Life Augmentation Results (SPDX):")
        print(f"  End of life date: {eol_refs[0].locator}")

    def test_augmentation_adds_all_lifecycle_dates_cyclonedx(self, sample_backend_metadata):
        """Test that augmentation adds all lifecycle dates together to CycloneDX 1.6."""
        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Add all lifecycle dates to backend metadata
        metadata_with_all = dict(sample_backend_metadata)
        metadata_with_all["release_date"] = "2024-06-15"
        metadata_with_all["support_period_end"] = "2026-12-31"
        metadata_with_all["end_of_life"] = "2028-12-31"

        # Create a CycloneDX 1.6 BOM
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augment with all lifecycle dates
        augmented_bom = augment_cyclonedx_sbom(bom, metadata_with_all, spec_version="1.6")

        # Check all properties were added (using official CycloneDX property taxonomy)
        props = list(augmented_bom.metadata.properties)
        prop_names = [p.name for p in props]
        assert "cdx:lifecycle:milestone:generalAvailability" in prop_names, (
            "Should have cdx:lifecycle:milestone:generalAvailability property"
        )
        assert "cdx:lifecycle:milestone:endOfSupport" in prop_names, (
            "Should have cdx:lifecycle:milestone:endOfSupport property"
        )
        assert "cdx:lifecycle:milestone:endOfLife" in prop_names, (
            "Should have cdx:lifecycle:milestone:endOfLife property"
        )

        print("\nAll Lifecycle Dates Augmentation Results (CycloneDX 1.6):")
        print(f"  Properties: {prop_names}")


class TestEnrichmentAndAugmentationProduceNTIACompliance:
    """Test that enrichment + augmentation produces NTIA-compliant output.

    NTIA compliance requires BOTH:
    - Enrichment: adds component-level metadata (publisher/supplier, description, licenses)
    - Augmentation: adds organizational metadata (authors, supplier at metadata level)

    These tests verify the complete pipeline produces compliant output.
    """

    @pytest.fixture
    def backend_metadata_with_authors(self):
        """Backend metadata that includes authors (Person entities)."""
        return {
            "supplier": {
                "name": "Acme Corporation",
                "url": ["https://acme.example.com"],
                "contact": [
                    {"name": "Security Team", "email": "security@acme.example.com"},
                ],
            },
            "authors": [
                {"name": "John Doe", "email": "john@acme.example.com"},
                {"name": "Jane Smith", "email": "jane@acme.example.com"},
            ],
            "licenses": ["MIT"],
        }

    @pytest.fixture
    def mock_pypi_response(self):
        """Mock PyPI API response with publisher/author info."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "author": "Kenneth Reitz",
                "author_email": "me@kennethreitz.org",
                "summary": "Python HTTP for Humans.",
                "home_page": "https://requests.readthedocs.io",
                "license": "Apache-2.0",
                "project_urls": {
                    "Source": "https://github.com/psf/requests",
                },
            },
        }
        return mock_response

    def test_enrichment_and_augmentation_produce_ntia_compliant_cyclonedx(
        self, backend_metadata_with_authors, mock_pypi_response, tmp_path
    ):
        """Test that enrichment + augmentation produces NTIA-compliant CycloneDX.

        Pipeline: scanner output → enrichment (adds publisher) → augmentation (adds authors)
        """
        from unittest.mock import patch

        from sbomify_action.augmentation import augment_cyclonedx_sbom
        from sbomify_action.enrichment import clear_cache, enrich_sbom

        clear_cache()

        # Create scanner output - has PURL but no publisher or authors
        scanner_output = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "trivy", "version": "0.50.0"}]},
                # No authors - typical scanner output
            },
            "components": [
                {
                    "type": "library",
                    "bom-ref": "pkg:pypi/requests@2.31.0",
                    "name": "requests",
                    "version": "2.31.0",
                    "purl": "pkg:pypi/requests@2.31.0",
                    # No publisher - typical scanner output
                },
            ],
            "dependencies": [{"ref": "pkg:pypi/requests@2.31.0", "dependsOn": []}],
        }

        # Write scanner output to file
        input_file = tmp_path / "scanner-output.cdx.json"
        with open(input_file, "w") as f:
            json.dump(scanner_output, f)

        # Verify scanner output is NOT NTIA-compliant
        is_compliant_before, _, missing_before = NTIAComplianceChecker.check_cyclonedx(scanner_output)
        assert not is_compliant_before, f"Scanner output should NOT be compliant. Missing: {missing_before}"
        assert "Supplier Name" in missing_before, "Should be missing supplier (scanner doesn't add this)"
        assert "Author of SBOM Data" in missing_before, "Should be missing authors"

        # Step 1: Enrichment - adds publisher from PyPI
        enriched_file = tmp_path / "enriched.cdx.json"
        with patch("requests.Session.get", return_value=mock_pypi_response):
            enrich_sbom(str(input_file), str(enriched_file), validate=False)

        # Load enriched SBOM
        with open(enriched_file) as f:
            enriched_sbom = json.load(f)

        # Verify enrichment added publisher
        components = enriched_sbom.get("components", [])
        requests_component = next((c for c in components if c.get("name") == "requests"), {})
        assert requests_component.get("publisher"), f"Enrichment should add publisher. Got: {requests_component}"

        # Step 2: Augmentation - adds authors from backend
        bom = Bom.from_json(enriched_sbom)
        augmented_bom = augment_cyclonedx_sbom(bom, backend_metadata_with_authors, spec_version="1.6")

        # Serialize final SBOM
        from cyclonedx.output.json import JsonV1Dot6

        outputter = JsonV1Dot6(augmented_bom)
        final_sbom = json.loads(outputter.output_as_string())

        # Verify NTIA compliance after full pipeline
        is_compliant, present, missing = NTIAComplianceChecker.check_cyclonedx(final_sbom)

        assert is_compliant, f"Enriched + Augmented SBOM should be NTIA-compliant. Missing: {missing}"
        assert "Supplier Name" in present, "Supplier should be present (from enrichment)"
        assert "Author of SBOM Data" in present, "Authors should be present (from augmentation)"
        assert "Timestamp" in present, "Timestamp should be present"
        assert "Dependency Relationships" in present, "Dependencies should be present"

        # Verify specific values
        authors = final_sbom.get("metadata", {}).get("authors", [])
        author_names = [a.get("name", "") for a in authors]
        assert "John Doe" in author_names, f"Backend author should be added. Got: {author_names}"

    def test_enrichment_and_augmentation_produce_ntia_compliant_spdx(
        self, backend_metadata_with_authors, mock_pypi_response, tmp_path
    ):
        """Test that enrichment + augmentation produces NTIA-compliant SPDX.

        Pipeline: scanner output → enrichment (adds originator) → augmentation (adds authors)
        """
        from datetime import datetime
        from unittest.mock import patch

        from spdx_tools.spdx.model import (
            Actor,
            ActorType,
            CreationInfo,
            Document,
            ExternalPackageRef,
            ExternalPackageRefCategory,
            Package,
            Relationship,
            RelationshipType,
        )
        from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

        from sbomify_action.augmentation import augment_spdx_sbom
        from sbomify_action.enrichment import clear_cache, enrich_sbom

        clear_cache()

        # Create scanner output - has PURL but no supplier or entity authors
        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-sbom",
            document_namespace="https://example.com/test-pipeline",
            creators=[Actor(ActorType.TOOL, "trivy-0.50.0")],  # Only tool, no person/org
            created=datetime(2024, 1, 1, 0, 0, 0),
        )

        # Main package - in real scenarios would have PURL from COMPONENT_PURL env var
        main_package = Package(
            spdx_id="SPDXRef-main",
            name="my-app",
            download_location="https://example.com/download",
            version="1.0.0",
        )
        # Add PURL - simulates COMPONENT_PURL being set or scanner detecting published package
        main_package.external_references.append(
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator="pkg:generic/myorg/my-app@1.0.0",
            )
        )

        dep_package = Package(
            spdx_id="SPDXRef-requests",
            name="requests",
            download_location="https://pypi.org/project/requests/",
            version="2.31.0",
            # No supplier/originator - typical scanner output
        )
        dep_package.external_references.append(
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator="pkg:pypi/requests@2.31.0",
            )
        )

        document = Document(
            creation_info=creation_info,
            packages=[main_package, dep_package],
            relationships=[
                Relationship(
                    spdx_element_id="SPDXRef-DOCUMENT",
                    relationship_type=RelationshipType.DESCRIBES,
                    related_spdx_element_id="SPDXRef-main",
                ),
                Relationship(
                    spdx_element_id="SPDXRef-main",
                    relationship_type=RelationshipType.DEPENDS_ON,
                    related_spdx_element_id="SPDXRef-requests",
                ),
            ],
        )

        # Write scanner output to file
        input_file = tmp_path / "scanner-output.spdx.json"
        spdx_write_file(document, str(input_file), validate=False)

        # Verify scanner output is NOT NTIA-compliant
        with open(input_file) as f:
            scanner_sbom = json.load(f)
        is_compliant_before, _, missing_before = NTIAComplianceChecker.check_spdx(scanner_sbom)
        assert not is_compliant_before, f"Scanner output should NOT be compliant. Missing: {missing_before}"
        assert "Author of SBOM Data" in missing_before, "Should be missing authors (only Tool creator)"

        # Step 1: Enrichment - adds originator from PyPI
        enriched_file = tmp_path / "enriched.spdx.json"
        with patch("requests.Session.get", return_value=mock_pypi_response):
            enrich_sbom(str(input_file), str(enriched_file), validate=False)

        # Load enriched document for augmentation
        from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file

        enriched_doc = spdx_parse_file(str(enriched_file))

        # Step 2: Augmentation - adds authors from backend
        augmented_doc = augment_spdx_sbom(enriched_doc, backend_metadata_with_authors)

        # Write final SBOM
        final_file = tmp_path / "final.spdx.json"
        spdx_write_file(augmented_doc, str(final_file), validate=False)
        with open(final_file) as f:
            final_sbom = json.load(f)

        # Verify NTIA compliance after full pipeline
        is_compliant, present, missing = NTIAComplianceChecker.check_spdx(final_sbom)

        assert is_compliant, f"Enriched + Augmented SBOM should be NTIA-compliant. Missing: {missing}"
        assert "Supplier Name" in present, "Supplier should be present"
        assert "Author of SBOM Data" in present, "Authors should be present (from augmentation)"
        assert "Timestamp" in present, "Timestamp should be present"
        assert "Dependency Relationships" in present, "Dependencies should be present"

        # Verify entity authors were added (not just tools)
        creators = final_sbom.get("creationInfo", {}).get("creators", [])
        entity_creators = [c for c in creators if not c.startswith("Tool:")]
        assert len(entity_creators) > 0, f"Should have Person/Organization creators. Got: {creators}"

    def test_augmentation_adds_entity_authors_not_just_tools_spdx(self, backend_metadata_with_authors, tmp_path):
        """Test that SPDX augmentation adds Person/Organization authors, not just tools.

        Per NTIA standard: "Author of SBOM Data" is the entity that creates the SBOM.
        Tools are software, not entities. This test verifies augmentation adds
        proper entity authors.
        """
        from datetime import datetime

        from spdx_tools.spdx.model import (
            Actor,
            ActorType,
            CreationInfo,
            Document,
            Package,
        )
        from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

        from sbomify_action.augmentation import augment_spdx_sbom

        # Create SPDX with only Tool creators
        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-sbom",
            document_namespace="https://example.com/test-entity-authors",
            creators=[Actor(ActorType.TOOL, "scanner-1.0")],
            created=datetime(2024, 1, 1, 0, 0, 0),
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
            relationships=[],
        )

        # Augment
        augmented_doc = augment_spdx_sbom(document, backend_metadata_with_authors)

        # Verify Person creators were added
        person_creators = [c for c in augmented_doc.creation_info.creators if c.actor_type == ActorType.PERSON]
        org_creators = [c for c in augmented_doc.creation_info.creators if c.actor_type == ActorType.ORGANIZATION]

        # Should have Person authors from backend metadata
        assert len(person_creators) >= 2, (
            f"Should have Person creators from backend authors. Got: {[str(c) for c in person_creators]}"
        )

        # Verify the actual names
        person_names = [c.name for c in person_creators]
        assert any("John Doe" in name for name in person_names), f"John Doe should be in creators. Got: {person_names}"
        assert any("Jane Smith" in name for name in person_names), (
            f"Jane Smith should be in creators. Got: {person_names}"
        )

        # Also verify supplier was added as Organization
        assert len(org_creators) >= 1, f"Should have Organization creator. Got: {[str(c) for c in org_creators]}"

        # Write and verify JSON compliance
        output_file = tmp_path / "entity-authors.spdx.json"
        spdx_write_file(augmented_doc, str(output_file), validate=False)
        with open(output_file) as f:
            augmented_sbom = json.load(f)

        is_compliant, present, _ = NTIAComplianceChecker.check_spdx(augmented_sbom)
        assert "Author of SBOM Data" in present, "Should pass NTIA author check with Person/Org creators"

    def test_augmentation_preserves_valid_iso8601_timestamp_cyclonedx(self, backend_metadata_with_authors):
        """Test that CycloneDX augmentation preserves valid ISO-8601 timestamps.

        NTIA requires ISO-8601 timestamps. This test verifies augmentation
        doesn't break existing valid timestamps.
        """
        from cyclonedx.output.json import JsonV1Dot6

        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Create BOM with valid ISO-8601 timestamp
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "version": 1,
            "metadata": {
                "timestamp": "2024-06-15T14:30:00Z",  # Valid ISO-8601
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augment
        augmented_bom = augment_cyclonedx_sbom(bom, backend_metadata_with_authors, spec_version="1.6")

        # Serialize and check
        outputter = JsonV1Dot6(augmented_bom)
        augmented_sbom = json.loads(outputter.output_as_string())

        # Verify timestamp is still valid ISO-8601
        timestamp = augmented_sbom.get("metadata", {}).get("timestamp", "")
        assert ISO8601_REGEX.match(timestamp), f"Timestamp should be valid ISO-8601. Got: {timestamp}"

        # Verify overall compliance
        is_compliant, present, _ = NTIAComplianceChecker.check_cyclonedx(augmented_sbom)
        assert "Timestamp" in present, "Timestamp should pass validation"


class TestNTIAEdgeCases:
    """Test edge cases that were previously not covered by NTIA tests."""

    def test_pypi_author_email_without_author(self, tmp_path):
        """Test that packages with empty author but valid author_email get supplier.

        This tests the uri-template scenario: author="" but author_email="Peter Linss <email>"
        """
        from sbomify_action.enrichment import clear_cache, enrich_sbom

        clear_cache()

        # Create SBOM with a package that will be looked up
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [
                {
                    "type": "library",
                    "name": "test-package",
                    "version": "1.0.0",
                    "purl": "pkg:pypi/test-package@1.0.0",
                    "bom-ref": "pkg:pypi/test-package@1.0.0",
                },
            ],
            "dependencies": [{"ref": "pkg:pypi/test-package@1.0.0", "dependsOn": []}],
        }

        input_file = tmp_path / "test.cdx.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.cdx.json"

        # Mock PyPI response with empty author but valid author_email (like uri-template)
        def mock_get(url, *args, **kwargs):
            mock_response = Mock()
            if "pypi.org/pypi/" in url:
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "info": {
                        "summary": "Test package description",
                        "author": "",  # Empty author!
                        "author_email": "Test Author <test@example.com>",  # But valid author_email
                        "maintainer": "",
                        "maintainer_email": "",
                        "license": "MIT",
                        "home_page": "https://example.com",
                    }
                }
            else:
                mock_response.status_code = 404
            return mock_response

        with patch("requests.Session.get", side_effect=mock_get):
            enrich_sbom(str(input_file), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        # Verify the component got publisher from author_email (extracted name: "Test Author")
        component = enriched_data["components"][0]
        assert component.get("publisher") == "Test Author", (
            f"Expected publisher 'Test Author' from author_email, got: {component.get('publisher')}"
        )

    def test_lockfile_components_have_version(self, tmp_path):
        """Test that lockfile components get version after enrichment.

        Previously, lockfiles were excluded from NTIA checks but they should
        still have compliant metadata including version.
        """
        from sbomify_action.enrichment import clear_cache, enrich_sbom

        clear_cache()

        # Create SBOM with lockfile component (no version, no purl)
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
                "component": {
                    "type": "application",
                    "name": "my-project",
                    "version": "1.2.3",
                },
            },
            "components": [
                {
                    "type": "application",
                    "name": "uv.lock",
                    "bom-ref": "lockfile-uv",
                    # No version, no purl - this is how Trivy generates lockfile components
                },
            ],
            "dependencies": [{"ref": "lockfile-uv", "dependsOn": []}],
        }

        input_file = tmp_path / "test.cdx.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.cdx.json"

        # Mock all external calls to 404
        mock_response = Mock()
        mock_response.status_code = 404

        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(input_file), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        # Find the lockfile component
        lockfile_component = next(
            (c for c in enriched_data["components"] if c.get("name") == "uv.lock"),
            None,
        )

        assert lockfile_component is not None, "Lockfile component should still exist"
        assert lockfile_component.get("version"), "Lockfile should have version after enrichment"
        assert lockfile_component.get("description"), "Lockfile should have description after enrichment"

    def test_root_component_gets_supplier_from_augmentation(self, tmp_path):
        """Test that root component (metadata.component) gets supplier from backend metadata.

        Previously, augmentation set metadata.supplier but not metadata.component.supplier.
        """
        from cyclonedx.model.bom import Bom

        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Create a minimal CycloneDX BOM with a root component but no supplier
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
                "component": {
                    "type": "application",
                    "name": "my-project",
                    "version": "1.0.0",
                    # No supplier!
                },
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augmentation data from backend
        augmentation_data = {
            "supplier": {
                "name": "My Company Inc",
                "url": ["https://mycompany.com"],
            },
        }

        # Augment the BOM
        augmented_bom = augment_cyclonedx_sbom(bom, augmentation_data, spec_version="1.6")

        # Verify both metadata.supplier AND metadata.component.supplier are set
        assert augmented_bom.metadata.supplier is not None, "metadata.supplier should be set"
        assert augmented_bom.metadata.supplier.name == "My Company Inc"

        assert augmented_bom.metadata.component is not None, "metadata.component should exist"
        assert augmented_bom.metadata.component.supplier is not None, (
            "metadata.component.supplier should be propagated from backend"
        )
        assert augmented_bom.metadata.component.supplier.name == "My Company Inc"

    def test_self_referencing_component_gets_supplier(self, tmp_path):
        """Test that self-referencing components (project's own package in dependencies) get supplier.

        When a project scans itself, it may include its own package as a dependency.
        This package won't be found in external registries, so it should inherit
        supplier from the root component.
        """
        from sbomify_action.enrichment import clear_cache, enrich_sbom

        clear_cache()

        # Create SBOM where the project includes itself as a dependency
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:44444444-4444-4444-4444-444444444444",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
                "component": {
                    "type": "application",
                    "name": "my-project",
                    "version": "1.0.0",
                },
                "supplier": {
                    "name": "My Company Inc",
                    "url": ["https://mycompany.com"],
                },
            },
            "components": [
                {
                    "type": "library",
                    "name": "my-project",  # Same as root component name!
                    "version": "1.0.0",
                    "purl": "pkg:pypi/my-project@1.0.0",
                    "bom-ref": "pkg:pypi/my-project@1.0.0",
                    # No publisher - this is the project itself, won't be found in PyPI
                },
            ],
            "dependencies": [{"ref": "pkg:pypi/my-project@1.0.0", "dependsOn": []}],
        }

        input_file = tmp_path / "test.cdx.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.cdx.json"

        # Mock all external calls to 404 (package not found - it's a private project)
        mock_response = Mock()
        mock_response.status_code = 404

        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(input_file), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        # Find the self-referencing component
        self_component = next(
            (c for c in enriched_data["components"] if c.get("name") == "my-project"),
            None,
        )

        assert self_component is not None, "Self-referencing component should exist"
        assert self_component.get("publisher") == "My Company Inc", (
            f"Self-referencing component should inherit publisher from root. Got: {self_component.get('publisher')}"
        )

    def test_ecosystems_uses_platform_as_supplier(self, tmp_path):
        """Test that ecosyste.ms uses distribution platform as supplier.

        The distribution platform (PyPI, npm, etc.) is the supplier, not the
        individual package author/maintainer.
        """
        import requests
        from packageurl import PackageURL

        from sbomify_action._enrichment.sources.ecosystems import EcosystemsSource

        # Create mock response with ecosystem and maintainer
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "ecosystem": "pypi",
                "description": "Test package",
                "normalized_licenses": ["MIT"],
                "maintainers": [
                    {"login": "testuser", "name": None}  # Maintainer info preserved in maintainer_name
                ],
            }
        ]

        source = EcosystemsSource()
        session = requests.Session()

        with patch.object(session, "get", return_value=mock_response):
            purl = PackageURL.from_string("pkg:pypi/test-package@1.0.0")
            metadata = source.fetch(purl, session)

        # Supplier should be the distribution platform
        assert metadata is not None
        assert metadata.supplier == "Python Package Index (PyPI)", (
            f"Should use platform as supplier. Got: {metadata.supplier}"
        )
        # Maintainer info is preserved separately
        assert metadata.maintainer_name == "testuser"
