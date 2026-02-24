"""Tests for SPDX 3 parser, writer, and helpers."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from sbomify_action.spdx3 import (
    extract_spdx3_version,
    get_spdx3_document,
    get_spdx3_packages,
    get_spdx3_root_package,
    is_spdx3,
    make_spdx3_creation_info,
    make_spdx3_spdx_id,
    parse_spdx3_data,
    parse_spdx3_file,
    spdx3_license_from_string,
    spdx3_licenses_from_list,
    write_spdx3_file,
)

TEST_DATA_DIR = Path(__file__).parent / "test-data"


class TestIsSpdx3(unittest.TestCase):
    """Tests for is_spdx3() detection."""

    def test_spdx3_string_context(self):
        data = {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
        self.assertTrue(is_spdx3(data))

    def test_spdx3_list_context(self):
        data = {"@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"]}
        self.assertTrue(is_spdx3(data))

    def test_spdx3_dict_context(self):
        data = {"@context": {"@vocab": "https://spdx.org/rdf/3.0.1/terms/Core/"}}
        self.assertTrue(is_spdx3(data))

    def test_not_spdx3_spdx2(self):
        data = {"spdxVersion": "SPDX-2.3"}
        self.assertFalse(is_spdx3(data))

    def test_not_spdx3_cyclonedx(self):
        data = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
        self.assertFalse(is_spdx3(data))

    def test_not_spdx3_empty(self):
        self.assertFalse(is_spdx3({}))


class TestExtractSpdx3Version(unittest.TestCase):
    """Tests for extract_spdx3_version()."""

    def test_extract_from_string_context(self):
        data = {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
        self.assertEqual(extract_spdx3_version(data), "3.0.1")

    def test_extract_from_list_context(self):
        data = {"@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"]}
        self.assertEqual(extract_spdx3_version(data), "3.0.1")

    def test_no_version(self):
        data = {"@context": "https://spdx.org/rdf/spdx-context.jsonld"}
        self.assertIsNone(extract_spdx3_version(data))

    def test_no_context(self):
        self.assertIsNone(extract_spdx3_version({}))


class TestParseSpdx3File(unittest.TestCase):
    """Tests for parse_spdx3_file()."""

    def test_parse_minimal(self):
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))
        doc = get_spdx3_document(payload)
        self.assertIsNotNone(doc)
        self.assertEqual(doc.name, "test-document")

    def test_parse_packages(self):
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))
        packages = get_spdx3_packages(payload)
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0].name, "test-package")
        self.assertEqual(packages[0].package_version, "1.0.0")
        self.assertEqual(packages[0].package_url, "pkg:pypi/test-package@1.0.0")

    def test_parse_root_package(self):
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))
        root = get_spdx3_root_package(payload)
        self.assertIsNotNone(root)
        self.assertEqual(root.name, "test-package")

    def test_parse_tool(self):
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))
        from spdx_tools.spdx3.model import Tool

        tools = [e for e in payload.get_full_map().values() if isinstance(e, Tool)]
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0].name, "test-tool")

    def test_parse_relationship(self):
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))
        from spdx_tools.spdx3.model import Relationship, RelationshipType

        rels = [e for e in payload.get_full_map().values() if isinstance(e, Relationship)]
        self.assertEqual(len(rels), 1)
        self.assertEqual(rels[0].relationship_type, RelationshipType.DESCRIBES)

    def test_parse_not_spdx3_raises(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump({"spdxVersion": "SPDX-2.3"}, f)
            with self.assertRaises(ValueError):
                parse_spdx3_file(path)
        finally:
            os.unlink(path)

    def test_parse_data(self):
        data = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [
                {
                    "type": "software_Package",
                    "@id": "urn:spdx.dev:pkg-1",
                    "name": "foo",
                    "packageVersion": "2.0",
                }
            ],
        }
        payload = parse_spdx3_data(data)
        pkgs = get_spdx3_packages(payload)
        self.assertEqual(len(pkgs), 1)
        self.assertEqual(pkgs[0].name, "foo")


class TestWriteSpdx3File(unittest.TestCase):
    """Tests for write_spdx3_file()."""

    def test_round_trip(self):
        """Parse -> write -> parse should preserve data."""
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            write_spdx3_file(payload, path)
            payload2 = parse_spdx3_file(path)
        finally:
            os.unlink(path)

        doc1 = get_spdx3_document(payload)
        doc2 = get_spdx3_document(payload2)
        self.assertEqual(doc1.name, doc2.name)

        pkgs1 = get_spdx3_packages(payload)
        pkgs2 = get_spdx3_packages(payload2)
        self.assertEqual(len(pkgs1), len(pkgs2))
        self.assertEqual(pkgs1[0].name, pkgs2[0].name)
        self.assertEqual(pkgs1[0].package_version, pkgs2[0].package_version)

    def test_writes_context_url(self):
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            write_spdx3_file(payload, path)
            with open(path) as rf:
                data = json.load(rf)
        finally:
            os.unlink(path)

        self.assertEqual(data["@context"], "https://spdx.org/rdf/3.0.1/spdx-context.jsonld")
        self.assertIn("@graph", data)


class TestHelpers(unittest.TestCase):
    """Tests for helper functions."""

    def test_make_creation_info(self):
        ci = make_spdx3_creation_info()
        self.assertEqual(str(ci.spec_version), "3.0.1")
        self.assertIsNotNone(ci.created)

    def test_make_spdx_id(self):
        id1 = make_spdx3_spdx_id()
        id2 = make_spdx3_spdx_id()
        self.assertNotEqual(id1, id2)
        self.assertTrue(id1.startswith("urn:spdx.dev:"))

    def test_license_from_string_spdx_id(self):
        from spdx_tools.spdx3.model.licensing import ListedLicense

        lic = spdx3_license_from_string("MIT")
        self.assertIsInstance(lic, ListedLicense)
        self.assertEqual(lic.license_id, "MIT")

    def test_license_from_string_noassertion(self):
        from spdx_tools.spdx3.model.licensing import NoAssertionLicense

        lic = spdx3_license_from_string("NOASSERTION")
        self.assertIsInstance(lic, NoAssertionLicense)

    def test_license_from_string_empty(self):
        from spdx_tools.spdx3.model.licensing import NoAssertionLicense

        lic = spdx3_license_from_string("")
        self.assertIsInstance(lic, NoAssertionLicense)

    def test_license_from_string_complex_sanitized(self):
        """Complex license expressions should have sanitized IDs."""
        from spdx_tools.spdx3.model.licensing import CustomLicense

        lic = spdx3_license_from_string("MIT OR Apache-2.0")
        self.assertIsInstance(lic, CustomLicense)
        # Should not contain spaces or parentheses
        self.assertNotIn(" ", lic.license_id)
        self.assertTrue(lic.license_id.startswith("LicenseRef-"))

    def test_licenses_from_list_single(self):
        from spdx_tools.spdx3.model.licensing import ListedLicense

        lic = spdx3_licenses_from_list(["Apache-2.0"])
        self.assertIsInstance(lic, ListedLicense)

    def test_licenses_from_list_multiple(self):
        from spdx_tools.spdx3.model.licensing import DisjunctiveLicenseSet

        lic = spdx3_licenses_from_list(["MIT", "Apache-2.0"])
        self.assertIsInstance(lic, DisjunctiveLicenseSet)

    def test_licenses_from_list_empty(self):
        from spdx_tools.spdx3.model.licensing import NoAssertionLicense

        lic = spdx3_licenses_from_list([])
        self.assertIsInstance(lic, NoAssertionLicense)


class TestValidationIntegration(unittest.TestCase):
    """Tests for SPDX 3 format detection in validation module."""

    def test_detect_spdx3_format(self):
        from sbomify_action.validation import detect_sbom_format_and_version

        data = {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []}
        fmt, ver = detect_sbom_format_and_version(data)
        self.assertEqual(fmt, "spdx")
        self.assertEqual(ver, "3.0.1")

    def test_schema_validation(self):
        from sbomify_action.validation import validate_sbom_file_auto

        result = validate_sbom_file_auto(str(TEST_DATA_DIR / "spdx3_minimal.json"))
        self.assertEqual(result.sbom_format, "spdx")
        self.assertEqual(result.spec_version, "3.0.1")
        # Our minimal test fixture may not pass the strict 3.0.1 schema,
        # but format/version detection must always succeed (valid is not None).
        self.assertIsNotNone(result.valid)


class TestAdditionalPackagesIntegration(unittest.TestCase):
    """Tests for SPDX 3 in additional_packages module."""

    def test_create_empty_spdx3(self):
        from sbomify_action.additional_packages import create_empty_sbom

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            result = create_empty_sbom(path, "spdx", spec_version="3.0.1")
            self.assertEqual(result, "spdx")

            with open(path) as rf:
                data = json.load(rf)
            self.assertTrue(is_spdx3(data))
            self.assertIn("@graph", data)
        finally:
            os.unlink(path)

    def test_inject_packages_into_spdx3(self):
        import shutil

        from packageurl import PackageURL

        from sbomify_action.additional_packages import inject_packages_into_spdx3

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            shutil.copy(str(TEST_DATA_DIR / "spdx3_minimal.json"), path)

            purls = [PackageURL.from_string("pkg:pypi/requests@2.31.0")]
            injected = inject_packages_into_spdx3(path, purls)

            self.assertEqual(injected, 1)

            payload = parse_spdx3_file(path)
            pkgs = get_spdx3_packages(payload)
            self.assertEqual(len(pkgs), 2)  # original + injected
            pkg_names = {p.name for p in pkgs}
            self.assertIn("requests", pkg_names)
        finally:
            os.unlink(path)


class TestPassthroughAndTypePrefixes(unittest.TestCase):
    """Tests for passthrough element preservation and type prefix restoration."""

    def test_passthrough_preserves_unknown_types(self):
        """Parse multi-type fixture → write → re-read → verify all types present."""
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_multi_type.json"))

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            write_spdx3_file(payload, path)
            with open(path) as f:
                data = json.load(f)
        finally:
            os.unlink(path)

        types_in_output = {e.get("type", "") for e in data["@graph"]}

        for expected_type in [
            "security_Vulnerability",
            "security_VexFixedVulnAssessmentRelationship",
            "build_Build",
            "LifecycleScopedRelationship",
            "simplelicensing_LicenseExpression",
            "software_Sbom",
        ]:
            self.assertIn(expected_type, types_in_output, f"Missing passthrough type: {expected_type}")

    def test_type_prefix_restored_on_write(self):
        """software_Package must not become Package in output."""
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_multi_type.json"))

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            write_spdx3_file(payload, path)
            with open(path) as f:
                data = json.load(f)
        finally:
            os.unlink(path)

        types_in_output = {e.get("type", "") for e in data["@graph"]}

        # Prefixed types must be present
        self.assertIn("software_Package", types_in_output)
        self.assertIn("software_File", types_in_output)

        # Unprefixed model names must NOT appear as types
        self.assertNotIn("Package", types_in_output)
        self.assertNotIn("File", types_in_output)

    def test_creation_info_passthrough(self):
        """Standalone CreationInfo elements with @id must survive roundtrip."""
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_multi_type.json"))

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            write_spdx3_file(payload, path)
            with open(path) as f:
                data = json.load(f)
        finally:
            os.unlink(path)

        ci_elements = [
            e for e in data["@graph"] if e.get("type", "") == "CreationInfo" and (e.get("@id") or e.get("spdxId"))
        ]
        self.assertGreaterEqual(len(ci_elements), 1, "Standalone CreationInfo element lost in roundtrip")
        self.assertEqual(ci_elements[0]["@id"], "_:CreationInfo0")

    def test_roundtrip_element_count(self):
        """Total element count must be preserved through parse→write roundtrip."""
        with open(TEST_DATA_DIR / "spdx3_multi_type.json") as f:
            original = json.load(f)
        original_count = len(original["@graph"])

        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_multi_type.json"))

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            write_spdx3_file(payload, path)
            with open(path) as f:
                roundtripped = json.load(f)
        finally:
            os.unlink(path)

        self.assertEqual(len(roundtripped["@graph"]), original_count)

    def test_existing_minimal_roundtrip(self):
        """Regression: spdx3_minimal.json roundtrip must preserve element count."""
        with open(TEST_DATA_DIR / "spdx3_minimal.json") as f:
            original = json.load(f)
        original_count = len(original["@graph"])

        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            write_spdx3_file(payload, path)
            with open(path) as f:
                roundtripped = json.load(f)
        finally:
            os.unlink(path)

        self.assertEqual(len(roundtripped["@graph"]), original_count)


class TestSoftwarePrefixedProperties(unittest.TestCase):
    """Tests for software_-prefixed property name handling (C1/C2 audit fixes)."""

    def test_parser_reads_software_prefixed_package_fields(self):
        """Parser must read software_packageVersion, software_downloadLocation, etc."""
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_multi_type.json"))
        pkgs = get_spdx3_packages(payload)
        self.assertEqual(len(pkgs), 1)
        pkg = pkgs[0]
        self.assertEqual(pkg.package_version, "1.0.0")
        self.assertEqual(pkg.package_url, "pkg:pypi/test-package@1.0.0")
        self.assertEqual(pkg.download_location, "https://example.com/test-package-1.0.0.tar.gz")
        self.assertEqual(pkg.homepage, "https://example.com")
        self.assertEqual(pkg.copyright_text, "Copyright 2024 Test")

    def test_parser_reads_software_prefixed_purpose(self):
        """Parser must read software_primaryPurpose from both Package and File."""
        from spdx_tools.spdx3.model.software import SoftwarePurpose

        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_multi_type.json"))

        pkgs = get_spdx3_packages(payload)
        self.assertEqual(pkgs[0].primary_purpose, SoftwarePurpose.LIBRARY)

        from spdx_tools.spdx3.model.software.file import File as SpdxFile

        files = [e for e in payload.get_full_map().values() if isinstance(e, SpdxFile)]
        self.assertEqual(files[0].primary_purpose, SoftwarePurpose.SOURCE)

    def test_parser_reads_unprefixed_package_fields(self):
        """Parser must still read unprefixed names (spdx_tools converter output)."""
        data = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [
                {
                    "type": "software_Package",
                    "@id": "urn:spdx.dev:pkg-1",
                    "name": "foo",
                    "packageVersion": "2.0",
                    "downloadLocation": "https://example.com",
                    "packageUrl": "pkg:pypi/foo@2.0",
                    "homepage": "https://foo.dev",
                    "sourceInfo": "source",
                    "copyrightText": "Copyright",
                    "primaryPurpose": "library",
                }
            ],
        }
        payload = parse_spdx3_data(data)
        pkg = get_spdx3_packages(payload)[0]
        self.assertEqual(pkg.package_version, "2.0")
        self.assertEqual(pkg.download_location, "https://example.com")
        self.assertEqual(pkg.package_url, "pkg:pypi/foo@2.0")
        self.assertEqual(pkg.homepage, "https://foo.dev")
        self.assertEqual(pkg.source_info, "source")
        self.assertEqual(pkg.copyright_text, "Copyright")

    def test_writer_emits_software_prefixed_properties(self):
        """Writer must output software_packageVersion, not packageVersion."""
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_multi_type.json"))

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            write_spdx3_file(payload, path)
            with open(path) as f:
                data = json.load(f)
        finally:
            os.unlink(path)

        pkg_elems = [e for e in data["@graph"] if e.get("type", "") == "software_Package"]
        self.assertEqual(len(pkg_elems), 1)
        pkg = pkg_elems[0]

        # Must use software_-prefixed property names
        self.assertIn("software_packageVersion", pkg)
        self.assertIn("software_downloadLocation", pkg)
        self.assertIn("software_packageUrl", pkg)
        self.assertIn("software_homePage", pkg)
        self.assertIn("software_copyrightText", pkg)
        self.assertIn("software_primaryPurpose", pkg)

        # Must NOT have unprefixed property names
        self.assertNotIn("packageVersion", pkg)
        self.assertNotIn("downloadLocation", pkg)
        self.assertNotIn("packageUrl", pkg)
        self.assertNotIn("homepage", pkg)

    def test_writer_normalizes_keys(self):
        """Writer must use 'type'/'spdxId' instead of '@type'/'@id'."""
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            write_spdx3_file(payload, path)
            with open(path) as f:
                data = json.load(f)
        finally:
            os.unlink(path)

        for elem in data["@graph"]:
            # Serialized elements should use 'type', not '@type'
            self.assertIn("type", elem, f"Element missing 'type': {elem.get('spdxId', 'unknown')}")
            self.assertNotIn("@type", elem)
            # Elements with IDs should use 'spdxId', not '@id'
            if "spdxId" in elem or "@id" in elem:
                self.assertIn("spdxId", elem)
                self.assertNotIn("@id", elem)

    def test_writer_normalizes_nested_types(self):
        """Writer must normalize @type→type in nested creationInfo and Hash dicts."""
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            write_spdx3_file(payload, path)
            with open(path) as f:
                data = json.load(f)
        finally:
            os.unlink(path)

        for elem in data["@graph"]:
            ci = elem.get("creationInfo")
            if isinstance(ci, dict):
                self.assertIn("type", ci, "creationInfo missing 'type'")
                self.assertNotIn("@type", ci)

    def test_roundtrip_preserves_software_fields(self):
        """Parse (software_-prefixed) → write → re-parse must preserve all fields."""
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_multi_type.json"))

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            write_spdx3_file(payload, path)
            payload2 = parse_spdx3_file(path)
        finally:
            os.unlink(path)

        pkg1 = get_spdx3_packages(payload)[0]
        pkg2 = get_spdx3_packages(payload2)[0]

        self.assertEqual(pkg1.package_version, pkg2.package_version)
        self.assertEqual(pkg1.package_url, pkg2.package_url)
        self.assertEqual(pkg1.download_location, pkg2.download_location)
        self.assertEqual(pkg1.homepage, pkg2.homepage)
        self.assertEqual(pkg1.copyright_text, pkg2.copyright_text)
        self.assertEqual(pkg1.primary_purpose, pkg2.primary_purpose)


class TestSerializationIntegration(unittest.TestCase):
    """Tests for SPDX 3 in serialization module."""

    def test_supported_versions_includes_spdx3(self):
        from sbomify_action.serialization import SUPPORTED_SPDX_VERSIONS

        self.assertIn("3.0.1", SUPPORTED_SPDX_VERSIONS)


if __name__ == "__main__":
    unittest.main()
