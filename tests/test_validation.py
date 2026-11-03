"""Tests for SBOM validation module."""

import json
import tempfile
import unittest
from pathlib import Path

from sbomify_action.spdx3 import extract_spdx3_version
from sbomify_action.validation import (
    ValidationResult,
    detect_sbom_format_and_version,
    validate_sbom_data,
    validate_sbom_file,
    validate_sbom_file_auto,
)


class TestValidationResult(unittest.TestCase):
    """Tests for ValidationResult dataclass."""

    def test_success_result(self):
        """Test creating a success result."""
        result = ValidationResult.success("cyclonedx", "1.6")
        self.assertTrue(result.valid)
        self.assertEqual(result.sbom_format, "cyclonedx")
        self.assertEqual(result.spec_version, "1.6")
        self.assertIsNone(result.error_message)

    def test_failure_result(self):
        """Test creating a failure result."""
        result = ValidationResult.failure("cyclonedx", "1.6", "Test error", error_path="components.0.name")
        self.assertFalse(result.valid)
        self.assertEqual(result.error_message, "Test error")
        self.assertEqual(result.error_path, "components.0.name")


class TestDetectSBOMFormatAndVersion(unittest.TestCase):
    """Tests for detect_sbom_format_and_version function."""

    def test_detect_cyclonedx(self):
        """Test detecting CycloneDX format."""
        data = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
        format, version = detect_sbom_format_and_version(data)
        self.assertEqual(format, "cyclonedx")
        self.assertEqual(version, "1.6")

    def test_detect_spdx(self):
        """Test detecting SPDX format."""
        data = {"spdxVersion": "SPDX-2.3"}
        format, version = detect_sbom_format_and_version(data)
        self.assertEqual(format, "spdx")
        self.assertEqual(version, "2.3")

    def test_detect_unknown_format(self):
        """Test detecting unknown format."""
        data = {"unknown": "format"}
        format, version = detect_sbom_format_and_version(data)
        self.assertIsNone(format)
        self.assertIsNone(version)

    def test_detect_cyclonedx_no_version(self):
        """Test CycloneDX without version."""
        data = {"bomFormat": "CycloneDX"}
        format, version = detect_sbom_format_and_version(data)
        self.assertEqual(format, "cyclonedx")
        self.assertIsNone(version)


class TestValidateSBOMData(unittest.TestCase):
    """Tests for validate_sbom_data function."""

    def test_valid_cyclonedx_minimal(self):
        """Test validating minimal valid CycloneDX."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
        }
        result = validate_sbom_data(data, "cyclonedx", "1.6")
        self.assertTrue(result.valid)

    def test_valid_cyclonedx_1_3_minimal(self):
        """Test validating minimal valid CycloneDX 1.3."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "version": 1,
        }
        result = validate_sbom_data(data, "cyclonedx", "1.3")
        self.assertTrue(result.valid)

    def test_invalid_cyclonedx_wrong_type(self):
        """Test validating CycloneDX with wrong field type."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": "not_an_integer",  # Should be integer
        }
        result = validate_sbom_data(data, "cyclonedx", "1.6")
        self.assertFalse(result.valid)
        self.assertIsNotNone(result.error_message)

    def test_valid_spdx_minimal(self):
        """Test validating minimal valid SPDX."""
        data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {
                "created": "2023-01-01T00:00:00Z",
                "creators": ["Tool: test"],
            },
        }
        result = validate_sbom_data(data, "spdx", "2.3")
        self.assertTrue(result.valid)


class TestValidateSBOMFile(unittest.TestCase):
    """Tests for validate_sbom_file function."""

    def test_file_not_found(self):
        """Test validating non-existent file."""
        result = validate_sbom_file("/nonexistent/file.json", "cyclonedx", "1.6")
        self.assertFalse(result.valid)
        self.assertIn("not found", result.error_message.lower())

    def test_invalid_json(self):
        """Test validating file with invalid JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {")
            temp_path = f.name

        try:
            result = validate_sbom_file(temp_path, "cyclonedx", "1.6")
            self.assertFalse(result.valid)
            self.assertIn("invalid json", result.error_message.lower())
        finally:
            Path(temp_path).unlink()

    def test_valid_file(self):
        """Test validating valid SBOM file."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            result = validate_sbom_file(temp_path, "cyclonedx", "1.6")
            self.assertTrue(result.valid)
        finally:
            Path(temp_path).unlink()


class TestValidateSBOMFileAuto(unittest.TestCase):
    """Tests for validate_sbom_file_auto function."""

    def test_auto_detect_cyclonedx(self):
        """Test auto-detecting and validating CycloneDX."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            result = validate_sbom_file_auto(temp_path)
            self.assertTrue(result.valid)
            self.assertEqual(result.sbom_format, "cyclonedx")
            self.assertEqual(result.spec_version, "1.6")
        finally:
            Path(temp_path).unlink()

    def test_auto_detect_spdx(self):
        """Test auto-detecting and validating SPDX."""
        data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {
                "created": "2023-01-01T00:00:00Z",
                "creators": ["Tool: test"],
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            result = validate_sbom_file_auto(temp_path)
            self.assertTrue(result.valid)
            self.assertEqual(result.sbom_format, "spdx")
            self.assertEqual(result.spec_version, "2.3")
        finally:
            Path(temp_path).unlink()

    def test_file_not_found(self):
        """Test auto-validating non-existent file."""
        result = validate_sbom_file_auto("/nonexistent/file.json")
        self.assertFalse(result.valid)
        self.assertIn("not found", result.error_message.lower())

    def test_unknown_format(self):
        """Test auto-validating file with unknown format."""
        data = {"unknown": "format"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            result = validate_sbom_file_auto(temp_path)
            self.assertFalse(result.valid)
            self.assertIn("could not detect", result.error_message.lower())
        finally:
            Path(temp_path).unlink()


class TestValidationWithSPDXLicenses(unittest.TestCase):
    """Tests for CycloneDX validation with SPDX license IDs.

    These tests verify that the schema registry correctly resolves
    the spdx.schema.json reference without fetching remote schemas.
    This was the root cause of the 'Unresolvable: spdx.schema.json' bug.
    """

    def test_cyclonedx_with_spdx_license_id(self):
        """Test validating CycloneDX with SPDX license ID (MIT)."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "test-package",
                    "version": "1.0.0",
                    "licenses": [{"license": {"id": "MIT"}}],
                }
            ],
        }
        result = validate_sbom_data(data, "cyclonedx", "1.6")
        self.assertTrue(result.valid, f"Validation failed: {result.error_message}")

    def test_cyclonedx_with_multiple_spdx_licenses(self):
        """Test validating CycloneDX with multiple SPDX license IDs."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "test-package",
                    "version": "1.0.0",
                    "licenses": [
                        {"license": {"id": "Apache-2.0"}},
                        {"license": {"id": "GPL-3.0-only"}},
                    ],
                }
            ],
        }
        result = validate_sbom_data(data, "cyclonedx", "1.6")
        self.assertTrue(result.valid, f"Validation failed: {result.error_message}")

    def test_cyclonedx_with_named_license(self):
        """Test validating CycloneDX with named license (non-SPDX)."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "test-package",
                    "version": "1.0.0",
                    "licenses": [{"license": {"name": "Custom License"}}],
                }
            ],
        }
        result = validate_sbom_data(data, "cyclonedx", "1.6")
        self.assertTrue(result.valid, f"Validation failed: {result.error_message}")

    def test_cyclonedx_1_5_with_spdx_license(self):
        """Test validating CycloneDX 1.5 with SPDX license ID."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "test-package",
                    "version": "1.0.0",
                    "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                }
            ],
        }
        result = validate_sbom_data(data, "cyclonedx", "1.5")
        self.assertTrue(result.valid, f"Validation failed: {result.error_message}")

    def test_cyclonedx_1_4_with_spdx_license(self):
        """Test validating CycloneDX 1.4 with SPDX license ID."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "test-package",
                    "version": "1.0.0",
                    "licenses": [{"license": {"id": "ISC"}}],
                }
            ],
        }
        result = validate_sbom_data(data, "cyclonedx", "1.4")
        self.assertTrue(result.valid, f"Validation failed: {result.error_message}")

    def test_cyclonedx_with_invalid_spdx_license(self):
        """Test validating CycloneDX with invalid SPDX license ID."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "test-package",
                    "version": "1.0.0",
                    "licenses": [{"license": {"id": "NOT-A-VALID-SPDX-ID"}}],
                }
            ],
        }
        result = validate_sbom_data(data, "cyclonedx", "1.6")
        # Should fail validation because the license ID is not in the SPDX list
        self.assertFalse(result.valid)
        self.assertIsNotNone(result.error_message)


class TestSchemaRegistry(unittest.TestCase):
    """Tests for the schema registry functionality."""

    def test_registry_caching(self):
        """Test that the schema registry is cached."""
        from sbomify_action.validation import _get_schema_registry

        registry1 = _get_schema_registry()
        registry2 = _get_schema_registry()
        # Should return the same cached instance
        self.assertIs(registry1, registry2)

    def test_registry_contains_spdx_schema(self):
        """Test that the registry contains the SPDX license schema."""
        from sbomify_action.validation import _get_schema_registry

        registry = _get_schema_registry()
        # The registry should be able to resolve the SPDX schema URI
        # This is the URI referenced by CycloneDX schemas
        uri = "http://cyclonedx.org/schema/spdx.schema.json"
        # Try to get the resource - should not raise
        retrieved = registry.get_or_retrieve(uri)
        self.assertIsNotNone(retrieved)


class TestValidationWithRealSchemas(unittest.TestCase):
    """Tests using real schema files from the project."""

    def test_validate_real_cyclonedx_file(self):
        """Test validating a real CycloneDX test file."""
        test_file = Path(__file__).parent / "test-data" / "trivy.cdx.json"
        if test_file.exists():
            result = validate_sbom_file_auto(str(test_file))
            # The test file should be valid
            self.assertTrue(result.valid, f"Validation failed: {result.error_message}")
            self.assertEqual(result.sbom_format, "cyclonedx")

    def test_validate_real_spdx_file(self):
        """Test validating a real SPDX test file."""
        test_file = Path(__file__).parent / "test-data" / "trivy.spdx.json"
        if test_file.exists():
            result = validate_sbom_file_auto(str(test_file))
            # The test file should be valid
            self.assertTrue(result.valid, f"Validation failed: {result.error_message}")
            self.assertEqual(result.sbom_format, "spdx")


class TestSPDX300IsCheckedNotSkipped(unittest.TestCase):
    """3.0 and 3.0.1 are separate documents, not a version label on one.

    Only 3.0.1 was bundled, so a 3.0 document validated as "skipped" and
    passed through unchecked while the README said otherwise. 3.0 is what
    syft, Microsoft sbom-tool, JFrog Xray and Zephyr emit, and what the
    published Yocto 5.1 image SBOM declares.
    """

    FIXTURE = Path(__file__).parent / "test-data" / "spdx3_conformant.json"

    def _document(self, version: str, file_extra: dict | None = None) -> dict:
        document = json.loads(self.FIXTURE.read_text())
        document["@context"] = f"https://spdx.org/rdf/{version}/spdx-context.jsonld"
        for element in document["@graph"]:
            if element.get("type") == "CreationInfo":
                element["specVersion"] = version
        if file_extra:
            document["@graph"].append(
                {
                    "type": "software_File",
                    "spdxId": "urn:acme:file1",
                    "creationInfo": "_:creationinfo",
                    "name": "README",
                    **file_extra,
                }
            )
        return document

    def test_a_valid_300_document_is_valid(self):
        result = validate_sbom_data(self._document("3.0.0"), "spdx", "3.0.0")

        self.assertIs(result.valid, True, result.error_message or "skipped rather than checked")

    def test_an_invalid_300_document_says_so(self):
        document = self._document("3.0.0")
        document["@graph"].append({"type": "software_Package", "spdxId": "urn:acme:p2", "nonsense": True})

        result = validate_sbom_data(document, "spdx", "3.0.0")

        self.assertIs(result.valid, False, "a skip reports valid=None, which is not a rejection")
        self.assertTrue(result.error_message)

    def test_the_real_yocto_51_image_is_detected_as_300(self):
        """It declares the 3.0.0 context, which is why it was never checked."""
        document = {"@context": "https://spdx.org/rdf/3.0.0/spdx-context.jsonld", "@graph": []}

        self.assertEqual(detect_sbom_format_and_version(document), ("spdx", "3.0.0"))

    def test_the_two_schemas_are_not_interchangeable(self):
        """3.0.1 renamed File.software_contentType to contentType, so each
        schema rejects what the other requires. Pointing 3.0 at the 3.0.1
        schema would fail documents that are correct."""
        as_300 = self._document("3.0.0", {"software_contentType": "text/plain"})
        as_301 = self._document("3.0.1", {"contentType": "text/plain"})

        self.assertIs(validate_sbom_data(as_300, "spdx", "3.0.0").valid, True)
        self.assertIs(validate_sbom_data(as_300, "spdx", "3.0.1").valid, False)
        self.assertIs(validate_sbom_data(as_301, "spdx", "3.0.1").valid, True)
        self.assertIs(validate_sbom_data(as_301, "spdx", "3.0.0").valid, False)


class TestAnUnknownSPDX3VersionFails(unittest.TestCase):
    """A skip is how every SPDX 3 document reached the upload unchecked.

    Refusing means a version nobody has bundled yet is a loud failure rather
    than a silent pass, which is the safer default for a format still adding
    versions.
    """

    def test_it_fails_rather_than_skipping(self):
        result = validate_sbom_data({"@graph": []}, "spdx", "3.1.0")

        self.assertIs(result.valid, False, "a skip reports valid=None, which is not a rejection")

    def test_the_message_names_the_version_and_what_to_send(self):
        result = validate_sbom_data({"@graph": []}, "spdx", "3.1.0")

        self.assertIn("3.1.0", result.error_message)
        self.assertIn("3.0.1", result.error_message)

    def test_it_does_not_refuse_a_version_it_claims_to_accept(self):
        """The wording came from the backend, where "3.0.x" is true because
        its schema takes a semver pattern. Here a schema is chosen by exact
        key, so 3.0.2 is refused, and the sentence was refusing a 3.0.x while
        claiming to accept 3.0.x."""
        result = validate_sbom_data({"@graph": []}, "spdx", "3.0.2")

        self.assertIs(result.valid, False)
        self.assertNotIn("3.0.x", result.error_message)

    def test_the_list_is_what_is_bundled_rather_than_a_written_out_one(self):
        """So bundling a version updates the sentence with it."""
        from sbomify_action.validation import SPDX_SCHEMAS

        message = validate_sbom_data({"@graph": []}, "spdx", "3.1.0").error_message

        for version in SPDX_SCHEMAS:
            if version == "3.0":  # the alias key, not a version anyone sends
                continue
            self.assertIn(version, message)

    def test_an_unbundled_spdx_2_version_still_only_skips(self):
        """2.1 predates every reader here and nothing claims to check it, so
        this deliberately keeps the old behaviour."""
        result = validate_sbom_data({"spdxVersion": "SPDX-2.1"}, "spdx", "2.1")

        self.assertIsNone(result.valid)


class TestSPDX31IsRejectedByName(unittest.TestCase):
    """SPDX 3.1 is at RC1, BSI accepts released versions only, and the backend
    refuses it, so shipping it here would need a backend change first.

    Both spellings used to end somewhere unhelpful. `/rdf/3.1/` carries no
    patch number, so the version regex found nothing and the document failed
    as "Could not detect spdx spec version", naming neither SPDX nor 3.1.
    `/rdf/3.1.0/` fell through to the unvalidated-skip path.
    """

    FIXTURE = Path(__file__).parent / "test-data" / "spdx3_conformant.json"

    def _document(self, context_version: str, spec_version: str | None) -> dict:
        document = json.loads(self.FIXTURE.read_text())
        document["@context"] = f"https://spdx.org/rdf/{context_version}/spdx-context.jsonld"
        for element in document["@graph"]:
            if element.get("type") == "CreationInfo":
                if spec_version is None:
                    element.pop("specVersion", None)
                else:
                    element["specVersion"] = spec_version
        return document

    def _validate(self, document: dict) -> ValidationResult:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sbom.json"
            path.write_text(json.dumps(document))
            return validate_sbom_file_auto(str(path))

    def test_an_unversioned_31_context_is_named(self):
        result = self._validate(self._document("3.1", None))

        self.assertIs(result.valid, False)
        self.assertIn("SPDX 3.1 is not supported", result.error_message)

    def test_a_310_context_is_named_too(self):
        result = self._validate(self._document("3.1.0", "3.1.0"))

        self.assertIs(result.valid, False)
        self.assertIn("SPDX 3.1.0 is not supported", result.error_message)

    def test_it_no_longer_reads_as_an_undetectable_version(self):
        result = self._validate(self._document("3.1", None))

        self.assertNotIn("Could not detect", result.error_message)

    def test_the_wording_matches_the_backend(self):
        """A user who hits both the action and the upload should hear one
        answer, not two.

        Matched in shape rather than character for character. The backend says
        it accepts "3.0.x", which is true there because its schema takes a
        semver pattern; here a schema is chosen by exact key, so repeating the
        phrase meant refusing a 3.0.x while claiming to accept 3.0.x. The
        version list is the one part that has to be this tool's own, and a
        message that contradicts the tool it lives in is worse than one that
        differs from its sibling.
        """
        result = self._validate(self._document("3.1", None))

        self.assertIn("is not supported. sbomify accepts SPDX", result.error_message)
        self.assertIn("BSI TR-03183-2", result.error_message)

    def test_301_still_processes(self):
        self.assertIs(self._validate(self._document("3.0.1", "3.0.1")).valid, True)

    def test_300_still_processes(self):
        self.assertIs(self._validate(self._document("3.0.0", "3.0.0")).valid, True)


class TestTheVersionTheDocumentStates(unittest.TestCase):
    """`CreationInfo_props` requires specVersion and every Element requires a
    creationInfo, so a conformant document always states its version. That is
    the normative claim; the @context is a resolution hint, and it can be an
    unversioned alias.
    """

    def test_spec_version_beats_the_context(self):
        document = {
            "@context": "https://spdx.org/rdf/3.0/spdx-context.jsonld",
            "@graph": [{"type": "CreationInfo", "specVersion": "3.0.0"}],
        }

        self.assertEqual(extract_spdx3_version(document), "3.0.0")

    def test_the_context_is_the_fallback(self):
        document = {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []}

        self.assertEqual(extract_spdx3_version(document), "3.0.1")

    def test_a_two_part_context_is_read_rather_than_ignored(self):
        """The regex wanted three dotted numbers, so the alias read as no
        version at all and surfaced as "could not detect"."""
        document = {"@context": "https://spdx.org/rdf/3.1/spdx-context.jsonld", "@graph": []}

        self.assertEqual(extract_spdx3_version(document), "3.1")

    def test_a_spec_version_on_anything_else_does_not_speak_for_the_document(self):
        """This answer chooses the schema the whole document is held to."""
        document = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [{"type": "software_Package", "specVersion": "9.9.9"}],
        }

        self.assertEqual(extract_spdx3_version(document), "3.0.1")

    def test_an_inline_creation_info_counts(self):
        document = {
            "@context": "https://spdx.org/rdf/3.0/spdx-context.jsonld",
            "@graph": [{"type": "SpdxDocument", "creationInfo": {"specVersion": "3.0.1"}}],
        }

        self.assertEqual(extract_spdx3_version(document), "3.0.1")


class TestTheUnversionedContextAlias(unittest.TestCase):
    """`https://spdx.org/rdf/3.0/spdx-context.jsonld` resolves, and is
    byte-identical to the 3.0.1 context today.

    It cannot be validated against either schema, and not because of anything
    this repo chose: both official schemas pin `@context` with a `const` to
    their own fully qualified URL, so SPDX itself says a conformant document
    names a released version. What this can do is reach that answer instead of
    "could not detect spec version".
    """

    def test_both_schemas_pin_their_own_context(self):
        for version in ("3.0.0", "3.0.1"):
            schema = json.loads(
                (
                    Path(__file__).parent.parent / "sbomify_action" / "schemas" / "spdx" / f"spdx-{version}.schema.json"
                ).read_text()
            )

            self.assertEqual(
                schema["properties"]["@context"]["const"],
                f"https://spdx.org/rdf/{version}/spdx-context.jsonld",
            )

    def test_the_error_names_the_context_to_use(self):
        document = {
            "@context": "https://spdx.org/rdf/3.0/spdx-context.jsonld",
            "@graph": [
                {
                    "type": "CreationInfo",
                    "@id": "_:ci",
                    "specVersion": "3.0.0",
                    "created": "2026-01-01T00:00:00Z",
                    "createdBy": ["urn:a"],
                }
            ],
        }

        result = validate_sbom_data(document, "spdx", extract_spdx3_version(document))

        self.assertIs(result.valid, False)
        self.assertIn("https://spdx.org/rdf/3.0.0/spdx-context.jsonld", result.error_message)

    def test_it_is_not_reported_as_an_unsupported_version(self):
        """3.0.0 is supported. The alias is the problem, so saying "SPDX 3.0
        is not supported" would send the user to fix the wrong thing."""
        document = {"@context": "https://spdx.org/rdf/3.0/spdx-context.jsonld", "@graph": []}

        result = validate_sbom_data(document, "spdx", extract_spdx3_version(document))

        self.assertNotIn("is not supported", result.error_message or "")


if __name__ == "__main__":
    unittest.main()
