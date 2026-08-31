"""Tests for the console module."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sbomify_action.console import (
    BRAND_COLORS,
    BRAND_COLORS_ADAPTIVE,
    BRAND_COLORS_HEX,
    IS_CI,
    IS_GITHUB_ACTIONS,
    AuditEntry,
    AuditTrail,
    TransformationTracker,
    _audit_path,
    console,
    get_audit_trail,
    get_transformation_tracker,
    gha_error,
    gha_group,
    gha_notice,
    gha_warning,
    print_banner,
    print_duplicate_sbom_error,
    print_enrichment_summary,
    print_final_failure,
    print_final_success,
    print_sanitization_summary,
    print_step_end,
    print_step_header,
    print_summary_table,
    print_transformation_summary,
    print_upload_summary,
    reset_audit_trail,
    reset_transformation_tracker,
)


class TestBrandColors(unittest.TestCase):
    """Tests for brand color constants."""

    def test_brand_colors_defined(self):
        """Test that all brand colors are defined."""
        expected_colors = ["blue", "purple_light", "purple", "pink", "peach", "orange"]
        for color in expected_colors:
            self.assertIn(color, BRAND_COLORS)
            self.assertIn(color, BRAND_COLORS_HEX)
            self.assertIn(color, BRAND_COLORS_ADAPTIVE)

    def test_brand_colors_hex_are_valid_hex(self):
        """Test that hex colors are valid hex format."""
        for name, color in BRAND_COLORS_HEX.items():
            self.assertTrue(color.startswith("#"), f"{name} should start with #")
            self.assertEqual(len(color), 7, f"{name} should be 7 chars (#RRGGBB)")

    def test_brand_colors_adaptive_are_ansi_names(self):
        """Test that adaptive colors are standard ANSI color names."""
        valid_ansi_colors = {
            "black",
            "red",
            "green",
            "yellow",
            "blue",
            "magenta",
            "cyan",
            "white",
            "bright_black",
            "bright_red",
            "bright_green",
            "bright_yellow",
            "bright_blue",
            "bright_magenta",
            "bright_cyan",
            "bright_white",
        }
        for name, color in BRAND_COLORS_ADAPTIVE.items():
            self.assertIn(
                color, valid_ansi_colors, f"{name}: '{color}' should be a valid ANSI color name for theme adaptability"
            )

    def test_brand_colors_selected_based_on_ci(self):
        """Test that BRAND_COLORS is selected based on CI environment."""
        # BRAND_COLORS should be either HEX or ADAPTIVE based on IS_CI
        if IS_CI:
            self.assertEqual(BRAND_COLORS, BRAND_COLORS_ADAPTIVE)
        else:
            self.assertEqual(BRAND_COLORS, BRAND_COLORS_HEX)


class TestCIDetection(unittest.TestCase):
    """Tests for CI environment detection."""

    def test_ci_detection_constants_exist(self):
        """Test that CI detection constants are defined."""
        # These are boolean values
        self.assertIsInstance(IS_CI, bool)
        self.assertIsInstance(IS_GITHUB_ACTIONS, bool)


class TestConsoleInstance(unittest.TestCase):
    """Tests for the shared console instance."""

    def test_console_exists(self):
        """Test that console instance is created."""
        self.assertIsNotNone(console)


class TestPrintBanner(unittest.TestCase):
    """Tests for print_banner function."""

    def test_print_banner_runs(self):
        """Test that print_banner runs without error."""
        # Just verify it doesn't raise an exception
        print_banner("1.0.0")

    def test_print_banner_unknown_version(self):
        """Test that print_banner works with unknown version."""
        print_banner("unknown")


class TestStepHeader(unittest.TestCase):
    """Tests for step header functions."""

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}, clear=False)
    def test_step_header_local(self):
        """Test step header in local mode."""
        # Should not raise
        print_step_header(1, "Test Step")

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=False)
    def test_step_header_gha(self):
        """Test step header in GitHub Actions mode."""
        with patch("builtins.print") as mock_print:
            # Re-import to get fresh GHA detection
            from sbomify_action import console as c

            # Force GHA detection
            original = c.IS_GITHUB_ACTIONS
            c.IS_GITHUB_ACTIONS = True
            try:
                c.print_step_header(1, "Test Step")
                # Should have printed ::group::
                mock_print.assert_called()
            finally:
                c.IS_GITHUB_ACTIONS = original


class TestStepEnd(unittest.TestCase):
    """Tests for step end function."""

    def test_step_end_success(self):
        """Test step end with success."""
        print_step_end(1, success=True)

    def test_step_end_failure(self):
        """Test step end with failure."""
        print_step_end(1, success=False)


class TestGHAAnnotations(unittest.TestCase):
    """Tests for GitHub Actions annotation functions."""

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}, clear=False)
    def test_gha_warning_local(self):
        """Test gha_warning in local mode."""
        gha_warning("Test warning")
        gha_warning("Test warning with title", title="Warning Title")

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}, clear=False)
    def test_gha_error_local(self):
        """Test gha_error in local mode."""
        gha_error("Test error")
        gha_error("Test error with title", title="Error Title")

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}, clear=False)
    def test_gha_notice_local(self):
        """Test gha_notice in local mode."""
        gha_notice("Test notice")
        gha_notice("Test notice with title", title="Notice Title")

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=False)
    def test_gha_warning_gha_mode(self):
        """Test gha_warning in GitHub Actions mode."""
        with patch("builtins.print") as mock_print:
            from sbomify_action import console as c

            original = c.IS_GITHUB_ACTIONS
            c.IS_GITHUB_ACTIONS = True
            try:
                c.gha_warning("Test warning")
                mock_print.assert_called_with("::warning::Test warning")
            finally:
                c.IS_GITHUB_ACTIONS = original

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=False)
    def test_gha_error_gha_mode(self):
        """Test gha_error in GitHub Actions mode."""
        with patch("builtins.print") as mock_print:
            from sbomify_action import console as c

            original = c.IS_GITHUB_ACTIONS
            c.IS_GITHUB_ACTIONS = True
            try:
                c.gha_error("Test error")
                mock_print.assert_called_with("::error::Test error")
            finally:
                c.IS_GITHUB_ACTIONS = original


class TestGHAGroup(unittest.TestCase):
    """Tests for gha_group context manager."""

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}, clear=False)
    def test_gha_group_local(self):
        """Test gha_group in local mode."""
        with gha_group("Test Group"):
            pass  # Should not raise

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=False)
    def test_gha_group_gha_mode(self):
        """Test gha_group in GitHub Actions mode."""
        with patch("builtins.print") as mock_print:
            from sbomify_action import console as c

            original = c.IS_GITHUB_ACTIONS
            c.IS_GITHUB_ACTIONS = True
            try:
                with c.gha_group("Test Group"):
                    pass
                # Should have printed ::group:: and ::endgroup::
                self.assertEqual(mock_print.call_count, 2)
            finally:
                c.IS_GITHUB_ACTIONS = original


class TestSummaryTable(unittest.TestCase):
    """Tests for summary table function."""

    def test_summary_table_with_data(self):
        """Test summary table with data."""
        data = [("Metric 1", 10), ("Metric 2", 20)]
        print_summary_table("Test Summary", data)

    def test_summary_table_empty(self):
        """Test summary table with empty data."""
        print_summary_table("Test Summary", [])

    def test_summary_table_filters_zeros(self):
        """Test that zeros are filtered by default."""
        data = [("Metric 1", 10), ("Metric 2", 0), ("Metric 3", 5)]
        print_summary_table("Test Summary", data)

    def test_summary_table_show_if_empty(self):
        """Test showing table even with zero values."""
        data = [("Metric 1", 0), ("Metric 2", 0)]
        print_summary_table("Test Summary", data, show_if_empty=True)


class TestEnrichmentSummary(unittest.TestCase):
    """Tests for enrichment summary function."""

    def test_enrichment_summary_basic(self):
        """Test basic enrichment summary."""
        stats = {
            "components_enriched": 45,
            "descriptions_added": 42,
            "licenses_added": 38,
            "publishers_added": 10,
        }
        print_enrichment_summary(stats, 50)

    def test_enrichment_summary_with_sources(self):
        """Test enrichment summary with sources breakdown."""
        stats = {
            "components_enriched": 45,
            "descriptions_added": 42,
            "licenses_added": 38,
            "sources": {"pypi": 20, "depsdev": 15, "ecosystems": 10},
        }
        print_enrichment_summary(stats, 50)

    def test_enrichment_summary_empty(self):
        """Test enrichment summary with empty stats."""
        stats = {"components_enriched": 0}
        print_enrichment_summary(stats, 0)


class TestSanitizationSummary(unittest.TestCase):
    """Tests for sanitization summary function."""

    def test_sanitization_summary_basic(self):
        """Test basic sanitization summary."""
        print_sanitization_summary(
            vcs_normalized=23,
            purls_normalized=5,
            purls_cleared=3,
            urls_rejected=2,
        )

    def test_sanitization_summary_with_details(self):
        """Test sanitization summary with details."""
        details = [
            "VCS: git@github.com:foo/bar -> git+https://github.com/foo/bar",
            "PURL cleared: pkg:npm/foo (missing version)",
        ]
        print_sanitization_summary(
            vcs_normalized=1,
            purls_cleared=1,
            details=details,
        )

    def test_sanitization_summary_empty(self):
        """Test sanitization summary with all zeros."""
        print_sanitization_summary()


class TestUploadSummary(unittest.TestCase):
    """Tests for upload summary function."""

    def test_upload_summary_success(self):
        """Test upload summary for successful upload."""
        print_upload_summary(
            destination="sbomify",
            success=True,
            sbom_format="cyclonedx",
            sbom_id="abc123",
        )

    def test_upload_summary_failure(self):
        """Test upload summary for failed upload."""
        print_upload_summary(
            destination="sbomify",
            success=False,
            sbom_format="cyclonedx",
            error_message="Connection timeout",
        )


class TestDuplicateSbomError(unittest.TestCase):
    """Tests for duplicate SBOM error function."""

    def test_print_duplicate_sbom_error_cyclonedx(self):
        """Test duplicate SBOM error for CycloneDX format."""
        # Should not raise an exception
        print_duplicate_sbom_error(
            component_id="my-component",
            sbom_format="cyclonedx",
        )

    def test_print_duplicate_sbom_error_spdx(self):
        """Test duplicate SBOM error for SPDX format."""
        # Should not raise an exception
        print_duplicate_sbom_error(
            component_id="another-component",
            sbom_format="spdx",
        )

    def test_print_duplicate_sbom_error_with_version(self):
        """Test duplicate SBOM error includes version when provided."""
        # Should not raise an exception
        print_duplicate_sbom_error(
            component_id="my-component",
            sbom_format="cyclonedx",
            component_version="1.2.3",
        )

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "true"})
    def test_print_duplicate_sbom_error_gha(self):
        """Test duplicate SBOM error emits GHA annotation."""
        # Should not raise an exception and emit GHA error
        print_duplicate_sbom_error(
            component_id="test-component",
            sbom_format="cyclonedx",
            component_version="2.0.0",
        )

    @patch("sbomify_action.console.IS_GITHUB_ACTIONS", True)
    def test_print_duplicate_non_sbom_annotation_matches_guidance(self):
        """The GHA annotation for a non-SBOM duplicate must mirror the panel:
        the version to bump lives inside the authored document, and
        COMPONENT_VERSION advice does not apply."""
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            print_duplicate_sbom_error(
                component_id="c1",
                sbom_format="cyclonedx",
                artifact_kind="VEX",
            )
        annotations = [line for line in buf.getvalue().splitlines() if line.startswith("::error")]
        self.assertTrue(annotations)
        self.assertIn("authored document", annotations[0])
        self.assertNotIn("component version", annotations[0])


class TestFinalMessages(unittest.TestCase):
    """Tests for final success/failure messages."""

    def test_final_success(self):
        """Test final success message."""
        print_final_success()

    def test_final_failure(self):
        """Test final failure message."""
        print_final_failure("Test failure message")


class TestTransformationTracker(unittest.TestCase):
    """Tests for the TransformationTracker class."""

    def setUp(self):
        """Reset the global tracker before each test."""
        reset_transformation_tracker()

    def test_tracker_initially_empty(self):
        """Test that a new tracker has no transformations."""
        tracker = TransformationTracker()
        self.assertFalse(tracker.has_transformations())

    def test_record_vcs_normalization(self):
        """Test recording VCS URL normalization."""
        tracker = TransformationTracker()
        tracker.record_vcs_normalization("git@github.com:foo/bar.git", "git+https://github.com/foo/bar")
        self.assertTrue(tracker.has_transformations())
        self.assertEqual(len(tracker.vcs_normalizations), 1)

    def test_record_purl_normalization(self):
        """Test recording PURL normalization."""
        tracker = TransformationTracker()
        tracker.record_purl_normalization("my-package", "pkg:npm/my-package@@1.0.0", "pkg:npm/my-package@1.0.0")
        self.assertTrue(tracker.has_transformations())
        self.assertEqual(len(tracker.purl_normalizations), 1)

    def test_record_purl_cleared(self):
        """Test recording cleared PURL."""
        tracker = TransformationTracker()
        tracker.record_purl_cleared("my-package", "pkg:file:/local/path", "file: scheme not allowed")
        self.assertTrue(tracker.has_transformations())
        self.assertEqual(len(tracker.purls_cleared), 1)

    def test_record_url_rejected(self):
        """Test recording rejected URL."""
        tracker = TransformationTracker()
        tracker.record_url_rejected("homepage", "javascript:alert('xss')", "disallowed scheme: javascript")
        self.assertTrue(tracker.has_transformations())
        self.assertEqual(len(tracker.urls_rejected), 1)

    def test_record_stub_added(self):
        """Test recording stub component added."""
        tracker = TransformationTracker()
        tracker.record_stub_added("pkg:npm/orphan@1.0.0", "orphan", "1.0.0")
        self.assertTrue(tracker.has_transformations())
        self.assertEqual(len(tracker.stubs_added), 1)

    def test_format_details(self):
        """Test formatting transformation details."""
        tracker = TransformationTracker()
        tracker.record_vcs_normalization("git@github.com:a/b", "git+https://github.com/a/b")
        tracker.record_purl_cleared("pkg", "pkg:file:/x", "invalid")

        details = tracker._format_details()
        self.assertEqual(len(details), 2)
        self.assertIn("VCS:", details[0])
        self.assertIn("PURL cleared", details[1])

    def test_print_summary_no_transformations(self):
        """Test that print_summary does nothing when empty."""
        tracker = TransformationTracker()
        # Should not raise
        tracker.print_summary()

    def test_print_summary_with_transformations(self):
        """Test print_summary with transformations."""
        tracker = TransformationTracker()
        tracker.record_vcs_normalization("git@example.com:a/b", "git+https://example.com/a/b")
        # Should not raise
        tracker.print_summary()

    def test_global_tracker_functions(self):
        """Test get_transformation_tracker and reset_transformation_tracker."""
        # Get tracker
        tracker1 = get_transformation_tracker()
        tracker1.record_vcs_normalization("a", "b")

        # Get again should return same instance
        tracker2 = get_transformation_tracker()
        self.assertEqual(len(tracker2.vcs_normalizations), 1)

        # Reset should clear
        tracker3 = reset_transformation_tracker()
        self.assertFalse(tracker3.has_transformations())

    def test_print_transformation_summary(self):
        """Test the convenience function."""
        reset_transformation_tracker()
        tracker = get_transformation_tracker()
        tracker.record_stub_added("ref", "name", "1.0")
        # Should not raise
        print_transformation_summary()


class TestAuditEntry(unittest.TestCase):
    """Tests for the AuditEntry class."""

    def test_format_for_file_basic(self):
        """Test basic file formatting."""
        entry = AuditEntry(
            timestamp="2026-01-18T12:00:00Z",
            category="AUGMENTATION",
            operation="added",
            field="supplier.name",
            new_value="Example Corp",
            source="sbomify-api",
        )
        formatted = entry.format_for_file()
        self.assertIn("[2026-01-18T12:00:00Z]", formatted)
        self.assertIn("AUGMENTATION", formatted)
        self.assertIn("supplier.name", formatted)
        self.assertIn("ADDED", formatted)
        self.assertIn("Example Corp", formatted)
        self.assertIn("sbomify-api", formatted)

    def test_format_for_file_with_component(self):
        """Test file formatting with component."""
        entry = AuditEntry(
            timestamp="2026-01-18T12:00:00Z",
            category="ENRICHMENT",
            operation="added",
            field="description",
            component="pkg:pypi/requests@2.31.0",
            new_value="HTTP library",
            source="pypi",
        )
        formatted = entry.format_for_file()
        self.assertIn("pkg:pypi/requests@2.31.0", formatted)
        self.assertIn("description", formatted)

    def test_format_for_file_with_old_value(self):
        """Test file formatting with old value (modification)."""
        entry = AuditEntry(
            timestamp="2026-01-18T12:00:00Z",
            category="OVERRIDE",
            operation="modified",
            field="component.version",
            old_value="1.0.0",
            new_value="2.0.0",
        )
        formatted = entry.format_for_file()
        self.assertIn("1.0.0", formatted)
        self.assertIn("2.0.0", formatted)
        self.assertIn("->", formatted)

    def test_format_for_file_truncates_long_values(self):
        """Test that very long values are truncated."""
        long_value = "x" * 300
        entry = AuditEntry(
            timestamp="2026-01-18T12:00:00Z",
            category="ENRICHMENT",
            operation="added",
            field="description",
            new_value=long_value,
        )
        formatted = entry.format_for_file()
        self.assertIn("...", formatted)
        self.assertLess(len(formatted), 400)

    def test_format_for_summary(self):
        """Test summary formatting."""
        entry = AuditEntry(
            timestamp="2026-01-18T12:00:00Z",
            category="AUGMENTATION",
            operation="added",
            field="supplier.name",
            new_value="Example Corp",
        )
        summary = entry.format_for_summary()
        self.assertIn("supplier.name", summary)


class TestAuditTrail(unittest.TestCase):
    """Tests for the AuditTrail class."""

    def setUp(self):
        """Reset the global audit trail before each test."""
        reset_audit_trail()

    def test_audit_trail_initially_empty(self):
        """Test that a new audit trail has no changes."""
        trail = AuditTrail()
        self.assertFalse(trail.has_changes())
        self.assertEqual(len(trail.entries), 0)

    def test_record_augmentation(self):
        """Test recording augmentation changes."""
        trail = AuditTrail()
        trail.record_augmentation("supplier.name", "Example Corp")
        self.assertTrue(trail.has_changes())
        self.assertEqual(trail._augmentation_count, 1)
        self.assertEqual(len(trail.entries), 1)
        self.assertEqual(trail.entries[0].category, "AUGMENTATION")

    def test_record_supplier_added(self):
        """Test recording supplier addition."""
        trail = AuditTrail()
        trail.record_supplier_added("ACME Inc")
        self.assertEqual(trail._augmentation_count, 1)
        self.assertIn("supplier.name", trail.entries[0].field)

    def test_record_author_added(self):
        """Test recording author addition."""
        trail = AuditTrail()
        trail.record_author_added("John Doe", "john@example.com")
        self.assertEqual(trail._augmentation_count, 1)
        self.assertIn("John Doe", trail.entries[0].new_value)
        self.assertIn("john@example.com", trail.entries[0].new_value)

    def test_record_enrichment(self):
        """Test recording enrichment changes."""
        trail = AuditTrail()
        trail.record_enrichment("pkg:pypi/requests@2.31.0", "description", "HTTP library", "pypi")
        self.assertTrue(trail.has_changes())
        self.assertEqual(trail._enrichment_count, 1)
        self.assertEqual(trail.entries[0].category, "ENRICHMENT")
        self.assertEqual(trail.entries[0].component, "pkg:pypi/requests@2.31.0")

    def test_record_component_enriched(self):
        """Test recording multiple fields enriched."""
        trail = AuditTrail()
        trail.record_component_enriched("pkg:pypi/requests@2.31.0", ["description", "license", "publisher"], "pypi")
        self.assertEqual(trail._enrichment_count, 3)
        self.assertEqual(len(trail.entries), 3)

    def test_record_override(self):
        """Test recording CLI/env overrides."""
        trail = AuditTrail()
        trail.record_component_version_override("2.0.0", "1.0.0")
        self.assertTrue(trail.has_changes())
        self.assertEqual(trail._override_count, 1)
        self.assertEqual(trail.entries[0].category, "OVERRIDE")
        self.assertEqual(trail.entries[0].old_value, "1.0.0")
        self.assertEqual(trail.entries[0].new_value, "2.0.0")

    def test_record_component_name_override(self):
        """Test recording component name override."""
        trail = AuditTrail()
        trail.record_component_name_override("my-app", "old-name")
        self.assertEqual(trail._override_count, 1)
        self.assertIn("component.name", trail.entries[0].field)

    def test_record_component_purl_override(self):
        """Test recording component PURL override."""
        trail = AuditTrail()
        trail.record_component_purl_override("pkg:npm/my-app@1.0.0")
        self.assertEqual(trail._override_count, 1)
        self.assertIn("component.purl", trail.entries[0].field)

    def test_legacy_compatibility_vcs_normalization(self):
        """Test legacy TransformationTracker compatibility for VCS normalization."""
        trail = AuditTrail()
        trail.record_vcs_normalization("git@github.com:foo/bar", "git+https://github.com/foo/bar")
        # Legacy list should be populated
        self.assertEqual(len(trail.vcs_normalizations), 1)
        # Audit entries should also be created
        self.assertEqual(trail._sanitization_count, 1)
        self.assertEqual(trail.entries[0].category, "SANITIZATION")

    def test_legacy_compatibility_purl_normalization(self):
        """Test legacy TransformationTracker compatibility for PURL normalization."""
        trail = AuditTrail()
        trail.record_purl_normalization("my-pkg", "pkg:npm/my-pkg@@1.0", "pkg:npm/my-pkg@1.0")
        self.assertEqual(len(trail.purl_normalizations), 1)
        self.assertEqual(trail._sanitization_count, 1)

    def test_legacy_compatibility_purl_cleared(self):
        """Test legacy TransformationTracker compatibility for cleared PURLs."""
        trail = AuditTrail()
        trail.record_purl_cleared("my-pkg", "pkg:file:/local/path", "file: scheme not allowed")
        self.assertEqual(len(trail.purls_cleared), 1)
        self.assertEqual(trail._sanitization_count, 1)

    def test_legacy_compatibility_url_rejected(self):
        """Test legacy TransformationTracker compatibility for rejected URLs."""
        trail = AuditTrail()
        trail.record_url_rejected("homepage", "javascript:alert(1)", "disallowed scheme")
        self.assertEqual(len(trail.urls_rejected), 1)
        self.assertEqual(trail._sanitization_count, 1)

    def test_legacy_compatibility_stub_added(self):
        """Test legacy TransformationTracker compatibility for stub components."""
        trail = AuditTrail()
        trail.record_stub_added("pkg:npm/orphan@1.0", "orphan", "1.0")
        self.assertEqual(len(trail.stubs_added), 1)
        self.assertEqual(trail._sanitization_count, 1)

    def test_get_summary_counts(self):
        """Test getting summary counts by category."""
        trail = AuditTrail()
        trail.record_supplier_added("Corp")
        trail.record_author_added("John")
        trail.record_enrichment("pkg:npm/foo@1.0", "desc", "Desc", "npm")
        trail.record_vcs_normalization("a", "b")
        trail.record_component_version_override("2.0")

        counts = trail.get_summary_counts()
        self.assertEqual(counts["augmentation"], 2)
        self.assertEqual(counts["enrichment"], 1)
        self.assertEqual(counts["sanitization"], 1)
        self.assertEqual(counts["override"], 1)
        self.assertEqual(counts["total"], 5)

    def test_get_entries_by_category(self):
        """Test filtering entries by category."""
        trail = AuditTrail()
        trail.record_supplier_added("Corp")
        trail.record_enrichment("pkg:npm/foo@1.0", "desc", "Desc", "npm")
        trail.record_vcs_normalization("a", "b")

        aug_entries = trail.get_entries_by_category("AUGMENTATION")
        self.assertEqual(len(aug_entries), 1)

        enrich_entries = trail.get_entries_by_category("ENRICHMENT")
        self.assertEqual(len(enrich_entries), 1)

        san_entries = trail.get_entries_by_category("SANITIZATION")
        self.assertEqual(len(san_entries), 1)

    def test_write_audit_file(self):
        """Test writing audit trail to file."""
        trail = AuditTrail()
        trail.input_file = "requirements.txt"
        trail.output_file = "sbom_output.json"
        trail.record_supplier_added("ACME Corp")
        trail.record_enrichment("pkg:pypi/requests@2.31.0", "license", "Apache-2.0", "pypi")
        trail.record_vcs_normalization("git@github.com:foo/bar", "git+https://github.com/foo/bar")
        trail.record_component_version_override("2.0.0", "1.0.0")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            trail.write_audit_file(f.name)
            audit_path = f.name

        with open(audit_path, "r") as f:
            content = f.read()

        # Check file structure
        self.assertIn("# SBOM Audit Trail", content)
        self.assertIn("# Input: requirements.txt", content)
        self.assertIn("# Output: sbom_output.json", content)
        self.assertIn("## Override", content)
        self.assertIn("## Augmentation", content)
        self.assertIn("## Enrichment", content)
        self.assertIn("## Sanitization", content)

        # Check content
        self.assertIn("ACME Corp", content)
        self.assertIn("pkg:pypi/requests@2.31.0", content)
        self.assertIn("Apache-2.0", content)
        self.assertIn("git+https://github.com/foo/bar", content)
        self.assertIn("2.0.0", content)

        # Cleanup
        os.unlink(audit_path)

    def test_print_summary_no_changes(self):
        """Test that print_summary works with no changes."""
        trail = AuditTrail()
        # Should not raise
        trail.print_summary()

    def test_print_summary_with_changes(self):
        """Test that print_summary works with changes."""
        trail = AuditTrail()
        trail.record_supplier_added("Corp")
        trail.record_vcs_normalization("a", "b")
        # Should not raise
        trail.print_summary()

    def test_print_to_stdout_for_attestation(self):
        """Test printing full audit trail to stdout."""
        trail = AuditTrail()
        trail.record_supplier_added("Corp")
        # Should not raise
        trail.print_to_stdout_for_attestation()

    def test_global_audit_trail_functions(self):
        """Test get_audit_trail and reset_audit_trail."""
        # Get trail
        trail1 = get_audit_trail()
        trail1.record_supplier_added("Corp")

        # Get again should return same instance
        trail2 = get_audit_trail()
        self.assertEqual(len(trail2.entries), 1)

        # Reset should clear
        trail3 = reset_audit_trail()
        self.assertFalse(trail3.has_changes())

    def test_transformation_tracker_alias(self):
        """Test that TransformationTracker is aliased to AuditTrail."""
        # TransformationTracker should be the same as AuditTrail
        trail = TransformationTracker()
        trail.record_vcs_normalization("a", "b")
        self.assertTrue(trail.has_transformations())
        self.assertTrue(trail.has_changes())

    def test_audit_file_relativizes_path_inside_cwd(self):
        """An input inside the working directory is recorded relative to it."""
        with tempfile.TemporaryDirectory() as workdir:
            nested = os.path.join(workdir, "src")
            os.mkdir(nested)
            lock_file = os.path.join(nested, "requirements.txt")

            trail = AuditTrail()
            trail.input_file = lock_file
            trail.output_file = os.path.join(workdir, "sbom_output.json")
            trail.record_supplier_added("ACME Corp")

            audit_path = os.path.join(workdir, "audit_trail.txt")
            with patch("sbomify_action.console.Path.cwd", return_value=Path(workdir)):
                trail.write_audit_file(audit_path)

            with open(audit_path, "r") as f:
                content = f.read()

        self.assertIn("# Input: src/requirements.txt", content)
        self.assertIn("# Output: sbom_output.json", content)
        self.assertNotIn(workdir, content)

    def test_audit_file_strips_path_outside_cwd(self):
        """An input from elsewhere on the machine keeps only its file name.

        The audit trail is handed to a third party, so the generating
        machine's directory layout and username must not travel with it.
        """
        with tempfile.TemporaryDirectory() as workdir, tempfile.TemporaryDirectory() as elsewhere:
            lock_file = os.path.join(elsewhere, "requirements.txt")

            trail = AuditTrail()
            trail.input_file = lock_file
            trail.record_supplier_added("ACME Corp")

            audit_path = os.path.join(workdir, "audit_trail.txt")
            with patch("sbomify_action.console.Path.cwd", return_value=Path(workdir)):
                trail.write_audit_file(audit_path)

            with open(audit_path, "r") as f:
                content = f.read()

        self.assertIn("# Input: requirements.txt", content)
        self.assertNotIn(elsewhere, content)

    def test_audit_path_passes_through_non_paths(self):
        """Relative paths and non-path inputs are recorded verbatim."""
        self.assertEqual(_audit_path("requirements.txt"), "requirements.txt")
        self.assertEqual(_audit_path("src/requirements.txt"), "src/requirements.txt")
        self.assertEqual(_audit_path("docker:nginx:latest"), "docker:nginx:latest")
        self.assertEqual(_audit_path("additional-packages-only"), "additional-packages-only")

    def test_attestation_stdout_relativizes_path(self):
        """The stdout copy of the trail is sanitized the same way as the file."""
        with tempfile.TemporaryDirectory() as elsewhere:
            trail = AuditTrail()
            trail.input_file = os.path.join(elsewhere, "requirements.txt")
            trail.record_supplier_added("ACME Corp")

            with patch("builtins.print") as mock_print:
                trail.print_to_stdout_for_attestation()

            printed = " ".join(str(call.args[0]) for call in mock_print.call_args_list if call.args)

        self.assertIn("# Input: requirements.txt", printed)
        self.assertNotIn(elsewhere, printed)

    def test_has_transformations_legacy(self):
        """Test legacy has_transformations method."""
        trail = AuditTrail()
        self.assertFalse(trail.has_transformations())
        trail.record_supplier_added("Corp")
        self.assertTrue(trail.has_transformations())


if __name__ == "__main__":
    unittest.main()
