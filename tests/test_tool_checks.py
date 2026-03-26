"""Tests for tool_checks module."""

import unittest
from unittest.mock import patch

from sbomify_action.tool_checks import (
    ToolInfo,
    ToolStatus,
    check_all_tools,
    check_tool_available,
    check_tool_for_input,
    format_no_tools_error,
    get_available_tools,
    get_external_tools,
    get_missing_tools,
    get_tool_install_message,
    log_tool_status,
)


class TestToolInfo(unittest.TestCase):
    """Tests for ToolInfo dataclass."""

    def test_tool_info_creation(self):
        """Test creating ToolInfo."""
        info = ToolInfo(
            name="Test Tool",
            command="test-cmd",
            description="A test tool",
            install_instructions="pip install test",
            homepage="https://example.com",
            required_for=["testing"],
        )
        self.assertEqual(info.name, "Test Tool")
        self.assertEqual(info.command, "test-cmd")
        self.assertEqual(info.description, "A test tool")
        self.assertEqual(info.install_instructions, "pip install test")
        self.assertEqual(info.homepage, "https://example.com")
        self.assertEqual(info.required_for, ["testing"])

    def test_tool_info_default_required_for(self):
        """Test default required_for is empty list."""
        info = ToolInfo(
            name="Test",
            command="test",
            description="desc",
            install_instructions="install",
            homepage="https://example.com",
        )
        self.assertEqual(info.required_for, [])


class TestToolStatus(unittest.TestCase):
    """Tests for ToolStatus dataclass."""

    def test_tool_status_available(self):
        """Test ToolStatus for available tool."""
        status = ToolStatus(
            name="trivy",
            available=True,
            path="/usr/local/bin/trivy",
        )
        self.assertTrue(status.available)
        self.assertEqual(status.path, "/usr/local/bin/trivy")

    def test_tool_status_unavailable(self):
        """Test ToolStatus for unavailable tool."""
        status = ToolStatus(name="trivy", available=False)
        self.assertFalse(status.available)
        self.assertIsNone(status.path)


class TestExternalTools(unittest.TestCase):
    """Tests for get_external_tools function."""

    def test_external_tools_does_not_contain_trivy(self):
        """Test external tools does not contain trivy (temporarily disabled)."""
        external_tools = get_external_tools()
        self.assertNotIn("trivy", external_tools)

    def test_external_tools_contains_syft(self):
        """Test external tools contains syft."""
        external_tools = get_external_tools()
        self.assertIn("syft", external_tools)
        self.assertEqual(external_tools["syft"].command, "syft")

    def test_external_tools_contains_cdxgen(self):
        """Test external tools contains cdxgen."""
        external_tools = get_external_tools()
        self.assertIn("cdxgen", external_tools)
        self.assertEqual(external_tools["cdxgen"].command, "cdxgen")

    def test_external_tools_contains_cyclonedx_py(self):
        """Test external tools contains cyclonedx-py."""
        external_tools = get_external_tools()
        self.assertIn("cyclonedx-py", external_tools)
        self.assertEqual(external_tools["cyclonedx-py"].command, "cyclonedx-py")

    def test_external_tools_contains_cargo_cyclonedx(self):
        """Test external tools contains cargo-cyclonedx."""
        external_tools = get_external_tools()
        self.assertIn("cargo-cyclonedx", external_tools)
        self.assertEqual(external_tools["cargo-cyclonedx"].command, "cargo-cyclonedx")

    def test_external_tools_dynamically_built_from_registry(self):
        """Test that external tools mapping is consistent with tool commands."""
        external_tools = get_external_tools()

        # The mapping should not be empty
        self.assertTrue(external_tools, "get_external_tools() returned an empty mapping")

        # For each tool, the command should match the key name
        for name, info in external_tools.items():
            with self.subTest(tool=name):
                self.assertEqual(
                    info.command,
                    name,
                    f"ToolInfo.command for '{name}' should match its key in external_tools",
                )


class TestCheckToolAvailable(unittest.TestCase):
    """Tests for check_tool_available function."""

    @patch("sbomify_action.tool_checks.shutil.which")
    def test_tool_available(self, mock_which):
        """Test detecting an available tool."""
        mock_which.return_value = "/usr/local/bin/trivy"
        available, path = check_tool_available("trivy")
        self.assertTrue(available)
        self.assertEqual(path, "/usr/local/bin/trivy")

    @patch("sbomify_action.tool_checks.shutil.which")
    def test_tool_unavailable(self, mock_which):
        """Test detecting an unavailable tool."""
        mock_which.return_value = None
        available, path = check_tool_available("nonexistent")
        self.assertFalse(available)
        self.assertIsNone(path)


class TestCheckAllTools(unittest.TestCase):
    """Tests for check_all_tools function."""

    @patch("sbomify_action.tool_checks.check_tool_available")
    def test_check_all_tools_all_available(self, mock_check):
        """Test checking all tools when all are available."""
        mock_check.return_value = (True, "/usr/local/bin/tool")
        results = check_all_tools()
        self.assertNotIn("trivy", results)  # Trivy temporarily disabled
        self.assertIn("syft", results)
        self.assertIn("cdxgen", results)
        self.assertIn("cyclonedx-py", results)
        self.assertIn("cargo-cyclonedx", results)
        for status in results.values():
            self.assertTrue(status.available)

    @patch("sbomify_action.tool_checks.check_tool_available")
    def test_check_all_tools_none_available(self, mock_check):
        """Test checking all tools when none are available."""
        mock_check.return_value = (False, None)
        results = check_all_tools()
        for status in results.values():
            self.assertFalse(status.available)


class TestGetAvailableTools(unittest.TestCase):
    """Tests for get_available_tools function."""

    @patch("sbomify_action.tool_checks.check_all_tools")
    def test_get_available_tools(self, mock_check_all):
        """Test getting list of available tools."""
        mock_check_all.return_value = {
            "syft": ToolStatus(name="syft", available=True, path="/usr/bin/syft"),
            "cdxgen": ToolStatus(name="cdxgen", available=False),
        }
        available = get_available_tools()
        self.assertEqual(available, ["syft"])


class TestGetMissingTools(unittest.TestCase):
    """Tests for get_missing_tools function."""

    @patch("sbomify_action.tool_checks.check_all_tools")
    def test_get_missing_tools(self, mock_check_all):
        """Test getting list of missing tools."""
        mock_check_all.return_value = {
            "syft": ToolStatus(name="syft", available=True, path="/usr/bin/syft"),
            "cdxgen": ToolStatus(name="cdxgen", available=False),
        }
        missing = get_missing_tools()
        self.assertEqual(missing, ["cdxgen"])


class TestLogToolStatus(unittest.TestCase):
    """Tests for log_tool_status function."""

    @patch("sbomify_action.tool_checks.check_all_tools")
    @patch("sbomify_action.tool_checks.logger")
    def test_log_tool_status_with_available(self, mock_logger, mock_check_all):
        """Test logging when some tools are available."""
        external_tools = get_external_tools()
        mock_check_all.return_value = {
            "syft": ToolStatus(
                name="Syft",
                available=True,
                path="/usr/bin/syft",
                info=external_tools["syft"],
            ),
            "cdxgen": ToolStatus(
                name="cdxgen",
                available=False,
                info=external_tools["cdxgen"],
            ),
        }
        log_tool_status(verbose=False)
        mock_logger.info.assert_called()
        mock_logger.warning.assert_called()

    @patch("sbomify_action.tool_checks.check_all_tools")
    @patch("sbomify_action.tool_checks.logger")
    def test_log_tool_status_verbose(self, mock_logger, mock_check_all):
        """Test verbose logging with install instructions."""
        external_tools = get_external_tools()
        mock_check_all.return_value = {
            "syft": ToolStatus(
                name="Syft",
                available=False,
                info=external_tools["syft"],
            ),
        }
        log_tool_status(verbose=True)
        # Should have multiple info calls for install instructions
        self.assertGreater(mock_logger.info.call_count, 1)


class TestGetToolInstallMessage(unittest.TestCase):
    """Tests for get_tool_install_message function."""

    def test_get_install_message_single_tool(self):
        """Test install message for single tool."""
        message = get_tool_install_message(["syft"])
        self.assertIn("Syft", message)
        self.assertIn("brew install syft", message)

    def test_get_install_message_multiple_tools(self):
        """Test install message for multiple tools."""
        message = get_tool_install_message(["syft", "cdxgen"])
        self.assertIn("Syft", message)
        self.assertIn("cdxgen", message)

    def test_get_install_message_unknown_tool(self):
        """Test install message ignores unknown tools."""
        message = get_tool_install_message(["unknown_tool"])
        self.assertNotIn("unknown_tool", message.lower())


class TestCheckToolForInput(unittest.TestCase):
    """Tests for check_tool_for_input function."""

    @patch("sbomify_action.tool_checks.check_all_tools")
    def test_check_tool_for_docker_image(self, mock_check_all):
        """Test checking tools for Docker image input."""
        mock_check_all.return_value = {
            "syft": ToolStatus(name="syft", available=True),
            "cdxgen": ToolStatus(name="cdxgen", available=False),
            "cyclonedx-py": ToolStatus(name="cyclonedx-py", available=True),
        }
        available, missing = check_tool_for_input("docker_image")
        self.assertIn("syft", available)
        self.assertIn("cdxgen", missing)

    @patch("sbomify_action.tool_checks.check_all_tools")
    def test_check_tool_for_python_lockfile(self, mock_check_all):
        """Test checking tools for Python lock file."""
        mock_check_all.return_value = {
            "syft": ToolStatus(name="syft", available=False),
            "cdxgen": ToolStatus(name="cdxgen", available=False),
            "cyclonedx-py": ToolStatus(name="cyclonedx-py", available=True),
        }
        available, missing = check_tool_for_input("lock_file", "requirements.txt")
        self.assertIn("cyclonedx-py", available)

    @patch("sbomify_action.tool_checks.check_all_tools")
    def test_check_tool_for_java_lockfile(self, mock_check_all):
        """Test checking tools for Java lock file (cdxgen preferred)."""
        mock_check_all.return_value = {
            "syft": ToolStatus(name="syft", available=True),
            "cdxgen": ToolStatus(name="cdxgen", available=False),
            "cyclonedx-py": ToolStatus(name="cyclonedx-py", available=True),
        }
        available, missing = check_tool_for_input("lock_file", "pom.xml")
        self.assertIn("syft", available)
        self.assertIn("cdxgen", missing)

    @patch("sbomify_action.tool_checks.check_all_tools")
    def test_check_tool_for_dart_lockfile(self, mock_check_all):
        """Test checking tools for Dart lock file."""
        mock_check_all.return_value = {
            "syft": ToolStatus(name="syft", available=True),
            "cdxgen": ToolStatus(name="cdxgen", available=False),
            "cyclonedx-py": ToolStatus(name="cyclonedx-py", available=False),
        }
        available, missing = check_tool_for_input("lock_file", "pubspec.lock")
        self.assertIn("syft", available)
        self.assertIn("cdxgen", missing)

    @patch("sbomify_action.tool_checks.check_all_tools")
    def test_check_tool_for_terraform_lockfile(self, mock_check_all):
        """Test checking tools for Terraform lock file (only syft)."""
        mock_check_all.return_value = {
            "syft": ToolStatus(name="syft", available=True),
            "cdxgen": ToolStatus(name="cdxgen", available=False),
            "cyclonedx-py": ToolStatus(name="cyclonedx-py", available=False),
        }
        available, missing = check_tool_for_input("lock_file", ".terraform.lock.hcl")
        self.assertEqual(available, ["syft"])
        self.assertEqual(missing, [])

    @patch("sbomify_action.tool_checks.check_all_tools")
    def test_check_tool_for_sbom_file(self, mock_check_all):
        """Test checking tools for existing SBOM file (no tools needed)."""
        mock_check_all.return_value = {}
        available, missing = check_tool_for_input("sbom_file")
        self.assertEqual(available, [])
        self.assertEqual(missing, [])


class TestFormatNoToolsError(unittest.TestCase):
    """Tests for format_no_tools_error function."""

    @patch("sbomify_action.tool_checks.check_tool_for_input")
    def test_format_error_docker_image(self, mock_check):
        """Test error message for Docker image with no tools."""
        mock_check.return_value = ([], ["syft", "cdxgen"])
        error = format_no_tools_error("docker_image")
        self.assertIn("Docker images", error)
        self.assertIn("Syft", error)
        self.assertIn("cdxgen", error)
        self.assertIn("sbomifyhub/sbomify-action", error)

    @patch("sbomify_action.tool_checks.check_tool_for_input")
    def test_format_error_lock_file(self, mock_check):
        """Test error message for lock file with no tools."""
        mock_check.return_value = ([], ["cyclonedx-py", "cdxgen", "syft"])
        error = format_no_tools_error("lock_file", "requirements.txt")
        self.assertIn("requirements.txt", error)
        self.assertIn("cyclonedx-py", error)

    @patch("sbomify_action.tool_checks.check_tool_for_input")
    def test_format_error_with_available_tools(self, mock_check):
        """Test error message when tools are actually available."""
        mock_check.return_value = (["syft"], [])
        error = format_no_tools_error("docker_image")
        self.assertIn("Tools available but generation failed", error)

    @patch("sbomify_action.tool_checks.check_tool_for_input")
    def test_format_error_lock_file_without_filename(self, mock_check):
        """Test error message for lock_file input without filename."""
        mock_check.return_value = ([], ["syft", "cdxgen"])
        error = format_no_tools_error("lock_file", None)
        self.assertIn("this input", error)


class TestCheckToolForInputEdgeCases(unittest.TestCase):
    """Additional edge case tests for check_tool_for_input."""

    @patch("sbomify_action.tool_checks.check_all_tools")
    def test_check_tool_for_general_lockfile(self, mock_check_all):
        """Test checking tools for a general/unknown lock file type."""
        mock_check_all.return_value = {
            "syft": ToolStatus(name="syft", available=False),
            "cdxgen": ToolStatus(name="cdxgen", available=True),
            "cyclonedx-py": ToolStatus(name="cyclonedx-py", available=False),
        }
        # Use a generic lock file that's not specifically handled
        available, missing = check_tool_for_input("lock_file", "some-other.lock")
        self.assertIn("cdxgen", available)
        self.assertIn("syft", missing)

    @patch("sbomify_action.tool_checks.check_all_tools")
    def test_check_tool_for_unknown_input_type(self, mock_check_all):
        """Test checking tools for an unknown input type."""
        mock_check_all.return_value = {
            "syft": ToolStatus(name="syft", available=True),
            "cdxgen": ToolStatus(name="cdxgen", available=False),
            "cyclonedx-py": ToolStatus(name="cyclonedx-py", available=False),
        }
        # Use an unknown input type - should default to syft, cdxgen
        available, missing = check_tool_for_input("unknown_type")
        self.assertIn("syft", available)
        self.assertIn("cdxgen", missing)


if __name__ == "__main__":
    unittest.main()
