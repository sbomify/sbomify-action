import json
import os
import tempfile
import unittest
from importlib import import_module
from unittest.mock import patch

from click.testing import CliRunner

from sbomify_action.cli.main import cli

# Import the module using importlib to avoid shadowing by __init__.py exports
cli_main_module = import_module("sbomify_action.cli.main")


class TestIntegration(unittest.TestCase):
    """Integration tests for the main workflow."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        self.runner = CliRunner()

    def tearDown(self):
        """Clean up test fixtures."""
        os.chdir(self.original_cwd)
        # Clean up temporary files
        for file in ["step_1.json", "step_2.json", "step_3.json", "output.json", "sbom_output.json", "test_sbom.json"]:
            if os.path.exists(file):
                os.remove(file)

    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_main_sbom_file_workflow(self, mock_sentry, mock_setup):
        """Test main workflow with SBOM file input."""
        # Create a temporary SBOM file
        test_sbom = {"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1}
        with open("test_sbom.json", "w") as f:
            json.dump(test_sbom, f)

        # Use Click's CliRunner to invoke the CLI with arguments
        with patch.object(cli_main_module, "print_banner"):
            result = self.runner.invoke(
                cli,
                [
                    "--sbom-file",
                    "test_sbom.json",
                    "--token",
                    "test-token",
                    "--component-id",
                    "test-component",
                    "--no-upload",
                    "--no-augment",
                    "--no-enrich",
                ],
            )

        # Check the command succeeded
        if result.exit_code != 0:
            print(f"CLI output: {result.output}")
            print(f"CLI exception: {result.exception}")

        self.assertEqual(result.exit_code, 0, f"CLI failed with: {result.output}")

        # Verify setup_dependencies was called
        mock_setup.assert_called_once()

        # Note: initialize_sentry is NOT called because TELEMETRY=false is set
        # globally by conftest.py to prevent Sentry events during tests
        mock_sentry.assert_not_called()

        # Verify output file was created
        self.assertTrue(os.path.exists("sbom_output.json"))


if __name__ == "__main__":
    unittest.main()
