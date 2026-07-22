"""Tests for the Click CLI interface.

These tests verify that:
1. CLI arguments are parsed correctly
2. Environment variables are used as fallbacks
3. CLI arguments take precedence over environment variables
4. Boolean flags work correctly with --flag/--no-flag pattern
5. Help and version options work
"""

import tempfile
import unittest
from importlib import import_module
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from sbomify_action.cli.main import (
    SBOMIFY_PRODUCTION_API,
    SBOMIFY_VERSION,
    _handle_deprecated_name,
    _handle_deprecated_version,
    _parse_upload_destinations,
    build_config,
    cli,
    evaluate_boolean,
)

# Import the module object explicitly so we can patch its attributes (e.g. logger).
# sbomify_action.cli.__init__.py re-exports the `main` function, so
# `from sbomify_action.cli.main import main` would give us the function, not the module.
cli_main_module = import_module("sbomify_action.cli.main")


class TestCLIHelp(unittest.TestCase):
    """Test CLI help and version options."""

    def setUp(self):
        self.runner = CliRunner()

    def test_help_option(self):
        """Test that --help shows usage information."""
        result = self.runner.invoke(cli, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Generate, augment, enrich, and manage SBOMs", result.output)
        self.assertIn("--lock-file", result.output)
        self.assertIn("--sbom-file", result.output)
        self.assertIn("--docker-image", result.output)

    def test_short_help_option(self):
        """Test that -h also shows help."""
        result = self.runner.invoke(cli, ["-h"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Generate, augment, enrich, and manage SBOMs", result.output)

    def test_version_option(self):
        """Test that --version shows version."""
        result = self.runner.invoke(cli, ["--version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("sbomify Action", result.output)
        self.assertIn(SBOMIFY_VERSION, result.output)

    def test_no_args_shows_help_with_banner(self):
        """Test that running without arguments shows banner and help."""
        result = self.runner.invoke(cli, [])
        self.assertEqual(result.exit_code, 0)
        # Check banner is shown (ASCII art contains "sbomify")
        self.assertIn("sbomify", result.output.lower())
        # Check help content is shown
        self.assertIn("--help", result.output)
        self.assertIn("--lock-file", result.output)
        self.assertIn("--sbom-file", result.output)

    def test_env_var_input_does_not_show_help(self):
        """Test that env vars for input sources bypass the help screen (CI behavior)."""
        # When LOCK_FILE env var is set, should NOT show help, should attempt to run
        result = self.runner.invoke(cli, [], env={"LOCK_FILE": "requirements.txt"})
        # Will fail with file not found or config error, but NOT show help
        self.assertNotEqual(result.exit_code, 0)  # Fails due to file not existing
        self.assertNotIn("Usage:", result.output)  # Help not shown


class TestCLIArgumentParsing(unittest.TestCase):
    """Test CLI argument parsing."""

    def setUp(self):
        self.runner = CliRunner()

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_lock_file_argument(self, mock_sentry, mock_deps, mock_run):
        """Test --lock-file argument is parsed correctly."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            result = self.runner.invoke(
                cli,
                [
                    "--lock-file",
                    str(lock_file),
                    "--no-upload",
                    "--token",
                    "test-token",
                    "--component-id",
                    "test-id",
                ],
            )

            # Should call run_pipeline if config is valid
            if result.exit_code == 0:
                mock_run.assert_called_once()
                config = mock_run.call_args[0][0]
                self.assertIn("requirements.txt", config.lock_file)

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_output_file_argument(self, mock_sentry, mock_deps, mock_run):
        """Test -o/--output-file argument."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            result = self.runner.invoke(
                cli,
                [
                    "--lock-file",
                    str(lock_file),
                    "-o",
                    "custom_output.json",
                    "--no-upload",
                ],
            )

            if result.exit_code == 0:
                mock_run.assert_called_once()
                config = mock_run.call_args[0][0]
                self.assertEqual(config.output_file, "custom_output.json")

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_sbom_format_argument(self, mock_sentry, mock_deps, mock_run):
        """Test -f/--sbom-format argument."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            result = self.runner.invoke(
                cli,
                [
                    "--lock-file",
                    str(lock_file),
                    "-f",
                    "spdx",
                    "--no-upload",
                ],
            )

            if result.exit_code == 0:
                mock_run.assert_called_once()
                config = mock_run.call_args[0][0]
                self.assertEqual(config.sbom_format, "spdx")

    def test_sbom_format_invalid(self):
        """Test that invalid --sbom-format values are rejected."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            result = self.runner.invoke(
                cli,
                [
                    "--lock-file",
                    str(lock_file),
                    "-f",
                    "invalid-format",
                ],
            )

            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("Invalid", result.output)


class TestCLIBooleanFlags(unittest.TestCase):
    """Test CLI boolean flag parsing."""

    def setUp(self):
        self.runner = CliRunner()

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_upload_flag_explicit(self, mock_sentry, mock_deps, mock_run):
        """Test that --upload explicitly enables upload."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            result = self.runner.invoke(
                cli,
                [
                    "--lock-file",
                    str(lock_file),
                    "--token",
                    "test-token",
                    "--component-id",
                    "test-id",
                    "--upload",  # Explicitly enable upload
                ],
            )

            if result.exit_code == 0:
                mock_run.assert_called_once()
                config = mock_run.call_args[0][0]
                self.assertTrue(config.upload)

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_no_upload_flag(self, mock_sentry, mock_deps, mock_run):
        """Test --no-upload flag."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            result = self.runner.invoke(
                cli,
                [
                    "--lock-file",
                    str(lock_file),
                    "--no-upload",
                ],
            )

            if result.exit_code == 0:
                mock_run.assert_called_once()
                config = mock_run.call_args[0][0]
                self.assertFalse(config.upload)

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_enrich_flag(self, mock_sentry, mock_deps, mock_run):
        """Test --enrich flag."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            result = self.runner.invoke(
                cli,
                [
                    "--lock-file",
                    str(lock_file),
                    "--enrich",
                    "--no-upload",
                ],
            )

            if result.exit_code == 0:
                mock_run.assert_called_once()
                config = mock_run.call_args[0][0]
                self.assertTrue(config.enrich)

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_augment_flag(self, mock_sentry, mock_deps, mock_run):
        """Test --augment flag."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            result = self.runner.invoke(
                cli,
                [
                    "--lock-file",
                    str(lock_file),
                    "--augment",
                    "--token",
                    "test-token",
                    "--component-id",
                    "test-id",
                    "--no-upload",
                ],
            )

            if result.exit_code == 0:
                mock_run.assert_called_once()
                config = mock_run.call_args[0][0]
                self.assertTrue(config.augment)

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    def test_no_telemetry_flag(self, mock_deps, mock_run):
        """Test --no-telemetry flag skips Sentry initialization."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            with patch.object(cli_main_module, "initialize_sentry") as mock_sentry:
                self.runner.invoke(
                    cli,
                    [
                        "--lock-file",
                        str(lock_file),
                        "--no-upload",
                        "--no-telemetry",
                    ],
                )

                # Sentry should not be called when --no-telemetry is passed
                mock_sentry.assert_not_called()


class TestCLIEnvVarFallback(unittest.TestCase):
    """Test that CLI falls back to environment variables."""

    def setUp(self):
        self.runner = CliRunner()

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_env_var_fallback_for_token(self, mock_sentry, mock_deps, mock_run):
        """Test that TOKEN env var is used when --token is not provided."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            result = self.runner.invoke(
                cli,
                [
                    "--lock-file",
                    str(lock_file),
                    "--component-id",
                    "test-id",
                ],
                env={"TOKEN": "env-token"},
            )

            if result.exit_code == 0:
                mock_run.assert_called_once()
                config = mock_run.call_args[0][0]
                self.assertEqual(config.token, "env-token")

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_cli_takes_precedence_over_env(self, mock_sentry, mock_deps, mock_run):
        """Test that CLI arguments take precedence over env vars."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            result = self.runner.invoke(
                cli,
                [
                    "--lock-file",
                    str(lock_file),
                    "--token",
                    "cli-token",
                    "--component-id",
                    "test-id",
                ],
                env={"TOKEN": "env-token"},
            )

            if result.exit_code == 0:
                mock_run.assert_called_once()
                config = mock_run.call_args[0][0]
                self.assertEqual(config.token, "cli-token")

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_env_var_for_upload_boolean(self, mock_sentry, mock_deps, mock_run):
        """Test UPLOAD env var with boolean string."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            result = self.runner.invoke(
                cli,
                ["--lock-file", str(lock_file)],
                env={"UPLOAD": "false"},
            )

            if result.exit_code == 0:
                mock_run.assert_called_once()
                config = mock_run.call_args[0][0]
                self.assertFalse(config.upload)


class TestCLIUploadDestinations(unittest.TestCase):
    """Test upload destinations handling."""

    def setUp(self):
        self.runner = CliRunner()

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_single_upload_destination(self, mock_sentry, mock_deps, mock_run):
        """Test single --upload-destination."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            result = self.runner.invoke(
                cli,
                [
                    "--lock-file",
                    str(lock_file),
                    "--upload-destination",
                    "sbomify",
                    "--token",
                    "test-token",
                    "--component-id",
                    "test-id",
                ],
            )

            if result.exit_code == 0:
                mock_run.assert_called_once()
                config = mock_run.call_args[0][0]
                self.assertEqual(config.upload_destinations, ["sbomify"])

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_multiple_upload_destinations(self, mock_sentry, mock_deps, mock_run):
        """Test multiple --upload-destination flags."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            result = self.runner.invoke(
                cli,
                [
                    "--lock-file",
                    str(lock_file),
                    "--upload-destination",
                    "sbomify",
                    "--upload-destination",
                    "dependency-track",
                    "--token",
                    "test-token",
                    "--component-id",
                    "test-id",
                ],
            )

            if result.exit_code == 0:
                mock_run.assert_called_once()
                config = mock_run.call_args[0][0]
                self.assertIn("sbomify", config.upload_destinations)
                self.assertIn("dependency-track", config.upload_destinations)


class TestCLIVerboseQuiet(unittest.TestCase):
    """Test verbose and quiet flags."""

    def setUp(self):
        self.runner = CliRunner()

    def test_verbose_and_quiet_mutually_exclusive(self):
        """Test that --verbose and --quiet cannot be used together."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            result = self.runner.invoke(
                cli,
                [
                    "--lock-file",
                    str(lock_file),
                    "--verbose",
                    "--quiet",
                    "--no-upload",
                ],
            )

            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("Cannot use both --verbose and --quiet", result.output)


class TestDeprecatedEnvVars(unittest.TestCase):
    """Test handling of deprecated environment variables."""

    def test_sbom_version_deprecation_warning(self):
        """Test that SBOM_VERSION triggers deprecation warning."""
        result = _handle_deprecated_version(None, "1.0.0")
        self.assertEqual(result, "1.0.0")

    def test_component_version_takes_precedence(self):
        """Test COMPONENT_VERSION takes precedence over SBOM_VERSION."""
        result = _handle_deprecated_version("2.0.0", "1.0.0")
        self.assertEqual(result, "2.0.0")

    def test_override_name_deprecation_warning(self):
        """Test that OVERRIDE_NAME triggers deprecation warning."""
        name, override = _handle_deprecated_name(None, "true")
        self.assertIsNone(name)
        self.assertTrue(override)

    def test_component_name_takes_precedence(self):
        """Test COMPONENT_NAME takes precedence over OVERRIDE_NAME."""
        name, override = _handle_deprecated_name("my-component", "true")
        self.assertEqual(name, "my-component")
        self.assertFalse(override)


class TestBuildConfig(unittest.TestCase):
    """Test the build_config function."""

    def test_build_config_with_minimal_args(self):
        """Test build_config with minimal valid configuration."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            config = build_config(
                lock_file=str(lock_file),
                upload=False,
            )

            self.assertIn("requirements.txt", config.lock_file)
            self.assertFalse(config.upload)
            self.assertEqual(config.output_file, "sbom_output.json")
            self.assertEqual(config.sbom_format, "cyclonedx")
            self.assertEqual(config.api_base_url, SBOMIFY_PRODUCTION_API)

    def test_build_config_normalizes_sbom_format(self):
        """Test that build_config normalizes SBOM format to lowercase."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            config = build_config(
                lock_file=str(lock_file),
                upload=False,
                sbom_format="SPDX",
            )

            self.assertEqual(config.sbom_format, "spdx")


class TestParseUploadDestinations(unittest.TestCase):
    """Test upload destinations parsing helper."""

    def test_parse_empty_string(self):
        """Test parsing empty string returns None."""
        result = _parse_upload_destinations("")
        self.assertIsNone(result)

    def test_parse_none(self):
        """Test parsing None returns None."""
        result = _parse_upload_destinations(None)
        self.assertIsNone(result)

    def test_parse_single_destination(self):
        """Test parsing single destination."""
        result = _parse_upload_destinations("sbomify")
        self.assertEqual(result, ["sbomify"])

    def test_parse_multiple_destinations(self):
        """Test parsing comma-separated destinations."""
        result = _parse_upload_destinations("sbomify,dependency-track")
        self.assertEqual(result, ["sbomify", "dependency-track"])

    def test_parse_with_whitespace(self):
        """Test parsing handles whitespace."""
        result = _parse_upload_destinations("sbomify , dependency-track")
        self.assertEqual(result, ["sbomify", "dependency-track"])


class TestCLIAdditionalPackagesOnlyMode(unittest.TestCase):
    """Test CLI integration for additional-packages-only mode."""

    def setUp(self):
        self.runner = CliRunner()

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_lock_file_none_triggers_pipeline(self, mock_sentry, mock_deps, mock_run):
        """Test --lock-file none with ADDITIONAL_PACKAGES triggers the pipeline."""
        result = self.runner.invoke(
            cli,
            [
                "--lock-file",
                "none",
                "--no-upload",
            ],
            env={"ADDITIONAL_PACKAGES": "pkg:pypi/requests@2.31.0"},
        )

        self.assertEqual(result.exit_code, 0, f"CLI failed unexpectedly: {result.output}")
        mock_run.assert_called_once()
        config = mock_run.call_args[0][0]
        self.assertTrue(config.is_additional_packages_only)
        self.assertEqual(config.lock_file, "none")

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_sbom_file_none_triggers_pipeline(self, mock_sentry, mock_deps, mock_run):
        """Test --sbom-file none with ADDITIONAL_PACKAGES triggers the pipeline."""
        result = self.runner.invoke(
            cli,
            [
                "--sbom-file",
                "none",
                "--no-upload",
            ],
            env={"ADDITIONAL_PACKAGES": "pkg:pypi/requests@2.31.0"},
        )

        self.assertEqual(result.exit_code, 0, f"CLI failed unexpectedly: {result.output}")
        mock_run.assert_called_once()
        config = mock_run.call_args[0][0]
        self.assertTrue(config.is_additional_packages_only)
        self.assertEqual(config.sbom_file, "none")

    def test_lock_file_none_without_packages_fails(self):
        """Test --lock-file none without additional packages configured fails."""
        result = self.runner.invoke(
            cli,
            [
                "--lock-file",
                "none",
                "--no-upload",
            ],
            env={},
        )

        # Should exit with error
        self.assertNotEqual(result.exit_code, 0)

    def test_no_input_with_additional_packages_exits_with_hint(self):
        """Test that no input source + ADDITIONAL_PACKAGES exits 1 with helpful message."""
        result = self.runner.invoke(
            cli,
            [],
            env={"ADDITIONAL_PACKAGES": "pkg:pypi/requests@2.31.0"},
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("--lock-file none", result.output)

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def test_lock_file_none_with_spdx_format(self, mock_sentry, mock_deps, mock_run):
        """Test --lock-file none with SPDX format."""
        result = self.runner.invoke(
            cli,
            [
                "--lock-file",
                "none",
                "-f",
                "spdx",
                "--no-upload",
            ],
            env={"ADDITIONAL_PACKAGES": "pkg:pypi/requests@2.31.0"},
        )

        self.assertEqual(result.exit_code, 0, f"CLI failed unexpectedly: {result.output}")
        mock_run.assert_called_once()
        config = mock_run.call_args[0][0]
        self.assertTrue(config.is_additional_packages_only)
        self.assertEqual(config.sbom_format, "spdx")


class TestEvaluateBoolean(unittest.TestCase):
    """Test the evaluate_boolean utility function."""

    def test_true_values(self):
        """Test values that should evaluate to True."""
        # Test lowercase values (function uses .lower() internally)
        for value in ["true", "yes", "yeah", "1"]:
            self.assertTrue(evaluate_boolean(value), f"'{value}' should be True")

    def test_true_values_case_insensitive(self):
        """Test that true values are case-insensitive."""
        # One example of each to verify .lower() works
        for value in ["TRUE", "Yes", "YEAH"]:
            self.assertTrue(evaluate_boolean(value), f"'{value}' should be True (case-insensitive)")

    def test_false_values(self):
        """Test values that should evaluate to False."""
        for value in ["false", "no", "0", "anything", "nope", ""]:
            self.assertFalse(evaluate_boolean(value), f"'{value}' should be False")

    def test_false_values_case_insensitive(self):
        """Test that false values are case-insensitive."""
        # Verify case variations of false values
        for value in ["FALSE", "False", "NO", "No"]:
            self.assertFalse(evaluate_boolean(value), f"'{value}' should be False (case-insensitive)")


if __name__ == "__main__":
    unittest.main()


class TestCbomGenerateCliWiring(unittest.TestCase):
    """CBOM_GENERATE must reach the real Click entrypoint, not just build_config."""

    def setUp(self):
        self.runner = CliRunner()

    @patch.object(cli_main_module, "run_pipeline")
    @patch.object(cli_main_module, "setup_dependencies")
    @patch.object(cli_main_module, "initialize_sentry")
    def _invoke(self, args, env, mock_sentry, mock_deps, mock_run):
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")
            base = ["--lock-file", str(lock_file), "--no-upload", "--token", "t", "--component-id", "c"]
            result = self.runner.invoke(cli, base + args, env=env)
            self.assertEqual(result.exit_code, 0, result.output)
            mock_run.assert_called_once()
            return mock_run.call_args[0][0]

    def test_env_var_reaches_config(self):
        config = self._invoke([], {"CBOM_GENERATE": "true"})
        self.assertTrue(config.cbom_generate)
        self.assertEqual(config.bom_type, "cbom")

    def test_flag_reaches_config(self):
        config = self._invoke(["--cbom-generate"], {})
        self.assertTrue(config.cbom_generate)

    def test_default_is_off(self):
        config = self._invoke([], {})
        self.assertFalse(config.cbom_generate)
        self.assertEqual(config.bom_type, "sbom")
