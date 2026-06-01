"""Tests for the CycloneDXCargoGenerator plugin."""

import unittest
from unittest.mock import MagicMock, patch

from sbomify_action._generation import (
    GenerationInput,
    GeneratorRegistry,
    create_default_registry,
)
from sbomify_action._generation.generators import (
    CdxgenFsGenerator,
    CycloneDXCargoGenerator,
    TrivyFsGenerator,
)
from sbomify_action._generation.protocol import (
    CARGO_CYCLONEDX_DEFAULT,
    CARGO_CYCLONEDX_VERSIONS,
)


@patch("sbomify_action._generation.generators.cyclonedx_cargo._CARGO_CYCLONEDX_AVAILABLE", True)
class TestCycloneDXCargoGenerator(unittest.TestCase):
    """Tests for CycloneDXCargoGenerator.

    The class-level patch forces ``_CARGO_CYCLONEDX_AVAILABLE=True`` so the
    ``supports()`` tests exercise the lock-file/format/version logic regardless
    of whether cargo-cyclonedx happens to be installed in the test env (it
    usually isn't — it's a Rust tool). Mirrors the pattern used for the
    syft/cyclonedx-py generators in test_generation_plugin.py.
    """

    def setUp(self):
        """Set up test fixtures."""
        self.generator = CycloneDXCargoGenerator()

    def test_name_and_priority(self):
        """Test generator name and priority."""
        self.assertEqual(self.generator.name, "cyclonedx-cargo")
        self.assertEqual(self.generator.priority, 10)

    def test_supported_formats(self):
        """Test supported formats."""
        formats = self.generator.supported_formats
        self.assertEqual(len(formats), 1)
        self.assertEqual(formats[0].format, "cyclonedx")
        self.assertEqual(formats[0].versions, CARGO_CYCLONEDX_VERSIONS)
        self.assertEqual(formats[0].default_version, CARGO_CYCLONEDX_DEFAULT)

    def test_supports_cargo_lock(self):
        """Test support for Cargo.lock files."""
        gen_input = GenerationInput(lock_file="/path/to/Cargo.lock", output_format="cyclonedx")
        self.assertTrue(self.generator.supports(gen_input))

    def test_does_not_support_other_lock_files(self):
        """Test that other lock files are not supported."""
        for lock_file in ["requirements.txt", "poetry.lock", "package.json", "go.mod"]:
            gen_input = GenerationInput(lock_file=f"/path/{lock_file}", output_format="cyclonedx")
            self.assertFalse(self.generator.supports(gen_input), f"Should not support {lock_file}")

    def test_does_not_support_spdx(self):
        """Test that SPDX format is not supported."""
        gen_input = GenerationInput(lock_file="/path/Cargo.lock", output_format="spdx")
        self.assertFalse(self.generator.supports(gen_input))

    def test_does_not_support_docker_images(self):
        """Test that Docker images are not supported."""
        gen_input = GenerationInput(docker_image="alpine:3.18", output_format="cyclonedx")
        self.assertFalse(self.generator.supports(gen_input))

    def test_supports_version_1_4(self):
        """Test support for CycloneDX 1.4."""
        gen_input = GenerationInput(
            lock_file="/path/Cargo.lock",
            output_format="cyclonedx",
            spec_version="1.4",
        )
        self.assertTrue(self.generator.supports(gen_input))

    def test_supports_version_1_5(self):
        """Test support for CycloneDX 1.5."""
        gen_input = GenerationInput(
            lock_file="/path/Cargo.lock",
            output_format="cyclonedx",
            spec_version="1.5",
        )
        self.assertTrue(self.generator.supports(gen_input))

    def test_supports_version_1_6(self):
        """Test support for CycloneDX 1.6."""
        gen_input = GenerationInput(
            lock_file="/path/Cargo.lock",
            output_format="cyclonedx",
            spec_version="1.6",
        )
        self.assertTrue(self.generator.supports(gen_input))

    def test_does_not_support_unsupported_versions(self):
        """Test that unsupported versions are rejected."""
        for version in ["1.0", "1.1", "1.2", "1.3", "1.7", "2.0"]:
            gen_input = GenerationInput(
                lock_file="/path/Cargo.lock",
                output_format="cyclonedx",
                spec_version=version,
            )
            self.assertFalse(
                self.generator.supports(gen_input),
                f"Should not support version {version}",
            )

    @patch("sbomify_action._generation.generators.cyclonedx_cargo.run_command")
    @patch("sbomify_action._generation.generators.cyclonedx_cargo.Path")
    def test_generate_success(self, mock_path_class, mock_run):
        """Test successful generation."""
        mock_run.return_value = MagicMock(returncode=0)

        # Mock Path.exists() to return True for output file check
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.resolve.return_value = "/abs/path/sbom.json"
        mock_path_instance.parent.resolve.return_value = "/path/to"
        mock_path_class.return_value = mock_path_instance

        gen_input = GenerationInput(lock_file="/path/to/Cargo.lock", output_file="sbom.json")
        result = self.generator.generate(gen_input)

        self.assertTrue(result.success)
        self.assertEqual(result.sbom_format, "cyclonedx")
        self.assertEqual(result.spec_version, CARGO_CYCLONEDX_DEFAULT)
        self.assertEqual(result.generator_name, "cyclonedx-cargo")

    @patch("sbomify_action._generation.generators.cyclonedx_cargo.run_command")
    def test_generate_failure(self, mock_run):
        """Test generation failure."""
        mock_run.return_value = MagicMock(returncode=1, stderr="Error message")

        gen_input = GenerationInput(lock_file="/path/to/Cargo.lock", output_file="sbom.json")
        result = self.generator.generate(gen_input)

        self.assertFalse(result.success)
        self.assertIsNotNone(result.error_message)
        self.assertEqual(result.generator_name, "cyclonedx-cargo")

    def test_unsupported_version_returns_failure(self):
        """Test that unsupported version returns failure result."""
        gen_input = GenerationInput(
            lock_file="/path/Cargo.lock",
            output_format="cyclonedx",
            spec_version="2.0",  # Invalid version
        )

        result = self.generator.generate(gen_input)

        self.assertFalse(result.success)
        self.assertIn("Unsupported CycloneDX version", result.error_message)


@patch("sbomify_action._generation.generators.cyclonedx_cargo._CARGO_CYCLONEDX_AVAILABLE", True)
class TestCycloneDXCargoGeneratorPriority(unittest.TestCase):
    """Tests for CycloneDXCargoGenerator priority in registry.

    Forces ``_CARGO_CYCLONEDX_AVAILABLE=True`` so ``get_generators_for`` (which
    filters on ``supports()``) includes the cargo generator regardless of
    whether the Rust tool is installed in the test env.
    """

    def test_cargo_generator_is_registered(self):
        """Test that CycloneDXCargoGenerator is in default registry."""
        registry = create_default_registry()
        generators = registry.list_generators()

        names = [g["name"] for g in generators]
        self.assertIn("cyclonedx-cargo", names)

    def test_cargo_generator_priority_10(self):
        """Test that CycloneDXCargoGenerator has priority 10."""
        registry = create_default_registry()
        generators = registry.list_generators()

        cargo_gen = next(g for g in generators if g["name"] == "cyclonedx-cargo")
        self.assertEqual(cargo_gen["priority"], 10)

    def test_cargo_generator_preferred_for_cargo_lock(self):
        """Test that CycloneDXCargoGenerator is preferred over cdxgen/Trivy/Syft for Cargo.lock."""
        registry = create_default_registry()

        gen_input = GenerationInput(
            lock_file="/path/Cargo.lock",
            output_format="cyclonedx",
        )

        generators = registry.get_generators_for(gen_input)

        # First generator should be cyclonedx-cargo (priority 10)
        self.assertGreater(len(generators), 0)
        self.assertEqual(generators[0].name, "cyclonedx-cargo")

    @patch("sbomify_action._generation.generators.trivy._TRIVY_AVAILABLE", True)
    @patch("sbomify_action._generation.generators.cdxgen._CDXGEN_AVAILABLE", True)
    def test_registry_order_for_cargo_lock(self):
        """Test the expected order of generators for Cargo.lock."""
        registry = GeneratorRegistry()
        registry.register(TrivyFsGenerator())  # Priority 30
        registry.register(CdxgenFsGenerator())  # Priority 20
        registry.register(CycloneDXCargoGenerator())  # Priority 10

        gen_input = GenerationInput(
            lock_file="/path/Cargo.lock",
            output_format="cyclonedx",
        )

        generators = registry.get_generators_for(gen_input)

        # Should be in priority order: cyclonedx-cargo (10), cdxgen (20), trivy (30)
        self.assertEqual(len(generators), 3)
        self.assertEqual(generators[0].name, "cyclonedx-cargo")
        self.assertEqual(generators[1].name, "cdxgen-fs")
        self.assertEqual(generators[2].name, "trivy-fs")


class TestCycloneDXCargoToolAvailability(unittest.TestCase):
    """Availability-guard regression tests (kept out of the class-patched
    classes so the False case isn't masked by a class-level True patch)."""

    @patch("sbomify_action._generation.generators.cyclonedx_cargo._CARGO_CYCLONEDX_AVAILABLE", False)
    def test_does_not_support_when_tool_missing(self):
        """When cargo-cyclonedx isn't installed, supports() must return False so
        the orchestrator falls through to a generic generator instead of
        picking cargo-cyclonedx and failing at generate() time with a spurious
        ERROR. Mirrors the cyclonedx-py / syft availability guards."""
        generator = CycloneDXCargoGenerator()
        gen_input = GenerationInput(lock_file="/path/to/Cargo.lock", output_format="cyclonedx")
        self.assertFalse(generator.supports(gen_input))

    @patch("sbomify_action._generation.generators.cyclonedx_cargo._CARGO_CYCLONEDX_AVAILABLE", True)
    def test_supports_when_tool_available(self):
        """Sanity: with the tool available, the Cargo.lock is supported."""
        generator = CycloneDXCargoGenerator()
        gen_input = GenerationInput(lock_file="/path/to/Cargo.lock", output_format="cyclonedx")
        self.assertTrue(generator.supports(gen_input))


class TestCycloneDXCargoGeneratorCommandLine(unittest.TestCase):
    """Tests for cargo-cyclonedx command line arguments."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = CycloneDXCargoGenerator()

    @patch("sbomify_action._generation.generators.cyclonedx_cargo.run_command")
    @patch("sbomify_action._generation.generators.cyclonedx_cargo.Path")
    def test_command_includes_spec_version(self, mock_path_class, mock_run):
        """Test that command includes --spec-version flag."""
        mock_run.return_value = MagicMock(returncode=0)

        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.resolve.return_value = "/abs/path/sbom.json"
        mock_path_instance.parent.resolve.return_value = "/path/to"
        mock_path_class.return_value = mock_path_instance

        gen_input = GenerationInput(
            lock_file="/path/to/Cargo.lock",
            output_file="sbom.json",
            spec_version="1.5",
        )
        self.generator.generate(gen_input)

        # Check that run_command was called with correct arguments
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]

        self.assertIn("cargo-cyclonedx", cmd)
        self.assertIn("cyclonedx", cmd)
        self.assertIn("--spec-version", cmd)
        self.assertIn("1.5", cmd)

    @patch("sbomify_action._generation.generators.cyclonedx_cargo.run_command")
    @patch("sbomify_action._generation.generators.cyclonedx_cargo.Path")
    def test_command_includes_json_format(self, mock_path_class, mock_run):
        """Test that command includes --format json flag."""
        mock_run.return_value = MagicMock(returncode=0)

        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.resolve.return_value = "/abs/path/sbom.json"
        mock_path_instance.parent.resolve.return_value = "/path/to"
        mock_path_class.return_value = mock_path_instance

        gen_input = GenerationInput(lock_file="/path/to/Cargo.lock", output_file="sbom.json")
        self.generator.generate(gen_input)

        cmd = mock_run.call_args[0][0]
        self.assertIn("--format", cmd)
        self.assertIn("json", cmd)

    @patch("sbomify_action._generation.generators.cyclonedx_cargo.run_command")
    @patch("sbomify_action._generation.generators.cyclonedx_cargo.Path")
    def test_command_runs_in_project_directory(self, mock_path_class, mock_run):
        """Test that command runs in the directory containing Cargo.lock."""
        mock_run.return_value = MagicMock(returncode=0)

        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.resolve.return_value = "/abs/path/sbom.json"
        mock_path_instance.parent.resolve.return_value = "/project/dir"
        mock_path_class.return_value = mock_path_instance

        gen_input = GenerationInput(
            lock_file="/project/dir/Cargo.lock",
            output_file="sbom.json",
        )
        self.generator.generate(gen_input)

        # Check that cwd was passed to run_command
        mock_run.assert_called_once()
        self.assertEqual(mock_run.call_args[1]["cwd"], "/project/dir")


if __name__ == "__main__":
    unittest.main()
