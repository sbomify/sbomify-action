"""Tests for the SBOM generation plugin architecture."""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from sbomify_action._generation import (
    FormatVersion,
    GenerationInput,
    GenerationResult,
    GeneratorOrchestrator,
    GeneratorRegistry,
    create_default_registry,
)
from sbomify_action._generation.generators import (
    CdxgenFsGenerator,
    CdxgenImageGenerator,
    CycloneDXPyGenerator,
    SyftFsGenerator,
    SyftImageGenerator,
    TrivyFsGenerator,
    TrivyImageGenerator,
)
from sbomify_action.exceptions import SBOMGenerationError, ToolNotAvailableError


class TestFormatVersion(unittest.TestCase):
    """Tests for FormatVersion dataclass."""

    def test_supports_version_true(self):
        """Test that supports_version returns True for supported versions."""
        fv = FormatVersion(format="cyclonedx", versions=("1.4", "1.5", "1.6"), default_version="1.6")
        self.assertTrue(fv.supports_version("1.5"))

    def test_supports_version_false(self):
        """Test that supports_version returns False for unsupported versions."""
        fv = FormatVersion(format="cyclonedx", versions=("1.4", "1.5", "1.6"), default_version="1.6")
        self.assertFalse(fv.supports_version("1.7"))


class TestGenerationInput(unittest.TestCase):
    """Tests for GenerationInput dataclass."""

    def test_lock_file_input(self):
        """Test creating input with lock file."""
        input = GenerationInput(lock_file="requirements.txt", output_file="sbom.json")
        self.assertTrue(input.is_lock_file)
        self.assertFalse(input.is_docker_image)
        self.assertEqual(input.lock_file_name, "requirements.txt")

    def test_docker_image_input(self):
        """Test creating input with Docker image."""
        input = GenerationInput(docker_image="alpine:3.18", output_file="sbom.json")
        self.assertTrue(input.is_docker_image)
        self.assertFalse(input.is_lock_file)
        self.assertIsNone(input.lock_file_name)

    def test_both_inputs_raises_error(self):
        """Test that providing both lock_file and docker_image raises error."""
        with self.assertRaises(ValueError):
            GenerationInput(lock_file="requirements.txt", docker_image="alpine:3.18")

    def test_no_inputs_raises_error(self):
        """Test that providing neither lock_file nor docker_image raises error."""
        with self.assertRaises(ValueError):
            GenerationInput(output_file="sbom.json")

    def test_format_defaults(self):
        """Test default format and version."""
        input = GenerationInput(lock_file="requirements.txt")
        self.assertEqual(input.output_format, "cyclonedx")
        self.assertIsNone(input.spec_version)


class TestGenerationResult(unittest.TestCase):
    """Tests for GenerationResult dataclass."""

    def test_success_result(self):
        """Test creating a success result."""
        result = GenerationResult.success_result(
            output_file="sbom.json",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="test",
        )
        self.assertTrue(result.success)
        self.assertEqual(result.output_file, "sbom.json")
        self.assertIsNone(result.error_message)

    def test_failure_result(self):
        """Test creating a failure result."""
        result = GenerationResult.failure_result(
            error_message="Test error",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="test",
        )
        self.assertFalse(result.success)
        self.assertIsNone(result.output_file)
        self.assertEqual(result.error_message, "Test error")


@patch("sbomify_action._generation.generators.syft._SYFT_AVAILABLE", True)
@patch("sbomify_action._generation.generators.cdxgen._CDXGEN_AVAILABLE", True)
@patch("sbomify_action._generation.generators.trivy._TRIVY_AVAILABLE", True)
@patch("sbomify_action._generation.generators.cyclonedx_py._CYCLONEDX_PY_AVAILABLE", True)
class TestGeneratorRegistry(unittest.TestCase):
    """Tests for GeneratorRegistry."""

    def setUp(self):
        """Set up test fixtures."""
        self.registry = GeneratorRegistry()

    def test_register_generator(self):
        """Test registering a generator."""
        generator = CycloneDXPyGenerator()
        self.registry.register(generator)
        generators = self.registry.list_generators()
        self.assertEqual(len(generators), 1)
        self.assertEqual(generators[0]["name"], "cyclonedx-py")

    def test_get_generators_for_python_cyclonedx(self):
        """Test getting generators for Python CycloneDX."""
        self.registry.register(CycloneDXPyGenerator())
        self.registry.register(CdxgenFsGenerator())
        self.registry.register(TrivyFsGenerator())
        self.registry.register(SyftFsGenerator())

        input = GenerationInput(lock_file="requirements.txt", output_format="cyclonedx")
        generators = self.registry.get_generators_for(input)

        # Should return all four, sorted by priority
        self.assertEqual(len(generators), 4)
        self.assertEqual(generators[0].name, "cyclonedx-py")  # Priority 10
        self.assertEqual(generators[1].name, "cdxgen-fs")  # Priority 20
        self.assertEqual(generators[2].name, "trivy-fs")  # Priority 30
        self.assertEqual(generators[3].name, "syft-fs")  # Priority 35

    def test_get_generators_for_python_spdx(self):
        """Test getting generators for Python SPDX (cyclonedx-py and cdxgen don't support)."""
        self.registry.register(CycloneDXPyGenerator())
        self.registry.register(CdxgenFsGenerator())
        self.registry.register(TrivyFsGenerator())
        self.registry.register(SyftFsGenerator())

        input = GenerationInput(lock_file="requirements.txt", output_format="spdx")
        generators = self.registry.get_generators_for(input)

        # cyclonedx-py and cdxgen don't support SPDX
        self.assertEqual(len(generators), 2)
        self.assertEqual(generators[0].name, "trivy-fs")
        self.assertEqual(generators[1].name, "syft-fs")

    def test_get_generators_for_java_pom_xml(self):
        """Test that Java pom.xml is handled by cdxgen (Syft doesn't support pom.xml)."""
        self.registry.register(CdxgenFsGenerator())
        self.registry.register(TrivyFsGenerator())
        self.registry.register(SyftFsGenerator())

        input = GenerationInput(lock_file="pom.xml", output_format="cyclonedx")
        generators = self.registry.get_generators_for(input)

        # Syft doesn't support pom.xml, so only cdxgen and Trivy
        self.assertEqual(len(generators), 2)
        self.assertEqual(generators[0].name, "cdxgen-fs")  # Priority 20
        self.assertEqual(generators[1].name, "trivy-fs")  # Priority 30

    def test_get_generators_for_version_filter(self):
        """Test version filtering when getting generators."""
        self.registry.register(CycloneDXPyGenerator())
        self.registry.register(TrivyFsGenerator())
        self.registry.register(SyftFsGenerator())

        # Request CycloneDX 1.7 - only cyclonedx-py supports it
        input = GenerationInput(lock_file="requirements.txt", output_format="cyclonedx", spec_version="1.7")
        generators = self.registry.get_generators_for(input)

        self.assertEqual(len(generators), 1)
        self.assertEqual(generators[0].name, "cyclonedx-py")

    def test_get_generators_for_spdx_2_2(self):
        """Test SPDX 2.2 only supported by Syft."""
        self.registry.register(TrivyFsGenerator())
        self.registry.register(SyftFsGenerator())

        # Request SPDX 2.2 - only Syft supports it
        input = GenerationInput(lock_file="requirements.txt", output_format="spdx", spec_version="2.2")
        generators = self.registry.get_generators_for(input)

        self.assertEqual(len(generators), 1)
        self.assertEqual(generators[0].name, "syft-fs")

    def test_get_generators_for_docker_image(self):
        """Test getting generators for Docker images."""
        self.registry.register(CycloneDXPyGenerator())
        self.registry.register(CdxgenImageGenerator())
        self.registry.register(TrivyImageGenerator())
        self.registry.register(SyftImageGenerator())

        input = GenerationInput(docker_image="alpine:3.18", output_format="cyclonedx")
        generators = self.registry.get_generators_for(input)

        # cyclonedx-py doesn't support Docker images
        self.assertEqual(len(generators), 3)
        self.assertEqual(generators[0].name, "cdxgen-image")  # Priority 20
        self.assertEqual(generators[1].name, "trivy-image")  # Priority 30
        self.assertEqual(generators[2].name, "syft-image")  # Priority 35


@patch("sbomify_action._generation.generators.cyclonedx_py._CYCLONEDX_PY_AVAILABLE", True)
class TestCycloneDXPyGenerator(unittest.TestCase):
    """Tests for CycloneDXPyGenerator."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = CycloneDXPyGenerator()

    def test_name_and_priority(self):
        """Test generator name and priority."""
        self.assertEqual(self.generator.name, "cyclonedx-py")
        self.assertEqual(self.generator.priority, 10)

    def test_supported_formats(self):
        """Test supported formats."""
        formats = self.generator.supported_formats
        self.assertEqual(len(formats), 1)
        self.assertEqual(formats[0].format, "cyclonedx")
        self.assertIn("1.7", formats[0].versions)

    def test_supports_python_lock_files(self):
        """Test support for Python lock files."""
        for lock_file in ["requirements.txt", "poetry.lock", "pyproject.toml", "Pipfile.lock"]:
            input = GenerationInput(lock_file=f"/path/{lock_file}", output_format="cyclonedx")
            self.assertTrue(self.generator.supports(input), f"Should support {lock_file}")

    def test_does_not_support_uv_lock(self):
        """Test that uv.lock is not supported (use Trivy instead)."""
        input = GenerationInput(lock_file="/path/uv.lock", output_format="cyclonedx")
        self.assertFalse(self.generator.supports(input))

    def test_does_not_support_spdx(self):
        """Test that SPDX format is not supported."""
        input = GenerationInput(lock_file="/path/requirements.txt", output_format="spdx")
        self.assertFalse(self.generator.supports(input))

    def test_does_not_support_docker_images(self):
        """Test that Docker images are not supported."""
        input = GenerationInput(docker_image="alpine:3.18", output_format="cyclonedx")
        self.assertFalse(self.generator.supports(input))

    @patch("sbomify_action._generation.generators.cyclonedx_py.run_command")
    def test_generate_success(self, mock_run):
        """Test successful generation."""
        mock_run.return_value = MagicMock(returncode=0)

        input = GenerationInput(lock_file="/path/requirements.txt", output_file="sbom.json")
        result = self.generator.generate(input)

        self.assertTrue(result.success)
        self.assertEqual(result.sbom_format, "cyclonedx")
        self.assertEqual(result.spec_version, "1.6")
        self.assertEqual(result.generator_name, "cyclonedx-py")


@patch("sbomify_action._generation.generators.trivy._TRIVY_AVAILABLE", True)
class TestTrivyFsGenerator(unittest.TestCase):
    """Tests for TrivyFsGenerator."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = TrivyFsGenerator()

    def test_name_and_priority(self):
        """Test generator name and priority."""
        self.assertEqual(self.generator.name, "trivy-fs")
        self.assertEqual(self.generator.priority, 30)

    def test_supported_formats(self):
        """Test supported formats."""
        formats = self.generator.supported_formats
        self.assertEqual(len(formats), 2)

        cyclonedx = next(f for f in formats if f.format == "cyclonedx")
        spdx = next(f for f in formats if f.format == "spdx")

        self.assertEqual(cyclonedx.versions, ("1.6",))
        self.assertEqual(spdx.versions, ("2.3",))

    def test_supports_all_lock_files(self):
        """Test support for various lock files."""
        lock_files = ["requirements.txt", "Cargo.lock", "package.json", "go.mod"]
        for lock_file in lock_files:
            input = GenerationInput(lock_file=f"/path/{lock_file}", output_format="cyclonedx")
            self.assertTrue(self.generator.supports(input), f"Should support {lock_file}")

    def test_does_not_support_docker_images(self):
        """Test that Docker images are not supported."""
        input = GenerationInput(docker_image="alpine:3.18", output_format="cyclonedx")
        self.assertFalse(self.generator.supports(input))

    def test_does_not_support_other_versions(self):
        """Test that other versions are not supported."""
        input = GenerationInput(lock_file="/path/requirements.txt", output_format="cyclonedx", spec_version="1.5")
        self.assertFalse(self.generator.supports(input))


@patch("sbomify_action._generation.generators.cdxgen._CDXGEN_AVAILABLE", True)
class TestCdxgenFsGenerator(unittest.TestCase):
    """Tests for CdxgenFsGenerator."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = CdxgenFsGenerator()

    def test_name_and_priority(self):
        """Test generator name and priority."""
        self.assertEqual(self.generator.name, "cdxgen-fs")
        self.assertEqual(self.generator.priority, 20)

    def test_supported_formats(self):
        """Test supported formats - CycloneDX only, no SPDX."""
        formats = self.generator.supported_formats
        self.assertEqual(len(formats), 1)

        cyclonedx = formats[0]
        self.assertEqual(cyclonedx.format, "cyclonedx")
        self.assertIn("1.4", cyclonedx.versions)
        self.assertIn("1.5", cyclonedx.versions)
        self.assertIn("1.6", cyclonedx.versions)
        self.assertIn("1.7", cyclonedx.versions)

    def test_supports_various_lock_files(self):
        """Test support for various lock files."""
        lock_files = ["requirements.txt", "Cargo.lock", "package.json", "pom.xml", "go.mod"]
        for lock_file in lock_files:
            input = GenerationInput(lock_file=f"/path/{lock_file}", output_format="cyclonedx")
            self.assertTrue(self.generator.supports(input), f"Should support {lock_file}")

    def test_supports_java_pom_xml(self):
        """Test that pom.xml (Java) is supported by cdxgen."""
        input = GenerationInput(lock_file="/path/pom.xml", output_format="cyclonedx")
        self.assertTrue(self.generator.supports(input))

    def test_does_not_support_spdx(self):
        """Test that SPDX format is not supported (cdxgen only outputs CycloneDX)."""
        input = GenerationInput(lock_file="/path/requirements.txt", output_format="spdx")
        self.assertFalse(self.generator.supports(input))

    def test_does_not_support_docker_images(self):
        """Test that Docker images are not supported."""
        input = GenerationInput(docker_image="alpine:3.18", output_format="cyclonedx")
        self.assertFalse(self.generator.supports(input))

    def test_supports_cyclonedx_1_7(self):
        """Test support for CycloneDX 1.7."""
        input = GenerationInput(lock_file="/path/requirements.txt", output_format="cyclonedx", spec_version="1.7")
        self.assertTrue(self.generator.supports(input))

    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    @patch("pathlib.Path.exists")
    def test_generate_success(self, mock_exists, mock_run):
        """Test successful generation."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_exists.return_value = True

        input = GenerationInput(lock_file="/path/requirements.txt", output_file="sbom.json")
        result = self.generator.generate(input)

        self.assertTrue(result.success)
        self.assertEqual(result.sbom_format, "cyclonedx")
        self.assertEqual(result.spec_version, "1.6")
        self.assertEqual(result.generator_name, "cdxgen-fs")

    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    @patch("pathlib.Path.exists")
    def test_generate_uses_no_recurse_flag_for_non_java(self, mock_exists, mock_run):
        """Test that --no-recurse flag is passed for non-Java ecosystems."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_exists.return_value = True

        # Python should use --no-recurse (not a parent/child ecosystem)
        input = GenerationInput(lock_file="/path/to/requirements.txt", output_file="sbom.json")
        self.generator.generate(input)

        cmd = mock_run.call_args[0][0]
        self.assertIn("--no-recurse", cmd)

    @patch("sbomify_action._generation.generators.cdxgen.ensure_java_maven_installed")
    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    @patch("pathlib.Path.exists")
    def test_generate_allows_recurse_for_java(self, mock_exists, mock_run, mock_java_install):
        """Test that --no-recurse is NOT passed for Java (Maven parent POMs need recursion)."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_exists.return_value = True

        input = GenerationInput(lock_file="/path/to/pom.xml", output_file="sbom.json")
        self.generator.generate(input)

        cmd = mock_run.call_args[0][0]

        # Java should NOT have --no-recurse (needs to follow parent POM modules)
        self.assertNotIn("--no-recurse", cmd)

    @patch("sbomify_action._generation.generators.cdxgen.ensure_java_maven_installed")
    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    @patch("pathlib.Path.exists")
    def test_generate_uses_type_flag_for_java(self, mock_exists, mock_run, mock_java_install):
        """Test that -t java flag is passed for pom.xml."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_exists.return_value = True

        input = GenerationInput(lock_file="/path/to/pom.xml", output_file="sbom.json")
        self.generator.generate(input)

        cmd = mock_run.call_args[0][0]

        # Check -t java flag is present
        self.assertIn("-t", cmd)
        type_index = cmd.index("-t")
        self.assertEqual(cmd[type_index + 1], "java")

    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    @patch("pathlib.Path.exists")
    def test_generate_uses_type_flag_for_python(self, mock_exists, mock_run):
        """Test that -t python flag is passed for requirements.txt."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_exists.return_value = True

        input = GenerationInput(lock_file="/path/to/requirements.txt", output_file="sbom.json")
        self.generator.generate(input)

        cmd = mock_run.call_args[0][0]

        # Check -t python flag is present
        self.assertIn("-t", cmd)
        type_index = cmd.index("-t")
        self.assertEqual(cmd[type_index + 1], "python")

    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    @patch("pathlib.Path.exists")
    def test_generate_uses_type_flag_for_javascript(self, mock_exists, mock_run):
        """Test that -t js flag is passed for package.json."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_exists.return_value = True

        input = GenerationInput(lock_file="/path/to/package.json", output_file="sbom.json")
        self.generator.generate(input)

        cmd = mock_run.call_args[0][0]

        # Check -t js flag is present
        self.assertIn("-t", cmd)
        type_index = cmd.index("-t")
        self.assertEqual(cmd[type_index + 1], "js")

    @patch("sbomify_action._generation.generators.cdxgen.ensure_java_maven_installed")
    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    @patch("pathlib.Path.exists")
    def test_generate_uses_required_only_flag_for_all_ecosystems(self, mock_exists, mock_run, mock_java_install):
        """Test that --required-only flag is passed for all ecosystems to exclude dev dependencies."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_exists.return_value = True

        # Test with JavaScript (pnpm-lock.yaml)
        js_input = GenerationInput(lock_file="/path/to/pnpm-lock.yaml", output_file="sbom.json")
        self.generator.generate(js_input)
        cmd = mock_run.call_args[0][0]
        self.assertIn("--required-only", cmd)

        # Test with Python (requirements.txt)
        python_input = GenerationInput(lock_file="/path/to/requirements.txt", output_file="sbom.json")
        self.generator.generate(python_input)
        cmd = mock_run.call_args[0][0]
        self.assertIn("--required-only", cmd)

        # Test with Java (pom.xml)
        java_input = GenerationInput(lock_file="/path/to/pom.xml", output_file="sbom.json")
        self.generator.generate(java_input)
        cmd = mock_run.call_args[0][0]
        self.assertIn("--required-only", cmd)

    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    @patch("pathlib.Path.exists")
    def test_generate_uses_fail_on_error_flag(self, mock_exists, mock_run):
        """Test that --fail-on-error flag is passed to catch issues early."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_exists.return_value = True

        gen_input = GenerationInput(lock_file="/path/to/requirements.txt", output_file="sbom.json")
        self.generator.generate(gen_input)

        cmd = mock_run.call_args[0][0]
        self.assertIn("--fail-on-error", cmd)

    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    @patch("pathlib.Path.exists")
    def test_generate_changes_to_lock_file_directory(self, mock_exists, mock_run):
        """Test that cdxgen runs from the lock file's directory using cwd parameter."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_exists.return_value = True

        gen_input = GenerationInput(lock_file="/path/to/project/requirements.txt", output_file="sbom.json")
        self.generator.generate(gen_input)

        # Verify cwd is passed to run_command
        call_kwargs = mock_run.call_args[1]
        self.assertIn("cwd", call_kwargs)
        self.assertEqual(call_kwargs["cwd"], "/path/to/project")

        # Verify scan path is "." (current directory)
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[-1], ".")

    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    @patch("pathlib.Path.exists")
    def test_generate_uses_absolute_output_path(self, mock_exists, mock_run):
        """Test that output file is converted to absolute path when using cwd."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_exists.return_value = True

        gen_input = GenerationInput(lock_file="/path/to/project/requirements.txt", output_file="sbom.json")
        result = self.generator.generate(gen_input)

        # Verify the command uses an absolute path for output
        cmd = mock_run.call_args[0][0]
        output_index = cmd.index("-o") + 1
        output_path = cmd[output_index]

        # Output path should be absolute
        self.assertTrue(Path(output_path).is_absolute())

        # Result should also have absolute path
        self.assertTrue(Path(result.output_file).is_absolute())

    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    @patch("pathlib.Path.exists")
    def test_generate_preserves_absolute_output_path(self, mock_exists, mock_run):
        """Test that already-absolute output paths are preserved correctly."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_exists.return_value = True

        gen_input = GenerationInput(
            lock_file="/path/to/project/requirements.txt",
            output_file="/absolute/output/sbom.json",
        )
        result = self.generator.generate(gen_input)

        # Verify the command uses the absolute path
        cmd = mock_run.call_args[0][0]
        output_index = cmd.index("-o") + 1
        output_path = cmd[output_index]

        # Output path should remain absolute and match the input
        self.assertTrue(Path(output_path).is_absolute())
        self.assertEqual(output_path, "/absolute/output/sbom.json")

        # Result should also have the same absolute path
        self.assertEqual(result.output_file, "/absolute/output/sbom.json")

    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    @patch("pathlib.Path.exists")
    def test_generate_handles_relative_lock_file_path(self, mock_exists, mock_run):
        """Test that relative lock file paths are handled correctly."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_exists.return_value = True

        gen_input = GenerationInput(lock_file="src/requirements.txt", output_file="sbom.json")
        self.generator.generate(gen_input)

        # Verify cwd is passed and resolved to absolute path
        call_kwargs = mock_run.call_args[1]
        self.assertIn("cwd", call_kwargs)
        # The cwd should be an absolute path (resolved from relative)
        self.assertTrue(Path(call_kwargs["cwd"]).is_absolute())

        # Verify scan path is "." (current directory)
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[-1], ".")


@patch("sbomify_action._generation.generators.cdxgen._CDXGEN_AVAILABLE", True)
class TestCdxgenImageGenerator(unittest.TestCase):
    """Tests for CdxgenImageGenerator."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = CdxgenImageGenerator()

    def test_name_and_priority(self):
        """Test generator name and priority."""
        self.assertEqual(self.generator.name, "cdxgen-image")
        self.assertEqual(self.generator.priority, 20)

    def test_supports_docker_images(self):
        """Test support for Docker images."""
        input = GenerationInput(docker_image="alpine:3.18", output_format="cyclonedx")
        self.assertTrue(self.generator.supports(input))

    def test_does_not_support_spdx(self):
        """Test that SPDX format is not supported."""
        input = GenerationInput(docker_image="alpine:3.18", output_format="spdx")
        self.assertFalse(self.generator.supports(input))

    def test_does_not_support_lock_files(self):
        """Test that lock files are not supported."""
        input = GenerationInput(lock_file="/path/requirements.txt", output_format="cyclonedx")
        self.assertFalse(self.generator.supports(input))

    def test_supports_cyclonedx_1_7(self):
        """Test support for CycloneDX 1.7."""
        input = GenerationInput(docker_image="alpine:3.18", output_format="cyclonedx", spec_version="1.7")
        self.assertTrue(self.generator.supports(input))

    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    @patch("pathlib.Path.exists")
    def test_generate_success(self, mock_exists, mock_run):
        """Test successful generation."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_exists.return_value = True

        gen_input = GenerationInput(
            docker_image="alpine:3.18", output_file="/output/sbom.json", output_format="cyclonedx"
        )
        result = self.generator.generate(gen_input)

        self.assertTrue(result.success)
        self.assertEqual(result.sbom_format, "cyclonedx")
        self.assertEqual(result.spec_version, "1.6")
        self.assertEqual(result.generator_name, "cdxgen-image")

    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    @patch("pathlib.Path.exists")
    def test_generate_uses_required_only_and_fail_on_error_flags(self, mock_exists, mock_run):
        """Test that --required-only and --fail-on-error flags are passed for image scanning."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_exists.return_value = True

        gen_input = GenerationInput(
            docker_image="alpine:3.18", output_file="/output/sbom.json", output_format="cyclonedx"
        )
        self.generator.generate(gen_input)

        cmd = mock_run.call_args[0][0]
        self.assertIn("--required-only", cmd)
        self.assertIn("--fail-on-error", cmd)


@patch("sbomify_action._generation.generators.syft._SYFT_AVAILABLE", True)
class TestSyftFsGenerator(unittest.TestCase):
    """Tests for SyftFsGenerator."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = SyftFsGenerator()

    def test_name_and_priority(self):
        """Test generator name and priority."""
        self.assertEqual(self.generator.name, "syft-fs")
        self.assertEqual(self.generator.priority, 35)

    def test_supported_versions(self):
        """Test supported versions."""
        formats = self.generator.supported_formats

        cyclonedx = next(f for f in formats if f.format == "cyclonedx")
        spdx = next(f for f in formats if f.format == "spdx")

        self.assertIn("1.5", cyclonedx.versions)
        self.assertNotIn("1.7", cyclonedx.versions)  # Syft doesn't support 1.7
        self.assertIn("2.2", spdx.versions)


class TestCreateDefaultRegistry(unittest.TestCase):
    """Tests for create_default_registry factory."""

    def test_creates_registry_with_enabled_generators(self):
        """Test that default registry has all enabled generators (Trivy temporarily disabled)."""
        registry = create_default_registry()
        generators = registry.list_generators()

        names = [g["name"] for g in generators]
        self.assertIn("cyclonedx-py", names)
        self.assertIn("cdxgen-fs", names)
        self.assertIn("cdxgen-image", names)
        # Trivy is temporarily disabled due to security vulnerabilities
        self.assertNotIn("trivy-fs", names)
        self.assertNotIn("trivy-image", names)
        self.assertIn("syft-fs", names)
        self.assertIn("syft-image", names)

    def test_generators_sorted_by_priority(self):
        """Test that generators are sorted by priority."""
        registry = create_default_registry()
        generators = registry.list_generators()

        priorities = [g["priority"] for g in generators]
        self.assertEqual(priorities, sorted(priorities))


class TestGeneratorOrchestrator(unittest.TestCase):
    """Tests for GeneratorOrchestrator."""

    def test_orchestrator_uses_default_registry(self):
        """Test that orchestrator creates default registry if none provided."""
        orchestrator = GeneratorOrchestrator()
        generators = orchestrator.list_all_generators()
        self.assertGreater(len(generators), 0)

    def test_orchestrator_uses_provided_registry(self):
        """Test that orchestrator uses provided registry."""
        registry = GeneratorRegistry()
        registry.register(CycloneDXPyGenerator())

        orchestrator = GeneratorOrchestrator(registry=registry)
        generators = orchestrator.list_all_generators()

        self.assertEqual(len(generators), 1)
        self.assertEqual(generators[0]["name"], "cyclonedx-py")

    @patch("sbomify_action._generation.generators.cyclonedx_py.run_command")
    def test_generate_uses_first_matching_generator(self, mock_run):
        """Test that generate uses the first matching generator by priority."""
        mock_run.return_value = MagicMock(returncode=0)

        orchestrator = GeneratorOrchestrator()
        input = GenerationInput(lock_file="/path/requirements.txt", output_file="sbom.json", output_format="cyclonedx")

        result = orchestrator.generate(input)

        # Should use cyclonedx-py (priority 10) for Python files
        self.assertTrue(result.success)
        self.assertEqual(result.generator_name, "cyclonedx-py")


@patch("sbomify_action._generation.generators.trivy._TRIVY_AVAILABLE", True)
class TestTrivyImageGenerator(unittest.TestCase):
    """Tests for TrivyImageGenerator."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = TrivyImageGenerator()

    def test_name_and_priority(self):
        """Test generator name and priority."""
        self.assertEqual(self.generator.name, "trivy-image")
        self.assertEqual(self.generator.priority, 30)

    def test_supports_docker_images(self):
        """Test support for Docker images."""
        input = GenerationInput(docker_image="alpine:3.18", output_format="cyclonedx")
        self.assertTrue(self.generator.supports(input))

    def test_supports_spdx(self):
        """Test support for SPDX format."""
        input = GenerationInput(docker_image="alpine:3.18", output_format="spdx")
        self.assertTrue(self.generator.supports(input))

    def test_does_not_support_lock_files(self):
        """Test that lock files are not supported."""
        input = GenerationInput(lock_file="/path/requirements.txt", output_format="cyclonedx")
        self.assertFalse(self.generator.supports(input))

    def test_does_not_support_cyclonedx_1_5(self):
        """Test that CycloneDX 1.5 is not supported (Trivy only outputs 1.6)."""
        input = GenerationInput(docker_image="alpine:3.18", output_format="cyclonedx", spec_version="1.5")
        self.assertFalse(self.generator.supports(input))

    @patch("sbomify_action._generation.generators.trivy.run_command")
    def test_generate_success_cyclonedx(self, mock_run):
        """Test successful CycloneDX generation."""
        mock_run.return_value = MagicMock(returncode=0, stdout='{"bomFormat": "CycloneDX"}')

        input = GenerationInput(docker_image="alpine:3.18", output_file="/tmp/sbom.json", output_format="cyclonedx")

        with patch("builtins.open", MagicMock()):
            with patch("json.loads", return_value={"bomFormat": "CycloneDX"}):
                with patch("json.dump"):
                    result = self.generator.generate(input)

        self.assertTrue(result.success)
        self.assertEqual(result.sbom_format, "cyclonedx")
        self.assertEqual(result.spec_version, "1.6")

    @patch("sbomify_action._generation.generators.trivy.run_command")
    def test_generate_success_spdx(self, mock_run):
        """Test successful SPDX generation."""
        mock_run.return_value = MagicMock(returncode=0, stdout='{"spdxVersion": "SPDX-2.3"}')

        input = GenerationInput(docker_image="alpine:3.18", output_file="/tmp/sbom.json", output_format="spdx")

        with patch("builtins.open", MagicMock()):
            with patch("json.loads", return_value={"spdxVersion": "SPDX-2.3"}):
                with patch("json.dump"):
                    result = self.generator.generate(input)

        self.assertTrue(result.success)
        self.assertEqual(result.sbom_format, "spdx")
        self.assertEqual(result.spec_version, "2.3")


@patch("sbomify_action._generation.generators.syft._SYFT_AVAILABLE", True)
class TestSyftImageGenerator(unittest.TestCase):
    """Tests for SyftImageGenerator."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = SyftImageGenerator()

    def test_name_and_priority(self):
        """Test generator name and priority."""
        self.assertEqual(self.generator.name, "syft-image")
        self.assertEqual(self.generator.priority, 35)

    def test_supports_docker_images(self):
        """Test support for Docker images."""
        input = GenerationInput(docker_image="alpine:3.18", output_format="cyclonedx")
        self.assertTrue(self.generator.supports(input))

    def test_supports_spdx(self):
        """Test support for SPDX format."""
        input = GenerationInput(docker_image="alpine:3.18", output_format="spdx")
        self.assertTrue(self.generator.supports(input))

    def test_supports_cyclonedx_1_5(self):
        """Test support for CycloneDX 1.5."""
        input = GenerationInput(docker_image="alpine:3.18", output_format="cyclonedx", spec_version="1.5")
        self.assertTrue(self.generator.supports(input))

    def test_does_not_support_cyclonedx_1_7(self):
        """Test that CycloneDX 1.7 is not supported by Syft."""
        input = GenerationInput(docker_image="alpine:3.18", output_format="cyclonedx", spec_version="1.7")
        self.assertFalse(self.generator.supports(input))

    def test_does_not_support_lock_files(self):
        """Test that lock files are not supported."""
        input = GenerationInput(lock_file="/path/requirements.txt", output_format="cyclonedx")
        self.assertFalse(self.generator.supports(input))


class TestRegistryGenerateWithFallback(unittest.TestCase):
    """Tests for registry generate with fallback behavior."""

    @patch("sbomify_action._generation.registry.check_tool_for_input")
    def test_generate_no_generators_raises_error(self, mock_check_tool):
        """Test that generate raises error when no generators available."""
        # Tools are available but none support this format/version
        mock_check_tool.return_value = (["trivy"], [])

        registry = GeneratorRegistry()

        input = GenerationInput(lock_file="/path/unknown.xyz", output_format="cyclonedx")

        with self.assertRaises(SBOMGenerationError) as cm:
            registry.generate(input)

        self.assertIn("No generator found", str(cm.exception))

    @patch("sbomify_action._generation.registry.check_tool_for_input")
    def test_generate_no_tools_raises_tool_not_available_error(self, mock_check_tool):
        """Test that generate raises ToolNotAvailableError when no tools are installed."""
        # Simulate no tools available - all tools missing
        mock_check_tool.return_value = ([], ["trivy", "syft", "cdxgen"])

        registry = GeneratorRegistry()

        input = GenerationInput(lock_file="/path/requirements.txt", output_format="cyclonedx")

        with self.assertRaises(ToolNotAvailableError) as cm:
            registry.generate(input)

        # Verify exception attributes
        self.assertEqual(cm.exception.input_type, "lock_file")
        self.assertEqual(cm.exception.lock_file, "/path/requirements.txt")

    @patch("sbomify_action._generation.generators.cyclonedx_py.run_command")
    def test_generate_falls_back_on_failure(self, mock_run):
        """Test that generate tries next generator on failure."""
        # First generator fails
        mock_run.side_effect = SBOMGenerationError("First generator failed")

        registry = GeneratorRegistry()
        registry.register(CycloneDXPyGenerator())

        # Add a mock generator that succeeds
        mock_generator = MagicMock()
        mock_generator.name = "mock-generator"
        mock_generator.priority = 20
        mock_generator.supported_formats = [FormatVersion("cyclonedx", ("1.6",), "1.6")]
        mock_generator.supports.return_value = True
        mock_generator.generate.return_value = GenerationResult.success_result(
            output_file="sbom.json",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="mock-generator",
        )
        registry.register(mock_generator)

        input = GenerationInput(lock_file="/path/requirements.txt", output_format="cyclonedx")
        result = registry.generate(input)

        # Should succeed with mock generator
        self.assertTrue(result.success)
        self.assertEqual(result.generator_name, "mock-generator")

    @patch("sbomify_action._generation.generators.syft._SYFT_AVAILABLE", True)
    @patch("sbomify_action._generation.generators.cdxgen._CDXGEN_AVAILABLE", True)
    @patch("sbomify_action._generation.generators.syft.run_command")
    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    def test_dart_fallback_cdxgen_to_syft(self, mock_cdxgen_run, mock_syft_run):
        """Test that Dart pubspec.lock falls back from cdxgen to Syft on failure.

        This test verifies the fix for the cdxgen TypeError bug where
        parentComponent is undefined when processing certain Dart files.
        """
        import os
        import tempfile

        # Create a temporary output file for Syft
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}')
            temp_output = f.name

        try:
            # cdxgen fails with the TypeError bug
            mock_cdxgen_run.side_effect = SBOMGenerationError("cdxgen command failed with return code 1")

            # Syft succeeds and creates output file
            def syft_side_effect(*args, **kwargs):
                # Extract output file from command args
                cmd = args[0]
                for i, arg in enumerate(cmd):
                    if arg == "-o" or arg.startswith("cyclonedx-json@"):
                        if "=" in arg:
                            output_file = arg.split("=")[-1]
                            # Create the output file
                            with open(output_file, "w") as f:
                                f.write('{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}')
                            break
                return MagicMock(returncode=0)

            mock_syft_run.side_effect = syft_side_effect

            registry = GeneratorRegistry()
            registry.register(CdxgenFsGenerator())  # Priority 20
            registry.register(SyftFsGenerator())  # Priority 35

            input = GenerationInput(
                lock_file="/path/pubspec.lock",
                output_file=temp_output,
                output_format="cyclonedx",
                spec_version="1.6",
            )
            result = registry.generate(input, validate=False)

            # Should fall back to Syft and succeed
            self.assertTrue(result.success, f"Expected success but got: {result.error_message}")
            self.assertEqual(result.generator_name, "syft-fs")

            # Verify cdxgen was tried first
            mock_cdxgen_run.assert_called_once()

            # Verify Syft was tried as fallback
            mock_syft_run.assert_called_once()
        finally:
            # Clean up temp file
            if os.path.exists(temp_output):
                os.unlink(temp_output)

    @patch("sbomify_action._generation.generators.syft._SYFT_AVAILABLE", True)
    @patch("sbomify_action._generation.generators.cdxgen._CDXGEN_AVAILABLE", True)
    def test_dart_both_generators_available(self):
        """Test that both cdxgen and Syft support Dart pubspec.lock files."""
        registry = GeneratorRegistry()
        registry.register(CdxgenFsGenerator())  # Priority 20
        registry.register(SyftFsGenerator())  # Priority 35

        input = GenerationInput(
            lock_file="/path/pubspec.lock",
            output_file="sbom.json",
            output_format="cyclonedx",
            spec_version="1.6",
        )

        generators = registry.get_generators_for(input)
        generator_names = [g.name for g in generators]

        # Both should support Dart
        self.assertIn("cdxgen-fs", generator_names)
        self.assertIn("syft-fs", generator_names)

        # cdxgen should come first (lower priority number = higher priority)
        self.assertEqual(generators[0].name, "cdxgen-fs")
        self.assertEqual(generators[1].name, "syft-fs")


class TestUtilsFunctions(unittest.TestCase):
    """Tests for utility functions in _generation/utils.py."""

    def test_get_lock_file_ecosystem_python(self):
        """Test ecosystem detection for Python lock files."""
        from sbomify_action._generation.utils import get_lock_file_ecosystem

        self.assertEqual(get_lock_file_ecosystem("requirements.txt"), "python")
        self.assertEqual(get_lock_file_ecosystem("poetry.lock"), "python")
        self.assertEqual(get_lock_file_ecosystem("Pipfile.lock"), "python")

    def test_get_lock_file_ecosystem_rust(self):
        """Test ecosystem detection for Rust lock files."""
        from sbomify_action._generation.utils import get_lock_file_ecosystem

        self.assertEqual(get_lock_file_ecosystem("Cargo.lock"), "rust")

    def test_get_lock_file_ecosystem_javascript(self):
        """Test ecosystem detection for JavaScript lock files."""
        from sbomify_action._generation.utils import get_lock_file_ecosystem

        self.assertEqual(get_lock_file_ecosystem("package.json"), "javascript")
        self.assertEqual(get_lock_file_ecosystem("yarn.lock"), "javascript")

    def test_get_lock_file_ecosystem_java(self):
        """Test ecosystem detection for Java lock files."""
        from sbomify_action._generation.utils import get_lock_file_ecosystem

        self.assertEqual(get_lock_file_ecosystem("pom.xml"), "java")

    def test_get_lock_file_ecosystem_unknown(self):
        """Test ecosystem detection for unknown lock files."""
        from sbomify_action._generation.utils import get_lock_file_ecosystem

        self.assertIsNone(get_lock_file_ecosystem("unknown.lock"))

    def test_is_supported_lock_file(self):
        """Test supported lock file detection."""
        from sbomify_action._generation.utils import is_supported_lock_file

        self.assertTrue(is_supported_lock_file("requirements.txt"))
        self.assertTrue(is_supported_lock_file("Cargo.lock"))
        self.assertFalse(is_supported_lock_file("unknown.lock"))


@patch("sbomify_action._generation.generators.cyclonedx_py._CYCLONEDX_PY_AVAILABLE", True)
class TestCycloneDXPyGeneratorVersionValidation(unittest.TestCase):
    """Tests for CycloneDX-py generator version validation."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = CycloneDXPyGenerator()

    def test_unsupported_version_returns_failure(self):
        """Test that unsupported version returns failure result."""
        input = GenerationInput(
            lock_file="/path/requirements.txt",
            output_format="cyclonedx",
            spec_version="2.0",  # Invalid version
        )

        result = self.generator.generate(input)

        self.assertFalse(result.success)
        self.assertIn("Unsupported CycloneDX version", result.error_message)


class TestGenerationResultValidation(unittest.TestCase):
    """Tests for GenerationResult validation."""

    def test_success_without_output_file_raises(self):
        """Test that success result without output file raises error."""
        with self.assertRaises(ValueError):
            GenerationResult(
                success=True,
                output_file=None,
                sbom_format="cyclonedx",
                spec_version="1.6",
                generator_name="test",
            )

    def test_failure_without_error_message_raises(self):
        """Test that failure result without error message raises error."""
        with self.assertRaises(ValueError):
            GenerationResult(
                success=False,
                output_file=None,
                sbom_format="cyclonedx",
                spec_version="1.6",
                generator_name="test",
                error_message=None,
            )


class TestRegistryListGenerators(unittest.TestCase):
    """Tests for registry list_generators functionality."""

    def test_list_generators_includes_format_info(self):
        """Test that list_generators includes format information."""
        registry = GeneratorRegistry()
        registry.register(CycloneDXPyGenerator())

        generators = registry.list_generators()

        self.assertEqual(len(generators), 1)
        self.assertEqual(generators[0]["name"], "cyclonedx-py")
        self.assertEqual(len(generators[0]["formats"]), 1)
        self.assertEqual(generators[0]["formats"][0]["format"], "cyclonedx")

    def test_clear_removes_all_generators(self):
        """Test that clear removes all generators."""
        registry = GeneratorRegistry()
        registry.register(CycloneDXPyGenerator())
        registry.register(TrivyFsGenerator())

        self.assertEqual(len(registry.list_generators()), 2)

        registry.clear()

        self.assertEqual(len(registry.list_generators()), 0)


class TestRegistryGenerateValidation(unittest.TestCase):
    """Tests for registry generate validation behavior."""

    def test_generate_validates_output_by_default(self):
        """Test that generate validates output when validate=True (default)."""
        registry = GeneratorRegistry()

        # Add a mock generator that succeeds
        mock_generator = MagicMock()
        mock_generator.name = "mock-generator"
        mock_generator.priority = 10
        mock_generator.supported_formats = [FormatVersion("cyclonedx", ("1.6",), "1.6")]
        mock_generator.supports.return_value = True
        mock_generator.generate.return_value = GenerationResult.success_result(
            output_file="/tmp/sbom.json",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="mock-generator",
        )
        registry.register(mock_generator)

        input = GenerationInput(lock_file="/path/requirements.txt", output_format="cyclonedx")

        with patch("sbomify_action._generation.registry.validate_sbom_file") as mock_validate:
            # Mock successful validation
            mock_result = MagicMock()
            mock_result.valid = True
            mock_result.sbom_format = "cyclonedx"
            mock_result.spec_version = "1.6"
            mock_validate.return_value = mock_result

            result = registry.generate(input, validate=True)

            # Validation should be called
            mock_validate.assert_called_once()
            self.assertTrue(result.success)

    def test_generate_skips_validation_when_disabled(self):
        """Test that generate skips validation when validate=False."""
        registry = GeneratorRegistry()

        # Add a mock generator that succeeds
        mock_generator = MagicMock()
        mock_generator.name = "mock-generator"
        mock_generator.priority = 10
        mock_generator.supported_formats = [FormatVersion("cyclonedx", ("1.6",), "1.6")]
        mock_generator.supports.return_value = True
        mock_generator.generate.return_value = GenerationResult.success_result(
            output_file="/tmp/sbom.json",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="mock-generator",
        )
        registry.register(mock_generator)

        input = GenerationInput(lock_file="/path/requirements.txt", output_format="cyclonedx")

        with patch("sbomify_action._generation.registry.validate_sbom_file") as mock_validate:
            result = registry.generate(input, validate=False)

            # Validation should NOT be called
            mock_validate.assert_not_called()
            self.assertTrue(result.success)

    def test_generate_validation_failure_sets_validation_error(self):
        """Test that validation failure sets validation_error on result."""
        registry = GeneratorRegistry()

        # Add a mock generator that succeeds
        mock_generator = MagicMock()
        mock_generator.name = "mock-generator"
        mock_generator.priority = 10
        mock_generator.supported_formats = [FormatVersion("cyclonedx", ("1.6",), "1.6")]
        mock_generator.supports.return_value = True
        mock_generator.generate.return_value = GenerationResult.success_result(
            output_file="/tmp/sbom.json",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="mock-generator",
        )
        registry.register(mock_generator)

        input = GenerationInput(lock_file="/path/requirements.txt", output_format="cyclonedx")

        with patch("sbomify_action._generation.registry.validate_sbom_file") as mock_validate:
            # Mock validation failure
            mock_result = MagicMock()
            mock_result.valid = False
            mock_result.error_message = "Schema validation failed: missing required field"
            mock_validate.return_value = mock_result

            result = registry.generate(input, validate=True)

            # SBOM was generated successfully, but validation found issues
            self.assertTrue(result.success)
            self.assertTrue(result.validated)
            # validation_error should contain the error message
            self.assertIsNotNone(result.validation_error)
            self.assertIn("Schema validation failed", result.validation_error)


class TestDockerImageNotFoundDetection(unittest.TestCase):
    """Tests for Docker image not found error detection."""

    def test_detect_manifest_unknown(self):
        """Test detection of MANIFEST_UNKNOWN error."""
        from sbomify_action._generation.utils import detect_docker_image_not_found

        stderr = "MANIFEST_UNKNOWN: manifest unknown; unknown tag=v0.11"
        self.assertTrue(detect_docker_image_not_found(stderr))

    def test_detect_manifest_unknown_lowercase(self):
        """Test detection of manifest unknown error (lowercase)."""
        from sbomify_action._generation.utils import detect_docker_image_not_found

        stderr = "manifest unknown; unknown tag=v0.11"
        self.assertTrue(detect_docker_image_not_found(stderr))

    def test_detect_manifest_not_found(self):
        """Test detection of 'manifest for X not found' error."""
        from sbomify_action._generation.utils import detect_docker_image_not_found

        stderr = "manifest for sbomifyhub/sbomify-action:v0.11 not found: manifest unknown"
        self.assertTrue(detect_docker_image_not_found(stderr))

    def test_detect_unable_to_find_image(self):
        """Test detection of 'unable to find the specified image' error."""
        from sbomify_action._generation.utils import detect_docker_image_not_found

        stderr = 'unable to find the specified image "sbomifyhub/sbomify-action:v0.11"'
        self.assertTrue(detect_docker_image_not_found(stderr))

    def test_detect_no_such_image(self):
        """Test detection of 'No such image' error."""
        from sbomify_action._generation.utils import detect_docker_image_not_found

        stderr = "Error response from daemon: No such image: alpine:nonexistent"
        self.assertTrue(detect_docker_image_not_found(stderr))

    def test_detect_pull_access_denied(self):
        """Test detection of 'pull access denied' error."""
        from sbomify_action._generation.utils import detect_docker_image_not_found

        stderr = "pull access denied for private/image, repository does not exist"
        self.assertTrue(detect_docker_image_not_found(stderr))

    def test_detect_repository_does_not_exist(self):
        """Test detection of 'repository does not exist' error."""
        from sbomify_action._generation.utils import detect_docker_image_not_found

        stderr = "repository does not exist or may require 'docker login'"
        self.assertTrue(detect_docker_image_not_found(stderr))

    def test_no_detection_for_other_errors(self):
        """Test that other errors are not detected as image not found."""
        from sbomify_action._generation.utils import detect_docker_image_not_found

        stderr = "some random error message"
        self.assertFalse(detect_docker_image_not_found(stderr))

    def test_no_detection_for_empty_stderr(self):
        """Test that empty stderr returns False."""
        from sbomify_action._generation.utils import detect_docker_image_not_found

        self.assertFalse(detect_docker_image_not_found(""))
        self.assertFalse(detect_docker_image_not_found(None))

    def test_detect_trivy_full_error(self):
        """Test detection of full Trivy error message."""
        from sbomify_action._generation.utils import detect_docker_image_not_found

        stderr = """2026-01-20T05:50:49Z	FATAL	Fatal error	run error: image scan error: unable to find the specified image "sbomifyhub/sbomify-action:v0.11" in ["docker" "containerd" "podman" "remote"]: 4 errors occurred:
        * docker error: unable to inspect the image (sbomifyhub/sbomify-action:v0.11): Error response from daemon: No such image: sbomifyhub/sbomify-action:v0.11
        * remote error: GET https://index.docker.io/v2/sbomifyhub/sbomify-action/manifests/v0.11: MANIFEST_UNKNOWN: manifest unknown; unknown tag=v0.11"""
        self.assertTrue(detect_docker_image_not_found(stderr))

    def test_detect_syft_full_error(self):
        """Test detection of full Syft error message."""
        from sbomify_action._generation.utils import detect_docker_image_not_found

        stderr = """[0001] ERROR could not determine source: errors occurred attempting to resolve 'sbomifyhub/sbomify-action:v0.11':
  - docker: pull failed: Error response from daemon: manifest for sbomifyhub/sbomify-action:v0.11 not found: manifest unknown
  - oci-registry: failed to get image descriptor from registry: GET https://index.docker.io/v2/sbomifyhub/sbomify-action/manifests/v0.11: MANIFEST_UNKNOWN: manifest unknown; unknown tag=v0.11"""
        self.assertTrue(detect_docker_image_not_found(stderr))


class TestDockerImageNotFoundError(unittest.TestCase):
    """Tests for DockerImageNotFoundError exception."""

    def test_exception_with_default_message(self):
        """Test creating exception with default message."""
        from sbomify_action.exceptions import DockerImageNotFoundError

        exc = DockerImageNotFoundError(image="alpine:nonexistent")
        self.assertEqual(exc.image, "alpine:nonexistent")
        self.assertIn("alpine:nonexistent", str(exc))
        self.assertIn("not found", str(exc))

    def test_exception_with_custom_message(self):
        """Test creating exception with custom message."""
        from sbomify_action.exceptions import DockerImageNotFoundError

        exc = DockerImageNotFoundError(
            image="alpine:nonexistent",
            message="Custom error message for alpine:nonexistent",
        )
        self.assertEqual(exc.image, "alpine:nonexistent")
        self.assertEqual(str(exc), "Custom error message for alpine:nonexistent")

    def test_exception_inherits_from_sbom_generation_error(self):
        """Test that DockerImageNotFoundError inherits from SBOMGenerationError."""
        from sbomify_action.exceptions import DockerImageNotFoundError, SBOMGenerationError

        exc = DockerImageNotFoundError(image="test:latest")
        self.assertIsInstance(exc, SBOMGenerationError)


class TestRunCommandDockerImageNotFound(unittest.TestCase):
    """Tests for run_command with Docker image not found errors."""

    @patch("subprocess.run")
    def test_raises_docker_image_not_found_error(self, mock_run):
        """Test that run_command raises DockerImageNotFoundError for image not found."""
        import subprocess

        from sbomify_action._generation.utils import run_command
        from sbomify_action.exceptions import DockerImageNotFoundError

        # Simulate a command failure with MANIFEST_UNKNOWN error
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd=["trivy", "image", "alpine:nonexistent"],
            stderr="MANIFEST_UNKNOWN: manifest unknown; unknown tag=nonexistent",
        )

        with self.assertRaises(DockerImageNotFoundError) as cm:
            run_command(
                ["trivy", "image", "alpine:nonexistent"],
                "trivy",
                docker_image="alpine:nonexistent",
            )

        self.assertEqual(cm.exception.image, "alpine:nonexistent")
        self.assertIn("not found", str(cm.exception))

    @patch("subprocess.run")
    def test_raises_sbom_generation_error_for_other_failures(self, mock_run):
        """Test that run_command raises SBOMGenerationError for non-image errors."""
        import subprocess

        from sbomify_action._generation.utils import run_command
        from sbomify_action.exceptions import DockerImageNotFoundError, SBOMGenerationError

        # Simulate a command failure with a different error
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd=["trivy", "image", "alpine:3.18"],
            stderr="Some other error",
        )

        with self.assertRaises(SBOMGenerationError) as cm:
            run_command(
                ["trivy", "image", "alpine:3.18"],
                "trivy",
                docker_image="alpine:3.18",
            )

        # Should NOT be DockerImageNotFoundError
        self.assertNotIsInstance(cm.exception, DockerImageNotFoundError)

    @patch("subprocess.run")
    def test_no_docker_image_not_found_without_image_param(self, mock_run):
        """Test that without docker_image param, SBOM error is raised even for manifest errors."""
        import subprocess

        from sbomify_action._generation.utils import run_command
        from sbomify_action.exceptions import DockerImageNotFoundError, SBOMGenerationError

        # Simulate a command failure with MANIFEST_UNKNOWN error
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd=["trivy", "image", "alpine:nonexistent"],
            stderr="MANIFEST_UNKNOWN: manifest unknown",
        )

        with self.assertRaises(SBOMGenerationError) as cm:
            # Note: docker_image parameter not provided
            run_command(["trivy", "image", "alpine:nonexistent"], "trivy")

        # Should NOT be DockerImageNotFoundError since docker_image wasn't provided
        self.assertNotIsInstance(cm.exception, DockerImageNotFoundError)


@patch("sbomify_action._generation.generators.trivy._TRIVY_AVAILABLE", True)
class TestTrivyImageGeneratorDockerNotFound(unittest.TestCase):
    """Tests for TrivyImageGenerator handling Docker image not found."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = TrivyImageGenerator()

    @patch("sbomify_action._generation.generators.trivy.run_command")
    def test_returns_clear_error_for_image_not_found(self, mock_run):
        """Test that clear error is returned when image is not found."""
        from sbomify_action.exceptions import DockerImageNotFoundError

        mock_run.side_effect = DockerImageNotFoundError(
            image="sbomifyhub/sbomify-action:v0.11",
            message="Docker image 'sbomifyhub/sbomify-action:v0.11' not found. Verify the image exists.",
        )

        gen_input = GenerationInput(
            docker_image="sbomifyhub/sbomify-action:v0.11",
            output_file="/tmp/sbom.json",
            output_format="spdx",
        )
        result = self.generator.generate(gen_input)

        self.assertFalse(result.success)
        self.assertIn("not found", result.error_message)
        self.assertIn("sbomifyhub/sbomify-action:v0.11", result.error_message)


@patch("sbomify_action._generation.generators.syft._SYFT_AVAILABLE", True)
class TestSyftImageGeneratorDockerNotFound(unittest.TestCase):
    """Tests for SyftImageGenerator handling Docker image not found."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = SyftImageGenerator()

    @patch("sbomify_action._generation.generators.syft.run_command")
    def test_returns_clear_error_for_image_not_found(self, mock_run):
        """Test that clear error is returned when image is not found."""
        from sbomify_action.exceptions import DockerImageNotFoundError

        mock_run.side_effect = DockerImageNotFoundError(
            image="sbomifyhub/sbomify-action:v0.11",
            message="Docker image 'sbomifyhub/sbomify-action:v0.11' not found. Verify the image exists.",
        )

        gen_input = GenerationInput(
            docker_image="sbomifyhub/sbomify-action:v0.11",
            output_file="/tmp/sbom.json",
            output_format="cyclonedx",
        )
        result = self.generator.generate(gen_input)

        self.assertFalse(result.success)
        self.assertIn("not found", result.error_message)
        self.assertIn("sbomifyhub/sbomify-action:v0.11", result.error_message)


@patch("sbomify_action._generation.generators.cdxgen._CDXGEN_AVAILABLE", True)
class TestCdxgenImageGeneratorDockerNotFound(unittest.TestCase):
    """Tests for CdxgenImageGenerator handling Docker image not found."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = CdxgenImageGenerator()

    @patch("sbomify_action._generation.generators.cdxgen.run_command")
    def test_returns_clear_error_for_image_not_found(self, mock_run):
        """Test that clear error is returned when image is not found."""
        from sbomify_action.exceptions import DockerImageNotFoundError

        mock_run.side_effect = DockerImageNotFoundError(
            image="sbomifyhub/sbomify-action:v0.11",
            message="Docker image 'sbomifyhub/sbomify-action:v0.11' not found. Verify the image exists.",
        )

        gen_input = GenerationInput(
            docker_image="sbomifyhub/sbomify-action:v0.11",
            output_file="/tmp/sbom.json",
            output_format="cyclonedx",
        )
        result = self.generator.generate(gen_input)

        self.assertFalse(result.success)
        self.assertIn("not found", result.error_message)
        self.assertIn("sbomifyhub/sbomify-action:v0.11", result.error_message)


class TestToolNotAvailableError(unittest.TestCase):
    """Tests for ToolNotAvailableError exception."""

    def test_exception_with_default_message(self):
        """Test creating exception with default message."""
        exc = ToolNotAvailableError(input_type="lock_file")
        self.assertEqual(exc.input_type, "lock_file")
        self.assertIsNone(exc.lock_file)
        self.assertIn("No SBOM generation tools available", str(exc))
        self.assertIn("lock_file", str(exc))

    def test_exception_with_lock_file(self):
        """Test creating exception with lock file info."""
        exc = ToolNotAvailableError(input_type="lock_file", lock_file="requirements.txt")
        self.assertEqual(exc.input_type, "lock_file")
        self.assertEqual(exc.lock_file, "requirements.txt")

    def test_exception_with_custom_message(self):
        """Test creating exception with custom message."""
        custom_msg = "Custom error: install trivy or syft"
        exc = ToolNotAvailableError(
            input_type="docker_image",
            message=custom_msg,
        )
        self.assertEqual(exc.input_type, "docker_image")
        self.assertEqual(str(exc), custom_msg)

    def test_exception_inherits_from_sbom_generation_error(self):
        """Test that ToolNotAvailableError inherits from SBOMGenerationError."""
        exc = ToolNotAvailableError(input_type="lock_file")
        self.assertIsInstance(exc, SBOMGenerationError)


class TestSBOMGenerationErrorEnhanced(unittest.TestCase):
    """Tests for enhanced SBOMGenerationError with stderr/stdout/returncode."""

    def test_exception_with_all_fields(self):
        """Test creating exception with all diagnostic fields."""
        from sbomify_action.exceptions import SBOMGenerationError

        exc = SBOMGenerationError(
            message="Command failed",
            stderr="FATAL: something went wrong",
            stdout="some output",
            returncode=1,
        )
        self.assertEqual(str(exc), "Command failed")
        self.assertEqual(exc.stderr, "FATAL: something went wrong")
        self.assertEqual(exc.stdout, "some output")
        self.assertEqual(exc.returncode, 1)

    def test_exception_with_defaults(self):
        """Test creating exception with default values."""
        from sbomify_action.exceptions import SBOMGenerationError

        exc = SBOMGenerationError("Command failed")
        self.assertEqual(str(exc), "Command failed")
        self.assertEqual(exc.stderr, "")
        self.assertEqual(exc.stdout, "")
        self.assertIsNone(exc.returncode)

    def test_docker_image_not_found_with_diagnostics(self):
        """Test DockerImageNotFoundError with diagnostic info."""
        from sbomify_action.exceptions import DockerImageNotFoundError

        exc = DockerImageNotFoundError(
            image="alpine:nonexistent",
            message="Image not found",
            stderr="MANIFEST_UNKNOWN",
            returncode=1,
        )
        self.assertEqual(exc.image, "alpine:nonexistent")
        self.assertEqual(exc.stderr, "MANIFEST_UNKNOWN")
        self.assertEqual(exc.returncode, 1)


class TestExtractErrorSummary(unittest.TestCase):
    """Tests for extract_error_summary helper function."""

    def test_extract_fatal_line(self):
        """Test extracting FATAL error lines."""
        from sbomify_action._generation.utils import extract_error_summary

        output = "INFO: Starting scan\nFATAL: Image not found\nINFO: Cleanup"
        result = extract_error_summary(output)
        self.assertIn("FATAL: Image not found", result)
        self.assertNotIn("INFO: Starting scan", result)

    def test_extract_error_line(self):
        """Test extracting ERROR lines."""
        from sbomify_action._generation.utils import extract_error_summary

        output = "DEBUG: checking\nERROR: connection refused\nDEBUG: done"
        result = extract_error_summary(output)
        self.assertIn("ERROR: connection refused", result)
        self.assertNotIn("DEBUG", result)

    def test_extract_lowercase_error(self):
        """Test extracting 'error:' lines (lowercase)."""
        from sbomify_action._generation.utils import extract_error_summary

        output = "info: starting\nerror: file not found\ninfo: done"
        result = extract_error_summary(output)
        self.assertIn("error: file not found", result)

    def test_extract_failed_pattern(self):
        """Test extracting lines with 'failed:' pattern."""
        from sbomify_action._generation.utils import extract_error_summary

        output = "step 1 ok\nstep 2 failed: timeout\nstep 3 skipped"
        result = extract_error_summary(output)
        self.assertIn("failed: timeout", result)

    def test_truncate_long_output(self):
        """Test that long output is truncated."""
        from sbomify_action._generation.utils import extract_error_summary

        output = "A" * 1000
        result = extract_error_summary(output, max_chars=100)
        self.assertLessEqual(len(result), 100)
        self.assertTrue(result.endswith("..."))

    def test_empty_output(self):
        """Test empty output returns empty string."""
        from sbomify_action._generation.utils import extract_error_summary

        self.assertEqual(extract_error_summary(""), "")
        self.assertEqual(extract_error_summary(None), "")

    def test_multiple_error_lines_joined(self):
        """Test multiple error lines are joined with pipe separator."""
        from sbomify_action._generation.utils import extract_error_summary

        output = "FATAL: first error\nERROR: second error"
        result = extract_error_summary(output)
        self.assertIn("FATAL: first error", result)
        self.assertIn("ERROR: second error", result)
        self.assertIn(" | ", result)

    def test_fallback_to_full_output(self):
        """Test fallback to full output when no error patterns found."""
        from sbomify_action._generation.utils import extract_error_summary

        output = "some random output\nwith multiple lines"
        result = extract_error_summary(output)
        # Should contain content from original, joined
        self.assertIn("some random output", result)

    def test_extract_prefixed_errors(self):
        """Test extracting errors with timestamp or tool prefixes."""
        from sbomify_action._generation.utils import extract_error_summary

        # Timestamp prefix
        output = "2024-01-28 10:00:00 ERROR: connection timeout\ninfo: retrying"
        result = extract_error_summary(output)
        self.assertIn("ERROR: connection timeout", result)
        self.assertNotIn("retrying", result)

        # Tool prefix
        output = "[trivy] FATAL: scan failed\n[trivy] info: cleanup"
        result = extract_error_summary(output)
        self.assertIn("FATAL: scan failed", result)
        self.assertNotIn("cleanup", result)


class TestRunCommandErrorMessages(unittest.TestCase):
    """Tests for run_command error message enhancement."""

    @patch("subprocess.run")
    def test_error_includes_stderr_summary(self, mock_run):
        """Test that SBOMGenerationError includes stderr summary."""
        import subprocess

        from sbomify_action._generation.utils import run_command
        from sbomify_action.exceptions import SBOMGenerationError

        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd=["trivy", "fs", "."],
            stderr="FATAL: unable to scan directory: permission denied",
        )

        with self.assertRaises(SBOMGenerationError) as cm:
            run_command(["trivy", "fs", "."], "trivy")

        # Error message should include the summary
        self.assertIn("FATAL", str(cm.exception))
        self.assertIn("permission denied", str(cm.exception))
        # Should also have the diagnostic fields
        self.assertEqual(cm.exception.returncode, 1)
        self.assertIn("permission denied", cm.exception.stderr)

    @patch("subprocess.run")
    def test_docker_image_error_includes_diagnostics(self, mock_run):
        """Test DockerImageNotFoundError includes full diagnostic info."""
        import subprocess

        from sbomify_action._generation.utils import run_command
        from sbomify_action.exceptions import DockerImageNotFoundError

        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd=["trivy", "image", "test:latest"],
            stderr="MANIFEST_UNKNOWN: manifest unknown; tag=latest",
        )

        with self.assertRaises(DockerImageNotFoundError) as cm:
            run_command(
                ["trivy", "image", "test:latest"],
                "trivy",
                docker_image="test:latest",
            )

        # Should have diagnostic info attached
        self.assertEqual(cm.exception.returncode, 1)
        self.assertIn("MANIFEST_UNKNOWN", cm.exception.stderr)


class TestRegistryErrorAggregation(unittest.TestCase):
    """Tests for registry error aggregation when all generators fail."""

    def test_aggregates_multiple_errors(self):
        """Test that registry aggregates errors from multiple generators."""
        registry = GeneratorRegistry()

        # Create mock generators that all fail
        mock_gen1 = MagicMock()
        mock_gen1.name = "gen1"
        mock_gen1.priority = 10
        mock_gen1.supported_formats = [FormatVersion("cyclonedx", ("1.6",), "1.6")]
        mock_gen1.supports.return_value = True
        mock_gen1.generate.return_value = GenerationResult.failure_result(
            error_message="gen1 failed: first error",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="gen1",
        )

        mock_gen2 = MagicMock()
        mock_gen2.name = "gen2"
        mock_gen2.priority = 20
        mock_gen2.supported_formats = [FormatVersion("cyclonedx", ("1.6",), "1.6")]
        mock_gen2.supports.return_value = True
        mock_gen2.generate.return_value = GenerationResult.failure_result(
            error_message="gen2 failed: second error",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="gen2",
        )

        registry.register(mock_gen1)
        registry.register(mock_gen2)

        gen_input = GenerationInput(lock_file="/path/requirements.txt", output_format="cyclonedx")
        result = registry.generate(gen_input)

        # Should include errors from both generators
        self.assertFalse(result.success)
        self.assertIn("gen1", result.error_message)
        self.assertIn("gen2", result.error_message)
        self.assertIn("first error", result.error_message)
        self.assertIn("second error", result.error_message)


if __name__ == "__main__":
    unittest.main()
