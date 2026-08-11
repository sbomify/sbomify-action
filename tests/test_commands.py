import unittest
from unittest.mock import MagicMock, patch

from sbomify_action._generation import GenerationResult
from sbomify_action.cli.main import evaluate_boolean
from sbomify_action.exceptions import (
    ConfigurationError,
    FileProcessingError,
    SBOMGenerationError,
)
from sbomify_action.generation import (
    generate_sbom,
    process_lock_file,
)


class TestLockFileProcessing(unittest.TestCase):
    """Test cases for lock file processing with mocking."""

    @patch("sbomify_action.generation.generate_sbom")
    def test_process_lock_file_python_requirements(self, mock_generate):
        """Test processing Python requirements.txt file."""
        mock_generate.return_value = GenerationResult.success_result(
            output_file="step_1.json",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="cyclonedx-py",
        )
        test_file = "/path/to/requirements.txt"

        result = process_lock_file(test_file)

        mock_generate.assert_called_once()
        call_args = mock_generate.call_args
        self.assertEqual(call_args.kwargs["lock_file"], test_file)
        self.assertEqual(call_args.kwargs["output_file"], "step_1.json")
        self.assertTrue(result.success)

    @patch("sbomify_action.generation.generate_sbom")
    def test_process_lock_file_python_uv_lock(self, mock_generate):
        """Test processing Python uv.lock file."""
        mock_generate.return_value = GenerationResult.success_result(
            output_file="step_1.json",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="trivy-fs",
        )
        test_file = "/path/to/uv.lock"

        result = process_lock_file(test_file)

        mock_generate.assert_called_once()
        call_args = mock_generate.call_args
        self.assertEqual(call_args.kwargs["lock_file"], test_file)
        self.assertTrue(result.success)

    @patch("sbomify_action.generation.generate_sbom")
    def test_process_lock_file_rust_cargo(self, mock_generate):
        """Test processing Rust Cargo.lock file."""
        mock_generate.return_value = GenerationResult.success_result(
            output_file="step_1.json",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="trivy-fs",
        )
        test_file = "/path/to/Cargo.lock"

        result = process_lock_file(test_file)

        mock_generate.assert_called_once()
        call_args = mock_generate.call_args
        self.assertEqual(call_args.kwargs["lock_file"], test_file)
        self.assertEqual(call_args.kwargs["output_file"], "step_1.json")
        self.assertTrue(result.success)

    @patch("sbomify_action.generation.generate_sbom")
    def test_process_lock_file_cpp_conan(self, mock_generate):
        """Test processing C++ conan.lock file."""
        mock_generate.return_value = GenerationResult.success_result(
            output_file="step_1.json",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="trivy-fs",
        )
        test_file = "/path/to/conan.lock"

        result = process_lock_file(test_file)

        mock_generate.assert_called_once()
        call_args = mock_generate.call_args
        self.assertEqual(call_args.kwargs["lock_file"], test_file)
        self.assertEqual(call_args.kwargs["output_file"], "step_1.json")
        self.assertTrue(result.success)

    def test_process_lock_file_unsupported_type(self):
        """Test processing unsupported lock file type."""
        test_file = "/path/to/unsupported.xyz"

        with self.assertRaises(FileProcessingError) as cm:
            process_lock_file(test_file)

        self.assertIn("not a recognized lock file type", str(cm.exception))

    @patch("sbomify_action.generation.generate_sbom")
    def test_process_lock_file_failure(self, mock_generate):
        """Test handling of SBOM generation failure."""
        mock_generate.return_value = GenerationResult.failure_result(
            error_message="Generation failed",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="cyclonedx-py",
        )

        with self.assertRaises(SBOMGenerationError):
            process_lock_file("/path/to/requirements.txt")

    @patch("sbomify_action.generation.generate_sbom")
    def test_process_lock_file_with_spdx_format(self, mock_generate):
        """Test processing lock file with SPDX format."""
        mock_generate.return_value = GenerationResult.success_result(
            output_file="step_1.json",
            sbom_format="spdx",
            spec_version="2.3",
            generator_name="trivy-fs",
        )
        test_file = "/path/to/requirements.txt"

        result = process_lock_file(test_file, output_format="spdx")

        mock_generate.assert_called_once()
        call_args = mock_generate.call_args
        self.assertEqual(call_args.kwargs["output_format"], "spdx")
        self.assertTrue(result.success)

    @patch("sbomify_action.generation.generate_sbom")
    def test_process_lock_file_with_spec_version(self, mock_generate):
        """Test processing lock file with specific version."""
        mock_generate.return_value = GenerationResult.success_result(
            output_file="step_1.json",
            sbom_format="cyclonedx",
            spec_version="1.5",
            generator_name="syft-fs",
        )
        test_file = "/path/to/requirements.txt"

        result = process_lock_file(test_file, output_format="cyclonedx", spec_version="1.5")

        mock_generate.assert_called_once()
        call_args = mock_generate.call_args
        self.assertEqual(call_args.kwargs["spec_version"], "1.5")
        self.assertTrue(result.success)

    @patch("sbomify_action.generation.generate_sbom")
    def test_process_lock_file_custom_output(self, mock_generate):
        """Test processing lock file with custom output file."""
        mock_generate.return_value = GenerationResult.success_result(
            output_file="custom_sbom.json",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="cyclonedx-py",
        )
        test_file = "/path/to/requirements.txt"

        result = process_lock_file(test_file, output_file="custom_sbom.json")

        mock_generate.assert_called_once()
        call_args = mock_generate.call_args
        self.assertEqual(call_args.kwargs["output_file"], "custom_sbom.json")
        self.assertTrue(result.success)


class TestGenerateSbom(unittest.TestCase):
    """Test cases for generate_sbom function."""

    @patch("sbomify_action.generation._get_orchestrator")
    def test_generate_sbom_lock_file(self, mock_get_orch):
        """Test generating SBOM from lock file."""
        mock_orch = MagicMock()
        mock_orch.generate.return_value = GenerationResult.success_result(
            output_file="sbom.json",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="cyclonedx-py",
        )
        mock_get_orch.return_value = mock_orch

        result = generate_sbom(
            lock_file="requirements.txt",
            output_file="sbom.json",
            output_format="cyclonedx",
        )

        self.assertTrue(result.success)
        mock_orch.generate.assert_called_once()

    @patch("sbomify_action.generation._get_orchestrator")
    def test_generate_sbom_docker_image(self, mock_get_orch):
        """Test generating SBOM from Docker image."""
        mock_orch = MagicMock()
        mock_orch.generate.return_value = GenerationResult.success_result(
            output_file="sbom.json",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="trivy-image",
        )
        mock_get_orch.return_value = mock_orch

        result = generate_sbom(
            docker_image="alpine:3.18",
            output_file="sbom.json",
            output_format="cyclonedx",
        )

        self.assertTrue(result.success)
        mock_orch.generate.assert_called_once()

    def test_generate_sbom_both_inputs_raises_error(self):
        """Test that providing both lock_file and docker_image raises error."""
        with self.assertRaises(ValueError):
            generate_sbom(
                lock_file="requirements.txt",
                docker_image="alpine:3.18",
            )

    def test_generate_sbom_no_inputs_raises_error(self):
        """Test that providing neither lock_file nor docker_image raises error."""
        with self.assertRaises(ValueError):
            generate_sbom(output_file="sbom.json")


class TestUtilityFunctions(unittest.TestCase):
    """Test cases for utility functions."""

    def test_evaluate_boolean_true_values(self):
        """Test that true values are evaluated correctly."""
        self.assertTrue(evaluate_boolean("true"))
        self.assertTrue(evaluate_boolean("True"))
        self.assertTrue(evaluate_boolean("TRUE"))
        self.assertTrue(evaluate_boolean("yes"))
        self.assertTrue(evaluate_boolean("Yes"))
        self.assertTrue(evaluate_boolean("yeah"))
        self.assertTrue(evaluate_boolean("1"))

    def test_evaluate_boolean_false_values(self):
        """Test that false values are evaluated correctly."""
        self.assertFalse(evaluate_boolean("false"))
        self.assertFalse(evaluate_boolean("False"))
        self.assertFalse(evaluate_boolean("FALSE"))
        self.assertFalse(evaluate_boolean("no"))
        self.assertFalse(evaluate_boolean("0"))
        self.assertFalse(evaluate_boolean("off"))

    def test_evaluate_boolean_rejects_unrecognised(self):
        """Unrecognised input raises instead of quietly meaning False."""
        with self.assertRaises(ConfigurationError):
            evaluate_boolean("anything_else")


if __name__ == "__main__":
    unittest.main()
