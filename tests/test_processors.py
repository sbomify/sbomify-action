"""
Tests for the SBOM processor plugin system.
"""

import unittest
from unittest.mock import Mock, patch

from sbomify_action._processors import (
    AggregateResult,
    ProcessorInput,
    ProcessorOrchestrator,
    ProcessorRegistry,
    ProcessorResult,
    SbomifyReleasesProcessor,
    SBOMProcessor,
    create_default_registry,
)
from sbomify_action.cli.main import _finalize_post_upload
from sbomify_action.exceptions import APIError


class TestFinalizePostUpload(unittest.TestCase):
    """A failed post-upload processor (e.g. a 403 creating a release) must fail
    the run, not be swallowed as success."""

    def test_processor_failure_exits_nonzero(self):
        results = AggregateResult(
            results=[
                ProcessorResult.failure_result("sbomify_releases", "[403] - Only owners and admins can create releases")
            ]
        )
        with self.assertRaises(SystemExit) as ctx:
            _finalize_post_upload(results)
        self.assertEqual(ctx.exception.code, 1)

    def test_all_success_does_not_exit(self):
        results = AggregateResult(results=[ProcessorResult.success_result("sbomify_releases", processed_items=1)])
        _finalize_post_upload(results)  # must not raise

    def test_skipped_processor_does_not_exit(self):
        results = AggregateResult(results=[ProcessorResult.skipped_result("sbomify_releases")])
        _finalize_post_upload(results)  # skipped is not a failure


class TestProcessorInput(unittest.TestCase):
    """Test ProcessorInput dataclass."""

    def test_processor_input_valid(self):
        """Test creating a valid ProcessorInput."""
        input_obj = ProcessorInput(
            sbom_id="sbom-123",
            sbom_file="/path/to/sbom.json",
            product_releases=["product-id:v1.0.0"],
            api_base_url="https://api.test.com",
            token="test-token",
        )

        self.assertEqual(input_obj.sbom_id, "sbom-123")
        self.assertEqual(input_obj.sbom_file, "/path/to/sbom.json")
        self.assertEqual(input_obj.product_releases, ["product-id:v1.0.0"])

    def test_processor_input_minimal(self):
        """Test creating ProcessorInput with only required fields."""
        input_obj = ProcessorInput(sbom_id="sbom-123")

        self.assertEqual(input_obj.sbom_id, "sbom-123")
        self.assertIsNone(input_obj.sbom_file)
        self.assertIsNone(input_obj.product_releases)

    def test_processor_input_requires_sbom_id(self):
        """Test that ProcessorInput requires sbom_id."""
        with self.assertRaises(ValueError) as cm:
            ProcessorInput(sbom_id="")

        self.assertIn("sbom_id is required", str(cm.exception))


class TestProcessorResult(unittest.TestCase):
    """Test ProcessorResult dataclass."""

    def test_success_result(self):
        """Test creating a successful result."""
        result = ProcessorResult.success_result(
            processor_name="releases",
            processed_items=3,
            metadata={"release_ids": ["r1", "r2", "r3"]},
        )

        self.assertTrue(result.success)
        self.assertEqual(result.processor_name, "releases")
        self.assertEqual(result.processed_items, 3)
        self.assertIsNone(result.error_message)
        self.assertEqual(result.metadata["release_ids"], ["r1", "r2", "r3"])

    def test_failure_result(self):
        """Test creating a failed result."""
        result = ProcessorResult.failure_result(
            processor_name="releases",
            error_message="API connection failed",
            processed_items=1,
            failed_items=2,
        )

        self.assertFalse(result.success)
        self.assertEqual(result.processor_name, "releases")
        self.assertEqual(result.error_message, "API connection failed")
        self.assertEqual(result.processed_items, 1)
        self.assertEqual(result.failed_items, 2)

    def test_skipped_result(self):
        """Test creating a skipped result."""
        result = ProcessorResult.skipped_result(
            processor_name="releases",
            reason="No product releases specified",
        )

        self.assertTrue(result.success)
        self.assertEqual(result.processor_name, "releases")
        self.assertTrue(result.metadata.get("skipped"))
        self.assertEqual(result.metadata.get("skip_reason"), "No product releases specified")

    def test_success_result_cannot_have_error_message(self):
        """Test that successful result cannot have error_message."""
        with self.assertRaises(ValueError):
            ProcessorResult(
                success=True,
                processor_name="releases",
                error_message="This should not be here",
            )

    def test_failure_result_must_have_error_message(self):
        """Test that failed result must have error_message."""
        with self.assertRaises(ValueError):
            ProcessorResult(
                success=False,
                processor_name="releases",
                error_message=None,
            )

    def test_has_failures_property(self):
        """Test has_failures property."""
        result_with_failures = ProcessorResult.success_result(
            processor_name="releases",
            processed_items=2,
        )
        result_with_failures.failed_items = 1

        self.assertTrue(result_with_failures.has_failures)

        result_no_failures = ProcessorResult.success_result(
            processor_name="releases",
            processed_items=2,
        )
        self.assertFalse(result_no_failures.has_failures)

    def test_total_items_property(self):
        """Test total_items property."""
        result = ProcessorResult.failure_result(
            processor_name="releases",
            error_message="Some failed",
            processed_items=3,
            failed_items=2,
        )

        self.assertEqual(result.total_items, 5)


class TestAggregateResult(unittest.TestCase):
    """Test AggregateResult dataclass."""

    def test_aggregate_empty(self):
        """Test empty aggregate result."""
        aggregate = AggregateResult()

        self.assertEqual(len(aggregate.results), 0)
        self.assertEqual(aggregate.total_processed, 0)
        self.assertEqual(aggregate.total_failed, 0)
        self.assertTrue(aggregate.all_successful)
        self.assertFalse(aggregate.any_failures)

    def test_aggregate_add_results(self):
        """Test adding results to aggregate."""
        aggregate = AggregateResult()

        aggregate.add(ProcessorResult.success_result("releases", processed_items=2))
        aggregate.add(ProcessorResult.success_result("signing", processed_items=1))

        self.assertEqual(len(aggregate.results), 2)
        self.assertEqual(aggregate.total_processed, 3)
        self.assertTrue(aggregate.all_successful)

    def test_aggregate_with_failures(self):
        """Test aggregate with some failures."""
        aggregate = AggregateResult()

        aggregate.add(ProcessorResult.success_result("releases", processed_items=2))
        aggregate.add(
            ProcessorResult.failure_result("signing", error_message="Failed", processed_items=0, failed_items=1)
        )

        self.assertFalse(aggregate.all_successful)
        self.assertTrue(aggregate.any_failures)
        self.assertEqual(aggregate.total_failed, 1)

    def test_aggregate_enabled_and_skipped(self):
        """Test filtering enabled vs skipped processors."""
        aggregate = AggregateResult()

        aggregate.add(ProcessorResult.success_result("releases", processed_items=2))
        aggregate.add(ProcessorResult.skipped_result("signing", reason="Not configured"))

        self.assertEqual(len(aggregate.enabled_processors), 1)
        self.assertEqual(len(aggregate.skipped_processors), 1)
        self.assertEqual(aggregate.enabled_processors[0].processor_name, "releases")
        self.assertEqual(aggregate.skipped_processors[0].processor_name, "signing")


class TestProcessorRegistry(unittest.TestCase):
    """Test ProcessorRegistry class."""

    def setUp(self):
        """Set up test fixtures."""
        self.registry = ProcessorRegistry()

    def test_register_processor(self):
        """Test registering a processor."""
        processor = Mock(spec=SBOMProcessor)
        processor.name = "test-processor"

        self.registry.register(processor)

        self.assertIsNotNone(self.registry.get("test-processor"))

    def test_get_processor_not_found(self):
        """Test getting a processor that doesn't exist."""
        result = self.registry.get("nonexistent")
        self.assertIsNone(result)

    def test_get_enabled_processors(self):
        """Test getting enabled processors for an input."""
        processor1 = Mock(spec=SBOMProcessor)
        processor1.name = "enabled"
        processor1.is_enabled.return_value = True

        processor2 = Mock(spec=SBOMProcessor)
        processor2.name = "disabled"
        processor2.is_enabled.return_value = False

        self.registry.register(processor1)
        self.registry.register(processor2)

        input_obj = ProcessorInput(sbom_id="sbom-123")
        enabled = self.registry.get_enabled_processors(input_obj)

        self.assertEqual(len(enabled), 1)
        self.assertEqual(enabled[0].name, "enabled")

    def test_process_specific_processor(self):
        """Test processing with a specific processor."""
        processor = Mock(spec=SBOMProcessor)
        processor.name = "releases"
        processor.is_enabled.return_value = True
        processor.process.return_value = ProcessorResult.success_result("releases", processed_items=1)

        self.registry.register(processor)

        input_obj = ProcessorInput(sbom_id="sbom-123")
        result = self.registry.process(input_obj, "releases")

        self.assertTrue(result.success)
        processor.process.assert_called_once_with(input_obj)

    def test_process_skips_disabled_processor(self):
        """Test that processing a disabled processor returns skipped result."""
        processor = Mock(spec=SBOMProcessor)
        processor.name = "releases"
        processor.is_enabled.return_value = False

        self.registry.register(processor)

        input_obj = ProcessorInput(sbom_id="sbom-123")
        result = self.registry.process(input_obj, "releases")

        self.assertTrue(result.success)
        self.assertTrue(result.metadata.get("skipped"))
        processor.process.assert_not_called()

    def test_process_not_found_raises(self):
        """Test processing a non-existent processor raises ValueError."""
        input_obj = ProcessorInput(sbom_id="sbom-123")

        with self.assertRaises(ValueError) as cm:
            self.registry.process(input_obj, "nonexistent")

        self.assertIn("not found", str(cm.exception))

    def test_process_all(self):
        """Test processing all processors."""
        processor1 = Mock(spec=SBOMProcessor)
        processor1.name = "releases"
        processor1.is_enabled.return_value = True
        processor1.process.return_value = ProcessorResult.success_result("releases", processed_items=2)

        processor2 = Mock(spec=SBOMProcessor)
        processor2.name = "signing"
        processor2.is_enabled.return_value = False

        self.registry.register(processor1)
        self.registry.register(processor2)

        input_obj = ProcessorInput(sbom_id="sbom-123")
        aggregate = self.registry.process_all(input_obj)

        self.assertEqual(len(aggregate.results), 2)
        self.assertEqual(len(aggregate.enabled_processors), 1)
        self.assertEqual(len(aggregate.skipped_processors), 1)

    def test_process_handles_exception(self):
        """Test that exceptions from processors are handled gracefully."""
        processor = Mock(spec=SBOMProcessor)
        processor.name = "releases"
        processor.is_enabled.return_value = True
        processor.process.side_effect = Exception("Unexpected error")

        self.registry.register(processor)

        input_obj = ProcessorInput(sbom_id="sbom-123")
        result = self.registry.process(input_obj, "releases")

        self.assertFalse(result.success)
        self.assertIn("Unexpected error", result.error_message)

    def test_list_processors(self):
        """Test listing all processors."""
        processor = Mock(spec=SBOMProcessor)
        processor.name = "releases"

        self.registry.register(processor)

        processors = self.registry.list_processors()

        self.assertEqual(len(processors), 1)
        self.assertEqual(processors[0]["name"], "releases")

    def test_clear_registry(self):
        """Test clearing the registry."""
        processor = Mock(spec=SBOMProcessor)
        processor.name = "releases"

        self.registry.register(processor)
        self.registry.clear()

        self.assertEqual(len(self.registry.list_processors()), 0)


class TestSbomifyReleasesProcessor(unittest.TestCase):
    """Test SbomifyReleasesProcessor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.processor = SbomifyReleasesProcessor(
            api_base_url="https://api.test.com",
            token="test-token",
        )

    def test_processor_name(self):
        """Test processor name property."""
        self.assertEqual(self.processor.name, "sbomify_releases")

    def test_is_enabled_with_releases(self):
        """Test is_enabled returns True when product_releases is set."""
        input_obj = ProcessorInput(
            sbom_id="sbom-123",
            product_releases=["product-id:v1.0.0"],
        )

        self.assertTrue(self.processor.is_enabled(input_obj))

    def test_is_enabled_without_releases(self):
        """Test is_enabled returns False when product_releases is not set."""
        input_obj = ProcessorInput(sbom_id="sbom-123")

        self.assertFalse(self.processor.is_enabled(input_obj))

    def test_is_enabled_with_empty_releases(self):
        """Test is_enabled returns False when product_releases is empty."""
        input_obj = ProcessorInput(sbom_id="sbom-123", product_releases=[])

        self.assertFalse(self.processor.is_enabled(input_obj))

    def test_process_without_releases_returns_skipped(self):
        """Test process returns skipped result when no releases specified."""
        input_obj = ProcessorInput(sbom_id="sbom-123")

        result = self.processor.process(input_obj)

        self.assertTrue(result.success)
        self.assertTrue(result.metadata.get("skipped"))

    def test_process_without_api_config_returns_failure(self):
        """Test process returns failure when API config is missing."""
        processor = SbomifyReleasesProcessor()  # No API config
        input_obj = ProcessorInput(
            sbom_id="sbom-123",
            product_releases=["product-id:v1.0.0"],
        )

        result = processor.process(input_obj)

        self.assertFalse(result.success)
        self.assertIn("API base URL and token are required", result.error_message)

    @patch("sbomify_action._processors.releases_api._client")
    def test_process_creates_and_tags_release(self, mock_client_factory):
        """Test process creates release and tags SBOM."""
        client = Mock()
        client.check_release_exists.return_value = False
        client.create_release.return_value = "new-release-id"
        client.tag_sbom_with_release.return_value = None
        client.get_release_details.return_value = None
        mock_client_factory.return_value = client

        input_obj = ProcessorInput(
            sbom_id="sbom-123",
            product_releases=["product-id:v1.0.0"],
            api_base_url="https://api.test.com",
            token="test-token",
        )

        result = self.processor.process(input_obj)

        self.assertTrue(result.success)
        self.assertEqual(result.processed_items, 1)
        self.assertIn("new-release-id", result.metadata["release_ids"])

    @patch("sbomify_action._processors.releases_api._client")
    def test_process_handles_existing_release(self, mock_client_factory):
        """Test process handles existing release by using its ID."""
        client = Mock()
        client.check_release_exists.return_value = True
        client.get_release_id.return_value = "existing-release-id"
        client.tag_sbom_with_release.return_value = None
        client.get_release_details.return_value = {
            "id": "existing-release-id",
            "version": "v1.0.0",
            "name": "Release v1.0.0",
        }
        mock_client_factory.return_value = client

        input_obj = ProcessorInput(
            sbom_id="sbom-123",
            product_releases=["product-id:v1.0.0"],
            api_base_url="https://api.test.com",
            token="test-token",
        )

        result = self.processor.process(input_obj)

        self.assertTrue(result.success)
        self.assertEqual(result.processed_items, 1)
        self.assertIn("existing-release-id", result.metadata["release_ids"])

    @patch("sbomify_action._processors.releases_api._client")
    def test_process_handles_duplicate_name_error(self, mock_client_factory):
        """Test process handles DUPLICATE_NAME error by fetching existing release."""
        # The client's create_release transparently recovers from DUPLICATE_NAME
        # and returns the existing ID — the processor just sees a successful create.
        client = Mock()
        client.check_release_exists.return_value = False
        client.create_release.return_value = "existing-release-id"
        client.tag_sbom_with_release.return_value = None
        client.get_release_details.return_value = {
            "id": "existing-release-id",
            "version": "v1.0.0",
            "name": "v1.0.0",
        }
        mock_client_factory.return_value = client

        input_obj = ProcessorInput(
            sbom_id="sbom-123",
            product_releases=["product-id:v1.0.0"],
            api_base_url="https://api.test.com",
            token="test-token",
        )

        result = self.processor.process(input_obj)

        self.assertTrue(result.success)
        self.assertEqual(result.processed_items, 1)

    @patch("sbomify_action._processors.releases_api._client")
    def test_process_handles_api_error(self, mock_client_factory):
        """Test process handles API errors gracefully."""
        client = Mock()
        client.check_release_exists.side_effect = APIError("API connection failed")
        mock_client_factory.return_value = client

        input_obj = ProcessorInput(
            sbom_id="sbom-123",
            product_releases=["product-id:v1.0.0"],
            api_base_url="https://api.test.com",
            token="test-token",
        )

        result = self.processor.process(input_obj)

        self.assertFalse(result.success)
        self.assertIn("API connection failed", result.error_message)


class TestProcessorOrchestrator(unittest.TestCase):
    """Test ProcessorOrchestrator class."""

    def test_create_default_registry(self):
        """Test creating default registry."""
        registry = create_default_registry(
            api_base_url="https://api.test.com",
            token="test-token",
        )

        processors = registry.list_processors()
        self.assertEqual(len(processors), 1)
        self.assertEqual(processors[0]["name"], "sbomify_releases")

    def test_orchestrator_with_default_registry(self):
        """Test orchestrator creates default registry."""
        orchestrator = ProcessorOrchestrator(
            api_base_url="https://api.test.com",
            token="test-token",
        )

        self.assertIsNotNone(orchestrator.registry)
        self.assertEqual(len(orchestrator.list_all_processors()), 1)

    def test_orchestrator_with_custom_registry(self):
        """Test orchestrator accepts custom registry."""
        custom_registry = ProcessorRegistry()
        processor = Mock(spec=SBOMProcessor)
        processor.name = "custom"
        custom_registry.register(processor)

        orchestrator = ProcessorOrchestrator(registry=custom_registry)

        self.assertEqual(orchestrator.list_all_processors(), ["custom"])

    def test_get_enabled_processors(self):
        """Test getting enabled processors."""
        orchestrator = ProcessorOrchestrator(
            api_base_url="https://api.test.com",
            token="test-token",
        )

        # With releases
        input_with_releases = ProcessorInput(
            sbom_id="sbom-123",
            product_releases=["product-id:v1.0.0"],
        )
        enabled = orchestrator.get_enabled_processors(input_with_releases)
        self.assertEqual(enabled, ["sbomify_releases"])

        # Without releases
        input_without_releases = ProcessorInput(sbom_id="sbom-123")
        enabled = orchestrator.get_enabled_processors(input_without_releases)
        self.assertEqual(enabled, [])

    def test_process_specific_processor(self):
        """Test processing with a specific processor."""
        custom_registry = ProcessorRegistry()
        processor = Mock(spec=SBOMProcessor)
        processor.name = "releases"
        processor.is_enabled.return_value = True
        processor.process.return_value = ProcessorResult.success_result("releases", processed_items=1)
        custom_registry.register(processor)

        orchestrator = ProcessorOrchestrator(registry=custom_registry)

        input_obj = ProcessorInput(sbom_id="sbom-123")
        result = orchestrator.process(input_obj, "releases")

        self.assertTrue(result.success)

    def test_process_all(self):
        """Test processing all processors."""
        custom_registry = ProcessorRegistry()
        processor = Mock(spec=SBOMProcessor)
        processor.name = "releases"
        processor.is_enabled.return_value = True
        processor.process.return_value = ProcessorResult.success_result("releases", processed_items=1)
        custom_registry.register(processor)

        orchestrator = ProcessorOrchestrator(registry=custom_registry)

        input_obj = ProcessorInput(sbom_id="sbom-123")
        aggregate = orchestrator.process_all(input_obj)

        self.assertEqual(len(aggregate.results), 1)
        self.assertTrue(aggregate.all_successful)


if __name__ == "__main__":
    unittest.main()
