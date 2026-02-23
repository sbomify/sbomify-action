"""
Unit tests for the upload plugin architecture.

Tests cover:
- UploadInput validation
- UploadResult construction
- DestinationRegistry operations
- SbomifyDestination upload logic
- DependencyTrackDestination upload logic
- UploadOrchestrator integration
- Public upload_sbom and upload_to_all APIs
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from sbomify_action._upload import (
    DependencyTrackConfig,
    DependencyTrackDestination,
    DestinationRegistry,
    SbomifyDestination,
    UploadInput,
    UploadOrchestrator,
    UploadResult,
    create_registry_with_sbomify,
)
from sbomify_action.upload import upload_sbom, upload_to_all


class TestUploadInput(unittest.TestCase):
    """Tests for UploadInput dataclass."""

    def test_valid_input(self):
        """Test creating a valid UploadInput."""
        input = UploadInput(
            sbom_file="sbom.json",
            sbom_format="cyclonedx",
        )
        self.assertEqual(input.sbom_file, "sbom.json")
        self.assertEqual(input.sbom_format, "cyclonedx")
        self.assertTrue(input.validate_before_upload)

    def test_valid_spdx_format(self):
        """Test creating input with SPDX format."""
        input = UploadInput(
            sbom_file="sbom.spdx.json",
            sbom_format="spdx",
        )
        self.assertEqual(input.sbom_format, "spdx")

    def test_missing_sbom_file_raises(self):
        """Test that missing sbom_file raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            UploadInput(sbom_file="", sbom_format="cyclonedx")
        self.assertIn("sbom_file is required", str(ctx.exception))

    def test_invalid_format_raises(self):
        """Test that invalid format raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            UploadInput(sbom_file="sbom.json", sbom_format="invalid")  # type: ignore
        self.assertIn("Invalid sbom_format", str(ctx.exception))


class TestUploadResult(unittest.TestCase):
    """Tests for UploadResult dataclass."""

    def test_success_result_with_validation(self):
        """Test creating a successful result with validated=True."""
        result = UploadResult.success_result(
            destination_name="sbomify",
            sbom_id="sbom-123",
            validated=True,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.destination_name, "sbomify")
        self.assertEqual(result.sbom_id, "sbom-123")
        self.assertIsNone(result.error_message)
        self.assertTrue(result.validated)

    def test_success_result_without_validation(self):
        """Test creating a successful result with validated=False."""
        result = UploadResult.success_result(
            destination_name="sbomify",
            sbom_id="sbom-456",
            validated=False,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.destination_name, "sbomify")
        self.assertEqual(result.sbom_id, "sbom-456")
        self.assertIsNone(result.error_message)
        self.assertFalse(result.validated)

    def test_failure_result(self):
        """Test creating a failed result."""
        result = UploadResult.failure_result(
            destination_name="sbomify",
            error_message="Connection failed",
        )
        self.assertFalse(result.success)
        self.assertEqual(result.destination_name, "sbomify")
        self.assertEqual(result.error_message, "Connection failed")
        self.assertIsNone(result.sbom_id)
        self.assertIsNone(result.error_code)

    def test_failure_result_with_error_code(self):
        """Test creating a failed result with error code."""
        result = UploadResult.failure_result(
            destination_name="sbomify",
            error_message="SBOM already exists",
            error_code="DUPLICATE_ARTIFACT",
        )
        self.assertFalse(result.success)
        self.assertEqual(result.destination_name, "sbomify")
        self.assertEqual(result.error_message, "SBOM already exists")
        self.assertEqual(result.error_code, "DUPLICATE_ARTIFACT")

    def test_has_sbom_id(self):
        """Test has_sbom_id property."""
        result_with_id = UploadResult.success_result(
            destination_name="sbomify",
            sbom_id="sbom-123",
        )
        result_without_id = UploadResult.success_result(
            destination_name="sbomify",
        )
        self.assertTrue(result_with_id.has_sbom_id)
        self.assertFalse(result_without_id.has_sbom_id)

    def test_success_with_error_message_raises(self):
        """Test that success=True with error_message raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            UploadResult(
                success=True,
                destination_name="sbomify",
                error_message="This should not be here",
            )
        self.assertIn("should not have error_message", str(ctx.exception))

    def test_failure_without_error_message_raises(self):
        """Test that success=False without error_message raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            UploadResult(
                success=False,
                destination_name="sbomify",
            )
        self.assertIn("must have error_message", str(ctx.exception))


class TestDestinationRegistry(unittest.TestCase):
    """Tests for DestinationRegistry."""

    def test_register_and_get_destination(self):
        """Test registering and retrieving a destination."""
        registry = DestinationRegistry()
        destination = SbomifyDestination(token="test", component_id="test")
        registry.register(destination)

        retrieved = registry.get("sbomify")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "sbomify")

    def test_get_nonexistent_returns_none(self):
        """Test that getting non-existent destination returns None."""
        registry = DestinationRegistry()
        self.assertIsNone(registry.get("nonexistent"))

    def test_list_destinations(self):
        """Test listing registered destinations."""
        registry = DestinationRegistry()
        registry.register(SbomifyDestination(token="test", component_id="test"))

        destinations = registry.list_destinations()
        self.assertEqual(len(destinations), 1)
        self.assertEqual(destinations[0]["name"], "sbomify")
        self.assertTrue(destinations[0]["configured"])

    def test_get_configured_destinations(self):
        """Test getting only configured destinations."""
        registry = DestinationRegistry()
        # Configured destination
        registry.register(SbomifyDestination(token="test", component_id="test"))
        # Unconfigured destination
        registry.register(SbomifyDestination())  # No token or component_id

        # Should only return configured ones (but we registered same name twice)
        # Let's test with different approach
        registry2 = DestinationRegistry()
        registry2.register(SbomifyDestination(token="test", component_id="test"))

        configured = registry2.get_configured_destinations()
        self.assertEqual(len(configured), 1)

    def test_clear(self):
        """Test clearing all destinations."""
        registry = DestinationRegistry()
        registry.register(SbomifyDestination(token="test", component_id="test"))
        self.assertEqual(len(registry.list_destinations()), 1)

        registry.clear()
        self.assertEqual(len(registry.list_destinations()), 0)

    def test_upload_with_unknown_destination_raises(self):
        """Test that uploading with unknown destination raises ValueError."""
        registry = DestinationRegistry()
        registry.register(SbomifyDestination(token="test", component_id="test"))

        input = UploadInput(
            sbom_file="sbom.json",
            sbom_format="cyclonedx",
        )

        with self.assertRaises(ValueError) as ctx:
            registry.upload(input, destination_name="unknown")
        self.assertIn("not found", str(ctx.exception))


class TestSbomifyDestination(unittest.TestCase):
    """Tests for SbomifyDestination."""

    def test_name(self):
        """Test destination name."""
        dest = SbomifyDestination()
        self.assertEqual(dest.name, "sbomify")

    def test_is_configured_with_credentials(self):
        """Test is_configured returns True with credentials."""
        dest = SbomifyDestination(token="test-token", component_id="my-component")
        self.assertTrue(dest.is_configured())

    def test_is_configured_without_token(self):
        """Test is_configured returns False without token."""
        dest = SbomifyDestination(component_id="my-component")
        self.assertFalse(dest.is_configured())

    def test_is_configured_without_component_id(self):
        """Test is_configured returns False without component_id."""
        dest = SbomifyDestination(token="test-token")
        self.assertFalse(dest.is_configured())

    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_upload_success(self, mock_post):
        """Test successful upload."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}, f)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = True
            mock_response.json.return_value = {"sbom_id": "sbom-123"}
            mock_post.return_value = mock_response

            dest = SbomifyDestination(token="test-token", component_id="my-component")
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertTrue(result.success)
            self.assertEqual(result.sbom_id, "sbom-123")
            self.assertEqual(result.destination_name, "sbomify")

            # Verify API call
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            self.assertIn("/api/v1/sboms/artifact/cyclonedx/my-component", call_args[0][0])
        finally:
            Path(sbom_file).unlink()

    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_upload_with_custom_api_url(self, mock_post):
        """Test upload with custom API base URL."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = True
            mock_response.json.return_value = {"id": "sbom-456"}
            mock_post.return_value = mock_response

            dest = SbomifyDestination(
                token="test-token",
                component_id="my-component",
                api_base_url="https://custom.sbomify.com",
            )
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertTrue(result.success)
            call_args = mock_post.call_args
            self.assertTrue(call_args[0][0].startswith("https://custom.sbomify.com"))
        finally:
            Path(sbom_file).unlink()

    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_upload_api_error(self, mock_post):
        """Test upload with API error response."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = False
            mock_response.status_code = 401
            mock_response.json.return_value = {"detail": "Invalid token"}
            mock_post.return_value = mock_response

            dest = SbomifyDestination(token="bad-token", component_id="my-component")
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertFalse(result.success)
            self.assertIn("401", result.error_message)
            self.assertIn("Invalid token", result.error_message)
        finally:
            Path(sbom_file).unlink()

    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_upload_connection_error(self, mock_post):
        """Test upload with connection error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            import requests

            mock_post.side_effect = requests.exceptions.ConnectionError("Connection failed")

            dest = SbomifyDestination(token="test-token", component_id="my-component")
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertFalse(result.success)
            self.assertIn("connect", result.error_message.lower())
        finally:
            Path(sbom_file).unlink()

    def test_upload_not_configured(self):
        """Test upload when destination is not configured."""
        dest = SbomifyDestination()  # No credentials
        input = UploadInput(sbom_file="sbom.json", sbom_format="cyclonedx")

        result = dest.upload(input)

        self.assertFalse(result.success)
        self.assertIn("not configured", result.error_message)

    def test_upload_file_not_found(self):
        """Test upload with non-existent file."""
        dest = SbomifyDestination(token="test-token", component_id="my-component")
        input = UploadInput(
            sbom_file="/nonexistent/path/sbom.json",
            sbom_format="cyclonedx",
            validate_before_upload=False,
        )

        result = dest.upload(input)

        self.assertFalse(result.success)
        self.assertIn("not found", result.error_message.lower())

    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_upload_duplicate_sbom_error(self, mock_post):
        """Test upload with 409 DUPLICATE_ARTIFACT error returns specific error code and message."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = False
            mock_response.status_code = 409
            mock_response.json.return_value = {
                "detail": "Artifact already exists",
                "error_code": "DUPLICATE_ARTIFACT",
            }
            mock_post.return_value = mock_response

            dest = SbomifyDestination(token="test-token", component_id="my-component")
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertFalse(result.success)
            self.assertEqual(result.error_code, "DUPLICATE_ARTIFACT")
            self.assertIn("already exists", result.error_message)
            self.assertIn("different version", result.error_message)
        finally:
            Path(sbom_file).unlink()

    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_upload_other_409_error(self, mock_post):
        """Test upload with 409 error without DUPLICATE_ARTIFACT still returns generic error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = False
            mock_response.status_code = 409
            mock_response.json.return_value = {
                "detail": "Some other conflict",
                "error_code": "OTHER_CONFLICT",
            }
            mock_post.return_value = mock_response

            dest = SbomifyDestination(token="test-token", component_id="my-component")
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertFalse(result.success)
            self.assertEqual(result.error_code, "OTHER_CONFLICT")
            self.assertIn("409", result.error_message)
            self.assertIn("Some other conflict", result.error_message)
        finally:
            Path(sbom_file).unlink()

    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_upload_component_not_found_error(self, mock_post):
        """Test upload with 404 error returns COMPONENT_NOT_FOUND error code and actionable message."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = False
            mock_response.status_code = 404
            mock_response.json.return_value = {
                "detail": "Component not found",
            }
            mock_post.return_value = mock_response

            dest = SbomifyDestination(token="test-token", component_id="nonexistent-component")
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertFalse(result.success)
            self.assertEqual(result.error_code, "COMPONENT_NOT_FOUND")
            self.assertIn("does not exist", result.error_message)
            self.assertIn("COMPONENT_ID", result.error_message)
        finally:
            Path(sbom_file).unlink()

    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_upload_component_not_found_no_json_body(self, mock_post):
        """Test upload with 404 error and no JSON body still returns COMPONENT_NOT_FOUND."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = False
            mock_response.status_code = 404
            mock_response.json.side_effect = ValueError("No JSON")
            mock_post.return_value = mock_response

            dest = SbomifyDestination(token="test-token", component_id="nonexistent-component")
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertFalse(result.success)
            self.assertEqual(result.error_code, "COMPONENT_NOT_FOUND")
            self.assertIn("does not exist", result.error_message)
        finally:
            Path(sbom_file).unlink()


class TestDependencyTrackConfig(unittest.TestCase):
    """Tests for DependencyTrackConfig."""

    def test_from_env_with_all_vars(self):
        """Test loading config from environment variables."""
        with patch.dict(
            os.environ,
            {
                "DTRACK_API_KEY": "test-api-key",
                "DTRACK_API_URL": "https://dtrack.example.com/api/",
                "DTRACK_PROJECT_ID": "project-uuid",
                "DTRACK_AUTO_CREATE": "true",
            },
        ):
            config = DependencyTrackConfig.from_env()

            self.assertIsNotNone(config)
            self.assertEqual(config.api_key, "test-api-key")
            # Only trailing slash stripped, /api preserved (user controls the full path)
            self.assertEqual(config.api_url, "https://dtrack.example.com/api")
            self.assertEqual(config.project_id, "project-uuid")
            self.assertTrue(config.auto_create)

    def test_from_env_preserves_custom_paths(self):
        """Test that custom API paths are preserved."""
        with patch.dict(
            os.environ,
            {
                "DTRACK_API_KEY": "test-api-key",
                "DTRACK_API_URL": "https://proxy.example.com/dtrack/api",
                "DTRACK_PROJECT_ID": "project-uuid",
            },
        ):
            config = DependencyTrackConfig.from_env()

            self.assertIsNotNone(config)
            # Custom path should be preserved as-is
            self.assertEqual(config.api_url, "https://proxy.example.com/dtrack/api")

    def test_from_env_with_subdomain_api(self):
        """Test API on subdomain without /api path."""
        with patch.dict(
            os.environ,
            {
                "DTRACK_API_KEY": "test-api-key",
                "DTRACK_API_URL": "https://api.dtrack.example.com",
                "DTRACK_PROJECT_ID": "project-uuid",
            },
        ):
            config = DependencyTrackConfig.from_env()

            self.assertIsNotNone(config)
            self.assertEqual(config.api_url, "https://api.dtrack.example.com")

    def test_from_env_minimal_config(self):
        """Test loading config with just API key and URL (no project_id)."""
        with patch.dict(
            os.environ,
            {
                "DTRACK_API_KEY": "test-api-key",
                "DTRACK_API_URL": "https://dtrack.example.com/api",
            },
            clear=True,
        ):
            config = DependencyTrackConfig.from_env()

            self.assertIsNotNone(config)
            self.assertIsNone(config.project_id)
            # is_configured() now just checks api_key and api_url
            self.assertTrue(config.is_configured())

    def test_from_env_missing_required(self):
        """Test that missing required vars returns None."""
        with patch.dict(os.environ, {}, clear=True):
            config = DependencyTrackConfig.from_env()
            self.assertIsNone(config)

    def test_is_configured_with_project_id(self):
        """Test is_configured with project_id."""
        config = DependencyTrackConfig(
            api_key="key",
            api_url="https://dtrack.example.com/api",
            project_id="uuid",
        )
        self.assertTrue(config.is_configured())

    def test_is_configured_without_project_id(self):
        """Test is_configured is True even without project_id (name/version come from UploadInput)."""
        config = DependencyTrackConfig(
            api_key="key",
            api_url="https://dtrack.example.com/api",
        )
        # is_configured() now just checks api_key and api_url
        # project name/version validation happens at upload time
        self.assertTrue(config.is_configured())

    def test_is_configured_missing_api_key(self):
        """Test is_configured returns False without api_key."""
        config = DependencyTrackConfig(
            api_key="",
            api_url="https://dtrack.example.com/api",
        )
        self.assertFalse(config.is_configured())


class TestDependencyTrackDestination(unittest.TestCase):
    """Tests for DependencyTrackDestination."""

    def test_name(self):
        """Test destination name."""
        dest = DependencyTrackDestination()
        self.assertEqual(dest.name, "dependency-track")

    def test_is_configured_without_env_vars(self):
        """Test is_configured returns False without env vars."""
        with patch.dict(os.environ, {}, clear=True):
            dest = DependencyTrackDestination()
            self.assertFalse(dest.is_configured())

    def test_is_configured_with_config(self):
        """Test is_configured with explicit config."""
        config = DependencyTrackConfig(
            api_key="key",
            api_url="https://dtrack.example.com/api",
            project_id="uuid",
        )
        dest = DependencyTrackDestination(config=config)
        self.assertTrue(dest.is_configured())

    @patch("sbomify_action._upload.destinations.dependency_track.requests.put")
    def test_upload_success_with_project_id(self, mock_put):
        """Test successful upload with project ID."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = True
            mock_response.json.return_value = {"token": "upload-token-123"}
            mock_put.return_value = mock_response

            config = DependencyTrackConfig(
                api_key="test-key",
                api_url="https://dtrack.example.com/api",  # Full API base URL
                project_id="project-uuid",
            )
            dest = DependencyTrackDestination(config=config)
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertTrue(result.success)
            self.assertEqual(result.sbom_id, "upload-token-123")
            self.assertEqual(result.destination_name, "dependency-track")

            # Verify API call - URL is api_url + /v1/bom
            mock_put.assert_called_once()
            call_args = mock_put.call_args
            self.assertEqual(call_args[0][0], "https://dtrack.example.com/api/v1/bom")
            self.assertEqual(call_args[1]["headers"]["X-Api-Key"], "test-key")
        finally:
            Path(sbom_file).unlink()

    @patch("sbomify_action._upload.destinations.dependency_track.requests.put")
    def test_upload_success_with_name_version(self, mock_put):
        """Test successful upload with project name and version."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = True
            mock_response.json.return_value = {"token": "upload-token-456"}
            mock_put.return_value = mock_response

            config = DependencyTrackConfig(
                api_key="test-key",
                api_url="https://dtrack.example.com/api",  # Full API base URL
                auto_create=True,
            )
            dest = DependencyTrackDestination(config=config)
            # Component name/version now come from UploadInput
            input = UploadInput(
                sbom_file=sbom_file,
                sbom_format="cyclonedx",
                component_name="my-project",
                component_version="1.0.0",
            )

            result = dest.upload(input)

            self.assertTrue(result.success)

            # Verify payload contains projectName and projectVersion from UploadInput
            call_args = mock_put.call_args
            payload = call_args[1]["json"]
            self.assertEqual(payload["projectName"], "my-project")
            self.assertEqual(payload["projectVersion"], "1.0.0")
            self.assertTrue(payload["autoCreate"])
        finally:
            Path(sbom_file).unlink()

    def test_upload_not_configured(self):
        """Test upload when destination is not configured."""
        with patch.dict(os.environ, {}, clear=True):
            dest = DependencyTrackDestination()
            input = UploadInput(sbom_file="sbom.json", sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertFalse(result.success)
            self.assertIn("not configured", result.error_message)

    def test_upload_missing_name_version(self):
        """Test upload fails when no project_id and no component_name/version."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            config = DependencyTrackConfig(
                api_key="test-key",
                api_url="https://dtrack.example.com/api",
            )
            dest = DependencyTrackDestination(config=config)
            # No component_name/version provided
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertFalse(result.success)
            self.assertIn("DTRACK_PROJECT_ID", result.error_message)
            self.assertIn("COMPONENT_NAME", result.error_message)
        finally:
            Path(sbom_file).unlink()

    def test_upload_rejects_spdx_format(self):
        """Test upload fails for SPDX format (DT only supports CycloneDX)."""
        config = DependencyTrackConfig(
            api_key="test-key",
            api_url="https://dtrack.example.com/api",
            project_id="project-uuid",
        )
        dest = DependencyTrackDestination(config=config)
        input = UploadInput(sbom_file="sbom.spdx.json", sbom_format="spdx")

        result = dest.upload(input)

        self.assertFalse(result.success)
        self.assertIn("CycloneDX", result.error_message)
        self.assertIn("spdx", result.error_message)


class TestUploadOrchestrator(unittest.TestCase):
    """Tests for UploadOrchestrator."""

    def test_default_registry_includes_destinations(self):
        """Test orchestrator creates registry with destinations."""
        orchestrator = UploadOrchestrator(
            sbomify_token="test",
            sbomify_component_id="test",
        )
        destinations = orchestrator.list_all_destinations()

        names = [d["name"] for d in destinations]
        self.assertIn("sbomify", names)
        self.assertIn("dependency-track", names)

    def test_get_configured_destinations(self):
        """Test getting configured destinations."""
        orchestrator = UploadOrchestrator(
            sbomify_token="test",
            sbomify_component_id="test",
        )
        # Only sbomify should be configured (no DTRACK env vars)
        with patch.dict(os.environ, {}, clear=True):
            configured = orchestrator.get_configured_destinations()
            self.assertIn("sbomify", configured)

    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_upload_to_specific_destination(self, mock_post):
        """Test uploading to a specific destination."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = True
            mock_response.json.return_value = {"sbom_id": "sbom-123"}
            mock_post.return_value = mock_response

            orchestrator = UploadOrchestrator(
                sbomify_token="test-token",
                sbomify_component_id="my-component",
            )
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = orchestrator.upload(input, destination="sbomify")

            self.assertTrue(result.success)
            self.assertEqual(result.destination_name, "sbomify")
        finally:
            Path(sbom_file).unlink()


class TestCreateRegistryWithSbomify(unittest.TestCase):
    """Tests for create_registry_with_sbomify factory function."""

    def test_creates_registry_with_destinations(self):
        """Test factory creates registry with multiple destinations."""
        registry = create_registry_with_sbomify(
            token="test",
            component_id="test",
        )
        destinations = registry.list_destinations()

        names = [d["name"] for d in destinations]
        self.assertIn("sbomify", names)
        self.assertIn("dependency-track", names)


class TestPublicUploadAPI(unittest.TestCase):
    """Tests for the public upload_sbom and upload_to_all functions."""

    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_upload_sbom_success(self, mock_post):
        """Test upload_sbom function success case."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = True
            mock_response.json.return_value = {"sbom_id": "public-api-123"}
            mock_post.return_value = mock_response

            result = upload_sbom(
                sbom_file=sbom_file,
                sbom_format="cyclonedx",
                token="test-token",
                component_id="my-component",
            )

            self.assertTrue(result.success)
            self.assertEqual(result.sbom_id, "public-api-123")
        finally:
            Path(sbom_file).unlink()

    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_upload_sbom_to_specific_destination(self, mock_post):
        """Test upload_sbom to specific destination."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = True
            mock_response.json.return_value = {"sbom_id": "sbom-456"}
            mock_post.return_value = mock_response

            result = upload_sbom(
                sbom_file=sbom_file,
                sbom_format="cyclonedx",
                token="test-token",
                component_id="my-component",
                destination="sbomify",
            )

            self.assertTrue(result.success)
        finally:
            Path(sbom_file).unlink()

    def test_upload_sbom_invalid_destination(self):
        """Test upload_sbom with invalid destination."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            with self.assertRaises(ValueError) as ctx:
                upload_sbom(
                    sbom_file=sbom_file,
                    sbom_format="cyclonedx",
                    token="test-token",
                    component_id="my-component",
                    destination="nonexistent",
                )
            self.assertIn("not found", str(ctx.exception))
        finally:
            Path(sbom_file).unlink()

    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_upload_to_all(self, mock_post):
        """Test upload_to_all function."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = True
            mock_response.json.return_value = {"sbom_id": "sbom-789"}
            mock_post.return_value = mock_response

            # Only sbomify configured (no DTRACK env vars)
            with patch.dict(os.environ, {}, clear=True):
                results = upload_to_all(
                    sbom_file=sbom_file,
                    sbom_format="cyclonedx",
                    token="test-token",
                    component_id="my-component",
                )

            # Should have result from sbomify only
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0].success)
            self.assertEqual(results[0].destination_name, "sbomify")
        finally:
            Path(sbom_file).unlink()


class TestSbomifyValidation(unittest.TestCase):
    """Tests for SBOM validation in SbomifyDestination."""

    def test_valid_cyclonedx_validation(self):
        """Test validation of valid CycloneDX SBOM."""
        dest = SbomifyDestination(token="test", component_id="test")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}, f)
            sbom_file = f.name

        try:
            result = dest._validate_cyclonedx_sbom(sbom_file)
            self.assertTrue(result)
        finally:
            Path(sbom_file).unlink()

    def test_invalid_cyclonedx_validation(self):
        """Test validation of invalid CycloneDX SBOM."""
        dest = SbomifyDestination(token="test", component_id="test")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"invalid": "sbom"}, f)
            sbom_file = f.name

        try:
            result = dest._validate_cyclonedx_sbom(sbom_file)
            self.assertFalse(result)
        finally:
            Path(sbom_file).unlink()


class TestDependencyTrackErrors(unittest.TestCase):
    """Tests for Dependency Track error handling."""

    @patch("sbomify_action._upload.destinations.dependency_track.requests.put")
    def test_upload_connection_error(self, mock_put):
        """Test upload with connection error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            import requests

            mock_put.side_effect = requests.exceptions.ConnectionError("Connection failed")

            config = DependencyTrackConfig(
                api_key="test-key",
                api_url="https://dtrack.example.com/api",
                project_id="project-uuid",
            )
            dest = DependencyTrackDestination(config=config)
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertFalse(result.success)
            self.assertIn("connect", result.error_message.lower())
        finally:
            Path(sbom_file).unlink()

    @patch("sbomify_action._upload.destinations.dependency_track.requests.put")
    def test_upload_timeout_error(self, mock_put):
        """Test upload with timeout error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            import requests

            mock_put.side_effect = requests.exceptions.Timeout("Request timed out")

            config = DependencyTrackConfig(
                api_key="test-key",
                api_url="https://dtrack.example.com/api",
                project_id="project-uuid",
            )
            dest = DependencyTrackDestination(config=config)
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertFalse(result.success)
            self.assertIn("timed out", result.error_message.lower())
        finally:
            Path(sbom_file).unlink()

    @patch("sbomify_action._upload.destinations.dependency_track.requests.put")
    def test_upload_api_error(self, mock_put):
        """Test upload with API error response."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = False
            mock_response.status_code = 403
            mock_response.text = "Forbidden"
            mock_put.return_value = mock_response

            config = DependencyTrackConfig(
                api_key="test-key",
                api_url="https://dtrack.example.com/api",
                project_id="project-uuid",
            )
            dest = DependencyTrackDestination(config=config)
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertFalse(result.success)
            self.assertIn("403", result.error_message)
        finally:
            Path(sbom_file).unlink()

    def test_upload_file_not_found(self):
        """Test upload with non-existent file."""
        config = DependencyTrackConfig(
            api_key="test-key",
            api_url="https://dtrack.example.com/api",
            project_id="project-uuid",
        )
        dest = DependencyTrackDestination(config=config)
        input = UploadInput(
            sbom_file="/nonexistent/path/sbom.json",
            sbom_format="cyclonedx",
            validate_before_upload=False,
        )

        result = dest.upload(input)

        self.assertFalse(result.success)
        self.assertIn("not found", result.error_message.lower())


class TestSbomifyGzipCompression(unittest.TestCase):
    """Tests for gzip compression of large SBOM uploads."""

    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_small_file_not_compressed(self, mock_post):
        """Files under GZIP_THRESHOLD are sent uncompressed."""
        small_data = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"})
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(small_data)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = True
            mock_response.json.return_value = {"sbom_id": "sbom-small"}
            mock_post.return_value = mock_response

            dest = SbomifyDestination(token="test-token", component_id="my-component")
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertTrue(result.success)
            call_kwargs = mock_post.call_args[1]
            # No Content-Encoding header for small files
            self.assertNotIn("Content-Encoding", call_kwargs["headers"])
            # Data sent is the raw bytes, not gzip
            self.assertEqual(call_kwargs["data"], small_data.encode())
        finally:
            Path(sbom_file).unlink()

    @patch("sbomify_action._upload.destinations.sbomify.GZIP_THRESHOLD", 100)
    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_large_file_compressed(self, mock_post):
        """Files over GZIP_THRESHOLD are gzip-compressed with Content-Encoding header."""
        import gzip

        large_data = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "padding": "x" * 200})
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(large_data)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = True
            mock_response.json.return_value = {"sbom_id": "sbom-large"}
            mock_post.return_value = mock_response

            dest = SbomifyDestination(token="test-token", component_id="my-component")
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertTrue(result.success)
            call_kwargs = mock_post.call_args[1]
            # Content-Encoding header must be set
            self.assertEqual(call_kwargs["headers"]["Content-Encoding"], "gzip")
            # Data is valid gzip that decompresses to original
            decompressed = gzip.decompress(call_kwargs["data"])
            self.assertEqual(decompressed, large_data.encode())
        finally:
            Path(sbom_file).unlink()

    @patch("sbomify_action._upload.destinations.sbomify.GZIP_THRESHOLD", 100)
    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_compressed_data_smaller_than_original(self, mock_post):
        """Compressed upload data should be smaller than the original."""
        # Highly repetitive data compresses well
        large_data = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "padding": "a" * 500})
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(large_data)
            sbom_file = f.name

        try:
            mock_response = Mock()
            mock_response.ok = True
            mock_response.json.return_value = {"sbom_id": "sbom-compressed"}
            mock_post.return_value = mock_response

            dest = SbomifyDestination(token="test-token", component_id="my-component")
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            dest.upload(input)

            call_kwargs = mock_post.call_args[1]
            self.assertLess(len(call_kwargs["data"]), len(large_data.encode()))
        finally:
            Path(sbom_file).unlink()


class TestSbomifyTimeout(unittest.TestCase):
    """Tests for Sbomify timeout handling."""

    @patch("sbomify_action._upload.destinations.sbomify.requests.post")
    def test_upload_timeout_error(self, mock_post):
        """Test upload with timeout error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, f)
            sbom_file = f.name

        try:
            import requests

            mock_post.side_effect = requests.exceptions.Timeout("Request timed out")

            dest = SbomifyDestination(token="test-token", component_id="my-component")
            input = UploadInput(sbom_file=sbom_file, sbom_format="cyclonedx")

            result = dest.upload(input)

            self.assertFalse(result.success)
            self.assertIn("timed out", result.error_message.lower())
        finally:
            Path(sbom_file).unlink()


if __name__ == "__main__":
    unittest.main()
