"""sbomify API destination for SBOM uploads."""

import gzip
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import requests

from sbomify_action.http_client import get_default_headers
from sbomify_action.logging_config import logger

from ..protocol import UploadInput
from ..result import UploadResult

# Default sbomify production API
SBOMIFY_PRODUCTION_API = "https://app.sbomify.com"

# Upload timeout in seconds (overridable via SBOMIFY_UPLOAD_TIMEOUT env var)
UPLOAD_TIMEOUT = int(os.environ.get("SBOMIFY_UPLOAD_TIMEOUT", "120"))

# Compress uploads larger than this threshold (1 MB)
GZIP_THRESHOLD = 1_000_000


class SbomifyDestination:
    """
    Destination for uploading SBOMs to the sbomify platform.

    This is the primary/native destination for the sbomify action.
    It uses the global config (token, component_id, api_base_url) that's
    also used for augmentation and other API calls.

    Configuration is passed from the caller (main.py's Config), not from
    separate environment variables.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        component_id: Optional[str] = None,
        api_base_url: Optional[str] = None,
    ):
        """
        Initialize sbomify destination.

        Args:
            token: sbomify API token
            component_id: Component ID to upload to
            api_base_url: API base URL (defaults to production)
        """
        self._token = token
        self._component_id = component_id
        self._api_base_url = api_base_url or SBOMIFY_PRODUCTION_API

    @property
    def name(self) -> str:
        return "sbomify"

    def is_configured(self) -> bool:
        """Check if sbomify destination is configured."""
        return bool(self._token and self._component_id)

    def upload(self, input: UploadInput) -> UploadResult:
        """
        Upload SBOM to sbomify API.

        Args:
            input: UploadInput with file and format

        Returns:
            UploadResult with sbom_id if successful
        """
        if not self.is_configured():
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message="sbomify destination not configured (missing token or component_id)",
            )

        # Validate SBOM before uploading if requested
        validated = False
        validation_error = None
        if input.validate_before_upload and input.sbom_format == "cyclonedx":
            validated = True
            validation_result = self._validate_cyclonedx_sbom(input.sbom_file)
            if not validation_result:
                validation_error = "SBOM validation failed"
                logger.warning("SBOM validation failed, but proceeding with upload")

        # Build the upload URL
        url = f"{self._api_base_url}/api/v1/sboms/artifact/{input.sbom_format}/{self._component_id}"

        # Prepare headers
        headers = get_default_headers(self._token, content_type="application/json")

        # Read SBOM file
        try:
            with Path(input.sbom_file).open("rb") as f:
                sbom_bytes = f.read()
        except FileNotFoundError:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=f"SBOM file not found: {input.sbom_file}",
                validated=validated,
                validation_error=validation_error,
            )
        except IOError as e:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=f"Failed to read SBOM file: {e}",
                validated=validated,
                validation_error=validation_error,
            )

        format_display = "CycloneDX" if input.sbom_format == "cyclonedx" else "SPDX"
        logger.info(f"Uploading {format_display} SBOM to component: {self._component_id}")

        # Gzip-compress large payloads to avoid upstream timeouts
        upload_data: bytes = sbom_bytes
        if len(sbom_bytes) > GZIP_THRESHOLD:
            upload_data = gzip.compress(sbom_bytes)
            headers["Content-Encoding"] = "gzip"
            logger.info(
                f"Compressed upload: {len(sbom_bytes):,} -> {len(upload_data):,} bytes "
                f"({len(sbom_bytes) / len(upload_data):.1f}x)"
            )

        # Execute the upload
        try:
            response = requests.post(
                url,
                headers=headers,
                data=upload_data,
                timeout=UPLOAD_TIMEOUT,
            )
        except requests.exceptions.ConnectionError:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message="Failed to connect to sbomify API for upload",
                validated=validated,
                validation_error=validation_error,
            )
        except requests.exceptions.Timeout:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message="SBOM upload timed out",
                validated=validated,
                validation_error=validation_error,
            )

        # Handle response
        if not response.ok:
            # Handle component not found error (check before JSON parsing)
            if response.status_code == 404:
                return UploadResult.failure_result(
                    destination_name=self.name,
                    error_message="The specified component does not exist. Verify your COMPONENT_ID is correct and the component exists in your sbomify dashboard.",
                    error_code="COMPONENT_NOT_FOUND",
                    validated=validated,
                    validation_error=validation_error,
                )

            error_code = None
            err_msg = f"Failed to upload SBOM file. [{response.status_code}]"
            try:
                response_json = response.json()
                error_code = response_json.get("error_code")
                if "detail" in response_json:
                    err_msg += f" - {response_json['detail']}"

                # Handle duplicate SBOM error with specific message
                if response.status_code == 409 and error_code == "DUPLICATE_ARTIFACT":
                    return UploadResult.failure_result(
                        destination_name=self.name,
                        error_message="An SBOM already exists for this component version. Use a different version or delete the existing SBOM.",
                        error_code=error_code,
                        validated=validated,
                        validation_error=validation_error,
                    )
            except (ValueError, json.JSONDecodeError):
                pass

            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=err_msg,
                error_code=error_code,
                validated=validated,
                validation_error=validation_error,
            )

        # Extract SBOM ID from response
        sbom_id = None
        response_metadata: Dict[str, Any] = {}
        try:
            response_data = response.json()
            sbom_id = response_data.get("sbom_id") or response_data.get("id")
            response_metadata = response_data
            if sbom_id:
                logger.info(f"SBOM ID: {sbom_id}")
        except (ValueError, json.JSONDecodeError):
            logger.warning("Could not extract SBOM ID from upload response")

        logger.info("SBOM uploaded successfully to sbomify")

        return UploadResult.success_result(
            destination_name=self.name,
            sbom_id=sbom_id,
            validated=validated,
            validation_error=validation_error,
            metadata=response_metadata,
        )

    def _validate_cyclonedx_sbom(self, sbom_file_path: str) -> bool:
        """
        Validate CycloneDX SBOM structure.

        Args:
            sbom_file_path: Path to the SBOM JSON file to validate

        Returns:
            True if valid, False if invalid
        """
        try:
            with Path(sbom_file_path).open("r") as f:
                sbom_data = json.load(f)

            # Check for basic CycloneDX structure
            if sbom_data.get("bomFormat") == "CycloneDX" and sbom_data.get("specVersion"):
                logger.debug("SBOM basic validation successful")
                return True
            else:
                logger.warning("SBOM basic validation failed: missing bomFormat or specVersion")
                return False

        except json.JSONDecodeError as e:
            logger.warning(f"SBOM validation failed: Invalid JSON - {e}")
            return False
        except FileNotFoundError:
            logger.warning(f"SBOM validation failed: File not found - {sbom_file_path}")
            return False
        except Exception as e:
            logger.warning(f"SBOM validation error: {e}")
            return False
