"""Dependency Track destination for SBOM uploads.

Dependency Track only supports CycloneDX format. SPDX uploads will be rejected.

Configuration via environment variables (DTRACK_* prefix):
    DTRACK_API_KEY: API key for authentication (required)
    DTRACK_API_URL: Full API base URL (required). We append /v1/bom to this.
                    Examples:
                    - https://dtrack.example.com/api (standard)
                    - https://api.dtrack.example.com (subdomain)
                    - https://proxy.example.com/dtrack/api (reverse proxy)
    DTRACK_PROJECT_ID: UUID of the project to upload to (optional if using name+version)
    DTRACK_AUTO_CREATE: Auto-create project if it doesn't exist (default: false)

Note: Project name and version come from the global COMPONENT_NAME and COMPONENT_VERSION
environment variables, not from DTRACK_* prefixed variables.
"""

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import requests

from sbomify_action.logging_config import logger

from ..protocol import DestinationConfig, UploadInput
from ..result import UploadResult

# Upload timeout in seconds
UPLOAD_TIMEOUT = 120


@dataclass
class DependencyTrackConfig(DestinationConfig):
    """
    Configuration for Dependency Track destination.

    Loaded from DTRACK_* prefixed environment variables.

    DTRACK_API_URL should be the full API base URL where the Dependency Track
    API is accessible. We append /v1/bom to this URL.

    Project name and version come from global COMPONENT_NAME/COMPONENT_VERSION.

    Examples:
        - https://dtrack.example.com/api (standard install)
        - https://api.dtrack.example.com (API on subdomain)
        - https://dtrack.example.com:8081/api (custom port)
        - https://proxy.example.com/dependency-track/api (behind reverse proxy)
    """

    ENV_PREFIX = "DTRACK"

    api_key: str
    api_url: str  # Full API base URL, we append /v1/bom
    project_id: Optional[str] = None
    auto_create: bool = False

    @classmethod
    def from_env(cls) -> Optional["DependencyTrackConfig"]:
        """Load configuration from DTRACK_* environment variables."""
        api_key = cls._get_env("API_KEY")
        api_url = cls._get_env("API_URL")

        # Require at least API key and URL
        if not api_key or not api_url:
            return None

        return cls(
            api_key=api_key,
            api_url=api_url.rstrip(
                "/"
            ),  # Only strip trailing "/" so custom paths like /api or /dtrack/api are preserved
            project_id=cls._get_env("PROJECT_ID"),
            auto_create=cls._get_env_bool("AUTO_CREATE", default=False),
        )

    def is_configured(self) -> bool:
        """
        Check if configuration is valid for upload.

        Note: Project name/version come from UploadInput, so we only check
        API credentials here. The full validation happens at upload time.
        """
        return bool(self.api_key and self.api_url)


class DependencyTrackDestination:
    """
    Destination for uploading SBOMs to Dependency Track.

    Dependency Track is an open source Component Analysis platform that
    allows organizations to identify and reduce risk in their software
    supply chain.

    Configuration is loaded from DTRACK_* prefixed environment variables.
    Project name/version come from the global COMPONENT_NAME/COMPONENT_VERSION.

    Environment Variables:
        DTRACK_API_KEY: API key for authentication (required)
        DTRACK_API_URL: Base URL of Dependency Track (required)
        DTRACK_PROJECT_ID: UUID of the project (optional, alternative to name/version)
        DTRACK_AUTO_CREATE: Auto-create project (default: false)
    """

    def __init__(self, config: Optional[DependencyTrackConfig] = None):
        """
        Initialize Dependency Track destination.

        Args:
            config: Configuration object. If None, loads from environment.
        """
        self._config = config or DependencyTrackConfig.from_env()

    @property
    def name(self) -> str:
        return "dependency-track"

    def is_configured(self) -> bool:
        """Check if Dependency Track destination is configured."""
        return self._config is not None and self._config.is_configured()

    def upload(self, input: UploadInput) -> UploadResult:
        """
        Upload SBOM to Dependency Track.

        Uses the /api/v1/bom endpoint to upload the SBOM.

        Args:
            input: UploadInput with file and format

        Returns:
            UploadResult with token if successful
        """
        if not self.is_configured() or self._config is None:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message="Dependency Track not configured (check DTRACK_* env vars)",
            )

        # Dependency Track only supports CycloneDX format
        if input.sbom_format != "cyclonedx":
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=f"Dependency Track only supports CycloneDX format, got: {input.sbom_format}",
            )

        # Read SBOM file
        try:
            with Path(input.sbom_file).open("r") as f:
                sbom_data = f.read()
        except FileNotFoundError:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=f"SBOM file not found: {input.sbom_file}",
            )
        except IOError as e:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=f"Failed to read SBOM file: {e}",
            )

        # Build the upload URL - append /v1/bom to the API base URL
        url = f"{self._config.api_url}/v1/bom"

        # Prepare headers
        headers = {
            "X-Api-Key": self._config.api_key,
            "Content-Type": "application/json",
        }

        # Prepare payload
        # Dependency Track expects base64-encoded BOM
        bom_base64 = base64.b64encode(sbom_data.encode()).decode()

        payload: Dict[str, Any] = {
            "bom": bom_base64,
            "autoCreate": self._config.auto_create,
        }

        # Add project identifier
        if self._config.project_id:
            payload["project"] = self._config.project_id
            logger.info(f"Uploading SBOM to Dependency Track project ID: {self._config.project_id}")
        elif input.component_name and input.component_version:
            payload["projectName"] = input.component_name
            payload["projectVersion"] = input.component_version
            logger.info(f"Uploading SBOM to Dependency Track project: {input.component_name}:{input.component_version}")
        else:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=(
                    "Dependency Track requires either DTRACK_PROJECT_ID or both COMPONENT_NAME and COMPONENT_VERSION"
                ),
            )

        # Execute the upload
        try:
            response = requests.put(
                url,
                headers=headers,
                json=payload,
                timeout=UPLOAD_TIMEOUT,
            )
        except requests.exceptions.ConnectionError:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=f"Failed to connect to Dependency Track at {self._config.api_url}",
            )
        except requests.exceptions.Timeout:
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message="SBOM upload to Dependency Track timed out",
            )
        except requests.exceptions.RequestException as e:
            # Any other transport-layer failure (SSLError, ProxyError,
            # TooManyRedirects, …). Return a clean failure result rather than
            # letting it propagate and crash the upload step — the upload
            # destination contract is to report failures, not raise.
            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=f"SBOM upload to Dependency Track failed: {e}",
            )

        # Handle response
        if not response.ok:
            err_msg = f"Failed to upload SBOM to Dependency Track. [{response.status_code}]"
            try:
                response_text = response.text[:500]
                if response_text:
                    err_msg += f" - {response_text}"
            except Exception:
                pass

            return UploadResult.failure_result(
                destination_name=self.name,
                error_message=err_msg,
            )

        # Extract token from response
        token = None
        response_metadata: Dict[str, Any] = {}
        try:
            response_data = response.json()
            token = response_data.get("token")
            response_metadata = response_data
            if token:
                logger.info(f"Dependency Track upload token: {token}")
        except (ValueError, Exception):
            logger.debug("Could not extract token from Dependency Track response")

        logger.info("SBOM uploaded successfully to Dependency Track")

        return UploadResult.success_result(
            destination_name=self.name,
            sbom_id=token,  # Use token as sbom_id for consistency
            validated=False,
            metadata=response_metadata,
        )
