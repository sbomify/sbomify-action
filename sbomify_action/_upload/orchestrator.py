"""Upload orchestrator and factory functions."""

from typing import Any, Dict, List, Optional

from sbomify_action import format_display_name
from sbomify_action.logging_config import logger

from .destinations import DependencyTrackDestination, SbomifyDestination
from .protocol import UploadInput
from .registry import DestinationRegistry
from .result import UploadResult


def create_registry_with_sbomify(
    token: Optional[str] = None,
    component_id: Optional[str] = None,
    api_base_url: Optional[str] = None,
    allow_insecure_http: bool = False,
) -> DestinationRegistry:
    """
    Create a DestinationRegistry with sbomify and other destinations.

    sbomify config is passed explicitly (from the global config).
    Other destinations load their config from environment variables.

    Args:
        token: sbomify API token
        component_id: sbomify component ID
        api_base_url: sbomify API base URL
        allow_insecure_http: API_ALLOW_INSECURE_HTTP for the sbomify destination

    Returns:
        Configured DestinationRegistry
    """
    registry = DestinationRegistry()

    # sbomify destination with explicit config
    registry.register(
        SbomifyDestination(
            token=token,
            component_id=component_id,
            api_base_url=api_base_url,
            allow_insecure_http=allow_insecure_http,
        )
    )

    # Dependency Track loads config from DTRACK_* env vars
    registry.register(DependencyTrackDestination())

    # Future destinations can be added here
    # Each loads its own config from prefixed env vars

    return registry


class UploadOrchestrator:
    """
    Main class for orchestrating SBOM uploads.

    The UploadOrchestrator manages multiple destinations and can upload
    to one or all configured destinations.

    Example:
        # Create orchestrator with sbomify config
        orchestrator = UploadOrchestrator(
            sbomify_token="...",
            sbomify_component_id="...",
        )

        # Upload to all configured destinations
        results = orchestrator.upload_all(UploadInput(
            sbom_file="sbom.json",
            sbom_format="cyclonedx",
        ))

        # Upload to specific destination
        result = orchestrator.upload(input, destination="sbomify")
    """

    def __init__(
        self,
        sbomify_token: Optional[str] = None,
        sbomify_component_id: Optional[str] = None,
        sbomify_api_base_url: Optional[str] = None,
        registry: Optional[DestinationRegistry] = None,
        sbomify_allow_insecure_http: bool = False,
    ) -> None:
        """
        Initialize the UploadOrchestrator.

        Args:
            sbomify_token: sbomify API token
            sbomify_component_id: sbomify component ID
            sbomify_api_base_url: sbomify API base URL
            registry: Optional custom registry (overrides other params)
            sbomify_allow_insecure_http: API_ALLOW_INSECURE_HTTP for the sbomify destination
        """
        if registry:
            self._registry = registry
        else:
            self._registry = create_registry_with_sbomify(
                token=sbomify_token,
                component_id=sbomify_component_id,
                api_base_url=sbomify_api_base_url,
                allow_insecure_http=sbomify_allow_insecure_http,
            )

    @property
    def registry(self) -> DestinationRegistry:
        """Get the destination registry."""
        return self._registry

    def upload(
        self,
        input: UploadInput,
        destination: str = "sbomify",
    ) -> UploadResult:
        """
        Upload an SBOM to a specific destination.

        Args:
            input: UploadInput with SBOM file and format
            destination: Name of destination to upload to (default: "sbomify")

        Returns:
            UploadResult with upload outcome and metadata
        """
        logger.info(
            f"Uploading SBOM to {destination}: format={format_display_name(input.sbom_format)}, file={input.sbom_file}"
        )

        return self._registry.upload(input, destination_name=destination)

    def upload_all(self, input: UploadInput) -> List[UploadResult]:
        """
        Upload an SBOM to all configured destinations.

        Args:
            input: UploadInput with SBOM file and format

        Returns:
            List of UploadResult from each configured destination
        """
        configured = self._registry.get_configured_destinations()
        logger.info(f"Uploading SBOM to {len(configured)} configured destination(s): {[d.name for d in configured]}")

        return self._registry.upload_all(input)

    def get_configured_destinations(self) -> List[str]:
        """
        Get names of all configured destinations.

        Returns:
            List of destination names that are ready for upload
        """
        return [d.name for d in self._registry.get_configured_destinations()]

    def list_all_destinations(self) -> List[Dict[str, Any]]:
        """
        List all registered destinations with their configuration status.

        Returns:
            List of destination info dicts
        """
        return self._registry.list_destinations()
