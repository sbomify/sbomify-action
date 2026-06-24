"""
Public API for SBOM uploads using the plugin architecture.

This module provides a simple interface for uploading SBOMs to various
destinations using the plugin-based upload system.

Destinations:
- sbomify: Uses global config (TOKEN, COMPONENT_ID, API_BASE_URL)
- dependency-track: Uses DTRACK_* prefixed environment variables:
    - DTRACK_API_KEY: API key (required)
    - DTRACK_API_URL: Full API base URL (required). We append /v1/bom.
      Examples: https://dtrack.example.com/api, https://api.dtrack.example.com
    - DTRACK_PROJECT_ID: Project UUID (optional, alternative to COMPONENT_NAME/VERSION)
    - DTRACK_AUTO_CREATE: Auto-create project (default: false)
  Project name/version come from global COMPONENT_NAME/COMPONENT_VERSION.

Usage:
    from sbomify_action.upload import upload_sbom, upload_to_all

    # Upload to sbomify (default)
    result = upload_sbom(
        sbom_file="sbom.json",
        sbom_format="cyclonedx",
        token="api-token",
        component_id="my-component",
    )

    # Upload to Dependency Track
    result = upload_sbom(
        sbom_file="sbom.json",
        sbom_format="cyclonedx",
        component_name="my-app",
        component_version="1.0.0",
        destination="dependency-track",
    )

    # Upload to all configured destinations
    results = upload_to_all(
        sbom_file="sbom.json",
        sbom_format="cyclonedx",
        token="api-token",
        component_id="my-component",
    )
"""

from typing import List, Optional

from ._upload import UploadInput, UploadOrchestrator, UploadResult


def upload_sbom(
    sbom_file: str,
    sbom_format: str,
    token: Optional[str] = None,
    component_id: Optional[str] = None,
    api_base_url: Optional[str] = None,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
    destination: str = "sbomify",
    validate_before_upload: bool = True,
    bom_type: Optional[str] = None,
) -> UploadResult:
    """
    Upload an SBOM to a specific destination.

    Args:
        sbom_file: Path to the SBOM file to upload
        sbom_format: Format of the SBOM ("cyclonedx" or "spdx")
        token: sbomify API token (for sbomify destination)
        component_id: sbomify component ID (for sbomify destination)
        api_base_url: sbomify API base URL (for sbomify destination)
        component_name: Component name (for Dependency Track project)
        component_version: Component version (for Dependency Track project)
        destination: Destination to upload to (default: "sbomify")
        validate_before_upload: Whether to validate SBOM before uploading
        bom_type: Artifact type recorded on upload (sbom/vex/cbom/hbom). None
            uploads a plain SBOM; non-SBOM types are sent verbatim.

    Returns:
        UploadResult with success status, sbom_id, and metadata

    Example:
        # Upload to sbomify
        result = upload_sbom(
            sbom_file="sbom.json",
            sbom_format="cyclonedx",
            token="my-token",
            component_id="my-component",
        )

        # Upload to Dependency Track (config from DTRACK_* env vars)
        result = upload_sbom(
            sbom_file="sbom.json",
            sbom_format="cyclonedx",
            component_name="my-app",
            component_version="1.0.0",
            destination="dependency-track",
        )
    """
    input_params = UploadInput(
        sbom_file=sbom_file,
        sbom_format=sbom_format,  # type: ignore[arg-type]
        bom_type=bom_type,
        component_name=component_name,
        component_version=component_version,
        validate_before_upload=validate_before_upload,
    )

    orchestrator = UploadOrchestrator(
        sbomify_token=token,
        sbomify_component_id=component_id,
        sbomify_api_base_url=api_base_url,
    )

    return orchestrator.upload(input_params, destination=destination)


def upload_to_all(
    sbom_file: str,
    sbom_format: str,
    token: Optional[str] = None,
    component_id: Optional[str] = None,
    api_base_url: Optional[str] = None,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
    validate_before_upload: bool = True,
    bom_type: Optional[str] = None,
) -> List[UploadResult]:
    """
    Upload an SBOM to all configured destinations.

    Destinations are configured via:
    - sbomify: token and component_id parameters
    - dependency-track: DTRACK_* environment variables

    Args:
        sbom_file: Path to the SBOM file to upload
        sbom_format: Format of the SBOM ("cyclonedx" or "spdx")
        token: sbomify API token
        component_id: sbomify component ID
        api_base_url: sbomify API base URL
        component_name: Component name (for Dependency Track)
        component_version: Component version (for Dependency Track)
        validate_before_upload: Whether to validate SBOM before uploading
        bom_type: Artifact type recorded on upload (sbom/vex/cbom/hbom). None
            uploads a plain SBOM; non-SBOM types are sent verbatim.

    Returns:
        List of UploadResult from each configured destination

    Example:
        results = upload_to_all(
            sbom_file="sbom.json",
            sbom_format="cyclonedx",
            token="my-token",
            component_id="my-component",
            component_name="my-app",
            component_version="1.0.0",
        )
        for result in results:
            if result.success:
                print(f"Uploaded to {result.destination_name}")
    """
    input_params = UploadInput(
        sbom_file=sbom_file,
        sbom_format=sbom_format,  # type: ignore[arg-type]
        bom_type=bom_type,
        component_name=component_name,
        component_version=component_version,
        validate_before_upload=validate_before_upload,
    )

    orchestrator = UploadOrchestrator(
        sbomify_token=token,
        sbomify_component_id=component_id,
        sbomify_api_base_url=api_base_url,
    )

    return orchestrator.upload_all(input_params)


# Re-export key types for convenience
__all__ = [
    "upload_sbom",
    "upload_to_all",
    "UploadInput",
    "UploadResult",
]
