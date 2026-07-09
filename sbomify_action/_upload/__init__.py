"""SBOM Upload Plugin Architecture.

This module provides a plugin-based system for SBOM uploads supporting:
- Multiple upload destinations (sbomify, Dependency Track, etc.)
- Destination-specific configuration via environment variables
- Upload to one or all configured destinations

Configuration:
- sbomify: Uses global config (TOKEN, COMPONENT_ID, API_BASE_URL)
- Dependency Track: Uses DTRACK_* prefixed env vars
- Future destinations: Each uses its own prefix

Usage:
    from sbomify_action._upload import (
        UploadOrchestrator,
        UploadInput,
        UploadResult,
    )

    # Create orchestrator with sbomify config
    orchestrator = UploadOrchestrator(
        sbomify_token="...",
        sbomify_component_id="...",
    )

    # Upload to sbomify
    result = orchestrator.upload(UploadInput(
        sbom_file="sbom.json",
        sbom_format="cyclonedx",
    ))

    # Upload to all configured destinations
    results = orchestrator.upload_all(input)
"""

from .destinations import (
    DependencyTrackConfig,
    DependencyTrackDestination,
    SbomifyDestination,
)
from .orchestrator import UploadOrchestrator, create_registry_with_sbomify
from .protocol import VALID_BOM_TYPES, Destination, DestinationConfig, SBOMFormat, UploadInput
from .registry import VALID_DESTINATIONS, DestinationRegistry
from .result import UploadResult

__all__ = [
    # Core types
    "SBOMFormat",
    "UploadInput",
    "VALID_BOM_TYPES",
    "UploadResult",
    "Destination",
    "DestinationConfig",
    # Registry and orchestration
    "DestinationRegistry",
    "VALID_DESTINATIONS",
    "UploadOrchestrator",
    "create_registry_with_sbomify",
    # Destination implementations
    "SbomifyDestination",
    "DependencyTrackDestination",
    "DependencyTrackConfig",
]
