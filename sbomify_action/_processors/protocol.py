"""SBOM Processor protocol for post-upload processing plugins.

This module defines the core protocol and types for the processor plugin system.
Processors handle operations that occur after an SBOM has been uploaded,
such as tagging releases or signing SBOMs.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional, Protocol

if TYPE_CHECKING:
    from .result import ProcessorResult


@dataclass
class ProcessorInput:
    """
    Input parameters for SBOM processors.

    Attributes:
        sbom_id: ID of the uploaded artifact (from sbomify API). Named for the
            SBOM case, which is the overwhelmingly common one; ``artifact_kind``
            says what the ID actually points at.
        sbom_file: Path to the SBOM file
        product_releases: List of product releases in "product_id:version" format
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        artifact_kind: "sbom" (default) or "document" -- a release holds both,
            and the API keys them differently
    """

    sbom_id: str
    sbom_file: Optional[str] = None
    product_releases: Optional[List[str]] = None
    api_base_url: Optional[str] = None
    token: Optional[str] = None
    artifact_kind: str = "sbom"

    def __post_init__(self) -> None:
        """Validate input parameters."""
        if not self.sbom_id:
            raise ValueError("sbom_id is required")
        if self.artifact_kind not in ("sbom", "document"):
            raise ValueError(f"Invalid artifact_kind: {self.artifact_kind}. Must be 'sbom' or 'document'")


class SBOMProcessor(Protocol):
    """
    Protocol defining the interface for SBOM processor plugins.

    Each processor implements this protocol to provide post-upload
    operations like release tagging, SBOM signing, etc.

    Example:
        class SbomifyReleasesProcessor:
            name = "sbomify_releases"

            def is_enabled(self, input: ProcessorInput) -> bool:
                return bool(input.product_releases)

            def process(self, input: ProcessorInput) -> ProcessorResult:
                # Process releases and return result
                ...
    """

    @property
    def name(self) -> str:
        """
        Human-readable name of this processor.

        Used for logging, selection, and tracking which processor handled the operation.
        Examples: "releases", "signing", "attestation"
        """
        ...

    def is_enabled(self, input: ProcessorInput) -> bool:
        """
        Check if this processor should run for the given input.

        Each processor determines its own trigger conditions based on the input.
        For example, ReleasesProcessor checks if product_releases is set.

        Args:
            input: ProcessorInput with SBOM and configuration details

        Returns:
            True if processor should run for this input
        """
        ...

    def process(self, input: ProcessorInput) -> "ProcessorResult":
        """
        Execute the processor's operation.

        Implementations should:
        1. Validate any required input fields
        2. Perform the operation (e.g., tag releases, sign SBOM)
        3. Handle errors gracefully
        4. Return a ProcessorResult with success/failure info

        Args:
            input: ProcessorInput with SBOM and configuration details

        Returns:
            ProcessorResult with operation outcome and metadata
        """
        ...
