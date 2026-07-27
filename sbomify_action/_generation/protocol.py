"""Generator Protocol for SBOM generation plugins.

This module defines the core protocol and types for the generation plugin system.
All version constants are defined here as the single source of truth.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Optional, Protocol

if TYPE_CHECKING:
    from .result import GenerationResult

# =============================================================================
# SBOM Format and Version Constants
# =============================================================================

# Supported SBOM formats
SBOMFormat = Literal["cyclonedx", "spdx"]

# CycloneDX versions that can be *generated*. Starts at 1.2 because JSON was
# only introduced in CycloneDX 1.2 -- 1.0/1.1 are XML-only, and this tool emits
# JSON, so requesting them fails in the generator with
# "CDX > JSON is not supported by CycloneDX in schema version 1.0".
CYCLONEDX_VERSIONS = ("1.2", "1.3", "1.4", "1.5", "1.6", "1.7")

# SPDX versions the *generator plugins* in this package can emit from a lock
# file or Docker image. 3.0.1 is deliberately absent: no plugin produces it.
# It is not unreachable overall, so this tuple must not be read as "every SPDX
# version the CLI can output" -- 3.0.1 also arrives via
# additional_packages.create_empty_sbom (additional-packages-only mode) and via
# spdx3.py, which parses an existing 3.0.1 document and writes it back. That
# wider set is what serialization.SUPPORTED_SPDX_VERSIONS describes.
SPDX_VERSIONS = ("2.2", "2.3")

# =============================================================================
# Generator-specific version support
# Each generator has its own capabilities
# =============================================================================

# cyclonedx-py (native Python generator) - supports all CycloneDX versions
CYCLONEDX_PY_VERSIONS = CYCLONEDX_VERSIONS
CYCLONEDX_PY_DEFAULT = "1.6"

# Trivy (fixed versions, no version selection)
TRIVY_CYCLONEDX_VERSION = "1.6"
TRIVY_SPDX_VERSION = "2.3"

# Syft (version selection supported)
SYFT_CYCLONEDX_VERSIONS = ("1.2", "1.3", "1.4", "1.5", "1.6")
SYFT_CYCLONEDX_DEFAULT = "1.6"
SYFT_SPDX_VERSIONS = ("2.2", "2.3")
SYFT_SPDX_DEFAULT = "2.3"

# cdxgen (version selection supported, CycloneDX only - no SPDX support)
CDXGEN_CYCLONEDX_VERSIONS = ("1.4", "1.5", "1.6", "1.7")
CDXGEN_CYCLONEDX_DEFAULT = "1.6"

# cargo-cyclonedx (native Rust generator) - CycloneDX only
CARGO_CYCLONEDX_VERSIONS = ("1.4", "1.5", "1.6")
CARGO_CYCLONEDX_DEFAULT = "1.6"


@dataclass
class FormatVersion:
    """
    Represents a format and its supported versions.

    Attributes:
        format: The SBOM format ("cyclonedx" or "spdx")
        versions: Tuple of supported spec versions
        default_version: Default version to use when not specified
    """

    format: SBOMFormat
    versions: tuple[str, ...]
    default_version: str

    def supports_version(self, version: str) -> bool:
        """Check if this format supports a specific version."""
        return version in self.versions


@dataclass
class GenerationInput:
    """
    Input parameters for SBOM generation.

    Attributes:
        lock_file: Path to lock file (mutually exclusive with docker_image)
        docker_image: Docker image name/tag (mutually exclusive with lock_file)
        output_file: Path to save the generated SBOM
        output_format: Desired SBOM format ("cyclonedx" or "spdx")
        spec_version: Specific spec version (None = use generator default)
    """

    lock_file: Optional[str] = None
    docker_image: Optional[str] = None
    output_file: str = "sbom.json"
    output_format: SBOMFormat = "cyclonedx"
    spec_version: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate input parameters."""
        if self.lock_file and self.docker_image:
            raise ValueError("Cannot specify both lock_file and docker_image")
        if not self.lock_file and not self.docker_image:
            raise ValueError("Must specify either lock_file or docker_image")

    @property
    def lock_file_name(self) -> Optional[str]:
        """Get the lock file name without path."""
        if self.lock_file:
            return Path(self.lock_file).name
        return None

    @property
    def is_docker_image(self) -> bool:
        """Check if input is a Docker image."""
        return self.docker_image is not None

    @property
    def is_lock_file(self) -> bool:
        """Check if input is a lock file."""
        return self.lock_file is not None


class Generator(Protocol):
    """
    Protocol defining the interface for SBOM generator plugins.

    Each generator implements this protocol to provide SBOM generation
    for specific input types (lock files, Docker images) in specific
    formats (CycloneDX, SPDX) and versions.

    Generators have priorities - lower numbers indicate higher priority
    (tried first). Native/authoritative generators should have low priorities
    (e.g., 10-20), generic generators higher (e.g., 30-50).

    Example:
        class CycloneDXPyGenerator:
            name = "cyclonedx-py"
            priority = 10

            @property
            def supported_formats(self) -> list[FormatVersion]:
                return [FormatVersion("cyclonedx", CYCLONEDX_VERSIONS, "1.6")]

            def supports(self, input: GenerationInput) -> bool:
                return input.is_lock_file and input.lock_file_name in PYTHON_LOCK_FILES

            def generate(self, input: GenerationInput) -> GenerationResult:
                # Generate SBOM and return result
                ...
    """

    @property
    def name(self) -> str:
        """
        Human-readable name of this generator.

        Used for logging and tracking which generator produced the SBOM.
        Examples: "cyclonedx-py", "trivy-fs", "syft"
        """
        ...

    @property
    def command(self) -> str:
        """
        The command-line tool this generator uses.

        Used for tool availability checks.
        Examples: "cyclonedx-py", "trivy", "syft", "cdxgen", "cargo-cyclonedx"
        """
        ...

    @property
    def priority(self) -> int:
        """
        Priority of this generator (lower = higher priority).

        When multiple generators support an input type, they are tried
        in priority order. Native generators should have low priorities
        (e.g., 10), generic generators higher (e.g., 30).

        Recommended priority ranges:
        - 1-20: Native/authoritative generators (cyclonedx-py for Python)
        - 21-50: Generic multi-ecosystem generators (Trivy, Syft)
        """
        ...

    @property
    def supported_formats(self) -> list[FormatVersion]:
        """
        List of supported output formats and their versions.

        Returns:
            List of FormatVersion objects describing supported formats
        """
        ...

    def supports(self, input: GenerationInput) -> bool:
        """
        Check if this generator can handle the given input.

        Implementations should check:
        1. Input type (lock file vs Docker image)
        2. Lock file type (if applicable)
        3. Requested format and version compatibility

        Args:
            input: GenerationInput with file/image and format requirements

        Returns:
            True if this generator can handle this input
        """
        ...

    def generate(self, input: GenerationInput) -> "GenerationResult":
        """
        Generate an SBOM for the given input.

        Implementations should:
        1. Execute the appropriate command/process
        2. Handle errors gracefully
        3. Return a GenerationResult with success/failure info

        Args:
            input: GenerationInput with all generation parameters

        Returns:
            GenerationResult with output file path and metadata
        """
        ...
