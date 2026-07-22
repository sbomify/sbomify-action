"""
SBOM Generation Module

This module provides the public API for SBOM generation using a plugin architecture.

Supported features:
- Multiple generators (cyclonedx-py, Trivy, Syft)
- Multiple output formats (CycloneDX, SPDX)
- Spec version selection
- Priority-based generator selection with fallback

Usage:
    from sbomify_action.generation import generate_sbom, process_lock_file

    # Generate SBOM from lock file
    result = generate_sbom(lock_file="requirements.txt", output_format="cyclonedx")

    # Generate SBOM from Docker image
    result = generate_sbom(docker_image="alpine:3.18", output_format="spdx")

    # Process lock file (writes to step_1.json)
    process_lock_file("requirements.txt")
"""

from pathlib import Path
from typing import Optional

from . import format_display_name

# Re-export public API from plugin architecture
from ._generation import (
    GenerationInput,
    GenerationResult,
    GeneratorOrchestrator,
    GeneratorRegistry,
    SBOMFormat,
    create_default_registry,
)
from ._generation.utils import (
    ALL_LOCK_FILES,
    CPP_LOCK_FILES,
    DART_LOCK_FILES,
    GO_LOCK_FILES,
    JAVASCRIPT_LOCK_FILES,
    PYTHON_LOCK_FILES,
    RUBY_LOCK_FILES,
    RUST_LOCK_FILES,
    get_lock_file_ecosystem,
    is_supported_lock_file,
)
from .exceptions import FileProcessingError, SBOMGenerationError
from .logging_config import logger

# Module-level orchestrator instance (lazy initialization)
_orchestrator: Optional[GeneratorOrchestrator] = None

__all__ = [
    # Core API
    "generate_sbom",
    "process_lock_file",
    # Types
    "GenerationInput",
    "GenerationResult",
    "SBOMFormat",
    # Advanced usage
    "GeneratorOrchestrator",
    "GeneratorRegistry",
    "create_default_registry",
    # Lock file constants
    "ALL_LOCK_FILES",
    "PYTHON_LOCK_FILES",
    "RUST_LOCK_FILES",
    "JAVASCRIPT_LOCK_FILES",
    "RUBY_LOCK_FILES",
    "GO_LOCK_FILES",
    "DART_LOCK_FILES",
    "CPP_LOCK_FILES",
    # Utilities
    "get_lock_file_ecosystem",
    "is_supported_lock_file",
]


def _get_orchestrator() -> GeneratorOrchestrator:
    """Get or create the module-level orchestrator."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = GeneratorOrchestrator()
    return _orchestrator


def generate_sbom(
    lock_file: Optional[str] = None,
    docker_image: Optional[str] = None,
    output_file: str = "sbom.json",
    output_format: SBOMFormat = "cyclonedx",
    spec_version: Optional[str] = None,
    include_crypto: bool = False,
) -> GenerationResult:
    """
    Generate an SBOM using the plugin architecture.

    This is the primary entry point for SBOM generation, supporting
    format and version selection with automatic generator selection.

    Args:
        lock_file: Path to lock file (mutually exclusive with docker_image)
        docker_image: Docker image name (mutually exclusive with lock_file)
        output_file: Path to save the generated SBOM
        output_format: Desired SBOM format ("cyclonedx" or "spdx")
        spec_version: Specific spec version (None = use generator default)

    Returns:
        GenerationResult with output file path and metadata

    Raises:
        ValueError: If neither or both lock_file and docker_image are provided

    Example:
        # Generate CycloneDX SBOM from Python requirements
        result = generate_sbom(
            lock_file="requirements.txt",
            output_file="sbom.json",
            output_format="cyclonedx",
            spec_version="1.6",
        )

        # Generate SPDX SBOM from Docker image
        result = generate_sbom(
            docker_image="alpine:3.18",
            output_file="sbom.spdx.json",
            output_format="spdx",
        )
    """
    input_params = GenerationInput(
        lock_file=lock_file,
        docker_image=docker_image,
        output_file=output_file,
        output_format=output_format,
        spec_version=spec_version,
        include_crypto=include_crypto,
    )

    orchestrator = _get_orchestrator()
    return orchestrator.generate(input_params)


def process_lock_file(
    file_path: str,
    output_file: str = "step_1.json",
    output_format: SBOMFormat = "cyclonedx",
    spec_version: Optional[str] = None,
    include_crypto: bool = False,
) -> GenerationResult:
    """
    Process a lock file and generate an SBOM.

    Args:
        file_path: Path to the lock file
        output_file: Path to save the generated SBOM (default: "step_1.json")
        output_format: Desired SBOM format ("cyclonedx" or "spdx")
        spec_version: Specific spec version (None = use generator default)

    Returns:
        GenerationResult with output file path and metadata

    Raises:
        FileProcessingError: If lock file type is not supported
        SBOMGenerationError: If SBOM generation fails
    """
    lock_file_name = Path(file_path).name

    # Check if lock file is supported
    if not is_supported_lock_file(lock_file_name):
        raise FileProcessingError(f"{file_path} is not a recognized lock file type")

    # Log detected ecosystem
    ecosystem = get_lock_file_ecosystem(lock_file_name)
    if ecosystem:
        logger.info(f"Detected {ecosystem.capitalize()} lockfile")

    # Use the plugin architecture
    result = generate_sbom(
        lock_file=file_path,
        output_file=output_file,
        output_format=output_format,
        spec_version=spec_version,
        include_crypto=include_crypto,
    )

    if not result.success:
        raise SBOMGenerationError(result.error_message or "SBOM generation failed")

    logger.info(
        f"Generated {format_display_name(result.sbom_format)} {result.spec_version} SBOM with {result.generator_name}"
    )
    return result
