"""Generator orchestrator and factory functions."""

from typing import Any, Dict, List, Optional

from sbomify_action.logging_config import logger

from .generators import (
    CdxgenFsGenerator,
    CdxgenImageGenerator,
    CycloneDXCargoGenerator,
    CycloneDXPyGenerator,
    SyftFsGenerator,
    SyftImageGenerator,
)
from .protocol import GenerationInput
from .registry import GeneratorRegistry
from .result import GenerationResult


def create_default_registry() -> GeneratorRegistry:
    """
    Create a GeneratorRegistry with default generators.

    Returns a registry configured with generators in priority order:

    Priority 10 - Native Sources:
    - CycloneDXPyGenerator: Native Python CycloneDX generator
      - Input: Python lock files only (requirements.txt, poetry.lock, Pipfile.lock, pyproject.toml)
      - Output: CycloneDX 1.0-1.7
    - CycloneDXCargoGenerator: Native Rust/Cargo CycloneDX generator
      - Input: Rust lock files only (Cargo.lock)
      - Output: CycloneDX 1.4-1.6

    Priority 20 - Comprehensive Multi-Ecosystem (cdxgen):
    - CdxgenFsGenerator: Filesystem/lock file scanning
      - Input: Python, JavaScript, Java/Gradle, Go, Rust, Ruby, Dart, C++,
               PHP, .NET, Swift, Elixir, Scala
      - Output: CycloneDX 1.4-1.7 (no SPDX support)
    - CdxgenImageGenerator: Docker image scanning
      - Input: Container images
      - Output: CycloneDX 1.4-1.7 (no SPDX support)

    Priority 30 - Generic Multi-Ecosystem (Trivy) [TEMPORARILY DISABLED]:
    - TrivyFsGenerator: Filesystem/lock file scanning
      - Input: Python, JavaScript, Java/Gradle, Go, Rust, Ruby, C++, PHP, .NET
               (NOT Dart, Swift, Elixir, Scala, Terraform)
      - Output: CycloneDX 1.6, SPDX 2.3
    - TrivyImageGenerator: Docker image scanning
      - Input: Container images
      - Output: CycloneDX 1.6, SPDX 2.3
    NOTE: Trivy is temporarily disabled due to recurring security vulnerabilities.

    Priority 35 - Generic Multi-Ecosystem (Syft):
    - SyftFsGenerator: Filesystem/lock file scanning
      - Input: Python, JavaScript, Go, Rust, Ruby, Dart, C++, PHP, .NET,
               Swift, Elixir, Terraform (NOT Java/Gradle lock files)
      - Output: CycloneDX 1.2-1.6, SPDX 2.2-2.3
    - SyftImageGenerator: Docker image scanning
      - Input: Container images
      - Output: CycloneDX 1.2-1.6, SPDX 2.2-2.3

    Generators are queried sequentially in priority order. The first
    generator that supports the input and requested format/version is used.

    Returns:
        Configured GeneratorRegistry
    """
    registry = GeneratorRegistry()

    # Priority 10: Native generators
    registry.register(CycloneDXPyGenerator())
    registry.register(CycloneDXCargoGenerator())

    # Priority 20: cdxgen generators (comprehensive multi-ecosystem)
    registry.register(CdxgenFsGenerator())
    registry.register(CdxgenImageGenerator())

    # Priority 30: Trivy generators - TEMPORARILY DISABLED due to recurring
    # security vulnerabilities in Trivy. To re-enable, uncomment the two lines
    # below and restore Trivy installation in Dockerfile and CI workflow.
    # registry.register(TrivyFsGenerator())
    # registry.register(TrivyImageGenerator())

    # Priority 35: Syft generators (version selection, wide ecosystem support)
    registry.register(SyftFsGenerator())
    registry.register(SyftImageGenerator())

    return registry


class GeneratorOrchestrator:
    """
    Main class for orchestrating SBOM generation.

    The GeneratorOrchestrator uses a GeneratorRegistry to find and
    execute the appropriate generator for each input, handling
    format and version selection.

    Example:
        orchestrator = GeneratorOrchestrator()

        # Generate CycloneDX SBOM from Python requirements
        result = orchestrator.generate(GenerationInput(
            lock_file="requirements.txt",
            output_file="sbom.json",
            output_format="cyclonedx",
            spec_version="1.6",
        ))

        # Generate SPDX SBOM from Docker image
        result = orchestrator.generate(GenerationInput(
            docker_image="alpine:3.18",
            output_file="sbom.spdx.json",
            output_format="spdx",
        ))
    """

    def __init__(self, registry: Optional[GeneratorRegistry] = None) -> None:
        """
        Initialize the GeneratorOrchestrator.

        Args:
            registry: Optional GeneratorRegistry. If not provided, creates
                     a default registry with all standard generators.
        """
        self._registry = registry or create_default_registry()

    @property
    def registry(self) -> GeneratorRegistry:
        """Get the generator registry."""
        return self._registry

    def generate(self, input: GenerationInput) -> GenerationResult:
        """
        Generate an SBOM using the appropriate generator.

        Finds the first matching generator (by priority) that supports
        the input type, format, and version, then executes it.

        Args:
            input: GenerationInput with all generation parameters

        Returns:
            GenerationResult with output file path and metadata
        """
        logger.info(
            f"Generating SBOM: format={input.output_format}, "
            f"version={input.spec_version or 'default'}, "
            f"{'docker_image=' + str(input.docker_image) if input.is_docker_image else 'lock_file=' + str(input.lock_file)}"
        )

        return self._registry.generate(input)

    def get_available_generators(self, input: GenerationInput) -> List[Dict[str, Any]]:
        """
        Get information about generators that could handle an input.

        Args:
            input: GenerationInput to check

        Returns:
            List of generator info dicts
        """
        generators = self._registry.get_generators_for(input)
        return [
            {
                "name": g.name,
                "priority": g.priority,
                "formats": [
                    {
                        "format": fv.format,
                        "versions": list(fv.versions),
                        "default": fv.default_version,
                    }
                    for fv in g.supported_formats
                ],
            }
            for g in generators
        ]

    def list_all_generators(self) -> List[Dict[str, Any]]:
        """
        List all registered generators.

        Returns:
            List of generator info dicts
        """
        return self._registry.list_generators()
