"""Trivy generator plugins for filesystem and Docker image scanning.

Priority: 30 (generic multi-ecosystem)

Trivy is a comprehensive scanner that supports many ecosystems.
It outputs fixed versions (no version selection):
- CycloneDX 1.6
- SPDX 2.3
"""

import json
from pathlib import Path

from sbomify_action import format_display_name
from sbomify_action.exceptions import DockerImageNotFoundError, SBOMGenerationError
from sbomify_action.logging_config import logger
from sbomify_action.tool_checks import check_tool_available

from ..protocol import (
    TRIVY_CYCLONEDX_VERSION,
    TRIVY_SPDX_VERSION,
    FormatVersion,
    GenerationInput,
)
from ..result import GenerationResult
from ..utils import DEFAULT_TIMEOUT, TRIVY_LOCK_FILES, run_command

# Check tool availability once at module load
_TRIVY_AVAILABLE, _TRIVY_PATH = check_tool_available("trivy")

# Trivy format flags
TRIVY_FORMAT_MAP = {
    "cyclonedx": "cyclonedx",
    "spdx": "spdx-json",
}


class TrivyFsGenerator:
    """
    Trivy filesystem scanner for lock files.

    Uses Trivy to scan lock files and generate SBOMs. Supports
    all ecosystems that Trivy supports.

    Verified capabilities (Trivy 0.68.2):
    - CycloneDX versions: 1.6 only (fixed)
    - SPDX versions: 2.3 only (fixed)
    - No version selection available
    """

    @property
    def name(self) -> str:
        return "trivy-fs"

    @property
    def command(self) -> str:
        return "trivy"

    @property
    def priority(self) -> int:
        # Generic multi-ecosystem
        return 30

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(
                format="cyclonedx",
                versions=(TRIVY_CYCLONEDX_VERSION,),
                default_version=TRIVY_CYCLONEDX_VERSION,
            ),
            FormatVersion(
                format="spdx",
                versions=(TRIVY_SPDX_VERSION,),
                default_version=TRIVY_SPDX_VERSION,
            ),
        ]

    def supports(self, input: GenerationInput) -> bool:
        """
        Check if this generator supports the given input.

        Supports all lock files for both CycloneDX and SPDX.
        Does not support Docker images (use TrivyImageGenerator).
        """
        # Check if trivy is installed
        if not _TRIVY_AVAILABLE:
            return False

        # Only supports lock files
        if not input.is_lock_file:
            return False

        # Check if it's a supported lock file for Trivy
        if input.lock_file_name not in TRIVY_LOCK_FILES:
            return False

        # Check format
        if input.output_format not in TRIVY_FORMAT_MAP:
            return False

        # Check version if specified (Trivy has fixed versions)
        if input.spec_version:
            if input.output_format == "cyclonedx" and input.spec_version != TRIVY_CYCLONEDX_VERSION:
                return False
            if input.output_format == "spdx" and input.spec_version != TRIVY_SPDX_VERSION:
                return False

        return True

    def generate(self, input: GenerationInput) -> GenerationResult:
        """Generate an SBOM using Trivy fs command."""
        assert input.lock_file is not None  # guaranteed by supports()
        trivy_format = TRIVY_FORMAT_MAP.get(input.output_format)
        if not trivy_format:
            return GenerationResult.failure_result(
                error_message=f"Unsupported format: {input.output_format}",
                sbom_format=input.output_format,
                spec_version=input.spec_version or self._get_default_version(input.output_format),
                generator_name=self.name,
            )

        spec_version = self._get_default_version(input.output_format)

        cmd = [
            "trivy",
            "fs",
            input.lock_file,
            "--parallel",
            "0",
            "--format",
            trivy_format,
        ]

        logger.info(f"Running trivy fs for {input.lock_file_name} ({format_display_name(input.output_format)})")

        try:
            # run_command raises SBOMGenerationError on failure (uses check=True)
            result = run_command(cmd, "trivy", timeout=DEFAULT_TIMEOUT)

            # Trivy outputs to stdout, save to file
            try:
                json_data = json.loads(result.stdout)
                with Path(input.output_file).open("w") as f:
                    json.dump(json_data, f, indent=4)

                return GenerationResult.success_result(
                    output_file=input.output_file,
                    sbom_format=input.output_format,
                    spec_version=spec_version,
                    generator_name=self.name,
                )
            except json.JSONDecodeError as e:
                return GenerationResult.failure_result(
                    error_message=f"Invalid JSON output from trivy: {e}",
                    sbom_format=input.output_format,
                    spec_version=spec_version,
                    generator_name=self.name,
                )
        except SBOMGenerationError as e:
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format=input.output_format,
                spec_version=spec_version,
                generator_name=self.name,
            )

    def _get_default_version(self, format: str) -> str:
        """Get the default version for a format."""
        if format == "cyclonedx":
            return TRIVY_CYCLONEDX_VERSION
        return TRIVY_SPDX_VERSION


class TrivyImageGenerator:
    """
    Trivy Docker image scanner.

    Uses Trivy to scan Docker images and generate SBOMs.

    Verified capabilities (Trivy 0.68.2):
    - CycloneDX versions: 1.6 only (fixed)
    - SPDX versions: 2.3 only (fixed)
    - No version selection available
    """

    @property
    def name(self) -> str:
        return "trivy-image"

    @property
    def command(self) -> str:
        return "trivy"

    @property
    def priority(self) -> int:
        # Generic multi-ecosystem
        return 30

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(
                format="cyclonedx",
                versions=(TRIVY_CYCLONEDX_VERSION,),
                default_version=TRIVY_CYCLONEDX_VERSION,
            ),
            FormatVersion(
                format="spdx",
                versions=(TRIVY_SPDX_VERSION,),
                default_version=TRIVY_SPDX_VERSION,
            ),
        ]

    def supports(self, input: GenerationInput) -> bool:
        """
        Check if this generator supports the given input.

        Supports Docker images for both CycloneDX and SPDX.
        Does not support lock files (use TrivyFsGenerator).
        """
        # Check if trivy is installed
        if not _TRIVY_AVAILABLE:
            return False

        # Only supports Docker images
        if not input.is_docker_image:
            return False

        # Check format
        if input.output_format not in TRIVY_FORMAT_MAP:
            return False

        # Check version if specified (Trivy has fixed versions)
        if input.spec_version:
            if input.output_format == "cyclonedx" and input.spec_version != TRIVY_CYCLONEDX_VERSION:
                return False
            if input.output_format == "spdx" and input.spec_version != TRIVY_SPDX_VERSION:
                return False

        return True

    def generate(self, input: GenerationInput) -> GenerationResult:
        """Generate an SBOM using Trivy image command."""
        assert input.docker_image is not None  # guaranteed by supports()
        trivy_format = TRIVY_FORMAT_MAP.get(input.output_format)
        if not trivy_format:
            return GenerationResult.failure_result(
                error_message=f"Unsupported format: {input.output_format}",
                sbom_format=input.output_format,
                spec_version=input.spec_version or self._get_default_version(input.output_format),
                generator_name=self.name,
            )

        spec_version = self._get_default_version(input.output_format)

        cmd = [
            "trivy",
            "image",
            "--parallel",
            "0",
            "--format",
            trivy_format,
            "--pkg-types",
            "os",  # Focus on OS packages for container SBOMs
            input.docker_image,
        ]

        logger.info(f"Running trivy image for {input.docker_image} ({format_display_name(input.output_format)})")

        try:
            # run_command raises SBOMGenerationError on failure (uses check=True)
            result = run_command(cmd, "trivy", timeout=DEFAULT_TIMEOUT, docker_image=input.docker_image)

            # Trivy outputs to stdout, save to file
            try:
                json_data = json.loads(result.stdout)
                with Path(input.output_file).open("w") as f:
                    json.dump(json_data, f, indent=4)

                return GenerationResult.success_result(
                    output_file=input.output_file,
                    sbom_format=input.output_format,
                    spec_version=spec_version,
                    generator_name=self.name,
                )
            except json.JSONDecodeError as e:
                return GenerationResult.failure_result(
                    error_message=f"Invalid JSON output from trivy: {e}",
                    sbom_format=input.output_format,
                    spec_version=spec_version,
                    generator_name=self.name,
                )
        except DockerImageNotFoundError as e:
            # Provide a clear error message for missing Docker images
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format=input.output_format,
                spec_version=spec_version,
                generator_name=self.name,
            )
        except SBOMGenerationError as e:
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format=input.output_format,
                spec_version=spec_version,
                generator_name=self.name,
            )

    def _get_default_version(self, format: str) -> str:
        """Get the default version for a format."""
        if format == "cyclonedx":
            return TRIVY_CYCLONEDX_VERSION
        return TRIVY_SPDX_VERSION
