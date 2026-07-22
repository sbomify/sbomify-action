"""Syft generator plugins for filesystem and Docker image scanning.

Priority: 35 (generic multi-ecosystem, lower than Trivy)

Syft is a comprehensive SBOM generator that supports version selection.
It supports more versions than Trivy but is slightly lower priority.

Verified capabilities (Syft 1.38.2):
- CycloneDX versions: 1.2, 1.3, 1.4, 1.5, 1.6 (default: 1.6)
- SPDX versions: 2.2, 2.3 (default: 2.3)
- Version selection: -o format@version=file
"""

from pathlib import Path

from sbomify_action import format_display_name
from sbomify_action.exceptions import DockerImageNotFoundError, SBOMGenerationError
from sbomify_action.logging_config import logger
from sbomify_action.tool_checks import check_tool_available

from ..protocol import (
    SYFT_CYCLONEDX_DEFAULT,
    SYFT_CYCLONEDX_VERSIONS,
    SYFT_SPDX_DEFAULT,
    SYFT_SPDX_VERSIONS,
    FormatVersion,
    GenerationInput,
)
from ..result import GenerationResult
from ..utils import DEFAULT_TIMEOUT, SYFT_LOCK_FILES, run_command

# Check tool availability once at module load
_SYFT_AVAILABLE, _SYFT_PATH = check_tool_available("syft")


class SyftFsGenerator:
    """
    Syft filesystem scanner for lock files.

    Uses Syft to scan lock files and generate SBOMs. Supports
    all ecosystems that Syft supports with version selection.

    Verified capabilities (Syft 1.38.2):
    - CycloneDX versions: 1.2, 1.3, 1.4, 1.5, 1.6 (default: 1.6)
    - SPDX versions: 2.2, 2.3 (default: 2.3)
    - Version selection: @VERSION suffix
    """

    @property
    def name(self) -> str:
        return "syft-fs"

    @property
    def command(self) -> str:
        return "syft"

    @property
    def priority(self) -> int:
        # Generic multi-ecosystem, slightly lower priority than Trivy
        return 35

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(
                format="cyclonedx",
                versions=SYFT_CYCLONEDX_VERSIONS,
                default_version=SYFT_CYCLONEDX_DEFAULT,
            ),
            FormatVersion(
                format="spdx",
                versions=SYFT_SPDX_VERSIONS,
                default_version=SYFT_SPDX_DEFAULT,
            ),
        ]

    def supports(self, input: GenerationInput) -> bool:
        """
        Check if this generator supports the given input.

        Supports all lock files for both CycloneDX and SPDX.
        Does not support Docker images (use SyftImageGenerator).
        """
        # Check if syft is installed
        if not _SYFT_AVAILABLE:
            return False

        # Only supports lock files
        if not input.is_lock_file:
            return False

        # Check if it's a supported lock file for Syft
        if input.lock_file_name not in SYFT_LOCK_FILES:
            return False

        # Check format
        if input.output_format not in ("cyclonedx", "spdx"):
            return False

        # Check version if specified
        if input.spec_version:
            if input.output_format == "cyclonedx":
                if input.spec_version not in SYFT_CYCLONEDX_VERSIONS:
                    return False
            elif input.output_format == "spdx":
                if input.spec_version not in SYFT_SPDX_VERSIONS:
                    return False

        return True

    def generate(self, input: GenerationInput) -> GenerationResult:
        """Generate an SBOM using Syft scan command."""
        assert input.lock_file is not None  # guaranteed by supports()
        # Determine format string and version
        if input.output_format == "cyclonedx":
            version = input.spec_version or SYFT_CYCLONEDX_DEFAULT
            format_str = "cyclonedx-json"
        else:  # spdx
            version = input.spec_version or SYFT_SPDX_DEFAULT
            format_str = "spdx-json"

        # Syft output format: -o format@version=file
        output_spec = f"{format_str}@{version}={input.output_file}"

        cmd = [
            "syft",
            "scan",
            input.lock_file,
            "-o",
            output_spec,
            "--source-name",
            input.lock_file_name or "unknown",
        ]

        logger.info(
            f"Running syft scan for {input.lock_file_name} ({format_display_name(input.output_format)} {version})"
        )

        try:
            # run_command raises SBOMGenerationError on failure (uses check=True)
            run_command(cmd, "syft", timeout=DEFAULT_TIMEOUT)

            # Verify output file was created
            if not Path(input.output_file).exists():
                return GenerationResult.failure_result(
                    error_message="Syft completed but output file not created",
                    sbom_format=input.output_format,
                    spec_version=version,
                    generator_name=self.name,
                )

            return GenerationResult.success_result(
                output_file=input.output_file,
                sbom_format=input.output_format,
                spec_version=version,
                generator_name=self.name,
            )
        except SBOMGenerationError as e:
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format=input.output_format,
                spec_version=input.spec_version or self._get_default_version(input.output_format),
                generator_name=self.name,
            )

    def _get_default_version(self, format: str) -> str:
        """Get the default version for a format."""
        if format == "cyclonedx":
            return SYFT_CYCLONEDX_DEFAULT
        return SYFT_SPDX_DEFAULT


class SyftImageGenerator:
    """
    Syft Docker image scanner.

    Uses Syft to scan Docker images and generate SBOMs.

    Verified capabilities (Syft 1.38.2):
    - CycloneDX versions: 1.2, 1.3, 1.4, 1.5, 1.6 (default: 1.6)
    - SPDX versions: 2.2, 2.3 (default: 2.3)
    - Version selection: @VERSION suffix
    """

    @property
    def name(self) -> str:
        return "syft-image"

    @property
    def command(self) -> str:
        return "syft"

    @property
    def priority(self) -> int:
        # Generic multi-ecosystem, slightly lower priority than Trivy
        return 35

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(
                format="cyclonedx",
                versions=SYFT_CYCLONEDX_VERSIONS,
                default_version=SYFT_CYCLONEDX_DEFAULT,
            ),
            FormatVersion(
                format="spdx",
                versions=SYFT_SPDX_VERSIONS,
                default_version=SYFT_SPDX_DEFAULT,
            ),
        ]

    def supports(self, input: GenerationInput) -> bool:
        """
        Check if this generator supports the given input.

        Supports Docker images for both CycloneDX and SPDX.
        Does not support lock files (use SyftFsGenerator).
        """
        # Check if syft is installed
        if not _SYFT_AVAILABLE:
            return False

        # Only supports Docker images
        if not input.is_docker_image:
            return False

        # Check format
        if input.output_format not in ("cyclonedx", "spdx"):
            return False

        # Check version if specified
        if input.spec_version:
            if input.output_format == "cyclonedx":
                if input.spec_version not in SYFT_CYCLONEDX_VERSIONS:
                    return False
            elif input.output_format == "spdx":
                if input.spec_version not in SYFT_SPDX_VERSIONS:
                    return False

        return True

    def generate(self, input: GenerationInput) -> GenerationResult:
        """Generate an SBOM using Syft scan command."""
        assert input.docker_image is not None  # guaranteed by supports()
        # Determine format string and version
        if input.output_format == "cyclonedx":
            version = input.spec_version or SYFT_CYCLONEDX_DEFAULT
            format_str = "cyclonedx-json"
        else:  # spdx
            version = input.spec_version or SYFT_SPDX_DEFAULT
            format_str = "spdx-json"

        # Syft output format: -o format@version=file
        output_spec = f"{format_str}@{version}={input.output_file}"

        cmd = [
            "syft",
            "scan",
            input.docker_image,
            "-o",
            output_spec,
        ]

        logger.info(
            f"Running syft scan for {input.docker_image} ({format_display_name(input.output_format)} {version})"
        )

        try:
            # run_command raises SBOMGenerationError on failure (uses check=True)
            run_command(cmd, "syft", timeout=DEFAULT_TIMEOUT, docker_image=input.docker_image)

            # Verify output file was created
            if not Path(input.output_file).exists():
                return GenerationResult.failure_result(
                    error_message="Syft completed but output file not created",
                    sbom_format=input.output_format,
                    spec_version=version,
                    generator_name=self.name,
                )

            return GenerationResult.success_result(
                output_file=input.output_file,
                sbom_format=input.output_format,
                spec_version=version,
                generator_name=self.name,
            )
        except DockerImageNotFoundError as e:
            # Provide a clear error message for missing Docker images
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format=input.output_format,
                spec_version=version,
                generator_name=self.name,
            )
        except SBOMGenerationError as e:
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format=input.output_format,
                spec_version=input.spec_version or self._get_default_version(input.output_format),
                generator_name=self.name,
            )

    def _get_default_version(self, format: str) -> str:
        """Get the default version for a format."""
        if format == "cyclonedx":
            return SYFT_CYCLONEDX_DEFAULT
        return SYFT_SPDX_DEFAULT
