"""cdxgen generator plugins for filesystem and Docker image scanning.

Priority: 20 (comprehensive multi-ecosystem)

cdxgen is a comprehensive SBOM generator that supports many ecosystems
and programming languages with excellent coverage.

Verified capabilities (cdxgen 12.0.0):
- CycloneDX versions: 1.4, 1.5, 1.6, 1.7 (default: 1.6)
- SPDX: Not supported (cdxgen only outputs CycloneDX format)
- Version selection: --spec-version
"""

from pathlib import Path

from sbomify_action.exceptions import DockerImageNotFoundError, SBOMGenerationError
from sbomify_action.logging_config import logger
from sbomify_action.tool_checks import check_tool_available

from ..protocol import (
    CDXGEN_CYCLONEDX_DEFAULT,
    CDXGEN_CYCLONEDX_VERSIONS,
    FormatVersion,
    GenerationInput,
)
from ..result import GenerationResult
from ..utils import (
    CDXGEN_LOCK_FILES,
    DEFAULT_TIMEOUT,
    ensure_go_installed,
    ensure_java_maven_installed,
    get_lock_file_ecosystem,
    run_command,
)

# Check tool availability once at module load
_CDXGEN_AVAILABLE, _CDXGEN_PATH = check_tool_available("cdxgen")

# Mapping from ecosystem names to cdxgen --type values
# See: https://cyclonedx.github.io/cdxgen/#/PROJECT_TYPES
CDXGEN_TYPE_MAP = {
    "java": "java",
    "python": "python",
    "javascript": "js",
    "go": "go",
    "rust": "rust",
    "ruby": "ruby",
    "php": "php",
    "dotnet": "dotnet",
    "swift": "swift",
    "dart": "dart",
    "elixir": "elixir",
    "scala": "scala",
    "cpp": "cpp",
}

# Ecosystems that use parent/child project structures (e.g., Maven parent POMs, Gradle multi-project)
# For these, we allow recursion so cdxgen can follow module references
# The -t flag will still restrict scanning to only that ecosystem
RECURSE_ECOSYSTEMS = {"java", "scala"}


class CdxgenFsGenerator:
    """
    cdxgen filesystem scanner for lock files.

    Uses cdxgen to scan lock files and generate SBOMs. Supports
    all ecosystems that cdxgen supports with version selection.

    Verified capabilities (cdxgen 12.0.0):
    - CycloneDX versions: 1.4, 1.5, 1.6, 1.7 (default: 1.6)
    - SPDX: Not supported
    - Version selection: --spec-version
    """

    @property
    def name(self) -> str:
        return "cdxgen-fs"

    @property
    def command(self) -> str:
        return "cdxgen"

    @property
    def priority(self) -> int:
        # Comprehensive multi-ecosystem, higher priority than Trivy/Syft
        return 20

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(
                format="cyclonedx",
                versions=CDXGEN_CYCLONEDX_VERSIONS,
                default_version=CDXGEN_CYCLONEDX_DEFAULT,
            ),
        ]

    def supports(self, input: GenerationInput) -> bool:
        """
        Check if this generator supports the given input.

        Supports all lock files for CycloneDX format only.
        Does not support SPDX or Docker images (use CdxgenImageGenerator).
        """
        # Check if cdxgen is installed
        if not _CDXGEN_AVAILABLE:
            return False

        # Only supports lock files
        if not input.is_lock_file:
            return False

        # Check if it's a supported lock file for cdxgen
        if input.lock_file_name not in CDXGEN_LOCK_FILES:
            return False

        # Only supports CycloneDX format (cdxgen doesn't output SPDX)
        if input.output_format != "cyclonedx":
            return False

        # Check version if specified
        if input.spec_version:
            if input.spec_version not in CDXGEN_CYCLONEDX_VERSIONS:
                return False

        return True

    def generate(self, input: GenerationInput) -> GenerationResult:
        """Generate an SBOM using cdxgen command."""
        assert input.lock_file is not None  # guaranteed by supports()
        version = input.spec_version or CDXGEN_CYCLONEDX_DEFAULT

        # Get the directory containing the lock file - we'll cd into it
        lock_file_path = Path(input.lock_file)
        lock_file_directory = lock_file_path.parent.resolve()

        # Convert output file to absolute path since we're changing cwd
        output_file_abs = str(Path(input.output_file).resolve())

        # Detect ecosystem and map to cdxgen type
        lock_file_name = input.lock_file_name
        assert lock_file_name is not None  # guaranteed by supports()
        ecosystem = get_lock_file_ecosystem(lock_file_name)
        cdxgen_type = CDXGEN_TYPE_MAP.get(ecosystem) if ecosystem else None

        # Install Java/Maven on-demand for Java/Scala ecosystems
        if ecosystem in ("java", "scala"):
            ensure_java_maven_installed()

        # Install Go on-demand for Go ecosystem
        if ecosystem == "go":
            ensure_go_installed()

        cmd = [
            "cdxgen",
            "-o",
            output_file_abs,
            "--spec-version",
            version,
        ]

        # Add type flag to restrict to detected ecosystem
        if cdxgen_type:
            cmd.extend(["-t", cdxgen_type])

        # For ecosystems with parent/child structures (Maven, Gradle), allow recursion
        # The -t flag will still restrict scanning to only that ecosystem
        # For other ecosystems, disable recursion to avoid scanning unrelated subdirectories
        if ecosystem not in RECURSE_ECOSYSTEMS:
            cmd.append("--no-recurse")

        # Exclude dev dependencies and local workspace packages across all ecosystems
        # This filters out development-only dependencies, keeping only production dependencies
        # For JavaScript, this also excludes local packages with path-based versions
        cmd.append("--required-only")

        # Fail on error to ensure we catch issues early
        cmd.append("--fail-on-error")

        # Scan current directory (we'll cd into lock file directory)
        cmd.append(".")

        logger.info(f"Running cdxgen for {input.lock_file_name} (CycloneDX {version}, type={cdxgen_type or 'auto'})")

        try:
            # run_command raises SBOMGenerationError on failure (uses check=True)
            run_command(cmd, "cdxgen", timeout=DEFAULT_TIMEOUT, cwd=str(lock_file_directory))

            # Verify output file was created
            if not Path(output_file_abs).exists():
                return GenerationResult.failure_result(
                    error_message="cdxgen completed but output file not created",
                    sbom_format="cyclonedx",
                    spec_version=version,
                    generator_name=self.name,
                )

            return GenerationResult.success_result(
                output_file=output_file_abs,
                sbom_format="cyclonedx",
                spec_version=version,
                generator_name=self.name,
            )
        except SBOMGenerationError as e:
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format="cyclonedx",
                spec_version=input.spec_version or CDXGEN_CYCLONEDX_DEFAULT,
                generator_name=self.name,
            )


class CdxgenImageGenerator:
    """
    cdxgen Docker image scanner.

    Uses cdxgen to scan Docker images and generate SBOMs.

    Verified capabilities (cdxgen 12.0.0):
    - CycloneDX versions: 1.4, 1.5, 1.6, 1.7 (default: 1.6)
    - SPDX: Not supported
    - Version selection: --spec-version
    - Image scanning: -t oci
    """

    @property
    def name(self) -> str:
        return "cdxgen-image"

    @property
    def command(self) -> str:
        return "cdxgen"

    @property
    def priority(self) -> int:
        # Comprehensive multi-ecosystem, higher priority than Trivy/Syft
        return 20

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(
                format="cyclonedx",
                versions=CDXGEN_CYCLONEDX_VERSIONS,
                default_version=CDXGEN_CYCLONEDX_DEFAULT,
            ),
        ]

    def supports(self, input: GenerationInput) -> bool:
        """
        Check if this generator supports the given input.

        Supports Docker images for CycloneDX format only.
        Does not support SPDX or lock files (use CdxgenFsGenerator).
        """
        # Check if cdxgen is installed
        if not _CDXGEN_AVAILABLE:
            return False

        # Only supports Docker images
        if not input.is_docker_image:
            return False

        # Only supports CycloneDX format (cdxgen doesn't output SPDX)
        if input.output_format != "cyclonedx":
            return False

        # Check version if specified
        if input.spec_version:
            if input.spec_version not in CDXGEN_CYCLONEDX_VERSIONS:
                return False

        return True

    def generate(self, input: GenerationInput) -> GenerationResult:
        """Generate an SBOM using cdxgen command for Docker images."""
        assert input.docker_image is not None  # guaranteed by supports()
        version = input.spec_version or CDXGEN_CYCLONEDX_DEFAULT

        cmd = [
            "cdxgen",
            "-t",
            "oci",
            "-o",
            input.output_file,
            "--spec-version",
            version,
            "--required-only",
            "--fail-on-error",
            input.docker_image,
        ]

        logger.info(f"Running cdxgen for {input.docker_image} (CycloneDX {version})")

        try:
            # run_command raises SBOMGenerationError on failure (uses check=True)
            run_command(cmd, "cdxgen", timeout=DEFAULT_TIMEOUT, docker_image=input.docker_image)

            # Verify output file was created
            if not Path(input.output_file).exists():
                return GenerationResult.failure_result(
                    error_message="cdxgen completed but output file not created",
                    sbom_format="cyclonedx",
                    spec_version=version,
                    generator_name=self.name,
                )

            return GenerationResult.success_result(
                output_file=input.output_file,
                sbom_format="cyclonedx",
                spec_version=version,
                generator_name=self.name,
            )
        except DockerImageNotFoundError as e:
            # Provide a clear error message for missing Docker images
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format="cyclonedx",
                spec_version=version,
                generator_name=self.name,
            )
        except SBOMGenerationError as e:
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format="cyclonedx",
                spec_version=input.spec_version or CDXGEN_CYCLONEDX_DEFAULT,
                generator_name=self.name,
            )
