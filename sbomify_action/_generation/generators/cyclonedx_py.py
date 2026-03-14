"""CycloneDX Python generator plugin.

This is the native/authoritative generator for Python packages.
Priority: 10 (native)

Supported inputs:
- requirements.txt
- poetry.lock / pyproject.toml
- Pipfile.lock

Supported outputs:
- CycloneDX 1.0-1.7 (via --spec-version)
"""

from pathlib import Path

from sbomify_action.exceptions import SBOMGenerationError
from sbomify_action.logging_config import logger
from sbomify_action.tool_checks import check_tool_available

from ..protocol import (
    CYCLONEDX_PY_DEFAULT,
    CYCLONEDX_PY_VERSIONS,
    FormatVersion,
    GenerationInput,
)
from ..result import GenerationResult
from ..utils import run_command

# Check tool availability once at module load
_CYCLONEDX_PY_AVAILABLE, _CYCLONEDX_PY_PATH = check_tool_available("cyclonedx-py")


class CycloneDXPyGenerator:
    """
    Native CycloneDX generator for Python lock files.

    Uses cyclonedx-py to generate CycloneDX SBOMs from Python
    dependency files. This is the authoritative generator for
    Python packages and should be preferred over generic tools.

    Verified capabilities (cyclonedx-py 7.2.1):
    - CycloneDX versions: 1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7
    - Default version: 1.6
    - Version selection: --spec-version flag
    """

    # Mapping of lock file to cyclonedx-py subcommand
    LOCK_FILE_COMMANDS = {
        "requirements.txt": "requirements",
        "poetry.lock": "poetry",
        "pyproject.toml": "poetry",
        "Pipfile.lock": "pipenv",
    }

    @property
    def name(self) -> str:
        return "cyclonedx-py"

    @property
    def command(self) -> str:
        return "cyclonedx-py"

    @property
    def priority(self) -> int:
        # Native/authoritative for Python
        return 10

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(
                format="cyclonedx",
                versions=CYCLONEDX_PY_VERSIONS,
                default_version=CYCLONEDX_PY_DEFAULT,
            )
        ]

    def supports(self, input: GenerationInput) -> bool:
        """
        Check if this generator supports the given input.

        Supports Python lock files when requesting CycloneDX format.
        Does not support Docker images or SPDX format.
        """
        # Check if cyclonedx-py is installed
        if not _CYCLONEDX_PY_AVAILABLE:
            return False

        # Only supports lock files, not Docker images
        if not input.is_lock_file:
            return False

        # Only supports CycloneDX format
        if input.output_format != "cyclonedx":
            return False

        # Check if lock file is a supported Python lock file
        lock_file_name = input.lock_file_name
        if lock_file_name not in self.LOCK_FILE_COMMANDS:
            return False

        # uv.lock is a Python file but not supported by cyclonedx-py
        if lock_file_name == "uv.lock":
            return False

        return True

    def generate(self, input: GenerationInput) -> GenerationResult:
        """Generate a CycloneDX SBOM using cyclonedx-py."""
        assert input.lock_file is not None  # guaranteed by supports()
        lock_file_name = input.lock_file_name
        assert lock_file_name is not None  # guaranteed by lock_file being set
        spec_version = input.spec_version or CYCLONEDX_PY_DEFAULT

        # Validate version
        if spec_version not in CYCLONEDX_PY_VERSIONS:
            return GenerationResult.failure_result(
                error_message=f"Unsupported CycloneDX version: {spec_version}. "
                f"Supported: {', '.join(CYCLONEDX_PY_VERSIONS)}",
                sbom_format="cyclonedx",
                spec_version=spec_version,
                generator_name=self.name,
            )

        # Get the appropriate subcommand
        subcommand = self.LOCK_FILE_COMMANDS.get(lock_file_name)
        if not subcommand:
            return GenerationResult.failure_result(
                error_message=f"Unsupported lock file: {lock_file_name}",
                sbom_format="cyclonedx",
                spec_version=spec_version,
                generator_name=self.name,
            )

        if subcommand == "poetry":
            # Poetry needs the directory, not the file
            return self._generate_poetry(input, spec_version)
        else:
            return self._generate_standard(input, subcommand, spec_version)

    def _generate_standard(self, input: GenerationInput, subcommand: str, spec_version: str) -> GenerationResult:
        """Generate SBOM for requirements.txt or Pipfile.lock."""
        assert input.lock_file is not None  # guaranteed by caller
        cmd = [
            "cyclonedx-py",
            subcommand,
            input.lock_file,
            "--spec-version",
            spec_version,
            "--output-file",
            input.output_file,
            "--mc-type",
            "application",
            "--validate",
            "--output-reproducible",
            "--output-format",
            "JSON",
        ]

        logger.info(f"Running cyclonedx-py {subcommand} for {input.lock_file_name}")

        try:
            # run_command raises SBOMGenerationError on failure (uses check=True)
            run_command(cmd, "cyclonedx-py", timeout=300)

            return GenerationResult.success_result(
                output_file=input.output_file,
                sbom_format="cyclonedx",
                spec_version=spec_version,
                generator_name=self.name,
            )
        except SBOMGenerationError as e:
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format="cyclonedx",
                spec_version=spec_version,
                generator_name=self.name,
            )

    def _generate_poetry(self, input: GenerationInput, spec_version: str) -> GenerationResult:
        """Generate SBOM for poetry.lock / pyproject.toml."""
        # Poetry needs the project directory
        assert input.lock_file is not None  # guaranteed by caller
        project_dir = str(Path(input.lock_file).parent)
        logger.info(f"Using Poetry project directory: {project_dir}")

        cmd = [
            "cyclonedx-py",
            "poetry",
            project_dir,
            "--spec-version",
            spec_version,
            "--output-file",
            input.output_file,
            "--mc-type",
            "application",
            "--validate",
            "--output-reproducible",
            "--output-format",
            "JSON",
            "--no-dev",  # Exclude dev dependencies for Poetry
        ]

        logger.info(f"Running cyclonedx-py poetry for {input.lock_file_name}")

        try:
            # run_command raises SBOMGenerationError on failure (uses check=True)
            run_command(cmd, "cyclonedx-py", timeout=300)

            return GenerationResult.success_result(
                output_file=input.output_file,
                sbom_format="cyclonedx",
                spec_version=spec_version,
                generator_name=self.name,
            )
        except SBOMGenerationError as e:
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format="cyclonedx",
                spec_version=spec_version,
                generator_name=self.name,
            )
