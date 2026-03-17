"""CycloneDX Cargo generator plugin for Rust projects.

This is the native/authoritative generator for Rust/Cargo packages.
Priority: 10 (native)

Supported inputs:
- Cargo.lock

Supported outputs:
- CycloneDX 1.4-1.6 (via --spec-version)
"""

from pathlib import Path

from sbomify_action.exceptions import SBOMGenerationError
from sbomify_action.logging_config import logger

from ..protocol import (
    CARGO_CYCLONEDX_DEFAULT,
    CARGO_CYCLONEDX_VERSIONS,
    FormatVersion,
    GenerationInput,
)
from ..result import GenerationResult
from ..utils import run_command


class CycloneDXCargoGenerator:
    """
    Native CycloneDX generator for Rust Cargo projects.

    Uses cargo-cyclonedx to generate CycloneDX SBOMs from Cargo.lock
    files. This is the authoritative generator for Rust packages
    and should be preferred over generic tools.

    Verified capabilities (cargo-cyclonedx 0.5.7):
    - CycloneDX versions: 1.4, 1.5, 1.6
    - Default version: 1.6
    - Version selection: --spec-version flag
    """

    @property
    def name(self) -> str:
        return "cyclonedx-cargo"

    @property
    def command(self) -> str:
        return "cargo-cyclonedx"

    @property
    def priority(self) -> int:
        # Native/authoritative for Rust
        return 10

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(
                format="cyclonedx",
                versions=CARGO_CYCLONEDX_VERSIONS,
                default_version=CARGO_CYCLONEDX_DEFAULT,
            )
        ]

    def supports(self, input: GenerationInput) -> bool:
        """
        Check if this generator supports the given input.

        Supports Cargo.lock files when requesting CycloneDX format.
        Does not support Docker images or SPDX format.
        """
        # Only supports lock files, not Docker images
        if not input.is_lock_file:
            return False

        # Only supports CycloneDX format
        if input.output_format != "cyclonedx":
            return False

        # Only supports Cargo.lock
        if input.lock_file_name != "Cargo.lock":
            return False

        # Check version if specified
        if input.spec_version:
            if input.spec_version not in CARGO_CYCLONEDX_VERSIONS:
                return False

        return True

    def generate(self, input: GenerationInput) -> GenerationResult:
        """Generate a CycloneDX SBOM using cargo-cyclonedx."""
        spec_version = input.spec_version or CARGO_CYCLONEDX_DEFAULT

        # Validate version
        if spec_version not in CARGO_CYCLONEDX_VERSIONS:
            return GenerationResult.failure_result(
                error_message=f"Unsupported CycloneDX version: {spec_version}. "
                f"Supported: {', '.join(CARGO_CYCLONEDX_VERSIONS)}",
                sbom_format="cyclonedx",
                spec_version=spec_version,
                generator_name=self.name,
            )

        # Exception handling at this level (wrapping _generate) rather than inline
        # in _generate, since this generator has a single execution path.
        try:
            return self._generate(input, spec_version)
        except SBOMGenerationError as e:
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format="cyclonedx",
                spec_version=spec_version,
                generator_name=self.name,
            )

    def _generate(self, input: GenerationInput, spec_version: str) -> GenerationResult:
        """Generate SBOM for Cargo.lock."""
        # cargo-cyclonedx needs to run from the project directory containing Cargo.lock
        assert input.lock_file is not None  # guaranteed by supports()
        lock_file_path = Path(input.lock_file)
        project_dir = lock_file_path.parent.resolve()

        # Convert output file to absolute path since we're changing cwd
        output_file_abs = str(Path(input.output_file).resolve())

        cmd = [
            "cargo-cyclonedx",
            "cyclonedx",
            "--spec-version",
            spec_version,
            "--format",
            "json",
            "--output-file",
            output_file_abs,
        ]

        logger.info(f"Running cargo-cyclonedx for {input.lock_file_name} (CycloneDX {spec_version})")

        # run_command raises SBOMGenerationError on failure (uses check=True)
        run_command(cmd, "cargo-cyclonedx", timeout=300, cwd=str(project_dir))

        # Verify output file was created
        if not Path(output_file_abs).exists():
            return GenerationResult.failure_result(
                error_message="cargo-cyclonedx completed but output file not created",
                sbom_format="cyclonedx",
                spec_version=spec_version,
                generator_name=self.name,
            )

        return GenerationResult.success_result(
            output_file=output_file_abs,
            sbom_format="cyclonedx",
            spec_version=spec_version,
            generator_name=self.name,
        )
