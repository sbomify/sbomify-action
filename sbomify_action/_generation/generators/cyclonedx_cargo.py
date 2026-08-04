"""CycloneDX Cargo generator plugin for Rust projects.

This is the native/authoritative generator for Rust/Cargo packages.
Priority: 10 (native)

Supported inputs:
- Cargo.lock

Supported outputs:
- CycloneDX 1.3-1.5 (via --spec-version; the tool does not emit 1.6)
"""

import shutil
from pathlib import Path

from sbomify_action.exceptions import SBOMGenerationError
from sbomify_action.logging_config import logger
from sbomify_action.runtimes import can_provide, ensure_runtime
from sbomify_action.tool_checks import check_tool_available

from ..protocol import (
    CARGO_CYCLONEDX_DEFAULT,
    CARGO_CYCLONEDX_VERSIONS,
    FormatVersion,
    GenerationInput,
)
from ..result import GenerationResult
from ..utils import has_required_manifest, run_command

# Check tool availability once at module load (mirrors cyclonedx_py / syft).
# Without this guard, supports() would claim a Cargo.lock and then fail at
# generate() time when cargo-cyclonedx isn't installed (eg pip installs that
# don't bundle it) — a spurious ERROR + wasted attempt before the orchestrator
# falls through to a generic generator.
# PATH first, so a pip install keeps the user's own binary; otherwise it is
# available only where we can fetch it. It is a cargo subcommand, so it is
# useless without the Rust toolchain, which generate() also fetches.
_CARGO_CYCLONEDX_AVAILABLE, _CARGO_CYCLONEDX_PATH = check_tool_available("cargo-cyclonedx")
if not _CARGO_CYCLONEDX_AVAILABLE:
    _CARGO_CYCLONEDX_AVAILABLE = can_provide("cargo-cyclonedx")


class CycloneDXCargoGenerator:
    """
    Native CycloneDX generator for Rust Cargo projects.

    Uses cargo-cyclonedx to generate CycloneDX SBOMs from Cargo.lock
    files. This is the authoritative generator for Rust packages
    and should be preferred over generic tools.

    Verified capabilities (cargo-cyclonedx 0.5.7):
    - CycloneDX versions: 1.3, 1.4, 1.5
    - Default version: 1.5
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
        # Check if cargo-cyclonedx is installed
        if not _CARGO_CYCLONEDX_AVAILABLE:
            return False

        # Only supports lock files, not Docker images
        if not input.is_lock_file:
            return False

        # Only supports CycloneDX format
        if input.output_format != "cyclonedx":
            return False

        # Only supports Cargo.lock
        if input.lock_file_name != "Cargo.lock":
            return False

        # ...and only alongside a Cargo.toml. cargo-cyclonedx drives
        # `cargo metadata`, which needs the manifest, not just the lock.
        if not has_required_manifest(input.lock_file):
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

        # cargo-cyclonedx has no --output-file: it always writes into the project
        # tree, naming the file after the crate. --override-filename sets the stem
        # and --format supplies the extension, so we write to a scratch name and
        # move it to the caller's path afterwards. The dot prefix avoids colliding
        # with a real "<crate>.json" in the repo.
        #
        # For a workspace it writes one file per member crate, in each member's
        # own directory, and nothing at the root -- so collect recursively rather
        # than assuming a single file next to Cargo.lock.
        scratch_stem = ".sbomify-cargo-cyclonedx"

        cmd = [
            "cargo-cyclonedx",
            "cyclonedx",
            "--spec-version",
            spec_version,
            "--format",
            "json",
            "--override-filename",
            scratch_stem,
        ]

        # cargo-cyclonedx is a cargo subcommand: it shells out to `cargo
        # metadata` for the dependency graph and to `rustc` for the host target
        # triple, and fails without either. The toolchain is fetched rather
        # than baked in -- ~630MB to support a 7MB subcommand -- and fetched
        # unconditionally rather than "only if cargo is missing", because
        # preferring whatever cargo is on PATH would run one toolchain while
        # the SBOM names the pinned one.
        ensure_runtime("cargo-cyclonedx")
        ensure_runtime("rust")

        logger.info(f"Running cargo-cyclonedx for {input.lock_file_name} (CycloneDX {spec_version})")

        produced: list[Path] = []
        try:
            # run_command raises SBOMGenerationError on failure (uses check=True)
            run_command(cmd, "cargo-cyclonedx", timeout=300, cwd=str(project_dir))

            produced = sorted(project_dir.rglob(f"{scratch_stem}.json"))

            if not produced:
                return GenerationResult.failure_result(
                    error_message="cargo-cyclonedx completed but output file not created",
                    sbom_format="cyclonedx",
                    spec_version=spec_version,
                    generator_name=self.name,
                )

            if len(produced) > 1:
                # A cargo workspace: one SBOM per member crate, and merging them
                # is not this generator's job. Decline -- explicitly, so the
                # orchestrator hands the input on instead of treating a routing
                # decision as a defect and aborting the run.
                return GenerationResult.declined_result(
                    error_message=(
                        f"cargo-cyclonedx produced {len(produced)} SBOMs "
                        "(cargo workspace with multiple member crates); "
                        "falling back to a generator that emits one document"
                    ),
                    sbom_format="cyclonedx",
                    spec_version=spec_version,
                    generator_name=self.name,
                )

            Path(output_file_abs).parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(produced[0]), output_file_abs)
        finally:
            # Never leave scratch files behind in someone's repo -- including the
            # per-crate ones a workspace scatters, and including when generation
            # failed partway through.
            for leftover in project_dir.rglob(f"{scratch_stem}.json"):
                leftover.unlink(missing_ok=True)

        return GenerationResult.success_result(
            output_file=output_file_abs,
            sbom_format="cyclonedx",
            spec_version=spec_version,
            generator_name=self.name,
        )
