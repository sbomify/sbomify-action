"""CycloneDX gomod generator plugin for Go modules.

The native/authoritative generator for Go, alongside cyclonedx-py for Python
and cyclonedx-cargo for Rust.
Priority: 10 (native)

Supported inputs:
- go.mod, with Go source beside it

Supported outputs:
- CycloneDX 1.4-1.6
"""

from pathlib import Path

from sbomify_action.exceptions import SBOMGenerationError
from sbomify_action.logging_config import logger
from sbomify_action.runtimes import ensure_runtime, fetching_is_enabled

from ..protocol import FormatVersion, GenerationInput
from ..result import GenerationResult
from ..utils import convert_to_spdx, run_command

#: Versions cyclonedx-gomod can emit via --spec-version.
GOMOD_CYCLONEDX_VERSIONS = ("1.4", "1.5", "1.6")
GOMOD_CYCLONEDX_DEFAULT = "1.6"

#: SPDX is converted from the CycloneDX above rather than scanned for. syft
#: reports more packages for hugo -- 185 against 157 -- but the extras are
#: actions/checkout and actions/setup-go, read out of .github/workflows and
#: not part of the shipped software. The resolver knows the build closure; a
#: scanner is guessing at it from files on disk.
GOMOD_SPDX_VERSIONS = ("SPDX-2.3",)
GOMOD_SPDX_DEFAULT = "SPDX-2.3"


def _has_go_source(lock_file: str | None) -> bool:
    """Whether there is Go source beside the module files.

    cyclonedx-gomod builds the module graph from real packages. Handed only
    go.mod and go.sum it does not degrade gracefully -- it panics:

        panic: runtime error: index out of range [0] with length 0

    Pointing the action at a bare pair of module files is legitimate, so this
    generator declines that case and syft takes it. Most repositories have
    source, which is where gomod is the better tool.
    """
    if not lock_file:
        return False
    project_dir = Path(lock_file).parent
    return any(project_dir.rglob("*.go"))


class CycloneDXGomodGenerator:
    """Native CycloneDX generator for Go modules.

    Reports the build closure rather than everything named in go.sum. On a
    realistic module that is 4 components with hashes against syft's 10, the
    extra six being test-only dependencies of dependencies, go.mod itself,
    and the main module. Over-reporting cannot be corrected downstream;
    the licences gomod omits are filled in by enrichment.
    """

    @property
    def name(self) -> str:
        return "cyclonedx-gomod"

    @property
    def command(self) -> str:
        return "cyclonedx-gomod"

    @property
    def priority(self) -> int:
        # Native/authoritative for Go.
        return 10

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(
                format="cyclonedx",
                versions=GOMOD_CYCLONEDX_VERSIONS,
                default_version=GOMOD_CYCLONEDX_DEFAULT,
            ),
            FormatVersion(
                format="spdx",
                versions=GOMOD_SPDX_VERSIONS,
                default_version=GOMOD_SPDX_DEFAULT,
            ),
        ]

    def supports(self, input: GenerationInput) -> bool:
        """Claim go.mod when there is source to analyse and we may fetch."""
        if not fetching_is_enabled():
            # Outside our image the user's toolchain decides; fetching a tool
            # they did not install would change which generator wins and so
            # change the SBOM they get.
            return False

        if not input.is_lock_file or input.output_format not in ("cyclonedx", "spdx"):
            return False

        if input.lock_file_name != "go.mod":
            return False

        if not _has_go_source(input.lock_file):
            return False

        allowed = GOMOD_SPDX_VERSIONS if input.output_format == "spdx" else GOMOD_CYCLONEDX_VERSIONS
        if input.spec_version and input.spec_version not in allowed:
            return False

        return True

    def generate(self, input: GenerationInput) -> GenerationResult:
        """Generate a CycloneDX SBOM using cyclonedx-gomod."""
        wants_spdx = input.output_format == "spdx"
        default = GOMOD_SPDX_DEFAULT if wants_spdx else GOMOD_CYCLONEDX_DEFAULT
        spec_version = input.spec_version or default
        assert input.lock_file is not None  # guaranteed by supports()

        project_dir = Path(input.lock_file).parent.resolve()
        output = Path(input.output_file).resolve()
        # gomod writes CycloneDX; SPDX is converted from it.
        produced = output.with_suffix(".cyclonedx.json") if wants_spdx else output
        output_file_abs = str(produced)

        try:
            ensure_runtime("cyclonedx-gomod")
            # It shells out to `go list`, so the toolchain has to be present.
            ensure_runtime("go")

            cmd = [
                "cyclonedx-gomod",
                "mod",
                "-json",
                "-output",
                output_file_abs,
                "-std",
                str(project_dir),
            ]
            logger.info(f"Running cyclonedx-gomod for {input.lock_file_name} (CycloneDX {spec_version})")
            run_command(cmd, "cyclonedx-gomod", timeout=600, cwd=str(project_dir))
            if wants_spdx:
                if not produced.exists():
                    raise SBOMGenerationError("cyclonedx-gomod produced no document to convert")
                convert_to_spdx(produced, output, project_dir)
                produced.unlink(missing_ok=True)
        except SBOMGenerationError as e:
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format=input.output_format,
                spec_version=spec_version,
                generator_name=self.name,
            )

        if not output.exists():
            return GenerationResult.failure_result(
                error_message="cyclonedx-gomod completed but wrote no output file",
                sbom_format=input.output_format,
                spec_version=spec_version,
                generator_name=self.name,
            )

        return GenerationResult.success_result(
            output_file=str(output),
            sbom_format=input.output_format,
            spec_version=spec_version,
            generator_name=self.name,
        )
