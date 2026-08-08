"""Syft generator plugins for filesystem and Docker image scanning.

Priority: 35 (generic multi-ecosystem, lower than Trivy)

Syft is a comprehensive SBOM generator that supports version selection.
It supports more versions than Trivy but is slightly lower priority.

Verified capabilities (Syft 1.38.2):
- CycloneDX versions: 1.2, 1.3, 1.4, 1.5, 1.6 (default: 1.6)
- SPDX versions: 2.2, 2.3 (default: 2.3)
- Version selection: -o format@version=file
"""

import os
from pathlib import Path

from sbomify_action import format_display_name
from sbomify_action.exceptions import DockerImageNotFoundError, SBOMGenerationError
from sbomify_action.logging_config import logger
from sbomify_action.runtimes import can_provide, ensure_runtime
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

# Whatever is already on PATH wins, so a pip install keeps using the syft
# the user installed. Failing that, syft is available if we can fetch it,
# which is now the default everywhere rather than only inside our own image --
# see runtimes.fetching_is_enabled, and SBOMIFY_FETCH_RUNTIMES=0 to opt out.
# The fetch itself happens in generate(), where a failure can be reported
# rather than silently dropping the generator from the chain.
_SYFT_PATH: str | None
_SYFT_AVAILABLE, _SYFT_PATH = check_tool_available("syft")
if not _SYFT_AVAILABLE:
    _SYFT_AVAILABLE = can_provide("syft")


def _swift_manifest_without_resolved(input: GenerationInput) -> GenerationResult | None:
    """Refuse Package.swift when the resolved file it needs is not there.

    Syft is the only generator that claims Package.swift -- cdxgen
    deliberately excludes SwiftPM, and no Swift toolchain ships in the image
    -- and syft cannot resolve a manifest. Measured across nine Swift
    projects, every single one produced an SBOM with zero components:
    swift-nio, swift-collections, swift-package-manager, swift-log,
    swift-argument-parser, SwiftyJSON and three more. Pointed at the
    Package.resolved beside it, the same tool works.

    promote_to_lockfile already redirects to Package.resolved when one is
    committed, so reaching here means it is genuinely absent. Rather than
    write an empty document, say what is missing and how to produce it --
    `swift package resolve` writes the file, and it is meant to be committed.

    Declining rather than failing keeps this a routing decision, so anything
    added to the chain later still gets its turn.
    """
    if input.is_source_dir or not input.lock_file:
        return None
    if os.path.basename(input.lock_file) != "Package.swift":
        return None
    if os.path.isfile(os.path.join(os.path.dirname(input.lock_file), "Package.resolved")):
        return None
    return GenerationResult.declined_result(
        error_message=(
            "Package.swift declares version ranges; SwiftPM resolves them into "
            "Package.resolved, which is what an SBOM can be built from. No "
            "Package.resolved was found beside it -- run `swift package resolve` "
            "and commit the result, then point LOCK_FILE at it."
        ),
        sbom_format=input.output_format or "cyclonedx",
        spec_version=input.spec_version or "",
        generator_name="syft-fs",
    )


#: Syft's file catalogers, which describe every file in the subject rather
#: than the software in it. Turned off on every scan, whatever the output
#: format -- what changes with the format is how much it matters, not whether
#: the flag is passed. CycloneDX is where they dominate: eclipse-temurin:21-jre
#: came out as 7,003 components of which 6,847 were `type: file` entries
#: carrying a path and nothing else -- no purl, no version, no licence, because
#: a file is not a package. They cannot be enriched or matched to an advisory,
#: and they bury the 156 packages that can.
#:
#: Verified to remove only noise. Scanning with and without, the package set
#: is identical -- alpine:3 goes from 96 components to 17 with the same 17
#: packages, redis:8-alpine from 454 to 24 with the same 24 -- so nothing a
#: consumer can act on is lost.
#:
#: SPDX output is where it makes no difference, which is why the flag is
#: unconditional rather than format-dependent: its file entries come from
#: package file ownership rather than from these catalogers, and the same scan
#: reports 17 packages and 79 files either way. One code path, no format to
#: special-case.
_NO_FILE_CATALOGERS = ["--select-catalogers", "-file"]


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

        # A directory is syft's own subject and needs no lock file to be
        # named. It is a different claim from a lock file -- what is on disk
        # rather than what an ecosystem resolved -- so it arrives as its own
        # input rather than as a lock_file that happens to be a directory.
        if input.is_source_dir:
            return input.output_format in ("cyclonedx", "spdx") and not (
                input.spec_version
                and input.spec_version
                not in (SYFT_SPDX_VERSIONS if input.output_format == "spdx" else SYFT_CYCLONEDX_VERSIONS)
            )

        subject = input.lock_file
        if not input.is_lock_file or subject is None:
            return False

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
        assert input.lock_file is not None or input.source_dir is not None  # guaranteed by supports()

        if declined := _swift_manifest_without_resolved(input):
            return declined

        ensure_runtime("syft")
        # Determine format string and version
        if input.output_format == "cyclonedx":
            version = input.spec_version or SYFT_CYCLONEDX_DEFAULT
            format_str = "cyclonedx-json"
        else:  # spdx
            version = input.spec_version or SYFT_SPDX_DEFAULT
            format_str = "spdx-json"

        # Syft output format: -o format@version=file
        output_spec = f"{format_str}@{version}={input.output_file}"

        # dir: is explicit rather than inferred. Syft guesses the source type
        # from the string, and a directory name that happens to look like an
        # image reference is read as one -- which is how bun.lock ended up
        # being handed to a container registry.
        subject = f"dir:{input.source_dir}" if input.is_source_dir else str(input.lock_file)
        cmd = [
            "syft",
            "scan",
            subject,
            "-o",
            output_spec,
            "--source-name",
            input.lock_file_name or "unknown",
            *_NO_FILE_CATALOGERS,
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
        ensure_runtime("syft")
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
            *_NO_FILE_CATALOGERS,
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
