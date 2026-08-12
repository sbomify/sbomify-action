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
from sbomify_action.runtimes import can_provide, ensure_runtime
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
    DOTNET_LOCK_FILES,
    DOTNET_PROJECT_SUFFIXES,
    composer_root_version,
    ensure_dotnet_installed,
    ensure_go_installed,
    ensure_java_maven_installed,
    ensure_php_installed,
    get_lock_file_ecosystem,
    has_required_manifest,
    resolve_npm_lockfile,
    run_command,
)

# cdxgen is no longer baked into the image, so a PATH probe at import time
# would answer "missing" and this generator would decline every input it is
# the best tool for. What matters now is whether it can be *made* available:
# it is a pinned runtime, so on a supported architecture it always can. The
# fetch itself happens in generate(), where a failure can be reported
# properly instead of silently removing the generator from the chain.
_CDXGEN_PATH: str | None
_CDXGEN_AVAILABLE, _CDXGEN_PATH = check_tool_available("cdxgen")
if not _CDXGEN_AVAILABLE:
    _CDXGEN_AVAILABLE = can_provide("cdxgen")

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
    "clojure": "clojure",
}

# Ecosystems that use parent/child project structures (e.g., Maven parent POMs, Gradle multi-project)
# For these, we allow recursion so cdxgen can follow module references
# The -t flag will still restrict scanning to only that ecosystem
# .NET belongs here too: project files sit at depth and the lock file often
# is not at the root -- Hangfire keeps its in .nuget/ -- so scanning only the
# top directory returns an empty document and exit code 0. Measured on the
# real repository, recursion takes it from 4 components to 306.
RECURSE_ECOSYSTEMS = {"java", "scala", "dotnet"}


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

        # Check if it's a supported lock file for cdxgen. .NET project files
        # are matched by extension: their names are the project's own, so
        # there is no fixed name to list. cdxgen reads the PackageReference
        # set out of one directly, without the SDK and without a lock file.
        name = input.lock_file_name or ""
        if name not in CDXGEN_LOCK_FILES and not name.endswith(DOTNET_PROJECT_SUFFIXES):
            return False

        # Some lock files need their project manifest beside them. Without
        # pubspec.yaml, cdxgen has no root component to hang the graph off and
        # dies with "Cannot read properties of undefined (reading 'bom-ref')".
        if not has_required_manifest(input.lock_file):
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

        # cdxgen is fetched rather than baked in: the bun runtime plus
        # node_modules was 619MB, which every user pulled whether or not they
        # had a project it could scan. The standalone binary is 35.6MB and
        # produces identical output.
        ensure_runtime("cdxgen")

        # Install Java/Maven on-demand for Java/Scala ecosystems
        if ecosystem in ("java", "scala"):
            ensure_java_maven_installed()

        # Install Go on-demand for Go ecosystem
        if ecosystem == "go":
            ensure_go_installed()

        # The .NET SDK, for the same reason: cdxgen invokes `dotnet` to read
        # packages.lock.json and fails without it.
        #
        # A project file is the exception, so the test is the file name and not
        # the ecosystem. cdxgen parses the PackageReference set straight out of
        # the XML, and measured on a three-package .csproj and the .sln naming
        # it, the SBOM is identical with the SDK absent from the image, from
        # the cache and from PATH. Fetching it anyway would cost a 289MB
        # download to reach the same three components -- and would make the
        # whole ecosystem unusable wherever no SDK build exists for the host.
        if lock_file_name in DOTNET_LOCK_FILES:
            ensure_dotnet_installed()

        # PHP, and the same distinction: the manifest needs resolving, the
        # lock file does not. cdxgen parses a committed composer.lock as data
        # and never shells out, but for a composer.json with no lock beside it
        # it stops with "No composer version found" -- and the chain then
        # hands the input to syft, which writes zero components and exits 0.
        #
        # That is the common case rather than the corner: PHP libraries
        # gitignore composer.lock, leaving the application to resolve it.
        #
        # Like the jvm bundle above, this one carries its own cdxgen, and
        # prepending its bin_dirs shadows the copy from [bundle.cdxgen]. That
        # is how the JVM path has always worked, and it is version-neutral:
        # both come from the same tools_release pin, and all three bundles
        # currently ship cdxgen 12.8.2 on Bun 1.3.14 -- checked, not assumed.
        # Composer resolves the manifest against Packagist, and to do that it
        # has to know what version *this* package is -- a project that depends
        # on its own version otherwise fails to resolve entirely. It normally
        # asks git, which refuses a workspace owned by another UID. See
        # composer_root_version() for what that costs and where the value
        # comes from instead.
        env: dict[str, str] | None = None
        if lock_file_name == "composer.json":
            ensure_php_installed()
            if root_version := composer_root_version():
                logger.info(f"Telling Composer this package is version {root_version}")
                env = {"COMPOSER_ROOT_VERSION": root_version}

        resolved_lockfile: Path | None = None

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
        # For JavaScript, this also excludes local packages with path-based versions.
        #
        # Skip for Go: cdxgen tags every `// indirect` line in go.mod as scope=optional,
        # but under Go 1.17+ module-graph pruning the indirect block IS the build closure
        # (those modules are compiled into the binary). --required-only would strip the
        # entire transitive closure along with the h1: hashes from go.sum. See issue #231.
        if ecosystem != "go":
            cmd.append("--required-only")

        # Fail on error to ensure we catch issues early
        cmd.append("--fail-on-error")

        # Scan current directory (we'll cd into lock file directory)
        cmd.append(".")

        logger.info(f"Running cdxgen for {input.lock_file_name} (CycloneDX {version}, type={cdxgen_type or 'auto'})")

        try:
            # Inside the try, because the finally below is what removes it. It
            # used to sit forty lines above, so anything raising in between --
            # building the command, fetching a runtime -- left a lock file we
            # created in someone else's checkout.
            if lock_file_name == "package.json":
                resolved_lockfile = resolve_npm_lockfile(lock_file_directory)

            # run_command raises SBOMGenerationError on failure (uses check=True).
            # log_errors=False: cdxgen is a priority-20 fallback that routinely
            # fails for ecosystems it doesn't handle (eg a Python uv.lock, where
            # cyclonedx-py/syft take over). Its failure is benign on the happy
            # path, so log it at DEBUG rather than spamming ERROR; the
            # orchestrator surfaces a real ERROR only if every generator fails.
            run_command(cmd, "cdxgen", timeout=DEFAULT_TIMEOUT, cwd=str(lock_file_directory), log_errors=False, env=env)

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
        finally:
            # A lock file we created is ours to remove. It is a working file,
            # not something the user asked for, and leaving it behind risks a
            # later step committing a resolution nobody chose.
            if resolved_lockfile is not None:
                resolved_lockfile.unlink(missing_ok=True)


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
        # Below syft (35), unlike the filesystem generator at 20.
        #
        # cdxgen is the better tool for lock files, but not for container
        # images. Measured across the 27 image pairs in tests/test-data:
        #
        #   total components   cdxgen 7389   syft 77795   (10.5x)
        #   per-image wins     syft 27       cdxgen 0
        #   gcr.io/distroless/static-debian12: cdxgen returns 0, syft 951
        #
        # Syft wins every image. Leaving cdxgen ahead meant every container
        # SBOM we produced was an order of magnitude thinner than it needed
        # to be, and nothing surfaced it: a short SBOM still looks like
        # success.
        return 40

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

        ensure_runtime("cdxgen")

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
            # run_command raises SBOMGenerationError on failure (uses check=True).
            # log_errors=False: cdxgen image scanning is a priority-20 fallback
            # ahead of syft; a benign failure here shouldn't spam ERROR when syft
            # can still succeed. (Docker-image-not-found is handled separately and
            # still logs at WARNING.)
            run_command(cmd, "cdxgen", timeout=DEFAULT_TIMEOUT, docker_image=input.docker_image, log_errors=False)

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
