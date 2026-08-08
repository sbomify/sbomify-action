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

import re
import tomllib
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

#: Build backends that mean "cyclonedx-py poetry can read this project".
#: `poetry.core.masonry.api` is current; `poetry.masonry.api` is the older
#: spelling still found in the wild.
_POETRY_BACKENDS = ("poetry.core.masonry.api", "poetry.masonry.api")

#: Distributions in `[build-system] requires` that mean the same thing, for
#: projects that pin the backend package without naming `build-backend`.
_POETRY_REQUIREMENTS = ("poetry-core", "poetry_core", "poetry")


def _is_poetry_project(pyproject: Path) -> bool:
    """Whether `cyclonedx-py poetry` can read this project.

    pyproject.toml is a *manifest*: it declares dependency ranges. It is not
    a lock file and does not pin anything, which is why `LOCK_FILE_COMMANDS`
    keying off the filename was the wrong question to ask of it. The
    `poetry` subcommand does not read the manifest either -- it reads the
    `poetry.lock` beside it -- so the real question is whether this project
    is one that *has* such a lock file. Only a Poetry project does.

    Everything else -- setuptools, hatchling, flit, pdm, maturin, meson --
    has to go elsewhere, so the question is worth answering from the file's
    contents rather than assuming from its name.

    Three signals, any of which is enough:

      * `[build-system] build-backend` names a Poetry backend;
      * `[build-system] requires` pins poetry-core, for projects that leave
        build-backend implicit;
      * `[tool.poetry]` exists at all, which predates PEP 517 metadata and
        is still how plenty of Poetry projects are written.

    An unreadable or malformed file answers False. The caller then hands the
    input to a generator that parses manifests generically, which is a
    better outcome than running Poetry against a file we could not parse.
    """
    try:
        with open(pyproject, "rb") as handle:
            data = tomllib.load(handle)
    except Exception:  # noqa: BLE001 - routing must not raise
        return False
    if not isinstance(data, dict):
        return False

    if isinstance(data.get("tool"), dict) and "poetry" in data["tool"]:
        return True

    build_system = data.get("build-system")
    if not isinstance(build_system, dict):
        return False

    backend = build_system.get("build-backend")
    if isinstance(backend, str) and backend.strip() in _POETRY_BACKENDS:
        return True

    requires = build_system.get("requires")
    if isinstance(requires, list):
        for requirement in requires:
            if not isinstance(requirement, str):
                continue
            # "poetry-core>=1.0.0" -> "poetry-core". Split on the first
            # character that cannot appear in a distribution name.
            distribution = re.split(r"[^A-Za-z0-9._-]", requirement.strip(), maxsplit=1)[0]
            if distribution.lower() in _POETRY_REQUIREMENTS:
                return True
    return False


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

        if lock_file_name == "pyproject.toml" and not _is_poetry_project(Path(input.lock_file)):
            # By this point promote_to_lockfile has already looked for a lock
            # file beside the manifest and found none, so what is left really
            # is just the manifest. cyclonedx-py has four subcommands --
            # environment, requirements, pipenv, poetry -- and every one of
            # them reads a lock file or an installed environment. None reads a
            # PEP 621 manifest.
            #
            # Claiming it anyway is what used to happen, and in the container a
            # generator that claims an input and fails is fatal, so
            # setuptools/hatchling/flit/pdm projects produced no SBOM at all:
            # 13 of 25 popular Python repositories, django and numpy and pandas
            # among them. Declining hands the manifest to a generator that can
            # parse one.
            return GenerationResult.declined_result(
                error_message=(
                    "pyproject.toml is a manifest, not a lock file, and this project does not "
                    "use Poetry -- no cyclonedx-py subcommand reads a PEP 621 manifest, so "
                    "handing on to a generator that does"
                ),
                sbom_format="cyclonedx",
                spec_version=spec_version,
                generator_name=self.name,
            )

        if subcommand == "poetry":
            # Poetry needs the directory, not the file
            return self._generate_poetry(input, spec_version)
        else:
            return self._generate_standard(input, subcommand, spec_version)

    #: Subcommands that take the project directory rather than the lock file.
    #: `cyclonedx-py requirements` wants the file; `pipenv` wants the directory
    #: and appends the filename itself, so handing it the file produced
    #: "Could not open lock file: .../Pipfile.lock/Pipfile.lock" on every run.
    #: It failed silently for as long as the orchestrator fell back to syft.
    DIRECTORY_SUBCOMMANDS = {"pipenv"}

    def _generate_standard(self, input: GenerationInput, subcommand: str, spec_version: str) -> GenerationResult:
        """Generate SBOM for requirements.txt or Pipfile.lock."""
        assert input.lock_file is not None  # guaranteed by caller
        target = str(Path(input.lock_file).parent) if subcommand in self.DIRECTORY_SUBCOMMANDS else input.lock_file
        cmd = [
            "cyclonedx-py",
            subcommand,
            target,
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
