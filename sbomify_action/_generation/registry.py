"""Generator registry for managing SBOM generator plugins."""

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

from sbomify_action import format_display_name
from sbomify_action.exceptions import SBOMGenerationError, ToolNotAvailableError
from sbomify_action.logging_config import logger
from sbomify_action.serialization import (
    restore_spdx_document_describes,
    sanitize_cyclonedx_licenses,
    sanitize_spdx_json_file,
    sanitize_spdx_licenses,
)
from sbomify_action.tool_checks import check_tool_for_input, format_no_tools_error
from sbomify_action.validation import validate_sbom_file

from .protocol import FormatVersion, GenerationInput, Generator
from .result import GenerationResult

# Set in the Dockerfile. Inside our own image the toolset is fixed and known,
# so a generator that claims an input and then breaks is our bug, not the
# user's environment -- and silently substituting a lower-priority tool hides
# it. That is exactly how cyclonedx-cargo shipped broken: it asked for a spec
# version it does not support, failed on every Rust project, and syft quietly
# produced the SBOM instead.
_CONTAINER_MARKER_ENV = "SBOMIFY_IN_CONTAINER"

# Escape hatch for anyone who wants the old permissive behaviour in-container.
_ALLOW_FALLBACK_ENV = "SBOMIFY_ALLOW_GENERATOR_FALLBACK"


def fallback_is_a_bug() -> bool:
    """Whether falling back to a lower-priority generator should abort.

    True inside our own container image, where the installed tools are fixed
    and a failure is a defect we shipped. False for pip installs, where the
    surrounding environment is unknown and using whatever is present is the
    helpful thing to do.
    """
    if os.environ.get(_ALLOW_FALLBACK_ENV, "").lower() in ("1", "true", "yes"):
        return False
    if os.environ.get(_CONTAINER_MARKER_ENV, "").lower() in ("1", "true", "yes"):
        return True
    # Belt and braces for images built before the marker existed.
    return Path("/.dockerenv").exists()


#: A manifest and the lock file that supersedes it, when both are present.
#:
#: These names are all documented as supported, and they are -- but a manifest
#: declares ranges while its lock file pins versions, and several tools read
#: only the latter. Pointed at pyproject.toml, package.json, composer.json or
#: go.sum, syft emitted a one-package SPDX document: valid, exit code 0, and
#: empty of everything the caller wanted. Package.swift was worse, producing
#: nothing at all in CycloneDX while Package.resolved beside it worked.
#:
#: So when a caller names the manifest and the lock file is right there, the
#: lock file is what gets read. It is the same project either way, described
#: more precisely. Absent the sibling, nothing changes.
LOCKFILE_FOR_MANIFEST = {
    "pyproject.toml": ("poetry.lock", "uv.lock", "Pipfile.lock"),
    "package.json": ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"),
    "composer.json": ("composer.lock",),
    "Package.swift": ("Package.resolved",),
    # go.sum records hashes for the whole module graph but is not itself a
    # manifest; cyclonedx-gomod wants the go.mod beside it.
    "go.sum": ("go.mod",),
}


#: Inputs that constrain dependencies without resolving them.
#:
#: The distinction is the whole point: a lock file records the versions a
#: project committed to, and a manifest records the versions it would accept.
#: An SBOM built from the first is a statement about the project. An SBOM
#: built from the second is a statement about the day it was generated --
#: `^4.18.0` resolves to whatever the registry offers at that moment, which is
#: not what the project shipped and not what a consumer will install.
#:
#: `requirements.txt` sits awkwardly here and is included deliberately. It can
#: be fully pinned with `==`, or a list of bare names, or anything between, and
#: nothing in the file says which. Treating a pinned one as inferred overstates
#: the doubt slightly; treating an unpinned one as authoritative understates it
#: badly, and only one of those errors puts fiction in a provenance document.
UNRESOLVED_MANIFESTS = frozenset(
    {
        "pyproject.toml",
        "requirements.txt",
        "package.json",
        "composer.json",
        "Cargo.toml",
        "go.mod",
        "build.gradle",
        "build.gradle.kts",
        "pom.xml",
        "build.sbt",
        "deps.edn",
        "project.clj",
        "stack.yaml",
        "mix.exs",
        "Package.swift",
    }
)


#: What to actually do about it, per manifest.
#:
#: "The versions were inferred" on its own is a complaint, not advice: it tells
#: a reader their document is worse without telling them how to make it
#: better, and the answer is different in every ecosystem. Each entry is the
#: command that produces the missing lock file and the file to commit.
#:
#: The JVM entries are the honest exception. Maven and Gradle have no lock file
#: by convention, so there is nothing to commit and the advice is to generate
#: the SBOM from the build itself, where the resolved graph exists.
RECOMMENDED_ACTION = {
    "composer.json": ("composer update", "composer.lock"),
    "package.json": ("npm install  (or pnpm/yarn/bun install)", "the lock file it writes"),
    "pyproject.toml": ("uv lock  (or poetry lock)", "uv.lock or poetry.lock"),
    "requirements.txt": ("pip-compile requirements.in", "a requirements.txt with every version pinned by =="),
    "Cargo.toml": ("cargo generate-lockfile", "Cargo.lock"),
    "go.mod": ("go mod tidy", "go.sum"),
    "Package.swift": ("swift package resolve", "Package.resolved"),
    "mix.exs": ("mix deps.get", "mix.lock"),
    "stack.yaml": ("stack build --dry-run", "stack.yaml.lock"),
    "deps.edn": ("clojure -Stree", "a pinned deps.edn, or generate from the build"),
    "project.clj": ("lein deps :tree", "a pinned project.clj, or generate from the build"),
    "pom.xml": ("", "Maven has no lock file; run the CycloneDX Maven plugin in your build instead"),
    "build.gradle": (
        "",
        "Gradle has no lock file by default; enable dependency locking, or run the CycloneDX Gradle plugin in your build",
    ),
    "build.gradle.kts": (
        "",
        "Gradle has no lock file by default; enable dependency locking, or run the CycloneDX Gradle plugin in your build",
    ),
    "build.sbt": ("", "sbt has no lock file; generate from the build with sbt-sbom instead"),
}


def recommended_action(lock_file: str | None) -> tuple[str, str] | None:
    """The command that would make this document authoritative, and what to commit."""
    if not lock_file:
        return None
    return RECOMMENDED_ACTION.get(os.path.basename(lock_file))


def resolution_was_inferred(lock_file: str | None) -> bool:
    """Whether the versions in the document were resolved rather than recorded.

    True when the input is a manifest and no lock file sits beside it, which
    is exactly the case ``promote_to_lockfile`` could not improve on. The
    caller has to say so: the versions are a snapshot of one moment, and a
    reader who assumes otherwise is being misled by a document whose entire
    job is to be trustworthy about provenance.
    """
    if not lock_file:
        return False
    name = os.path.basename(lock_file)
    if name not in UNRESOLVED_MANIFESTS:
        return False
    directory = os.path.dirname(lock_file)
    return not any(
        os.path.isfile(os.path.join(directory, candidate)) for candidate in LOCKFILE_FOR_MANIFEST.get(name, ())
    )


def promote_to_lockfile(input: GenerationInput) -> GenerationInput:
    """Read the lock file when the caller named a manifest sitting beside one."""
    if not input.lock_file:
        return input
    # os.path rather than Path: tests substitute Path in this module to drive
    # the fallback paths, and a helper this small should not be entangled with
    # that. The operations are basename/dirname/isfile either way.
    name = os.path.basename(input.lock_file)
    for candidate in LOCKFILE_FOR_MANIFEST.get(name, ()):
        sibling = os.path.join(os.path.dirname(input.lock_file), candidate)
        if os.path.isfile(sibling):
            logger.info(f"Reading {candidate} rather than {name}: it pins what the manifest only constrains")
            return replace(input, lock_file=sibling)
    return input


def _describes_nothing(result: GenerationResult) -> bool:
    """True when a successful result contains no components at all.

    Exit status alone made this invisible. cyclonedx-maven pointed at a
    multi-module aggregator, or syft pointed at a manifest whose lock file
    is not committed, writes a schema-valid document holding its root
    component and nothing else, and returns 0. The run then reported
    success while describing none of the software it was asked about.

    Worse, it stopped the search: the registry returns on the first
    generator that exits 0, so an empty result kept a working generator
    from ever being tried. On apache/dubbo, cyclonedx-maven produced 0
    components and cdxgen -- next in line, never reached -- produces 763.

    Emptiness is treated as "keep looking", not as failure, because an
    empty SBOM is the correct answer for a project with no dependencies.
    The caller only falls back to it once nothing else has found anything.

    Anything unreadable, unparseable or otherwise surprising returns False.
    This only classifies a result that already succeeded, so it must never
    be the reason a run fails -- hence the bare ``Exception`` and the plain
    ``open`` rather than ``Path``, which callers monkeypatch in this module.
    """
    if not result.output_file:
        return False
    try:
        with open(result.output_file, encoding="utf-8") as handle:
            document = json.load(handle)
    except Exception:  # noqa: BLE001 - classification must not raise
        return False
    if not isinstance(document, dict):
        return False
    # CycloneDX counts `components`, SPDX `packages`. An SPDX document
    # always describes the root as a package, so one entry there is the
    # same emptiness as zero in CycloneDX.
    if "packages" in document:
        packages = document.get("packages")
        return isinstance(packages, list) and len(packages) <= 1
    components = document.get("components")
    return isinstance(components, list) and len(components) == 0


class _DowngradeRefused(SBOMGenerationError):
    """Raised by strict mode to abort rather than silently downgrade.

    A dedicated type so the retry loop can let *this* through while still
    letting a generator's own SBOMGenerationError take the normal fallback
    path. Catching the base class here would abort for pip users too, which
    is exactly the behaviour strict mode is not supposed to change.
    """


def _degraded_message(failed: str, remaining: list[str], error: str) -> str:
    """Explain a silent quality downgrade that we are refusing to perform."""
    return (
        f"Generator '{failed}' claimed this input and then failed: {error}\n"
        f"Falling back to {', '.join(remaining)} would silently produce a "
        f"lower-quality SBOM than the one that was asked for, so this is being "
        f"treated as a bug in the sbomify image rather than papered over.\n"
        f"Set {_ALLOW_FALLBACK_ENV}=1 to fall back anyway."
    )


class GeneratorRegistry:
    """
    Registry for managing and querying SBOM generator plugins.

    The registry maintains a list of generators and provides methods
    to find applicable generators for a given input, sorted by priority.

    Example:
        registry = GeneratorRegistry()
        registry.register(CycloneDXPyGenerator())
        registry.register(TrivyFsGenerator())
        registry.register(SyftFsGenerator())

        # Get generators for a Python requirements file
        input = GenerationInput(lock_file="requirements.txt", output_format="cyclonedx")
        generators = registry.get_generators_for(input)

        # Generate SBOM using first matching generator
        result = registry.generate(input)
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._generators: list[Generator] = []

    def register(self, generator: Generator) -> None:
        """
        Register a generator.

        Generators are stored and later sorted by priority when queried.

        Args:
            generator: Generator implementation to register
        """
        self._generators.append(generator)
        logger.debug(f"Registered generator: {generator.name} (priority={generator.priority})")

    def get_generators_for(self, input: GenerationInput) -> list[Generator]:
        """
        Get all applicable generators for an input, sorted by priority.

        Filters generators by:
        1. Input type support (lock file type, Docker image)
        2. Output format support
        3. Spec version support (if specified)

        Args:
            input: GenerationInput with file/image and format requirements

        Returns:
            List of Generator instances that support this input,
            sorted by priority (lowest/highest priority first)
        """
        applicable = []

        for generator in self._generators:
            # Check if generator supports this input type
            if not generator.supports(input):
                continue

            # Check if generator supports requested format
            format_match = self._supports_format(generator, input.output_format)
            if not format_match:
                continue

            # Check version support if specified
            if input.spec_version:
                if not self._supports_version(generator, input.output_format, input.spec_version):
                    logger.debug(
                        f"Generator {generator.name} doesn't support {input.output_format} version {input.spec_version}"
                    )
                    continue

            applicable.append(generator)

        # Sort by priority (lower = higher priority)
        return sorted(applicable, key=lambda g: g.priority)

    def generate(self, input: GenerationInput, validate: bool = True) -> GenerationResult:
        """
        Generate an SBOM using the first matching generator.

        Tries generators in priority order until one succeeds.
        Optionally validates the generated SBOM against its schema.

        Args:
            input: GenerationInput with all generation parameters
            validate: Whether to validate the generated SBOM (default: True)

        Returns:
            GenerationResult from the first successful generator

        Raises:
            ValueError: If no generator supports the input
        """
        input = promote_to_lockfile(input)
        generators = self.get_generators_for(input)

        if not generators:
            # Determine input type for error messages
            if input.is_docker_image:
                input_type = "docker_image"
            elif input.is_lock_file:
                input_type = "lock_file"
            else:
                # SBOM file input or other - these don't need generation tools
                raise SBOMGenerationError(
                    f"No generator found for input. "
                    f"Requested: format={input.output_format}, version={input.spec_version}."
                )

            # Check if this is due to missing tools
            lock_file = input.lock_file if input.is_lock_file else None
            available_tools, missing_tools = check_tool_for_input(input_type, lock_file)

            if missing_tools and not available_tools:
                # No tools available - provide installation instructions
                error_msg = format_no_tools_error(input_type, lock_file)
                raise ToolNotAvailableError(input_type, lock_file, error_msg)
            else:
                # Tools available but don't support this format/version
                available_formats = self._get_available_formats()
                raise SBOMGenerationError(
                    f"No generator found for input. "
                    f"Requested: format={input.output_format}, version={input.spec_version}. "
                    f"Available formats: {available_formats}"
                )

        # Try generators in priority order, collecting errors for better diagnostics
        generator_names = [g.name for g in generators]
        logger.info(f"Found {len(generators)} applicable generator(s): {', '.join(generator_names)}")

        errors: list[str] = []
        attempted_generators: list[str] = []
        strict = fallback_is_a_bug()
        # A generator that exits 0 having described nothing. Kept rather than
        # returned, because a project with no dependencies is entitled to an
        # empty SBOM -- but only used if nothing else does better. See
        # _describes_nothing.
        empty: GenerationResult | None = None
        empty_from: str | None = None
        for index, generator in enumerate(generators):
            logger.info(f"Trying generator: {generator.name}")
            attempted_generators.append(generator.name)
            try:
                result = generator.generate(input)
                if result.success and _describes_nothing(result):
                    # Always hand on, including from the last generator.
                    # Returning here instead would skip the block after the
                    # loop, which is the only thing that tells the caller the
                    # document is empty and where to look -- and would hand
                    # back whichever generator happened to be last rather than
                    # the first, highest-priority one recorded below.
                    if empty is None:
                        empty, empty_from = result, generator.name
                    errors.append(f"{generator.name}: produced an SBOM with no components")
                    if remaining := [g.name for g in generators[index + 1 :]]:
                        logger.warning(
                            f"Generator '{generator.name}' produced an SBOM with no components; "
                            f"trying {remaining[0]} to see if it can read this input"
                        )
                    continue
                if result.success:
                    logger.info(f"Successfully generated SBOM with {generator.name}")

                    # Validate the generated SBOM
                    if validate and result.output_file:
                        result = self._validate_result(result)

                    return result

                remaining = [g.name for g in generators[index + 1 :]]
                errors.append(f"{generator.name}: {result.error_message}")
                if result.declined:
                    # A routing decision, not a defect: always hand on.
                    logger.info(f"Generator {generator.name} declined this input: {result.error_message}")
                elif strict and remaining:
                    raise _DowngradeRefused(_degraded_message(generator.name, remaining, str(result.error_message)))
                else:
                    self._warn_degraded(generator.name, remaining, str(result.error_message))
            except _DowngradeRefused:
                raise
            except Exception as e:
                remaining = [g.name for g in generators[index + 1 :]]
                errors.append(f"{generator.name}: {e}")
                if strict and remaining:
                    raise _DowngradeRefused(_degraded_message(generator.name, remaining, str(e))) from e
                self._warn_degraded(generator.name, remaining, str(e))

        # Nothing found components, but something did produce a well-formed
        # empty document. A project genuinely without dependencies is
        # entitled to exactly that, and refusing it would be worse than
        # reporting it -- so hand it back, saying clearly what it contains.
        if empty is not None:
            logger.warning(
                f"No generator found any components for this input; returning the empty "
                f"SBOM from '{empty_from}'. If this project does have dependencies, they "
                f"are not being read -- check that the file passed to LOCK_FILE is the one "
                f"that declares them."
            )
            if validate and empty.output_file:
                empty = self._validate_result(empty)
            return empty

        # All generators failed - check if it's a tool availability issue
        logger.info(f"All {len(attempted_generators)} generator(s) failed: {', '.join(attempted_generators)}")
        spec_version = input.spec_version or "default"
        input_type = "docker_image" if input.is_docker_image else "lock_file"
        lock_file = input.lock_file if input.is_lock_file else None
        available_tools, missing_tools = check_tool_for_input(input_type, lock_file)

        # Build error message with details from all failed generators (last 3)
        error_details = "; ".join(errors[-3:]) if errors else "unknown error"

        if missing_tools:
            # Some tools are missing - suggest installation
            missing_names = ", ".join(missing_tools)
            error_message = (
                f"All available generators failed. Errors: {error_details}\n"
                f"Additional tools that could help: {missing_names}\n"
                f"Install them for more generation options."
            )
        else:
            error_message = f"All generators failed. Errors: {error_details}"

        return GenerationResult.failure_result(
            error_message=error_message,
            sbom_format=input.output_format,
            spec_version=spec_version,
            generator_name="none",
        )

    def _warn_degraded(self, failed: str, remaining: list[str], error: str) -> None:
        """Say plainly what quality is being lost by moving down the chain."""
        if remaining:
            logger.warning(
                f"Generator '{failed}' failed and is being replaced by "
                f"'{remaining[0]}', which may produce a lower-quality SBOM: {error}"
            )
        else:
            logger.info(f"Generator {failed} failed and no generators remain: {error}")

    def _validate_result(self, result: GenerationResult) -> GenerationResult:
        """Validate a generation result and update with validation info."""
        if not result.output_file:
            return result

        # Sanitize SBOM before validation
        # Some generators produce output that needs fixing before validation passes
        if result.sbom_format == "cyclonedx":
            # CycloneDX: fix invalid license IDs (e.g., Trivy puts non-SPDX IDs in license.id)
            self._sanitize_cyclonedx_before_validation(result.output_file)
        elif result.sbom_format == "spdx":
            # SPDX: fix invalid licenses and enum values
            self._sanitize_spdx_before_validation(result.output_file)

        validation_result = validate_sbom_file(
            result.output_file,
            result.sbom_format,
            result.spec_version,
        )

        if validation_result.valid:
            logger.info(f"SBOM validated successfully: {format_display_name(result.sbom_format)} {result.spec_version}")
            return GenerationResult.success_result(
                output_file=result.output_file,
                sbom_format=result.sbom_format,
                spec_version=result.spec_version,
                generator_name=result.generator_name,
                validated=True,
                validation_error=None,
            )
        else:
            logger.warning(f"SBOM validation failed: {validation_result.error_message}")
            return GenerationResult.success_result(
                output_file=result.output_file,
                sbom_format=result.sbom_format,
                spec_version=result.spec_version,
                generator_name=result.generator_name,
                validated=True,
                validation_error=validation_result.error_message,
            )

    def _sanitize_cyclonedx_before_validation(self, output_file: str) -> None:
        """Sanitize CycloneDX SBOM licenses before validation.

        Some generators (like Trivy) put non-SPDX license identifiers in the
        license.id field, which causes schema validation failures. This method
        reads the generated SBOM, sanitizes invalid license IDs (moving them to
        license.name), and writes the file back.

        Args:
            output_file: Path to the CycloneDX SBOM file
        """
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            sanitized_count = sanitize_cyclonedx_licenses(data)

            if sanitized_count > 0:
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                logger.debug(f"Pre-validation: sanitized {sanitized_count} license ID(s)")
        except Exception as e:
            logger.debug(f"Could not sanitize licenses before validation: {e}")

    def _sanitize_spdx_before_validation(self, output_file: str) -> None:
        """Sanitize SPDX SBOM before validation.

        This fixes:
        1. Invalid license IDs (converted to LicenseRef-* format)
        2. Invalid enum values (e.g., Python enum names to SPDX spec values)
        3. Missing documentDescribes (reconstructed from DESCRIBES relationships)

        Args:
            output_file: Path to the SPDX SBOM file
        """
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Sanitize licenses first
            license_count = sanitize_spdx_licenses(data)

            if license_count > 0:
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                logger.debug(f"Pre-validation: sanitized {license_count} SPDX license(s)")

            # Then fix enum values (this reads/writes the file itself)
            sanitize_spdx_json_file(output_file)
            restore_spdx_document_describes(output_file)
        except Exception as e:
            logger.debug(f"Could not sanitize SPDX SBOM before validation: {e}")

    def _supports_format(self, generator: Generator, format: str) -> bool:
        """Check if generator supports a format."""
        for fv in generator.supported_formats:
            if fv.format == format:
                return True
        return False

    def _supports_version(self, generator: Generator, format: str, version: str) -> bool:
        """Check if generator supports a specific version of a format."""
        for fv in generator.supported_formats:
            if fv.format == format and fv.supports_version(version):
                return True
        return False

    def _get_format_version(self, generator: Generator, format: str) -> FormatVersion | None:
        """Get the FormatVersion for a specific format from a generator."""
        for fv in generator.supported_formats:
            if fv.format == format:
                return fv
        return None

    def _get_available_formats(self) -> dict[str, list[str]]:
        """Get all available formats and versions from registered generators."""
        formats: dict[str, set[str]] = {}
        for generator in self._generators:
            for fv in generator.supported_formats:
                if fv.format not in formats:
                    formats[fv.format] = set()
                formats[fv.format].update(fv.versions)
        return {f: sorted(v) for f, v in formats.items()}

    def list_generators(self) -> list[dict[str, Any]]:
        """
        List all registered generators with their capabilities.

        Returns:
            List of dicts with generator info
        """
        result = []
        for g in sorted(self._generators, key=lambda x: x.priority):
            formats = []
            for fv in g.supported_formats:
                formats.append(
                    {
                        "format": fv.format,
                        "versions": list(fv.versions),
                        "default": fv.default_version,
                    }
                )
            result.append(
                {
                    "name": g.name,
                    "priority": g.priority,
                    "formats": formats,
                }
            )
        return result

    def clear(self) -> None:
        """Remove all registered generators."""
        self._generators.clear()
