"""Generator registry for managing SBOM generator plugins."""

import json
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
        for generator in generators:
            logger.info(f"Trying generator: {generator.name}")
            attempted_generators.append(generator.name)
            try:
                result = generator.generate(input)
                if result.success:
                    logger.info(f"Successfully generated SBOM with {generator.name}")

                    # Validate the generated SBOM
                    if validate and result.output_file:
                        result = self._validate_result(result)

                    return result
                else:
                    errors.append(f"{generator.name}: {result.error_message}")
                    # Log at INFO level to ensure it appears in Sentry breadcrumbs
                    logger.info(f"Generator {generator.name} failed, will try next: {result.error_message}")
            except Exception as e:
                errors.append(f"{generator.name}: {e}")
                # Log at INFO level to ensure it appears in Sentry breadcrumbs
                logger.info(f"Generator {generator.name} raised exception, will try next: {e}")

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
