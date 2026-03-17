"""SBOM validation using JSON schemas.

This module provides validation for generated and processed SBOMs against their
respective JSON schemas (CycloneDX and SPDX).

Usage:
    from sbomify_action.validation import validate_sbom_file, validate_sbom_file_auto

    # Validate with known format and version
    result = validate_sbom_file("sbom.json", "cyclonedx", "1.6")
    if result.valid is None:
        print(f"Validation skipped: {result.error_message}")
    elif not result.valid:
        print(f"Validation failed: {result.error_message}")

    # Auto-detect format and version
    result = validate_sbom_file_auto("sbom.json")
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import jsonschema
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from sbomify_action import format_display_name
from sbomify_action.logging_config import logger

# SBOM format type - matches _generation.protocol.SBOMFormat
SBOMFormat = Literal["cyclonedx", "spdx"]

# Path to schemas within the package directory
PACKAGE_DIR = Path(__file__).parent
CDX_SCHEMA_DIR = PACKAGE_DIR / "schemas" / "cyclonedx"
SPDX_SCHEMA_DIR = PACKAGE_DIR / "schemas" / "spdx"

# Schema file mappings
CDX_SCHEMAS = {
    "1.3": CDX_SCHEMA_DIR / "cdx-1.3.schema.json",
    "1.4": CDX_SCHEMA_DIR / "cdx-1.4.schema.json",
    "1.5": CDX_SCHEMA_DIR / "cdx-1.5.schema.json",
    "1.6": CDX_SCHEMA_DIR / "cdx-1.6.schema.json",
    "1.7": CDX_SCHEMA_DIR / "cdx-1.7.schema.json",
}

SPDX_SCHEMAS = {
    "2.2": SPDX_SCHEMA_DIR / "spdx-2.2.schema.json",
    "2.3": SPDX_SCHEMA_DIR / "spdx-2.3.schema.json",
    "3.0.1": SPDX_SCHEMA_DIR / "spdx-3.0.1.schema.json",
}

# Cache for loaded schemas
_schema_cache: dict[str, dict[str, Any]] = {}

# Cache for the schema registry (built lazily)
_registry_cache: Registry | None = None


def _get_schema_registry() -> Registry:
    """
    Get or create a schema registry with bundled schemas.

    This registry includes the SPDX license enumeration schema from cyclonedx-python-lib,
    which is required for validating CycloneDX SBOMs with SPDX license IDs.
    The registry prevents jsonschema from trying to fetch remote schemas.

    Returns:
        A Registry with pre-registered schemas for local resolution
    """
    global _registry_cache
    if _registry_cache is not None:
        return _registry_cache

    # Import here to avoid circular imports and make the dependency explicit
    from cyclonedx.schema._res import SPDX_JSON

    # Load the SPDX license schema from cyclonedx-python-lib
    with open(SPDX_JSON) as f:
        spdx_schema = json.load(f)

    # Create registry with the SPDX schema pre-registered
    # The schema's $id is "http://cyclonedx.org/schema/spdx.schema.json"
    # which matches the $ref in CycloneDX schemas
    _registry_cache = Registry().with_resource(
        uri="http://cyclonedx.org/schema/spdx.schema.json",
        resource=Resource.from_contents(spdx_schema, default_specification=DRAFT7),
    )

    return _registry_cache


@dataclass
class ValidationResult:
    """Result of SBOM validation.

    The `valid` field has three states:
    - True: Validation passed
    - False: Validation failed
    - None: Validation was skipped (e.g., no schema available)
    """

    valid: bool | None
    sbom_format: SBOMFormat
    spec_version: str
    error_message: str | None = None
    error_path: str | None = None

    @classmethod
    def success(cls, sbom_format: SBOMFormat, spec_version: str) -> "ValidationResult":
        """Create a successful validation result."""
        return cls(valid=True, sbom_format=sbom_format, spec_version=spec_version)

    @classmethod
    def failure(
        cls,
        sbom_format: SBOMFormat,
        spec_version: str,
        error_message: str,
        error_path: str | None = None,
    ) -> "ValidationResult":
        """Create a failed validation result."""
        return cls(
            valid=False,
            sbom_format=sbom_format,
            spec_version=spec_version,
            error_message=error_message,
            error_path=error_path,
        )

    @classmethod
    def skipped(cls, sbom_format: SBOMFormat, spec_version: str, reason: str) -> "ValidationResult":
        """Create a result indicating validation was skipped (schema not available)."""
        return cls(
            valid=None,
            sbom_format=sbom_format,
            spec_version=spec_version,
            error_message=reason,
        )


def _load_schema(schema_path: Path) -> dict[str, Any] | None:
    """Load a JSON schema from disk with caching."""
    cache_key = str(schema_path)
    if cache_key in _schema_cache:
        return _schema_cache[cache_key]

    if not schema_path.exists():
        logger.warning(f"Schema file not found: {schema_path}")
        return None

    with open(schema_path) as f:
        schema: dict[str, Any] = json.load(f)
        _schema_cache[cache_key] = schema
        return schema


def get_schema_for_format(sbom_format: SBOMFormat, spec_version: str) -> dict[str, Any] | None:
    """
    Get the JSON schema for a specific format and version.

    Args:
        sbom_format: The SBOM format ("cyclonedx" or "spdx")
        spec_version: The spec version (e.g., "1.6" or "2.3")

    Returns:
        The JSON schema dict, or None if not found
    """
    if sbom_format == "cyclonedx":
        schema_path = CDX_SCHEMAS.get(spec_version)
    elif sbom_format == "spdx":
        schema_path = SPDX_SCHEMAS.get(spec_version)
    else:
        return None

    if schema_path is None:
        return None

    return _load_schema(schema_path)


def validate_sbom_data(
    sbom_data: dict[str, Any],
    sbom_format: SBOMFormat,
    spec_version: str,
) -> ValidationResult:
    """
    Validate SBOM data against its JSON schema.

    Args:
        sbom_data: The parsed SBOM JSON data
        sbom_format: The SBOM format ("cyclonedx" or "spdx")
        spec_version: The spec version (e.g., "1.6" or "2.3")

    Returns:
        ValidationResult with validation status and any errors
    """
    schema = get_schema_for_format(sbom_format, spec_version)

    if schema is None:
        # No schema available - skip validation but log warning
        reason = f"No schema available for {sbom_format} {spec_version}"
        logger.warning(f"{reason}, unable to validate SBOM")
        return ValidationResult.skipped(sbom_format, spec_version, reason)

    try:
        # Use a registry with bundled schemas to avoid fetching remote references
        # This is especially important for CycloneDX schemas that reference spdx.schema.json
        registry = _get_schema_registry()

        # Create a validator with the registry for local schema resolution
        # SPDX 3.x schemas use Draft 2020-12; others use Draft 7
        if sbom_format == "spdx" and spec_version and spec_version.startswith("3"):
            validator = jsonschema.Draft202012Validator(schema, registry=registry)
        else:
            validator = jsonschema.Draft7Validator(schema, registry=registry)

        # Validate and collect errors
        errors = list(validator.iter_errors(sbom_data))
        if errors:
            # Return the first error (most relevant)
            e = errors[0]
            error_path = ".".join(str(p) for p in e.absolute_path) if e.absolute_path else None
            logger.error(f"SBOM validation failed: {e.message}")
            if error_path:
                logger.error(f"Error at path: {error_path}")
            return ValidationResult.failure(
                sbom_format=sbom_format,
                spec_version=spec_version,
                error_message=e.message,
                error_path=error_path,
            )

        logger.info(f"SBOM validated successfully against {format_display_name(sbom_format)} {spec_version} schema")
        return ValidationResult.success(sbom_format, spec_version)
    except jsonschema.SchemaError as e:
        logger.error(f"Invalid schema: {e.message}")
        return ValidationResult.failure(
            sbom_format=sbom_format,
            spec_version=spec_version,
            error_message=f"Invalid schema: {e.message}",
        )


def validate_sbom_file(
    file_path: str,
    sbom_format: SBOMFormat,
    spec_version: str,
) -> ValidationResult:
    """
    Validate an SBOM file against its JSON schema.

    Args:
        file_path: Path to the SBOM JSON file
        sbom_format: The SBOM format ("cyclonedx" or "spdx")
        spec_version: The spec version (e.g., "1.6" or "2.3")

    Returns:
        ValidationResult with validation status and any errors
    """
    path = Path(file_path)
    if not path.exists():
        return ValidationResult.failure(
            sbom_format=sbom_format,
            spec_version=spec_version,
            error_message=f"File not found: {file_path}",
        )

    try:
        with open(path) as f:
            sbom_data = json.load(f)
    except json.JSONDecodeError as e:
        return ValidationResult.failure(
            sbom_format=sbom_format,
            spec_version=spec_version,
            error_message=f"Invalid JSON: {e}",
        )

    return validate_sbom_data(sbom_data, sbom_format, spec_version)


def detect_sbom_format_and_version(sbom_data: dict[str, Any]) -> tuple[SBOMFormat | None, str | None]:
    """
    Detect the format and version of an SBOM from its data.

    Args:
        sbom_data: The parsed SBOM JSON data

    Returns:
        Tuple of (format, version) or (None, None) if unrecognized
    """
    # CycloneDX detection
    if "bomFormat" in sbom_data and sbom_data.get("bomFormat") == "CycloneDX":
        spec_version = sbom_data.get("specVersion")
        if spec_version:
            return "cyclonedx", spec_version
        return "cyclonedx", None

    # SPDX 3 detection (must come before SPDX 2.x since SPDX 3 has no spdxVersion field)
    from .spdx3 import extract_spdx3_version, is_spdx3

    if is_spdx3(sbom_data):
        version = extract_spdx3_version(sbom_data)
        return "spdx", version

    # SPDX 2.x detection
    if "spdxVersion" in sbom_data:
        spdx_version = sbom_data.get("spdxVersion", "")
        # Extract version from "SPDX-2.3" format
        if spdx_version.startswith("SPDX-"):
            version = spdx_version[5:]  # Remove "SPDX-" prefix
            return "spdx", version
        return "spdx", None

    return None, None


def validate_sbom_file_auto(file_path: str) -> ValidationResult:
    """
    Validate an SBOM file, auto-detecting its format and version.

    Args:
        file_path: Path to the SBOM JSON file

    Returns:
        ValidationResult with validation status and any errors
    """
    path = Path(file_path)
    if not path.exists():
        return ValidationResult.failure(
            sbom_format="cyclonedx",  # Default for error reporting
            spec_version="unknown",
            error_message=f"File not found: {file_path}",
        )

    try:
        with open(path) as f:
            sbom_data = json.load(f)
    except json.JSONDecodeError as e:
        return ValidationResult.failure(
            sbom_format="cyclonedx",
            spec_version="unknown",
            error_message=f"Invalid JSON: {e}",
        )

    sbom_format, spec_version = detect_sbom_format_and_version(sbom_data)

    if sbom_format is None:
        return ValidationResult.failure(
            sbom_format="cyclonedx",
            spec_version="unknown",
            error_message="Could not detect SBOM format (not CycloneDX or SPDX)",
        )

    if spec_version is None:
        return ValidationResult.failure(
            sbom_format=sbom_format,
            spec_version="unknown",
            error_message=f"Could not detect {sbom_format} spec version",
        )

    return validate_sbom_data(sbom_data, sbom_format, spec_version)
