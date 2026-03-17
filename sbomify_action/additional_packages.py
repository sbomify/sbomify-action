"""Additional packages injection for SBOMs.

This module enables users to inject additional packages (as PURLs) into generated SBOMs.
Useful for dependencies not captured by lockfiles, runtime dependencies, or vendored code.

Supports three input methods:
1. Convention-based file: `additional_packages.txt` in working directory
2. Custom file path: `ADDITIONAL_PACKAGES_FILE` environment variable
3. Inline values: `ADDITIONAL_PACKAGES` environment variable (comma or newline separated)

All sources are merged and deduplicated before injection.
"""

import json
import os
import re
from pathlib import Path
from typing import List, Optional

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from packageurl import PackageURL
from spdx_tools.spdx.model import (  # type: ignore[attr-defined]
    Actor,
    ActorType,
    CreationInfo,
    Document,
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
    SpdxNoAssertion,
)
from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file
from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

from .logging_config import logger
from .serialization import restore_spdx_document_describes, sanitize_spdx_json_file, serialize_cyclonedx_bom
from .spdx3 import is_spdx3

# Default file name for additional packages
DEFAULT_PACKAGES_FILE = "additional_packages.txt"

# Environment variable names
ENV_PACKAGES_FILE = "ADDITIONAL_PACKAGES_FILE"
ENV_PACKAGES_INLINE = "ADDITIONAL_PACKAGES"

# Property name for tracking injection source
SBOMIFY_SOURCE_PROPERTY = "sbomify:source"
SBOMIFY_SOURCE_VALUE = "additional-packages"

# SPDX external reference type for PURLs
PURL_REFERENCE_TYPE = "purl"


def parse_additional_packages_file(file_path: str) -> List[str]:
    """
    Parse additional packages file.

    File format:
    - One PURL per line
    - Lines starting with # are comments
    - Empty lines are ignored
    - Whitespace is trimmed

    Args:
        file_path: Path to the packages file

    Returns:
        List of PURL strings

    Raises:
        FileNotFoundError: If file doesn't exist
    """
    purls = []
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Additional packages file not found: {file_path}")

    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            # Strip whitespace
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Skip comments
            if line.startswith("#"):
                continue

            # Validate and add PURL
            if validate_purl(line):
                purls.append(line)
            else:
                logger.warning(f"Invalid PURL on line {line_num}: {line}")

    return purls


def validate_purl(purl_string: str) -> bool:
    """
    Validate a PURL string.

    Args:
        purl_string: The PURL string to validate

    Returns:
        True if valid, False otherwise
    """
    try:
        PackageURL.from_string(purl_string)
        return True
    except Exception:
        return False


def parse_purl(purl_string: str) -> Optional[PackageURL]:
    """
    Parse a PURL string into a PackageURL object.

    Args:
        purl_string: The PURL string to parse

    Returns:
        PackageURL object or None if invalid
    """
    try:
        return PackageURL.from_string(purl_string)
    except Exception:
        return None


def has_additional_packages_configured() -> bool:
    """
    Check whether additional packages are configured via any source.

    This checks for the *presence* of configuration (env vars set, files exist)
    without parsing or validating the content. Use this to detect misconfiguration
    where sources exist but contain no valid PURLs.

    Returns:
        True if any additional packages source is configured
    """
    # Check default file
    if (Path.cwd() / DEFAULT_PACKAGES_FILE).exists():
        return True

    # Check custom file env var
    if os.getenv(ENV_PACKAGES_FILE):
        return True

    # Check inline env var
    if os.getenv(ENV_PACKAGES_INLINE):
        return True

    return False


def get_additional_packages() -> List[str]:
    """
    Collect additional packages from all sources.

    Sources (in order of processing):
    1. Default file: `additional_packages.txt` in working directory
    2. Custom file: Path from `ADDITIONAL_PACKAGES_FILE` env var
    3. Inline: PURLs from `ADDITIONAL_PACKAGES` env var

    All sources are merged and deduplicated.

    Returns:
        List of unique PURL strings
    """
    purls: List[str] = []

    # 1. Check for default file in working directory
    default_file = Path.cwd() / DEFAULT_PACKAGES_FILE
    if default_file.exists():
        logger.info(f"Found {DEFAULT_PACKAGES_FILE} in working directory")
        try:
            file_purls = parse_additional_packages_file(str(default_file))
            purls.extend(file_purls)
            logger.info(f"Loaded {len(file_purls)} package(s) from {DEFAULT_PACKAGES_FILE}")
        except Exception as e:
            logger.error(f"Failed to parse {DEFAULT_PACKAGES_FILE}: {e}")

    # 2. Check for custom file path via environment variable
    custom_file = os.getenv(ENV_PACKAGES_FILE)
    if custom_file:
        custom_path = Path(custom_file)
        if custom_path.exists():
            logger.info(f"Found custom packages file: {custom_file}")
            try:
                file_purls = parse_additional_packages_file(custom_file)
                purls.extend(file_purls)
                logger.info(f"Loaded {len(file_purls)} package(s) from {custom_file}")
            except Exception as e:
                logger.error(f"Failed to parse {custom_file}: {e}")
        else:
            logger.warning(f"Custom packages file not found: {custom_file}")

    # 3. Check for inline packages via environment variable
    inline_packages = os.getenv(ENV_PACKAGES_INLINE)
    if inline_packages:
        # Support both comma and newline separation (including mixed usage)
        inline_purls = [p.strip() for p in re.split(r"[\n,]", inline_packages) if p.strip()]

        valid_count = 0
        for purl in inline_purls:
            if validate_purl(purl):
                purls.append(purl)
                valid_count += 1
            else:
                logger.warning(f"Invalid PURL in {ENV_PACKAGES_INLINE}: {purl}")

        if valid_count > 0:
            logger.info(f"Loaded {valid_count} package(s) from {ENV_PACKAGES_INLINE}")

    # Deduplicate while preserving order
    seen = set()
    unique_purls = []
    for purl in purls:
        if purl not in seen:
            seen.add(purl)
            unique_purls.append(purl)

    if not unique_purls:
        logger.debug("No additional packages found from any source")

    return unique_purls


def _get_component_type(purl: PackageURL) -> ComponentType:
    """
    Map PURL type to CycloneDX ComponentType.

    Args:
        purl: Parsed PackageURL

    Returns:
        Appropriate ComponentType (defaults to LIBRARY)
    """
    # Most package types are libraries
    return ComponentType.LIBRARY


def inject_packages_into_cyclonedx(bom: Bom, purls: List[str]) -> int:
    """
    Inject additional packages into a CycloneDX BOM.

    Each PURL is converted to a Component with:
    - name: extracted from PURL
    - version: extracted from PURL (or "unknown" if not specified)
    - purl: the original PURL string
    - type: mapped from PURL type (defaults to library)
    - Property sbomify:source = additional-packages (for tracking)

    Args:
        bom: The Bom object to modify
        purls: List of PURL strings to inject

    Returns:
        Number of packages successfully injected
    """
    injected = 0

    for purl_str in purls:
        purl = parse_purl(purl_str)
        if not purl:
            logger.warning(f"Skipping invalid PURL: {purl_str}")
            continue

        # Check if component with same PURL already exists
        existing_purls = {str(c.purl) for c in bom.components if c.purl}
        if purl_str in existing_purls:
            logger.debug(f"Skipping duplicate PURL: {purl_str}")
            continue

        # Create component
        component = Component(
            name=purl.name,
            version=purl.version if purl.version else "unknown",
            type=_get_component_type(purl),
            purl=purl,
        )

        # Add tracking property
        component.properties.add(Property(name=SBOMIFY_SOURCE_PROPERTY, value=SBOMIFY_SOURCE_VALUE))

        # Add to BOM
        bom.components.add(component)
        injected += 1
        logger.debug(f"Injected component: {purl.name}@{purl.version or 'unknown'}")

    return injected


def inject_packages_into_spdx(document: Document, purls: List[str]) -> int:
    """
    Inject additional packages into an SPDX document.

    Each PURL is converted to a Package with:
    - name: extracted from PURL
    - version: extracted from PURL (or "unknown" if not specified)
    - SPDX ID: generated from package name and index
    - External reference: PURL
    - Comment: indicates source as additional-packages

    Args:
        document: The SPDX Document to modify
        purls: List of PURL strings to inject

    Returns:
        Number of packages successfully injected
    """
    injected = 0

    # Get existing PURLs to avoid duplicates
    existing_purls = set()
    for pkg in document.packages:
        for ref in pkg.external_references:
            if ref.reference_type == PURL_REFERENCE_TYPE:
                existing_purls.add(ref.locator)

    # Get existing SPDX IDs to avoid collisions
    existing_ids = {pkg.spdx_id for pkg in document.packages}

    for idx, purl_str in enumerate(purls):
        purl = parse_purl(purl_str)
        if not purl:
            logger.warning(f"Skipping invalid PURL: {purl_str}")
            continue

        # Check if PURL already exists
        if purl_str in existing_purls:
            logger.debug(f"Skipping duplicate PURL: {purl_str}")
            continue

        # Generate unique SPDX ID (sanitize to valid idstring: letters, numbers, . and -)
        sanitized_name = re.sub(r"[^a-zA-Z0-9.\-]", "-", purl.name)
        base_id = f"SPDXRef-additional-{sanitized_name}"
        spdx_id = base_id
        counter = 1
        while spdx_id in existing_ids:
            spdx_id = f"{base_id}-{counter}"
            counter += 1
        existing_ids.add(spdx_id)

        # Create package
        package = Package(
            spdx_id=spdx_id,
            name=purl.name,
            version=purl.version if purl.version else "unknown",
            download_location=SpdxNoAssertion(),
            comment=f"Injected via {SBOMIFY_SOURCE_VALUE}",
        )

        # Add PURL as external reference
        package.external_references.append(
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type=PURL_REFERENCE_TYPE,
                locator=purl_str,
            )
        )

        # Add to document
        document.packages.append(package)
        injected += 1
        logger.debug(f"Injected package: {purl.name}@{purl.version or 'unknown'}")

    return injected


def create_empty_sbom(output_file: str, sbom_format: str, spec_version: str | None = None) -> str:
    """
    Create a minimal valid empty SBOM file.

    Used in additional-packages-only mode to bootstrap an SBOM from scratch
    before injecting additional packages.

    Args:
        output_file: Path to write the empty SBOM
        sbom_format: Either "cyclonedx" or "spdx"
        spec_version: Optional spec version override (e.g. "3.0.1" for SPDX 3)

    Returns:
        The format string ("cyclonedx" or "spdx")

    Raises:
        ValueError: If sbom_format is not supported
    """
    import uuid
    from datetime import datetime, timezone

    from .serialization import DEFAULT_CYCLONEDX_VERSION, serialize_cyclonedx_bom

    if sbom_format == "cyclonedx":
        bom = Bom()
        serialized = serialize_cyclonedx_bom(bom, DEFAULT_CYCLONEDX_VERSION)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(serialized)
        logger.info(f"Created empty CycloneDX SBOM: {output_file}")
        return "cyclonedx"

    elif sbom_format == "spdx":
        # Check if SPDX 3 is requested
        if spec_version and spec_version.startswith("3"):
            return _create_empty_spdx3(output_file)

        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="additional-packages-sbom",
            document_namespace=f"https://sbomify.com/additional-packages/{uuid.uuid4()}",
            creators=[Actor(ActorType.TOOL, "sbomify-action")],
            created=datetime.now(timezone.utc),
        )
        document = Document(creation_info=creation_info)
        spdx_write_file(document, output_file, validate=False)
        sanitize_spdx_json_file(output_file)
        logger.info(f"Created empty SPDX SBOM: {output_file}")
        return "spdx"

    else:
        raise ValueError(f"Unsupported SBOM format: {sbom_format}. Must be 'cyclonedx' or 'spdx'.")


def _create_empty_spdx3(output_file: str) -> str:
    """Create a minimal valid empty SPDX 3 document."""
    from datetime import datetime, timezone

    from semantic_version import Version
    from spdx_tools.spdx3.model import CreationInfo as Spdx3CreationInfo
    from spdx_tools.spdx3.model import ProfileIdentifierType, SpdxDocument
    from spdx_tools.spdx3.model import Tool as Spdx3Tool
    from spdx_tools.spdx3.payload import Payload

    from .spdx3 import make_spdx3_spdx_id, write_spdx3_file

    creation_info = Spdx3CreationInfo(
        spec_version=Version("3.0.1"),
        created=datetime.now(timezone.utc),
        created_by=[],
        profile=[ProfileIdentifierType.CORE, ProfileIdentifierType.SOFTWARE],
    )

    tool_id = make_spdx3_spdx_id()
    tool = Spdx3Tool(spdx_id=tool_id, name="sbomify-action", creation_info=creation_info)

    doc_id = make_spdx3_spdx_id()
    doc = SpdxDocument(
        spdx_id=doc_id,
        name="additional-packages-sbom",
        element=[tool_id],
        root_element=[],
        creation_info=creation_info,
    )

    payload = Payload()
    payload.add_element(doc)
    payload.add_element(tool)
    write_spdx3_file(payload, output_file)
    logger.info(f"Created empty SPDX 3 SBOM: {output_file}")
    return "spdx"


def inject_packages_into_spdx3(sbom_file: str, purls: list[PackageURL]) -> int:
    """Inject additional packages into an SPDX 3 SBOM.

    Args:
        sbom_file: Path to the SPDX 3 JSON-LD file
        purls: List of PackageURL objects to inject

    Returns:
        Number of packages injected
    """
    from spdx_tools.spdx3.model.software.package import Package as Spdx3Package

    from .spdx3 import (
        get_spdx3_document,
        make_spdx3_creation_info,
        make_spdx3_spdx_id,
        parse_spdx3_file,
        write_spdx3_file,
    )

    payload = parse_spdx3_file(sbom_file)
    doc = get_spdx3_document(payload)
    injected = 0

    for purl in purls:
        pkg_id = make_spdx3_spdx_id()
        pkg_name = purl.name or "unknown"
        pkg_version = purl.version

        pkg = Spdx3Package(
            spdx_id=pkg_id,
            name=pkg_name,
            package_version=pkg_version,
            package_url=str(purl),
            creation_info=make_spdx3_creation_info(),
        )
        payload.add_element(pkg)

        # Add to document element list
        if doc:
            doc.element.append(pkg_id)

        injected += 1
        logger.debug(f"Injected SPDX 3 package: {pkg_name}@{pkg_version or 'unknown'}")

    if injected > 0:
        write_spdx3_file(payload, sbom_file)

    return injected


def inject_additional_packages(sbom_file: str) -> int:
    """
    Inject additional packages into an SBOM file.

    This is the main entry point that:
    1. Collects PURLs from all sources (file, env vars)
    2. Detects SBOM format (CycloneDX or SPDX)
    3. Injects packages into the SBOM
    4. Writes the modified SBOM back to the file

    Args:
        sbom_file: Path to the SBOM file to modify

    Returns:
        Number of packages injected (0 if no packages to inject)
    """
    # Collect packages from all sources
    purls = get_additional_packages()

    if not purls:
        logger.debug("No additional packages to inject")
        return 0

    logger.info(f"Injecting {len(purls)} additional package(s) into SBOM")

    # Load and detect format
    sbom_path = Path(sbom_file)
    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error(f"SBOM file not found: {sbom_file}")
        return 0
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in SBOM file: {e}")
        return 0

    # Handle CycloneDX
    if data.get("bomFormat") == "CycloneDX":
        spec_version = data.get("specVersion")
        if not spec_version:
            logger.error("CycloneDX SBOM missing specVersion")
            return 0

        try:
            bom = Bom.from_json(data)  # type: ignore[attr-defined]
        except Exception as e:
            logger.error(f"Failed to parse CycloneDX SBOM: {e}")
            return 0

        injected = inject_packages_into_cyclonedx(bom, purls)

        if injected > 0:
            # Write back
            serialized = serialize_cyclonedx_bom(bom, spec_version)
            with open(sbom_path, "w", encoding="utf-8") as f:
                f.write(serialized)
            logger.info(f"Injected {injected} additional package(s) into CycloneDX SBOM")

        return injected

    # Handle SPDX 3
    elif is_spdx3(data):
        purl_objects = [p for purl_str in purls if (p := parse_purl(purl_str)) is not None]
        injected = inject_packages_into_spdx3(str(sbom_path), purl_objects)

        if injected > 0:
            logger.info(f"Injected {injected} additional package(s) into SPDX 3 SBOM")

        return injected

    # Handle SPDX 2.x
    elif "spdxVersion" in data:
        spdx_version = data.get("spdxVersion")
        if not isinstance(spdx_version, str) or not spdx_version:
            logger.error("SPDX SBOM missing or invalid spdxVersion")
            return 0

        try:
            document = spdx_parse_file(str(sbom_path))
        except Exception as e:
            logger.error(f"Failed to parse SPDX SBOM: {e}")
            return 0

        injected = inject_packages_into_spdx(document, purls)

        if injected > 0:
            # Write back
            spdx_write_file(document, str(sbom_path), validate=False)
            sanitize_spdx_json_file(str(sbom_path))
            restore_spdx_document_describes(str(sbom_path))
            logger.info(f"Injected {injected} additional package(s) into SPDX SBOM")

        return injected

    else:
        logger.error("Unknown SBOM format - cannot inject additional packages")
        return 0
