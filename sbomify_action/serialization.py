"""
SBOM serialization utilities for version-aware output.

This module provides centralized serialization functions for both CycloneDX and SPDX
formats, supporting multiple versions and making it easy to add new versions in the future.
"""

import functools
import hashlib
import json
import re
import warnings
from typing import TYPE_CHECKING, Any, Optional

from cyclonedx.model.bom import Bom
from license_expression import ExpressionError, get_spdx_licensing

if TYPE_CHECKING:
    from cyclonedx.model.component import Component
from packageurl import PackageURL
from spdx_tools.spdx.model import Document  # type: ignore[attr-defined]

from .console import get_transformation_tracker
from .logging_config import logger


@functools.lru_cache(maxsize=1)
def _spdx_licensing_singleton() -> Any:
    """Return a cached SPDX licensing instance (singleton)."""
    return get_spdx_licensing()


# ============================================================================
# CycloneDX Version Management
# ============================================================================

# Lazy imports to avoid loading all versions upfront
_CYCLONEDX_OUTPUTTERS: dict[str, type[Any] | None] = {
    "1.3": None,  # JsonV1Dot3
    "1.4": None,  # JsonV1Dot4
    "1.5": None,  # JsonV1Dot5
    "1.6": None,  # JsonV1Dot6
    "1.7": None,  # JsonV1Dot7
    # Add new versions here as they become available:
    # "2.0": None,  # JsonV2Dot0
}

# Default version to use when version cannot be detected
DEFAULT_CYCLONEDX_VERSION = "1.6"


def _get_cyclonedx_outputter(spec_version: str) -> type[Any]:
    """
    Get the appropriate CycloneDX outputter class for a given spec version.

    Uses lazy loading to only import the outputter classes that are actually needed.

    Args:
        spec_version: CycloneDX spec version (e.g., "1.5", "1.6", "1.7", "2.0")

    Returns:
        Outputter class for the specified version

    Raises:
        ValueError: If version is not supported
    """
    # Normalize version to major.minor format
    if spec_version:
        major_minor = ".".join(spec_version.split(".")[:2])
    else:
        major_minor = DEFAULT_CYCLONEDX_VERSION

    # Lazy load the outputter class if not already loaded
    if major_minor in _CYCLONEDX_OUTPUTTERS and _CYCLONEDX_OUTPUTTERS[major_minor] is None:
        try:
            if major_minor == "1.3":
                from cyclonedx.output.json import JsonV1Dot3

                _CYCLONEDX_OUTPUTTERS["1.3"] = JsonV1Dot3
            elif major_minor == "1.4":
                from cyclonedx.output.json import JsonV1Dot4

                _CYCLONEDX_OUTPUTTERS["1.4"] = JsonV1Dot4
            elif major_minor == "1.5":
                from cyclonedx.output.json import JsonV1Dot5

                _CYCLONEDX_OUTPUTTERS["1.5"] = JsonV1Dot5
            elif major_minor == "1.6":
                from cyclonedx.output.json import JsonV1Dot6

                _CYCLONEDX_OUTPUTTERS["1.6"] = JsonV1Dot6
            elif major_minor == "1.7":
                from cyclonedx.output.json import JsonV1Dot7

                _CYCLONEDX_OUTPUTTERS["1.7"] = JsonV1Dot7
            # Add future versions here:
            # elif major_minor == "2.0":
            #     from cyclonedx.output.json import JsonV2Dot0
            #     _CYCLONEDX_OUTPUTTERS["2.0"] = JsonV2Dot0
        except ImportError as e:
            logger.warning(f"CycloneDX version {major_minor} not available in installed library: {e}")
            _CYCLONEDX_OUTPUTTERS[major_minor] = None

    outputter_class = _CYCLONEDX_OUTPUTTERS.get(major_minor)

    if outputter_class is None:
        # Build list of supported versions (either loaded or known to be available)
        supported_versions = [
            v for v, cls in _CYCLONEDX_OUTPUTTERS.items() if cls is not None or v in ["1.5", "1.6", "1.7"]
        ]
        raise ValueError(
            f"Unsupported CycloneDX version: {spec_version}. "
            f"Supported versions: {', '.join(sorted(supported_versions))}"
        )

    return outputter_class


# Display value for missing namespace in log messages
_NO_NAMESPACE_DISPLAY = "<none>"

# Default version for stub components when version cannot be determined
_UNKNOWN_VERSION = "unknown"


def _extract_component_info_from_purl(
    purl_string: str,
) -> tuple[Optional[str], Optional[str], Optional[str], Optional[PackageURL]]:
    """
    Extract component information from a PURL string for stub creation.

    Uses the packageurl library for robust parsing.

    Args:
        purl_string: PURL string (e.g., "pkg:npm/vue-chartjs@3.5.1" or "pkg:npm/%40scope/name@1.0.0")

    Returns:
        Tuple of (name, version, namespace, PackageURL) or (None, None, None, None) if parsing fails
    """
    try:
        purl_obj = PackageURL.from_string(purl_string)
        return purl_obj.name, purl_obj.version, purl_obj.namespace, purl_obj
    except ValueError:
        # ValueError: the provided PURL string is malformed
        return None, None, None, None


# Regex patterns for PURL encoding bug fixes
# These fix common encoding issues from various SBOM generators
_DOUBLE_ENCODED_AT_PATTERN = re.compile(r"(%40){2,}")  # %40%40... → %40
_DOUBLE_AT_PATTERN = re.compile(r"@@+")  # @@... → @

# Package types that require a version in the PURL
# These ecosystems always have versioned packages in standard usage
PURL_TYPES_REQUIRING_VERSION = frozenset(
    {
        "npm",  # JavaScript/Node.js
        "maven",  # Java
        "pypi",  # Python
        "cargo",  # Rust
        "gem",  # Ruby
        "golang",  # Go
        "nuget",  # .NET
    }
)


def normalize_purl(purl_str: str | None) -> tuple[str | None, bool]:
    """
    Normalize a PURL string, fixing common encoding bugs.

    Fixes:
    - Double @@ symbols (encoding bugs from some generators)
    - Double-encoded @ symbols (%40%40 → %40)

    Note: This function preserves %40 encoding in namespaces, which is the
    canonical form per the PURL spec. For API calls where %40 would be
    double-encoded, use purl_to_string() from _enrichment.utils instead.

    Args:
        purl_str: The PURL string to normalize

    Returns:
        Tuple of (normalized_purl, was_modified) where was_modified indicates
        if any changes were made
    """
    if not purl_str:
        return purl_str, False

    original = purl_str
    normalized = purl_str

    # Fix double-encoded @ symbols: %40%40 → %40
    # This happens when a generator encodes an already-encoded PURL
    normalized = _DOUBLE_ENCODED_AT_PATTERN.sub("%40", normalized)

    # Fix double @@ symbols (e.g., pkg:npm/@scope/pkg@@1.0.0)
    # This is a common encoding bug where @@ appears before the version
    normalized = _DOUBLE_AT_PATTERN.sub("@", normalized)

    was_modified = normalized != original

    if was_modified:
        logger.debug(f"Normalized PURL: {original} → {normalized}")

    return normalized, was_modified


def _is_invalid_purl(purl_str: str | None) -> tuple[bool, str]:
    """
    Check if a PURL is invalid and cannot be fixed.

    Invalid PURLs include:
    - Empty or None PURLs
    - PURLs with file: references in qualifiers (local workspace packages)
    - PURLs with path-based versions (e.g., @../../packages/foo)
    - PURLs with link: references (npm link)
    - PURLs missing version (except for certain ecosystems where this is acceptable)

    Note: Double @@ encoding issues are fixed by normalize_purl() rather than rejected.

    Args:
        purl_str: The PURL string to check (may be None or empty)

    Returns:
        Tuple of (is_invalid, reason) where reason explains why it's invalid
    """
    if not purl_str:
        return True, "empty or None PURL"

    # Check for file: references anywhere in the PURL
    if "file:" in purl_str:
        return True, "contains file: reference (local workspace package)"

    # Check for link: references (npm link)
    if "link:" in purl_str:
        return True, "contains link: reference (npm link)"

    # Check for path-based versions (e.g., @../../ or @../ or @./)
    if "@../../" in purl_str or "@../" in purl_str or "@./" in purl_str:
        return True, "contains path-based version"

    # Try to parse the PURL
    try:
        purl = PackageURL.from_string(purl_str)

        # Check for invalid root namespace (common SBOM generator bug)
        # Must check parsed namespace, not string matching, to avoid false positives
        if purl.namespace in {"root", "@root"}:
            return True, "contains invalid root namespace"

        # Check for file: in qualifiers
        if purl.qualifiers:
            for key, value in purl.qualifiers.items():
                if isinstance(value, str) and ("file:" in value or "link:" in value):
                    return True, f"qualifier '{key}' contains file:/link: reference"

        # Check for missing version in ecosystems that require it
        if purl.type in PURL_TYPES_REQUIRING_VERSION:
            if not purl.version:
                return True, f"missing version for {purl.type} package"

    except ValueError as e:
        return True, f"malformed PURL: {e}"

    return False, ""


def _sanitize_component_purl(comp: "Component", comp_type: str) -> tuple[int, int]:
    """
    Sanitize a single component's PURL.

    Args:
        comp: CycloneDX Component object with optional purl attribute
        comp_type: Description of component type for logging (e.g., "component", "metadata component")

    Returns:
        Tuple of (purls_normalized, purls_cleared) counts for this component
    """
    if not comp.purl:
        return 0, 0

    purls_normalized = 0
    purls_cleared = 0
    purl_str = str(comp.purl)

    tracker = get_transformation_tracker()
    original_purl = purl_str

    # First, try to normalize
    normalized_str, was_normalized = normalize_purl(purl_str)
    if was_normalized and normalized_str is not None:
        try:
            comp.purl = PackageURL.from_string(normalized_str)
            purl_str = normalized_str
            purls_normalized = 1
            # Record for attestation
            tracker.record_purl_normalization(comp.name, original_purl, normalized_str)
        except ValueError:
            # Normalization produced invalid PURL, will be caught below
            pass

    # Then check if it's still invalid
    is_invalid, reason = _is_invalid_purl(purl_str)
    if is_invalid:
        # Record for attestation
        tracker.record_purl_cleared(comp.name, purl_str, reason)
        comp.purl = None
        purls_cleared = 1

    return purls_normalized, purls_cleared


def sanitize_purls(bom: Bom) -> tuple[int, int]:
    """
    Normalize and sanitize PURLs in the BOM.

    This function:
    1. Normalizes PURLs (fixes encoding issues like double @@)
    2. Clears invalid PURLs that cannot be fixed (file: references, path-based versions, etc.)

    Components are NOT removed (to preserve dependency graph integrity),
    but their invalid PURLs are set to None.

    Args:
        bom: The CycloneDX BOM object to sanitize (modified in place)

    Returns:
        Tuple of (purls_normalized, purls_cleared)
    """
    purls_normalized = 0
    purls_cleared = 0

    # Process regular components
    for comp in bom.components:
        normalized, cleared = _sanitize_component_purl(comp, "component")
        purls_normalized += normalized
        purls_cleared += cleared

    # Process metadata component
    if bom.metadata and bom.metadata.component:
        normalized, cleared = _sanitize_component_purl(bom.metadata.component, "metadata component")
        purls_normalized += normalized
        purls_cleared += cleared

    # Process tools.components (CycloneDX 1.5+ modern format)
    if bom.metadata and bom.metadata.tools and bom.metadata.tools.components:
        for comp in bom.metadata.tools.components:
            normalized, cleared = _sanitize_component_purl(comp, "tools.component")
            purls_normalized += normalized
            purls_cleared += cleared

    if purls_normalized:
        logger.info(f"PURL sanitization: normalized {purls_normalized} PURL(s)")
    if purls_cleared:
        logger.info(f"PURL sanitization: cleared {purls_cleared} invalid PURL(s)")

    return purls_normalized, purls_cleared


def sanitize_spdx_purls(document: "Document") -> int:
    """
    Normalize PURLs in SPDX external references.

    This function normalizes PURL locators in package external references to ensure
    consistent encoding. For example, it fixes double-encoded @ symbols (%40%40 -> %40).

    Args:
        document: The SPDX Document object to sanitize (modified in place)

    Returns:
        Number of PURLs normalized
    """
    normalized_count = 0

    for package in document.packages:
        for ref in package.external_references:
            if ref.reference_type == "purl":
                normalized, was_normalized = normalize_purl(ref.locator)
                if was_normalized and normalized:
                    logger.info(f"Normalized SPDX PURL: {ref.locator} -> {normalized}")
                    ref.locator = normalized
                    normalized_count += 1

    if normalized_count:
        logger.info(f"SPDX PURL sanitization: normalized {normalized_count} PURL(s)")

    return normalized_count


# Map of invalid SPDX enum values to valid ones (workaround for spdx_tools enum-serialization bug;
# see the upstream spdx/tools-python issue tracker for the bug where enums are serialized using Python
# names with underscores instead of SPDX spec values with hyphens).
SPDX_PACKAGE_PURPOSE_FIXES = {
    "OPERATING_SYSTEM": "OPERATING-SYSTEM",
}


def sanitize_spdx_json_file(file_path: str) -> int:
    """
    Fix invalid enum values in SPDX JSON files.

    The spdx_tools library has a bug where it outputs Python enum names
    (e.g., OPERATING_SYSTEM) instead of SPDX spec values (e.g., OPERATING-SYSTEM).
    This function post-processes the JSON file to fix these values.

    Args:
        file_path: Path to the SPDX JSON file to sanitize (modified in place)

    Returns:
        Number of values fixed
    """
    try:
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(f"Failed to read SPDX file for sanitization: {e}")
        return 0

    fixed_count = 0

    # Fix primaryPackagePurpose values in packages
    for package in data.get("packages", []):
        purpose = package.get("primaryPackagePurpose")
        if purpose is None:
            continue
        fixed_value = SPDX_PACKAGE_PURPOSE_FIXES.get(purpose, purpose)
        if fixed_value != purpose:
            package["primaryPackagePurpose"] = fixed_value
            logger.debug(f"Fixed SPDX primaryPackagePurpose: {purpose} -> {fixed_value}")
            fixed_count += 1

    if fixed_count > 0:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            logger.info(f"SPDX JSON sanitization: fixed {fixed_count} invalid enum value(s)")
        except OSError as e:
            logger.warning(f"Failed to write sanitized SPDX file: {e}")
            return 0

    return fixed_count


def restore_spdx_document_describes(file_path: str) -> int:
    """Reconstruct documentDescribes from DESCRIBES relationships in SPDX JSON.

    Many SBOM consumers (sbomify server, Microsoft vcpkg, GitHub) expect the
    documentDescribes shorthand field. The spdx-tools library converts it to
    Relationship objects on parse and never writes it back, so we reconstruct
    it here from DESCRIBES relationships where spdxElementId is SPDXRef-DOCUMENT.

    Args:
        file_path: Path to the SPDX JSON file to patch (modified in place)

    Returns:
        Number of entries added to documentDescribes (0 if none found or on error)
    """
    try:
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(f"Failed to read SPDX file for documentDescribes restoration: {e}")
        return 0

    # Collect unique DESCRIBES targets, preserving first-seen order
    seen: set[str] = set()
    describes: list[str] = []
    for rel in data.get("relationships", []):
        if rel.get("spdxElementId") == "SPDXRef-DOCUMENT" and rel.get("relationshipType") == "DESCRIBES":
            related = rel.get("relatedSpdxElement")
            if related and related not in seen:
                seen.add(related)
                describes.append(related)

    if not describes:
        return 0

    # Merge with any existing documentDescribes to avoid discarding entries
    existing = data.get("documentDescribes")
    if isinstance(existing, list):
        existing_set = set(existing)
        new_entries = [d for d in describes if d not in existing_set]
        if not new_entries:
            return 0
        existing.extend(new_entries)
        added_count = len(new_entries)
    else:
        data["documentDescribes"] = describes
        added_count = len(describes)

    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        logger.debug(f"Restored documentDescribes with {added_count} element(s)")
    except OSError as e:
        logger.warning(f"Failed to write SPDX file with documentDescribes: {e}")
        return 0

    return added_count


def sanitize_dependency_graph(bom: Bom) -> int:
    """
    Fix orphaned dependency references by adding stub components for missing refs.

    Some SBOM generators (like CycloneDX webpack plugin) may produce SBOMs with
    dependency graph entries that reference components not included in the BOM.
    The cyclonedx-python library's validate() rejects such SBOMs. This function
    creates minimal stub components for missing references to make the tool
    resilient to malformed inputs while preserving the dependency graph structure.

    Args:
        bom: The CycloneDX BOM object to sanitize (modified in place)

    Returns:
        Number of stub components added
    """
    from cyclonedx.model import BomRef  # type: ignore[attr-defined]
    from cyclonedx.model.component import Component, ComponentType

    # Collect all known BomRef values
    known_refs: set[str] = set()

    # Add component BomRefs
    for comp in bom.components:
        if comp.bom_ref and comp.bom_ref.value:
            known_refs.add(comp.bom_ref.value)

    # Add service BomRefs
    for service in bom.services:
        if service.bom_ref and service.bom_ref.value:
            known_refs.add(service.bom_ref.value)

    # Add metadata component BomRef
    if bom.metadata and bom.metadata.component:
        if bom.metadata.component.bom_ref and bom.metadata.component.bom_ref.value:
            known_refs.add(bom.metadata.component.bom_ref.value)

    # Collect all refs used in dependency graph
    dependency_refs: set[str] = set()
    for dep in bom.dependencies:
        if dep.ref and dep.ref.value:
            dependency_refs.add(dep.ref.value)
        for nested_dep in dep.dependencies:
            if nested_dep.ref and nested_dep.ref.value:
                dependency_refs.add(nested_dep.ref.value)

    # Find orphaned refs (in dependencies but not in components)
    orphaned_refs = dependency_refs - known_refs

    if not orphaned_refs:
        return 0

    tracker = get_transformation_tracker()
    stubs_added = 0

    for ref_value in orphaned_refs:
        # Try to parse as PURL to get component info
        name, version, namespace, purl_obj = _extract_component_info_from_purl(ref_value)

        if name:
            # Create stub component from PURL info
            stub = Component(
                type=ComponentType.LIBRARY,
                name=name,
                version=version or _UNKNOWN_VERSION,
                bom_ref=BomRef(ref_value),
            )
            if namespace:
                stub.group = namespace
            if purl_obj:
                stub.purl = purl_obj

            # Record for attestation
            tracker.record_stub_added(ref_value, name, version or _UNKNOWN_VERSION)
        else:
            # Can't parse as PURL - create minimal stub with ref as name
            stub = Component(
                type=ComponentType.LIBRARY,
                name=ref_value,
                version=_UNKNOWN_VERSION,
                bom_ref=BomRef(ref_value),
            )
            # Record for attestation
            tracker.record_stub_added(ref_value, ref_value, _UNKNOWN_VERSION)

        bom.components.add(stub)
        stubs_added += 1

    logger.info(
        f"Dependency graph sanitization: added {stubs_added} stub component(s) for orphaned references. "
        "These stubs may be enriched in the enrichment step."
    )

    return stubs_added


def link_root_dependencies(bom: Bom) -> int:
    """
    Link top-level components as dependencies of the root component.

    When the root component has no dependencies defined, this function links all
    top-level components (those not already nested dependencies of other components)
    as direct dependencies of the root. This fixes CycloneDX library warnings about
    incomplete dependency graphs while preserving existing hierarchical relationships.

    Args:
        bom: The CycloneDX BOM object to modify (modified in place)

    Returns:
        Number of dependencies linked to root (0 if root already has dependencies
        or no root component exists)
    """
    from cyclonedx.model import BomRef  # type: ignore[attr-defined]
    from cyclonedx.model.dependency import Dependency

    # Check if root component exists
    if not bom.metadata or not bom.metadata.component:
        logger.debug("No root component found, skipping dependency linking")
        return 0

    root_component = bom.metadata.component
    if not root_component.bom_ref or not root_component.bom_ref.value:
        logger.debug("Root component has no bom-ref, skipping dependency linking")
        return 0

    root_ref_value = root_component.bom_ref.value

    # Find or create the root's dependency entry
    root_dep: Dependency | None = None
    for dep in bom.dependencies:
        if dep.ref and dep.ref.value == root_ref_value:
            root_dep = dep
            break

    # If root dependency entry doesn't exist, create it
    if root_dep is None:
        root_dep = Dependency(ref=BomRef(root_ref_value))
        bom.dependencies.add(root_dep)

    # Check if root already has dependencies defined
    if root_dep.dependencies and len(root_dep.dependencies) > 0:
        logger.debug(
            f"Root component '{root_component.name}' already has {len(root_dep.dependencies)} dependencies, skipping"
        )
        return 0

    # Collect all refs that are nested dependencies of other components
    # These are "transitive" dependencies - not top-level
    nested_refs: set[str] = set()
    for dep in bom.dependencies:
        for nested_dep in dep.dependencies:
            if nested_dep.ref and nested_dep.ref.value:
                nested_refs.add(nested_dep.ref.value)

    # Collect all component bom-refs
    all_component_refs: set[str] = set()
    for comp in bom.components:
        if comp.bom_ref and comp.bom_ref.value:
            all_component_refs.add(comp.bom_ref.value)

    # Top-level = all component refs - nested refs - root ref
    top_level_refs = all_component_refs - nested_refs - {root_ref_value}

    if not top_level_refs:
        logger.debug("No top-level components to link to root")
        return 0

    # Link top-level components as direct dependencies of root
    for ref_value in top_level_refs:
        root_dep.dependencies.add(Dependency(ref=BomRef(ref_value)))

    # Record for attestation
    tracker = get_transformation_tracker()
    tracker.record_root_dependencies_linked(root_component.name, len(top_level_refs))

    logger.info(f"Linked {len(top_level_refs)} top-level component(s) as dependencies of root '{root_component.name}'")

    return len(top_level_refs)


def serialize_cyclonedx_bom(bom: Bom, spec_version: Optional[str] = None) -> str:
    """
    Serialize a CycloneDX BOM to JSON string using the appropriate version outputter.

    This function automatically selects the correct serializer based on the spec version,
    supporting multiple CycloneDX versions (1.4, 1.5, 1.6, 1.7, and future versions like 2.0).

    Args:
        bom: The CycloneDX BOM object to serialize
        spec_version: The CycloneDX spec version (e.g., "1.5", "1.6", "1.7", "2.0").
                     If None, will try to detect from BOM object. Raises ValueError if not found.

    Returns:
        JSON string representation of the BOM

    Raises:
        ValueError: If spec_version is unsupported or cannot be determined

    Examples:
        >>> bom = Bom.from_json(data)
        >>> # Serialize as CycloneDX 1.6
        >>> json_str = serialize_cyclonedx_bom(bom, "1.6")
        >>>
        >>> # Auto-detect version from BOM
        >>> json_str = serialize_cyclonedx_bom(bom)
    """
    # Detect version if not provided
    if spec_version is None:
        # Try to get from BOM metadata if available
        if hasattr(bom, "spec_version") and bom.spec_version:
            spec_version = str(bom.spec_version)
        else:
            # Fail fast - do not default to a version
            raise ValueError(
                "spec_version is required for serialization. CycloneDX SBOM must have a valid specVersion field."
            )

    # Get the appropriate outputter class
    outputter_class = _get_cyclonedx_outputter(spec_version)

    logger.debug(f"Serializing CycloneDX BOM using version {spec_version}")

    # Capture CycloneDX library warnings and re-emit with cleaner formatting
    # The library emits UserWarnings for incomplete dependency graphs which can be confusing
    with warnings.catch_warnings(record=True) as caught_warnings:
        warnings.simplefilter("always", UserWarning)
        outputter = outputter_class(bom)
        result = outputter.output_as_string()

    # Process captured warnings and re-emit with user-friendly messages
    for w in caught_warnings:
        warning_msg = str(w.message)
        if "has no defined dependencies" in warning_msg:
            # Re-emit the CycloneDX dependency graph warning with cleaner message
            root_name = bom.metadata.component.name if bom.metadata.component else "unknown"
            logger.warning(
                f"SBOM dependency graph is incomplete: root component '{root_name}' has no dependencies defined. "
                f"This is common when the SBOM generator doesn't track dependency relationships."
            )
        else:
            # Re-emit other warnings as-is using our logger
            logger.warning(f"CycloneDX serialization warning: {warning_msg}")

    # Post-process JSON to fix PURL encoding bugs (double %40%40 or double @@)
    # Note: We preserve the canonical %40 encoding per PURL spec
    result = _fix_purl_encoding_bugs_in_json(result)

    return result


def _fix_purl_encoding_bugs_in_json(json_str: str) -> str:
    """
    Fix PURL encoding bugs in a serialized JSON string.

    This function fixes common encoding bugs in PURLs:
    - Double-encoded @ symbols: %40%40 → %40
    - Double @@ symbols: @@ → @

    Note: This preserves the canonical %40 encoding for @ in namespaces,
    which is correct per the PURL spec.

    Args:
        json_str: Serialized JSON string

    Returns:
        JSON string with fixed PURLs
    """
    # Fix double-encoded %40 sequences in PURLs
    result = _DOUBLE_ENCODED_AT_PATTERN.sub("%40", json_str)

    # Fix double @@ in PURLs (e.g., before version separator)
    # This regex targets @@ within PURL strings to avoid affecting other JSON content
    def fix_double_at(match: re.Match[str]) -> str:
        purl = match.group(0)
        return _DOUBLE_AT_PATTERN.sub("@", purl)

    # Use a more specific pattern to match valid PURLs and avoid unintended replacements
    result = re.sub(r'"pkg:[a-z0-9+.-]+[:/][^"]*"', fix_double_at, result)

    return result


def _add_compositions_if_missing(json_str: str) -> str:
    """Add CycloneDX compositions with completeness indicator if missing.

    BSI TR-03183-2 §5.2.2 requires dependencies with a completeness indicator.
    The CycloneDX library (v10.x) doesn't support compositions yet, so we
    inject it as JSON post-processing. Sets aggregate to "incomplete" (safe
    default — lockfile-based SBOMs may not capture all transitive deps).
    """
    import json as _json

    try:
        data = _json.loads(json_str)
    except _json.JSONDecodeError:
        return json_str

    if not isinstance(data, dict):
        return json_str

    if data.get("compositions"):
        return json_str  # already has compositions

    # Only add for CycloneDX 1.5+ (compositions introduced in 1.3,
    # but widely supported from 1.5+)
    spec_version = data.get("specVersion", "")
    if spec_version:
        try:
            major, minor = (int(x) for x in spec_version.split(".")[:2])
            if (major, minor) < (1, 5):
                return json_str
        except (ValueError, TypeError):
            pass  # unparseable version — proceed anyway

    # Add a top-level composition indicating dependency completeness.
    metadata = data.get("metadata") or {}
    main_component = metadata.get("component") or {}
    main_ref = main_component.get("bom-ref") if isinstance(main_component, dict) else None

    composition: dict[str, Any] = {"aggregate": "incomplete"}
    if main_ref:
        composition["assemblies"] = [main_ref]

    data["compositions"] = [composition]

    return _json.dumps(data, indent=2, ensure_ascii=False)


# ============================================================================
# SPDX Version Management
# ============================================================================

# SPDX versions supported (2.x via spdx-tools library, 3.0.1 via custom parser/writer in spdx3.py)
SUPPORTED_SPDX_VERSIONS = ["2.2", "2.3", "3.0.1"]

# Default SPDX version
DEFAULT_SPDX_VERSION = "2.3"


def detect_spdx_version(document: Document) -> str:
    """
    Detect SPDX version from a document.

    Args:
        document: SPDX document object

    Returns:
        Version string (e.g., "2.3", "3.0")

    Examples:
        >>> document = spdx_parse_file("sbom.spdx.json")
        >>> version = detect_spdx_version(document)
        >>> print(version)  # "2.3"
    """
    if hasattr(document, "creation_info") and hasattr(document.creation_info, "spdx_version"):
        version_str = document.creation_info.spdx_version
        # Extract version number from "SPDX-2.3" format
        if version_str and version_str.startswith("SPDX-"):
            return str(version_str.replace("SPDX-", ""))

    logger.debug(f"Could not detect SPDX version, defaulting to {DEFAULT_SPDX_VERSION}")
    return DEFAULT_SPDX_VERSION


def validate_spdx_version(version: str) -> bool:
    """
    Check if SPDX version is supported.

    Args:
        version: SPDX version string (e.g., "2.3", "3.0")

    Returns:
        True if supported, False otherwise

    Examples:
        >>> validate_spdx_version("2.3")
        True
        >>> validate_spdx_version("3.0")
        False  # Until SPDX 3.0 support is added
    """
    return version in SUPPORTED_SPDX_VERSIONS


def get_supported_cyclonedx_versions() -> list[str]:
    """
    Get list of supported CycloneDX versions.

    Returns:
        List of version strings (e.g., ["1.4", "1.5", "1.6"])
    """
    return sorted(_CYCLONEDX_OUTPUTTERS.keys())


def get_supported_spdx_versions() -> list[str]:
    """
    Get list of supported SPDX versions.

    Returns:
        List of version strings (e.g., ["2.2", "2.3"])
    """
    return SUPPORTED_SPDX_VERSIONS.copy()


# ============================================================================
# License Sanitization
# ============================================================================


def _is_compound_expression(license_str: str) -> bool:
    """Check if a license string is a compound SPDX expression (OR/AND).

    Uses the license-expression library's parsed AST to detect compound
    expressions. Returns True only for OR/AND nodes. WITH clauses and
    single IDs return False. Unparseable strings return False — they'll
    be caught by _is_valid_spdx_license_id and moved to license.name.
    """
    if not license_str or len(license_str) > 1024:
        return False

    from license_expression import AND, OR

    try:
        parsed = _spdx_licensing_singleton().parse(license_str, validate=False)
        return isinstance(parsed, (OR, AND))
    except ExpressionError:
        return False


def _is_valid_spdx_license_id(license_id: str) -> bool:
    """
    Check if a string is a valid SPDX license ID using the license-expression library.

    Args:
        license_id: The license ID string to check

    Returns:
        True if it's a valid SPDX license ID, False otherwise
    """
    if not license_id:
        return False

    # Import here to avoid circular imports
    from ._enrichment.license_utils import validate_spdx_expression

    return validate_spdx_expression(license_id)


def sanitize_cyclonedx_licenses(data: dict[str, Any]) -> int:
    """
    Sanitize CycloneDX license data by fixing invalid license IDs and expressions.

    This handles three cases:
    1. Compound expressions in license.id (OR/AND): moved to expression field
    2. Invalid license.id values: moved to license.name field
    3. Invalid expression values: invalid IDs replaced with LicenseRef-* format

    Some SBOM generators incorrectly put compound SPDX expressions or
    non-SPDX license strings in the license.id field, which causes
    schema validation failures.

    Args:
        data: CycloneDX SBOM data as a dict (modified in place)

    Returns:
        Number of licenses that were sanitized
    """
    sanitized_count = 0
    tracker = get_transformation_tracker()

    def _sanitize_license_choices(license_choices: list[Any], component: str | None = None) -> int:
        """Process a list of licenseChoice objects."""
        count = 0
        for choice in license_choices:
            if not isinstance(choice, dict):
                continue

            # Handle license.id field
            license_obj = choice.get("license")
            if isinstance(license_obj, dict):
                license_id = license_obj.get("id")
                if license_id:
                    # Compound expressions (containing OR/AND) belong in expression, not id
                    if _is_compound_expression(license_id):
                        # Remove the license wrapper — expression is a peer of license, not nested
                        existing_expr = choice.get("expression")
                        choice.pop("license", None)
                        if not existing_expr:
                            choice["expression"] = license_id
                            logger.debug("Moving compound expression from license.id to expression: %r", license_id)
                            tracker.record_license_sanitized(
                                license_id, f"expression:{license_id}", component=component
                            )
                        else:
                            logger.warning(
                                "Both license.id=%r (compound) and expression=%r present "
                                "in same licenseChoice — discarding license.id",
                                license_id,
                                existing_expr,
                            )
                        count += 1
                        continue  # skip expression sanitization for this choice
                    elif not _is_valid_spdx_license_id(license_id):
                        # Move invalid id to name
                        logger.debug(f"Sanitizing invalid license ID: {license_id} -> name")
                        del license_obj["id"]
                        license_obj["name"] = license_id
                        tracker.record_license_sanitized(license_id, f"name:{license_id}", component=component)
                        count += 1

            # Handle expression field
            expression = choice.get("expression")
            if expression and isinstance(expression, str):
                sanitized_expr, was_modified = _sanitize_spdx_license_expression(expression)
                if was_modified:
                    logger.debug(f"Sanitizing invalid license expression: {expression} -> {sanitized_expr}")
                    choice["expression"] = sanitized_expr
                    tracker.record_license_sanitized(expression, sanitized_expr, component=component)
                    count += 1

        return count

    # Process metadata licenses
    metadata = data.get("metadata", {})
    if "licenses" in metadata:
        sanitized_count += _sanitize_license_choices(metadata["licenses"], component="metadata")

    # Process component licenses
    components = data.get("components", [])
    for component in components:
        comp_name = component.get("name")
        if "licenses" in component:
            sanitized_count += _sanitize_license_choices(component["licenses"], component=comp_name)

    # Process service licenses (if present)
    services = data.get("services", [])
    for service in services:
        svc_name = service.get("name")
        if "licenses" in service:
            sanitized_count += _sanitize_license_choices(service["licenses"], component=svc_name)

    if sanitized_count > 0:
        logger.info(f"Sanitized {sanitized_count} license issue(s) (invalid IDs and/or compound expressions)")

    return sanitized_count


# "LicenseRef-" prefix (11 chars) + max 65 chars for the identifier
_MAX_LICENSE_REF_LENGTH = 76


def _to_license_ref(key: str) -> str:
    """Convert an arbitrary string to a valid LicenseRef-* identifier."""
    sanitized_id = re.sub(r"[^a-zA-Z0-9.\-]", "-", key)
    sanitized_id = re.sub(r"-+", "-", sanitized_id).strip("-")
    if sanitized_id:
        return f"LicenseRef-{sanitized_id}"
    return "LicenseRef-unknown"


def _sanitize_spdx_license_expression(expression: str) -> tuple[str, bool]:
    """
    Sanitize an SPDX license expression by converting invalid IDs to LicenseRef format.

    Uses the license-expression library to parse the expression tree, identify
    unknown license symbols, and substitute them with LicenseRef-* equivalents
    using the library's own subs() method (no regex needed).

    Args:
        expression: The license expression to sanitize

    Returns:
        Tuple of (sanitized expression, was_modified)
    """
    from license_expression import ExpressionError, LicenseWithExceptionSymbol, get_spdx_licensing

    if not expression or expression in ("NOASSERTION", "NONE"):
        return expression, False

    spdx_licensing = get_spdx_licensing()

    try:
        parsed = spdx_licensing.parse(expression, validate=False)
        unknown_keys = spdx_licensing.unknown_license_keys(parsed)

        if not unknown_keys:
            return expression, False

        # Build symbol substitution map: old_symbol -> new_expression
        unknown_set = {str(k) for k in unknown_keys}
        subs_map = {}
        for sym in parsed.symbols:
            # LicenseWithExceptionSymbol (e.g. "MIT WITH Exception") has no .key;
            # check its license_symbol and exception_symbol sub-keys instead.
            if isinstance(sym, LicenseWithExceptionSymbol):
                lic_key = sym.license_symbol.key
                exc_key = sym.exception_symbol.key
                lic_ref = (
                    _to_license_ref(lic_key)
                    if lic_key in unknown_set and not lic_key.startswith("LicenseRef-")
                    else lic_key
                )
                exc_ref = (
                    _to_license_ref(exc_key)
                    if exc_key in unknown_set and not exc_key.startswith("LicenseRef-")
                    else exc_key
                )
                if lic_ref != lic_key or exc_ref != exc_key:
                    logger.debug(
                        f"Converting invalid SPDX license WITH expression: '{lic_key} WITH {exc_key}' to '{lic_ref} WITH {exc_ref}'"
                    )
                    subs_map[sym] = spdx_licensing.parse(f"{lic_ref} WITH {exc_ref}", validate=False)
                continue

            key_str = sym.key
            if key_str not in unknown_set or key_str.startswith("LicenseRef-"):
                continue
            license_ref = _to_license_ref(key_str)
            logger.debug(f"Converting invalid SPDX license '{key_str}' to '{license_ref}'")
            subs_map[sym] = spdx_licensing.parse(license_ref, validate=False)

        if not subs_map:
            return expression, False

        result = parsed.subs(subs_map)
        return result.render(), True

    except ExpressionError as e:
        # Expression couldn't be parsed at all - convert entire thing to LicenseRef
        logger.debug(f"Could not parse license expression '{expression}': {e}")
        sanitized = _to_license_ref(expression)
        if len(sanitized) <= _MAX_LICENSE_REF_LENGTH:
            return sanitized, True
        else:
            hash_val = hashlib.md5(expression.encode(), usedforsecurity=False).hexdigest()[:16]
            return f"LicenseRef-{hash_val}", True


def sanitize_spdx_licenses(data: dict[str, Any]) -> int:
    """
    Sanitize SPDX license data by converting invalid license IDs to LicenseRef format.

    Some SBOM generators (like Trivy) output non-SPDX license strings in license fields.
    This function converts invalid licenses to LicenseRef-* format which is valid in SPDX.

    Args:
        data: SPDX SBOM data as a dict (modified in place)

    Returns:
        Number of licenses that were sanitized
    """
    sanitized_count = 0
    tracker = get_transformation_tracker()

    def _sanitize_license_field(obj: dict[str, Any], field: str, component: str | None = None) -> int:
        """Sanitize a single license field."""
        value = obj.get(field)
        if not value or not isinstance(value, str):
            return 0

        sanitized, was_modified = _sanitize_spdx_license_expression(value)
        if was_modified:
            logger.debug(f"Sanitizing invalid SPDX license: {value} -> {sanitized}")
            obj[field] = sanitized
            tracker.record_license_sanitized(value, sanitized, component=component)
            return 1
        return 0

    def _sanitize_license_list(obj: dict[str, Any], field: str, component: str | None = None) -> int:
        """Sanitize a list of license strings."""
        values = obj.get(field)
        if not values or not isinstance(values, list):
            return 0

        count = 0
        for i, value in enumerate(values):
            if not isinstance(value, str):
                continue
            sanitized, was_modified = _sanitize_spdx_license_expression(value)
            if was_modified:
                logger.debug(f"Sanitizing invalid SPDX license: {value} -> {sanitized}")
                values[i] = sanitized
                tracker.record_license_sanitized(value, sanitized, component=component)
                count += 1
        return count

    # Process packages
    for package in data.get("packages", []):
        pkg_name = package.get("name")
        sanitized_count += _sanitize_license_field(package, "licenseConcluded", component=pkg_name)
        sanitized_count += _sanitize_license_field(package, "licenseDeclared", component=pkg_name)
        sanitized_count += _sanitize_license_list(package, "licenseInfoFromFiles", component=pkg_name)

    # Process files
    for file in data.get("files", []):
        file_name = file.get("fileName") or file.get("SPDXID")
        sanitized_count += _sanitize_license_field(file, "licenseConcluded", component=file_name)
        sanitized_count += _sanitize_license_list(file, "licenseInfoInFiles", component=file_name)

    # Process snippets
    for snippet in data.get("snippets", []):
        snippet_name = snippet.get("name") or snippet.get("SPDXID")
        sanitized_count += _sanitize_license_field(snippet, "licenseConcluded", component=snippet_name)
        sanitized_count += _sanitize_license_list(snippet, "licenseInfoInSnippets", component=snippet_name)

    if sanitized_count > 0:
        logger.info(f"Sanitized {sanitized_count} invalid SPDX license(s) to LicenseRef format")

    return sanitized_count
