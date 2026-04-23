"""SBOM enrichment using plugin-based data sources with native library support.

This module provides SBOM enrichment through a plugin architecture that queries
multiple data sources in priority order to populate NTIA-required fields.

Data Source Priority (lower number = higher priority):
    Tier 0 - Pre-computed Databases (1-9):
    - LicenseDBSource (1): Pre-computed license database with validated SPDX
      licenses and full metadata for Alpine, Wolfi, Ubuntu, Rocky, Alma,
      CentOS, Fedora, and Amazon Linux packages. Top priority as it provides
      fast, accurate data without network requests.

    Tier 1 - Native Sources (10-19):
    - PyPISource (10): Direct from PyPI for Python packages
    - PubDevSource (10): Direct from pub.dev for Dart packages
    - CratesIOSource (10): Direct from crates.io for Rust packages
    - DebianSource (10): Direct from sources.debian.org

    Tier 2 - Primary Aggregators (40-49):
    - DepsDevSource (40): Google Open Source Insights
    - EcosystemsSource (45): ecosyste.ms multi-ecosystem aggregator

    Tier 3 - Fallback Sources (70-99):
    - PURLSource (70): Local PURL extraction for OS packages (no API)
    - ClearlyDefinedSource (75): License and attribution data
    - RepologySource (90): Cross-distro metadata (rate-limited)

NTIA Minimum Elements (July 2021):
    https://sbomify.com/compliance/ntia-minimum-elements/

    Enrichment adds to each component:
    - Supplier Name: CycloneDX components[].publisher / SPDX packages[].supplier
    - License: CycloneDX components[].licenses[] / SPDX packages[].licenseDeclared

CISA 2025 Additional Fields:
    https://sbomify.com/compliance/cisa-minimum-elements/

    Enrichment adds:
    - Component Hash: From generators (not enrichment)
    - License: CycloneDX components[].licenses[] / SPDX packages[].licenseDeclared

Field mappings per schema crosswalk:
    https://sbomify.com/compliance/schema-crosswalk/

Plugin architecture is in sbomify_action/_enrichment/:
- metadata.py: NormalizedMetadata dataclass
- protocol.py: DataSource protocol
- registry.py: SourceRegistry class
- enricher.py: Enricher orchestration class
- sources/: Individual data source implementations
"""

import json
import os
import re as _re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cyclonedx.model import ExternalReference, ExternalReferenceType, HashAlgorithm, HashType, Property, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.contact import OrganizationalContact, OrganizationalEntity
from cyclonedx.model.license import LicenseAcknowledgement, LicenseExpression
from spdx_tools.spdx.model import (  # type: ignore[attr-defined]
    Actor,
    ActorType,
    Checksum,
    ChecksumAlgorithm,
    Document,
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
    SpdxNoAssertion,
    SpdxNone,
)
from spdx_tools.spdx.parser.jsonlikedict.license_expression_parser import LicenseExpressionParser
from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file
from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

from . import format_display_name

# Import from plugin architecture
from ._enrichment.enricher import Enricher, clear_all_caches
from ._enrichment.lifecycle_data import get_distro_lifecycle
from ._enrichment.metadata import NormalizedMetadata
from ._enrichment.sanitization import (
    sanitize_description,
    sanitize_email,
    sanitize_license,
    sanitize_supplier,
    sanitize_url,
)
from ._enrichment.sources.purl import NAMESPACE_TO_SUPPLIER
from .console import get_audit_trail
from .exceptions import SBOMValidationError
from .generation import (
    CPP_LOCK_FILES,
    DART_LOCK_FILES,
    GO_LOCK_FILES,
    JAVASCRIPT_LOCK_FILES,
    PYTHON_LOCK_FILES,
    RUBY_LOCK_FILES,
    RUST_LOCK_FILES,
)
from .logging_config import logger
from .serialization import (
    link_root_dependencies,
    restore_spdx_document_describes,
    sanitize_cyclonedx_licenses,
    sanitize_dependency_graph,
    sanitize_purls,
    sanitize_spdx_json_file,
    sanitize_spdx_purls,
    serialize_cyclonedx_bom,
)
from .validation import validate_sbom_file_auto


def _sanitize_and_serialize_cyclonedx(bom: Bom, spec_version: str) -> str:
    """
    Sanitize PURLs, dependency graph and serialize CycloneDX BOM.

    This is the final modification step before serialization. It:
    1. Normalizes PURLs (fixes encoding issues like double @@)
    2. Clears invalid PURLs that cannot be fixed (local workspace packages, path-based versions)
    3. Adds stub components for any orphaned dependency references

    Args:
        bom: The CycloneDX BOM to sanitize and serialize
        spec_version: The CycloneDX spec version

    Returns:
        Serialized JSON string
    """
    normalized_count, cleared_count = sanitize_purls(bom)
    logger.debug(
        "PURL sanitization completed: %d normalized, %d cleared",
        normalized_count,
        cleared_count,
    )
    sanitize_dependency_graph(bom)
    link_root_dependencies(bom)
    return serialize_cyclonedx_bom(bom, spec_version)


# Combine all lockfile names into a single set for efficient lookup
ALL_LOCKFILE_NAMES = set(
    PYTHON_LOCK_FILES
    + RUST_LOCK_FILES
    + JAVASCRIPT_LOCK_FILES
    + RUBY_LOCK_FILES
    + GO_LOCK_FILES
    + DART_LOCK_FILES
    + CPP_LOCK_FILES
)

# Human-readable descriptions for lockfile types (for NTIA compliance)
# Note: This includes lockfiles we generate from AND those that might appear
# in container/filesystem scans via Trivy
LOCKFILE_DESCRIPTIONS = {
    # Python
    "requirements.txt": "Python pip requirements manifest",
    "pyproject.toml": "Python project configuration",
    "Pipfile": "Python Pipenv manifest",
    "Pipfile.lock": "Python Pipenv lockfile",
    "poetry.lock": "Python Poetry lockfile",
    "uv.lock": "Python uv lockfile",
    "pdm.lock": "Python PDM lockfile",
    "conda-lock.yml": "Conda environment lockfile",
    # Rust
    "Cargo.lock": "Rust Cargo lockfile",
    # JavaScript
    "package.json": "JavaScript package manifest",
    "package-lock.json": "JavaScript npm lockfile",
    "yarn.lock": "JavaScript Yarn lockfile",
    "pnpm-lock.yaml": "JavaScript pnpm lockfile",
    "bun.lock": "JavaScript Bun lockfile",
    "npm-shrinkwrap.json": "JavaScript npm shrinkwrap lockfile",
    # Ruby
    "Gemfile.lock": "Ruby Bundler lockfile",
    # Go
    "go.sum": "Go module checksums",
    "go.mod": "Go module definition",
    # Dart
    "pubspec.lock": "Dart pub lockfile",
    # C++
    "conan.lock": "C++ Conan lockfile",
    "vcpkg.json": "C++ vcpkg manifest",
}

# CycloneDX component type for operating system
COMPONENT_TYPE_OPERATING_SYSTEM = "operating_system"

# Delimiter used for SPDX package comment entries
COMMENT_DELIMITER = " | "


def clear_cache() -> None:
    """Clear all cached metadata from all data sources."""
    clear_all_caches()
    logger.debug("All metadata caches cleared")


def _is_lockfile_component(component: Component) -> bool:
    """Check if a CycloneDX component represents a lockfile artifact."""
    if component.type != ComponentType.APPLICATION:
        return False
    if component.purl:
        return False
    if component.name and component.name in ALL_LOCKFILE_NAMES:
        return True
    return False


def _enrich_lockfile_components(bom: Bom) -> int:
    """
    Enrich lockfile components in a CycloneDX BOM with NTIA-compliant metadata.

    Instead of removing lockfiles, we enrich them with:
    - Description: Human-readable description based on lockfile type
    - Supplier: Same as the root component (metadata.component or metadata.supplier)
    - Version: Inherited from root component or set to "0"

    Note: bom-ref already serves as the unique identifier for CycloneDX.

    This preserves the dependency graph integrity.
    """
    lockfile_components = [c for c in bom.components if _is_lockfile_component(c)]

    if not lockfile_components:
        return 0

    # Get supplier from root component or BOM metadata
    root_supplier = None
    if bom.metadata.component and bom.metadata.component.supplier:
        root_supplier = bom.metadata.component.supplier
    elif bom.metadata.supplier:
        root_supplier = bom.metadata.supplier

    # Get version from root component for lockfile version inheritance
    root_version = None
    if bom.metadata.component and bom.metadata.component.version:
        root_version = bom.metadata.component.version

    for component in lockfile_components:
        # Add description if not present
        if not component.description and component.name:
            description = LOCKFILE_DESCRIPTIONS.get(component.name)
            if description:
                component.description = description
                logger.debug(f"Added description to lockfile: {component.name}")

        # Add supplier from root component if not present
        if not component.supplier and root_supplier:
            component.supplier = root_supplier
            logger.debug(f"Added supplier to lockfile: {component.name}")

        # Add version if not present (lockfiles don't have natural versions)
        # Use root component version (set by COMPONENT_VERSION env var) or fallback to "unversioned"
        if not component.version:
            component.version = root_version if root_version else "unversioned"
            logger.debug(f"Added version to lockfile: {component.name} -> {component.version}")

        logger.info(f"Enriched lockfile component: {component.name}")

    return len(lockfile_components)


def _is_lockfile_package(package: Package) -> bool:
    """Check if an SPDX package represents a lockfile artifact.

    Handles full paths like /github/workspace/uv.lock by extracting the basename.
    """
    if not package.name:
        return False
    # Extract basename to handle full paths (e.g., /github/workspace/uv.lock -> uv.lock)
    basename = os.path.basename(package.name)
    if basename in ALL_LOCKFILE_NAMES:
        has_purl = any(ref.reference_type == "purl" for ref in package.external_references)
        if not has_purl:
            return True
    return False


def _enrich_lockfile_packages(document: Document) -> int:
    """
    Enrich lockfile packages in an SPDX document with NTIA-compliant metadata.

    Instead of removing lockfiles, we enrich them with:
    - Description: Human-readable description based on lockfile type
    - Supplier: Same as the main package (first package in document)
    - Version: Inherited from main package or set to "0"

    Note: SPDX spdx_id already serves as the unique identifier.

    This preserves the relationship graph integrity.
    """
    lockfile_packages = [p for p in document.packages if _is_lockfile_package(p)]

    if not lockfile_packages:
        return 0

    # Get supplier and version from the main package (usually first package represents the described component)
    root_supplier = None
    root_version = None
    if document.packages:
        for pkg in document.packages:
            if pkg.supplier and not isinstance(pkg.supplier, (SpdxNoAssertion, SpdxNone)):
                root_supplier = pkg.supplier
            if pkg.version and pkg.version != "NOASSERTION":
                root_version = pkg.version
            if root_supplier and root_version:
                break

    for pkg in lockfile_packages:
        # Add description if not present
        if (not pkg.description or pkg.description == "NOASSERTION") and pkg.name:
            # Use basename to lookup description (handles full paths like /github/workspace/uv.lock)
            basename = os.path.basename(pkg.name)
            description = LOCKFILE_DESCRIPTIONS.get(basename)
            if description:
                pkg.description = description
                logger.debug(f"Added description to lockfile: {pkg.name}")

        # Add supplier from root package if not present
        if root_supplier and (not pkg.supplier or isinstance(pkg.supplier, (SpdxNoAssertion, SpdxNone))):
            pkg.supplier = root_supplier
            logger.debug(f"Added supplier to lockfile: {pkg.name}")

        # Add version if not present (lockfiles don't have natural versions)
        # Use root package version (set by COMPONENT_VERSION env var) or fallback to "unversioned"
        if not pkg.version or pkg.version == "NOASSERTION":
            pkg.version = root_version if root_version else "unversioned"
            logger.debug(f"Added version to lockfile: {pkg.name} -> {pkg.version}")

        logger.info(f"Enriched lockfile package: {pkg.name}")

    return len(lockfile_packages)


def _add_enrichment_source_property(component: Component, source: str) -> None:
    """Add enrichment source property to a CycloneDX component."""
    property_name = "sbomify:enrichment:source"
    for prop in component.properties:
        if prop.name == property_name:
            return
    component.properties.add(Property(name=property_name, value=source))


def _add_enrichment_source_comment(package: Package, source: str) -> None:
    """Add enrichment source comment to an SPDX package."""
    enrichment_note = f"Enriched by sbomify from {source}"
    if package.comment:
        comment_entries = [entry.strip() for entry in package.comment.split(COMMENT_DELIMITER)]
        if enrichment_note not in comment_entries:
            comment_entries.append(enrichment_note)
        package.comment = COMMENT_DELIMITER.join(comment_entries)
    else:
        package.comment = enrichment_note


def _extract_components_from_cyclonedx(bom: Bom) -> List[Tuple[Component, str]]:
    """Extract components from CycloneDX BOM."""
    components = []
    for component in bom.components:
        if component.purl:
            components.append((component, str(component.purl)))
    return components


def _extract_packages_from_spdx(document: Document) -> List[Tuple[Package, str]]:
    """Extract packages from SPDX document."""
    packages = []
    for package in document.packages:
        purl = None
        for ref in package.external_references:
            if ref.reference_type == "purl":
                purl = ref.locator
                break
        if purl:
            packages.append((package, purl))
    return packages


# Filename suffixes that BSI TR-03183-2 §5.2.2 recognises as archives.
# Covers common language-agnostic wheel / tarball / zip / container formats.
_BSI_ARCHIVE_SUFFIXES = (
    ".whl",
    ".egg",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".zip",
    ".jar",
    ".war",
    ".ear",
    ".aar",
    ".gem",
    ".crate",
    ".deb",
    ".rpm",
    ".apk",
    ".nupkg",
    ".pkg",
    ".snap",
)

# Filename suffixes treated as stand-alone executables (not archives).
# When one of these is the filename, executable == "executable".
_BSI_EXECUTABLE_SUFFIXES = (
    ".exe",
    ".msi",
    ".bin",
    ".elf",
    ".app",
    ".dll",
    ".so",
    ".dylib",
)

# Strongly-typed components that carry enough semantics for BSI derivation
# without a distribution filename. Hoisted to module scope so the same
# tuple isn't rebuilt on every component in the enrichment loop.
_BSI_DEPLOYABLE_TYPES = (
    ComponentType.APPLICATION,
    ComponentType.CONTAINER,
    ComponentType.FIRMWARE,
    ComponentType.OPERATING_SYSTEM,
)


def _filename_suffix_matches(filename: str, suffixes: tuple[str, ...]) -> bool:
    """Case-insensitive suffix match that handles multi-part endings like .tar.gz."""
    lowered = filename.lower()
    return any(lowered.endswith(suffix) for suffix in suffixes)


def _apply_bsi_derived_properties(component: Component, metadata: NormalizedMetadata) -> List[str]:
    """Emit the three remaining BSI TR-03183-2 §5.2.2 boolean-style properties
    when they can be derived unambiguously. Each property is only added when
    absent — operator-supplied values always win.

    - bsi:component:executable   "executable" | "non-executable"
    - bsi:component:archive      "archive" | "no archive"
    - bsi:component:structured   emitted only as "structured" — any
                                 component that reaches derivation has a
                                 distribution filename or a strongly-typed
                                 packaging semantics, both of which imply
                                 an identifiable, parseable artefact per
                                 BSI §8.1.6. We don't have a reliable
                                 signal to emit "unstructured", so we
                                 leave that classification to operator
                                 input rather than guess.

    Derivation only triggers when we have a clear signal:
    - A distribution filename (filename extension drives archive/executable),
      OR
    - A strongly-typed component (application/container/firmware/operating-system)
      whose BSI semantics are unambiguous without a filename.

    A plain `library` with no filename gets nothing added — there is no
    reliable signal to distinguish a source tarball from a wheel from a
    shared-library binary.

    Returns the list of property names that were added (for audit trail).
    """
    added: List[str] = []
    # `Component.properties` can be None on deserialised or user-constructed
    # components (see _enrich_os_component which already handles this).
    # Initialise with a plain `set()` so the subsequent `.add()` calls work
    # without depending on `sortedcontainers`.
    if component.properties is None:
        component.properties = set()
    existing = {prop.name for prop in component.properties}
    filename = (metadata.distribution_filename or "").strip()
    component_type = getattr(component, "type", None)

    has_filename_signal = bool(filename)
    has_type_signal = component_type in _BSI_DEPLOYABLE_TYPES
    if not (has_filename_signal or has_type_signal):
        return added

    # --- archive ---
    archive_value: Optional[str] = None
    if "bsi:component:archive" not in existing:
        if filename and _filename_suffix_matches(filename, _BSI_ARCHIVE_SUFFIXES):
            archive_value = "archive"
        elif filename and _filename_suffix_matches(filename, _BSI_EXECUTABLE_SUFFIXES):
            archive_value = "no archive"
        elif component_type in (ComponentType.CONTAINER, ComponentType.FIRMWARE):
            archive_value = "archive"
        elif component_type in (ComponentType.APPLICATION, ComponentType.OPERATING_SYSTEM):
            # Installed OS / running application is not itself an archive.
            archive_value = "no archive"
        if archive_value is not None:
            component.properties.add(Property(name="bsi:component:archive", value=archive_value))
            added.append("bsi:component:archive")

    # --- executable ---
    exec_value: Optional[str] = None
    if "bsi:component:executable" not in existing:
        if filename and _filename_suffix_matches(filename, _BSI_EXECUTABLE_SUFFIXES):
            exec_value = "executable"
        elif component_type in _BSI_DEPLOYABLE_TYPES:
            exec_value = "executable"
        elif filename and _filename_suffix_matches(filename, _BSI_ARCHIVE_SUFFIXES):
            # Archive-packaged libraries are not themselves executable.
            exec_value = "non-executable"
        if exec_value is not None:
            component.properties.add(Property(name="bsi:component:executable", value=exec_value))
            added.append("bsi:component:executable")

    # --- structured ---
    # Packaged software artefacts (wheels, jars, debs, containers, firmware
    # images) all carry metadata files, so they qualify as "structured" per
    # BSI §8.1.6. Base the signal on the component's inherent shape, not on
    # whether this invocation happened to add archive/executable:
    #   1. A recognised filename suffix (archive OR executable) → structured.
    #   2. An existing bsi:component:archive / bsi:component:executable
    #      property already on the component (operator-supplied) → structured.
    #   3. A deployable component type (application / container / firmware /
    #      operating-system) → structured.
    # A bare `library` with an unrecognised filename suffix and no
    # operator-supplied archive/executable hints is ambiguous and gets
    # nothing — per the docstring contract, we do not guess "structured"
    # from weak signals.
    has_recognised_filename = bool(filename) and (
        _filename_suffix_matches(filename, _BSI_ARCHIVE_SUFFIXES)
        or _filename_suffix_matches(filename, _BSI_EXECUTABLE_SUFFIXES)
    )
    operator_has_archive_exec = "bsi:component:archive" in existing or "bsi:component:executable" in existing
    has_structured_signal = bool(
        has_recognised_filename
        or operator_has_archive_exec
        or archive_value is not None
        or exec_value is not None
        or component_type in _BSI_DEPLOYABLE_TYPES
    )
    if "bsi:component:structured" not in existing and has_structured_signal:
        component.properties.add(Property(name="bsi:component:structured", value="structured"))
        added.append("bsi:component:structured")

    return added


# Map SPDX-style algorithm names (PyPI digest keys) to CycloneDX HashAlgorithm.
# The CycloneDX taxonomy uses upper-case SHA-256 etc.; the PyPI JSON API and
# SPDX checksum fields use lower-case sha256 etc. We normalise to the enum.
_CYCLONEDX_HASH_ALGORITHMS: Dict[str, HashAlgorithm] = {
    "md5": HashAlgorithm.MD5,
    "sha1": HashAlgorithm.SHA_1,
    "sha-1": HashAlgorithm.SHA_1,
    "sha256": HashAlgorithm.SHA_256,
    "sha-256": HashAlgorithm.SHA_256,
    "sha384": HashAlgorithm.SHA_384,
    "sha-384": HashAlgorithm.SHA_384,
    "sha512": HashAlgorithm.SHA_512,
    "sha-512": HashAlgorithm.SHA_512,
    "sha3-256": HashAlgorithm.SHA3_256,
    "sha3-384": HashAlgorithm.SHA3_384,
    "sha3-512": HashAlgorithm.SHA3_512,
    # PyPI's JSON API historically emits BLAKE2b digests under the
    # `blake2b_256` key (underscore, not hyphen) — see pypi/warehouse
    # legacy.py. Accept both forms so PyPI-enriched SBOMs don't silently
    # drop their BLAKE2b hash. Hyphen is retained for other emitters
    # that follow the canonical BLAKE2 naming.
    "blake2b_256": HashAlgorithm.BLAKE2B_256,
    "blake2b_384": HashAlgorithm.BLAKE2B_384,
    "blake2b_512": HashAlgorithm.BLAKE2B_512,
    "blake2b-256": HashAlgorithm.BLAKE2B_256,
    "blake2b-384": HashAlgorithm.BLAKE2B_384,
    "blake2b-512": HashAlgorithm.BLAKE2B_512,
    "blake3": HashAlgorithm.BLAKE3,
}


# SPDX ChecksumAlgorithm mapping — superset of CycloneDX since SPDX has
# SHA-224, MD2/MD4/MD6 and ADLER32 in addition.
_SPDX_CHECKSUM_ALGORITHMS: Dict[str, ChecksumAlgorithm] = {
    "md5": ChecksumAlgorithm.MD5,
    "sha1": ChecksumAlgorithm.SHA1,
    "sha-1": ChecksumAlgorithm.SHA1,
    "sha224": ChecksumAlgorithm.SHA224,
    "sha-224": ChecksumAlgorithm.SHA224,
    "sha256": ChecksumAlgorithm.SHA256,
    "sha-256": ChecksumAlgorithm.SHA256,
    "sha384": ChecksumAlgorithm.SHA384,
    "sha-384": ChecksumAlgorithm.SHA384,
    "sha512": ChecksumAlgorithm.SHA512,
    "sha-512": ChecksumAlgorithm.SHA512,
    "sha3-256": ChecksumAlgorithm.SHA3_256,
    "sha3-384": ChecksumAlgorithm.SHA3_384,
    "sha3-512": ChecksumAlgorithm.SHA3_512,
    # PyPI underscore variants (see comment on the CDX mapping).
    "blake2b_256": ChecksumAlgorithm.BLAKE2B_256,
    "blake2b_384": ChecksumAlgorithm.BLAKE2B_384,
    "blake2b_512": ChecksumAlgorithm.BLAKE2B_512,
    "blake2b-256": ChecksumAlgorithm.BLAKE2B_256,
    "blake2b-384": ChecksumAlgorithm.BLAKE2B_384,
    "blake2b-512": ChecksumAlgorithm.BLAKE2B_512,
    "blake3": ChecksumAlgorithm.BLAKE3,
}


def _apply_spdx_checksums(package: Package, hashes: Dict[str, str]) -> List[str]:
    """Add distribution-artefact checksums to an SPDX package.

    Shares the same hex-length validation as the CycloneDX path so that
    any non-hex or malformed payload is rejected rather than written out
    verbatim.
    """
    added: List[str] = []
    existing = {(c.algorithm, (c.value or "").lower()) for c in (package.checksums or [])}
    for raw_alg, raw_value in hashes.items():
        alg_key = raw_alg.strip().lower()
        spdx_alg = _SPDX_CHECKSUM_ALGORITHMS.get(alg_key)
        if spdx_alg is None:
            continue
        value = (raw_value or "").strip().lower()
        if not value or not _is_valid_hex_hash(alg_key, value):
            continue
        if (spdx_alg, value) in existing:
            continue
        package.checksums.append(Checksum(algorithm=spdx_alg, value=value))
        added.append(f"checksum:{alg_key}")
        existing.add((spdx_alg, value))
    return added


# Pre-compiled hex check — restricts hash content to the characters the
# schema actually allows. Length is checked separately via _HASH_HEX_LENGTHS
# so a malicious / misbehaving source can't inject non-hex payloads (which
# would land verbatim in the emitted SBOM otherwise).
_HEX_RE = _re.compile(r"^[0-9a-f]+$")

_HASH_HEX_LENGTHS: Dict[str, int] = {
    "md5": 32,
    "sha1": 40,
    "sha-1": 40,
    "sha224": 56,
    "sha-224": 56,
    "sha256": 64,
    "sha-256": 64,
    "sha384": 96,
    "sha-384": 96,
    "sha512": 128,
    "sha-512": 128,
    "sha3-256": 64,
    "sha3-384": 96,
    "sha3-512": 128,
    # Both PyPI underscore variants (warehouse legacy.py emits
    # `blake2b_256`) and the canonical hyphen form — keep the two
    # maps mutually consistent with _CYCLONEDX_HASH_ALGORITHMS /
    # _SPDX_CHECKSUM_ALGORITHMS. Missing an entry here silently falls
    # back to the presence-only "unknown algorithm" branch, which
    # would accept a 4-char or 80-char hex payload as a valid hash.
    "blake2b_256": 64,
    "blake2b_384": 96,
    "blake2b_512": 128,
    "blake2b-256": 64,
    "blake2b-384": 96,
    "blake2b-512": 128,
}


def _is_valid_hex_hash(alg_key: str, value: str) -> bool:
    """Return True if value is a lower-case hex string of the expected
    length for the named algorithm. Unknown algorithms pass through the
    format check (presence-only) so BLAKE3 and future additions still work."""
    if not _HEX_RE.match(value):
        return False
    expected = _HASH_HEX_LENGTHS.get(alg_key)
    if expected is None:
        # For algorithms with no fixed expected length (e.g. BLAKE3),
        # just require non-empty hex.
        return len(value) > 0
    return len(value) == expected


def _apply_component_hashes(component: Component, hashes: Dict[str, str]) -> List[str]:
    """Add distribution-artefact hashes to a CycloneDX component from a
    `{algorithm: hex}` map. Only recognised algorithms with valid hex
    content of the expected length are emitted; the same (alg, content)
    pair is not duplicated across enrichment runs.

    `Component.hashes` defaults to an empty collection in the CycloneDX
    library, but deserialised or user-constructed components may legitimately
    have `hashes is None`. Initialise with a plain `set()` (matching
    `_hash_enrichment/enricher.py`) so enrichment does not crash on such
    input and does not depend on the transitive `sortedcontainers` package.
    """
    added: List[str] = []
    if component.hashes is None:
        component.hashes = set()
    existing = {(str(h.alg), str(h.content).lower()) for h in (component.hashes or [])}
    for raw_alg, raw_value in hashes.items():
        alg_key = raw_alg.strip().lower()
        cdx_alg = _CYCLONEDX_HASH_ALGORITHMS.get(alg_key)
        if cdx_alg is None:
            continue
        value = (raw_value or "").strip().lower()
        if not value or not _is_valid_hex_hash(alg_key, value):
            continue
        if (str(cdx_alg), value) in existing:
            continue
        # `component.hashes` is typed as Iterable[HashType] by the
        # cyclonedx lib (the concrete default is SortedSet), so cast it
        # locally to suppress mypy while preserving runtime behaviour.
        component.hashes.add(HashType(alg=cdx_alg, content=value))  # type: ignore[union-attr]
        added.append(f"hash:{alg_key}")
        existing.add((str(cdx_alg), value))
    return added


def _apply_metadata_to_cyclonedx_component(
    component: Component, metadata: NormalizedMetadata, source: str = "unknown"
) -> List[str]:
    """
    Apply NormalizedMetadata to a CycloneDX component.

    All values are sanitized before being applied to protect against injection attacks.

    Args:
        component: Component to enrich
        metadata: Normalized metadata to apply
        source: Data source name for audit trail

    Returns:
        List of added field names for logging
    """
    added_fields = []
    audit_trail = get_audit_trail()
    purl_str = str(component.purl) if component.purl else component.name

    # `Component.properties` / `.licenses` / `.external_references` can be
    # `None` on deserialised or user-constructed components. The enrichment
    # path below iterates/adds to all three, so normalise them up-front
    # rather than scattering `is None` guards across every branch. Plain
    # `set()` matches `_hash_enrichment/enricher.py` and avoids relying on
    # the transitive `sortedcontainers` default.
    if component.properties is None:
        component.properties = set()
    if component.licenses is None:
        component.licenses = set()
    if component.external_references is None:
        component.external_references = set()

    # Description (sanitized)
    if not component.description and metadata.description:
        sanitized_desc = sanitize_description(metadata.description)
        if sanitized_desc:
            component.description = sanitized_desc
            added_fields.append("description")

    # Licenses (sanitized) — marked as "declared" because enrichment pulls
    # the licence straight from the upstream registry (PyPI trove classifier,
    # package metadata, etc.), which is BSI §5.2.4's "original licence".
    has_licenses = component.licenses is not None and len(component.licenses) > 0
    if not has_licenses and metadata.licenses:
        sanitized_licenses: list[str] = [s for lic in metadata.licenses if (s := sanitize_license(lic)) is not None]
        if sanitized_licenses:
            if len(sanitized_licenses) == 1:
                license_expression = sanitized_licenses[0]
            else:
                license_expression = " OR ".join(sanitized_licenses)
            license_expr = LicenseExpression(
                value=license_expression,
                acknowledgement=LicenseAcknowledgement.DECLARED,
            )
            component.licenses.add(license_expr)
            added_fields.append("license")

    # Publisher - use maintainer_name (author), not supplier (distribution platform)
    if not component.publisher and metadata.maintainer_name:
        sanitized_publisher = sanitize_supplier(metadata.maintainer_name)
        if sanitized_publisher:
            component.publisher = sanitized_publisher
            added_fields.append("publisher")

    # Distribution filename (BSI TR-03183-2 §5.2.2 "Filename" requirement)
    if metadata.distribution_filename:
        sanitized_fn = metadata.distribution_filename.strip()
        if sanitized_fn:
            # Only add if not already present (avoid duplicates across enrichment runs)
            existing_filenames = {p.value for p in component.properties if p.name == "bsi:component:filename"}
            if sanitized_fn not in existing_filenames:
                filename_prop = Property(name="bsi:component:filename", value=sanitized_fn)
                component.properties.add(filename_prop)
                added_fields.append("filename")

    # BSI TR-03183-2 §5.2.2 derived properties: executable / archive / structured.
    # Derive sensible defaults from component type and distribution filename so
    # BSI-compliant SBOMs don't require every generator to emit these by hand.
    _added_bsi = _apply_bsi_derived_properties(component, metadata)
    added_fields.extend(_added_bsi)

    # Hashes (NTIA / BSI §5.2.2 / CISA "Component Hash"). Only add algorithms
    # we recognise and that aren't already on the component.
    if metadata.hashes:
        _added_hashes = _apply_component_hashes(component, metadata.hashes)
        added_fields.extend(_added_hashes)

    # Manufacturer - component creator with email for BSI TR-03183-2 compliance.
    # Uses maintainer_name + maintainer_email from PyPI author/author_email fields.
    # Only set if we have a valid email — BSI requires contact info, not just a name.
    if not component.manufacturer and metadata.maintainer_name and metadata.maintainer_email:
        sanitized_name = sanitize_supplier(metadata.maintainer_name)
        sanitized_email = sanitize_email(metadata.maintainer_email) if metadata.maintainer_email else None
        if sanitized_name and sanitized_email:
            contact = OrganizationalContact(name=sanitized_name, email=sanitized_email)
            component.manufacturer = OrganizationalEntity(name=sanitized_name, contacts=[contact])
            added_fields.append("manufacturer")

    # Supplier - use supplier (distribution platform like PyPI, npm, etc.)
    if not component.supplier and metadata.supplier:
        sanitized_supplier = sanitize_supplier(metadata.supplier)
        if sanitized_supplier:
            component.supplier = OrganizationalEntity(name=sanitized_supplier)
            added_fields.append("supplier")

    # External references helper (with URL sanitization)
    def _add_external_ref(ref_type: ExternalReferenceType, url: str, field_name: str = "url") -> bool:
        sanitized_url = sanitize_url(url, field_name=field_name) if url else None
        if sanitized_url:
            for existing in component.external_references:
                if existing.type == ref_type and str(existing.url) == sanitized_url:
                    return False
            component.external_references.add(ExternalReference(type=ref_type, url=XsUri(sanitized_url)))
            return True
        return False

    # Homepage (sanitized)
    if metadata.homepage:
        if _add_external_ref(ExternalReferenceType.WEBSITE, metadata.homepage, "homepage"):
            added_fields.append("homepage")

    # Repository (sanitized)
    if metadata.repository_url:
        if _add_external_ref(ExternalReferenceType.VCS, metadata.repository_url, "repository_url"):
            added_fields.append("repository")

    # Registry/Distribution (sanitized)
    if metadata.registry_url:
        if _add_external_ref(ExternalReferenceType.DISTRIBUTION, metadata.registry_url, "registry_url"):
            added_fields.append("distribution")

    # Issue tracker (sanitized)
    if metadata.issue_tracker_url:
        if _add_external_ref(ExternalReferenceType.ISSUE_TRACKER, metadata.issue_tracker_url, "issue_tracker_url"):
            added_fields.append("issue-tracker")

    # CLE (Common Lifecycle Enumeration) properties - ECMA-428
    def _add_cle_property(name: str, value: str) -> bool:
        """Add a CLE property if not already present."""
        for prop in component.properties:
            if prop.name == name:
                return False
        component.properties.add(Property(name=name, value=value))
        return True

    if metadata.cle_eos:
        if _add_cle_property("cdx:lifecycle:milestone:endOfSupport", metadata.cle_eos):
            added_fields.append("cdx:lifecycle:milestone:endOfSupport")

    if metadata.cle_eol:
        if _add_cle_property("cdx:lifecycle:milestone:endOfLife", metadata.cle_eol):
            added_fields.append("cdx:lifecycle:milestone:endOfLife")

    if metadata.cle_release_date:
        if _add_cle_property("cdx:lifecycle:milestone:generalAvailability", metadata.cle_release_date):
            added_fields.append("cdx:lifecycle:milestone:generalAvailability")

    # Record to audit trail if any fields were added
    if added_fields:
        audit_trail.record_component_enriched(purl_str, added_fields, source)

    return added_fields


def _is_spdx_license_empty(license_value: object) -> bool:
    """Check if an SPDX license field is empty or NOASSERTION."""
    if license_value is None:
        return True
    if isinstance(license_value, (SpdxNoAssertion, SpdxNone)):
        return True
    return False


def _apply_metadata_to_spdx_package(
    package: Package, metadata: NormalizedMetadata, source: str = "unknown"
) -> List[str]:
    """
    Apply NormalizedMetadata to an SPDX package.

    All values are sanitized before being applied to protect against injection attacks.

    Args:
        package: Package to enrich
        metadata: Normalized metadata to apply
        source: Data source name for audit trail

    Returns:
        List of added field names for logging
    """
    added_fields = []
    audit_trail = get_audit_trail()
    purl_str = package.spdx_id or package.name

    # Description (sanitized)
    if not package.description and metadata.description:
        sanitized_desc = sanitize_description(metadata.description)
        if sanitized_desc:
            package.description = sanitized_desc
            added_fields.append("description")

    # Homepage (sanitized)
    if not package.homepage and metadata.homepage:
        sanitized_homepage = sanitize_url(metadata.homepage, field_name="homepage")
        if sanitized_homepage:
            package.homepage = sanitized_homepage
            added_fields.append("homepage")

    # Download location (sanitized)
    if not package.download_location or package.download_location == "NOASSERTION":
        download_url = metadata.registry_url or metadata.download_url or metadata.repository_url
        sanitized_download = sanitize_url(download_url, field_name="download_location") if download_url else None
        if sanitized_download:
            package.download_location = sanitized_download
            added_fields.append("downloadLocation")

    # Checksums (NTIA / BSI §5.2.2 / CISA "Component Hash"). SPDX 2.x uses
    # package.checksums with a ChecksumAlgorithm enum.
    if metadata.hashes:
        _added_sums = _apply_spdx_checksums(package, metadata.hashes)
        added_fields.extend(_added_sums)

    # Licenses (sanitized) - use helper to avoid boolean evaluation of LicenseExpression
    if _is_spdx_license_empty(package.license_declared) and metadata.licenses:
        sanitized_licenses: list[str] = [s for lic in metadata.licenses if (s := sanitize_license(lic)) is not None]
        if sanitized_licenses:
            if len(sanitized_licenses) == 1:
                license_expression = sanitized_licenses[0]
            else:
                license_expression = " OR ".join(sanitized_licenses)

            license_parser = LicenseExpressionParser()
            try:
                parsed_expression = license_parser.parse_license_expression(license_expression)
                package.license_declared = parsed_expression
                added_fields.append(f"license_declared ({license_expression})")
            except Exception as e:
                logger.warning(f"Failed to parse license expression '{license_expression}': {e}")
                source = metadata.source or "enrichment"
                if package.license_comment:
                    package.license_comment += f" | Licenses from {source}: {license_expression}"
                else:
                    package.license_comment = f"Licenses from {source}: {license_expression}"
                added_fields.append(f"license_comment ({license_expression})")

    # Source info (sanitized)
    if not package.source_info and metadata.repository_url:
        sanitized_repo = sanitize_url(metadata.repository_url, field_name="repository_url")
        if sanitized_repo:
            package.source_info = f"acquired from {sanitized_repo}"
            added_fields.append("sourceInfo")

    # Originator (sanitized)
    if not package.originator and metadata.maintainer_name:
        sanitized_name = sanitize_supplier(metadata.maintainer_name)
        if sanitized_name:
            originator_str = sanitized_name
            if metadata.maintainer_email:
                sanitized_email = sanitize_email(metadata.maintainer_email)
                if sanitized_email:
                    originator_str += f" ({sanitized_email})"
            package.originator = Actor(ActorType.PERSON, originator_str)
            added_fields.append(f"originator ({sanitized_name})")

    # Supplier (sanitized)
    if not package.supplier and metadata.supplier:
        sanitized_supplier = sanitize_supplier(metadata.supplier)
        if sanitized_supplier:
            package.supplier = Actor(ActorType.ORGANIZATION, sanitized_supplier)
            added_fields.append(f"supplier ({sanitized_supplier})")

    # External references helper (with URL sanitization)
    def _add_external_ref(category: ExternalPackageRefCategory, ref_type: str, locator: str) -> bool:
        sanitized_locator = sanitize_url(locator) if locator else None
        if sanitized_locator:
            for existing in package.external_references:
                if existing.locator == sanitized_locator:
                    return False
            package.external_references.append(
                ExternalPackageRef(category=category, reference_type=ref_type, locator=sanitized_locator)
            )
            return True
        return False

    # Registry URL (sanitized)
    if metadata.registry_url:
        if _add_external_ref(ExternalPackageRefCategory.PACKAGE_MANAGER, "url", metadata.registry_url):
            added_fields.append("externalRef (registry)")

    # Documentation URL (sanitized)
    if metadata.documentation_url:
        if _add_external_ref(ExternalPackageRefCategory.OTHER, "url", metadata.documentation_url):
            added_fields.append("externalRef (documentation)")

    # Issue tracker URL (sanitized) - parity with CycloneDX
    if metadata.issue_tracker_url:
        if _add_external_ref(ExternalPackageRefCategory.OTHER, "issue-tracker", metadata.issue_tracker_url):
            added_fields.append("externalRef (issue-tracker)")

    # Repository/VCS URL as external reference (sanitized) - parity with CycloneDX
    # Note: CycloneDX adds repository_url as VCS external reference
    # In addition to source_info, we also add as external ref for tool interoperability
    if metadata.repository_url:
        if _add_external_ref(ExternalPackageRefCategory.OTHER, "vcs", metadata.repository_url):
            added_fields.append("externalRef (vcs)")

    # CycloneDX lifecycle milestone properties
    # For SPDX, we add lifecycle info to the package comment
    # See: https://cyclonedx.github.io/cyclonedx-property-taxonomy/cdx/lifecycle.html
    cle_parts = []
    if metadata.cle_eos:
        cle_parts.append(f"cdx:lifecycle:milestone:endOfSupport={metadata.cle_eos}")
    if metadata.cle_eol:
        cle_parts.append(f"cdx:lifecycle:milestone:endOfLife={metadata.cle_eol}")
    if metadata.cle_release_date:
        cle_parts.append(f"cdx:lifecycle:milestone:generalAvailability={metadata.cle_release_date}")

    if cle_parts:
        cle_comment = f"CLE lifecycle: {', '.join(cle_parts)}"
        if package.comment:
            # Only add if not already present
            if "CLE lifecycle:" not in package.comment:
                package.comment = f"{package.comment} | {cle_comment}"
                added_fields.append("comment (CLE)")
        else:
            package.comment = cle_comment
            added_fields.append("comment (CLE)")

    # Record to audit trail if any fields were added
    if added_fields:
        audit_trail.record_component_enriched(purl_str, added_fields, source)

    return added_fields


def _enrich_os_component(component: Component) -> List[str]:
    """Enrich an operating-system type component with supplier and lifecycle info."""
    if component.type.name.lower() != COMPONENT_TYPE_OPERATING_SYSTEM:
        return []

    added_fields = []
    os_name = component.name.lower() if component.name else ""
    os_version = component.version or ""

    # Add publisher/supplier if missing
    if not component.publisher:
        supplier = NAMESPACE_TO_SUPPLIER.get(os_name)
        if supplier:
            component.publisher = supplier
            added_fields.append(f"publisher ({supplier})")

    # Add CLE (Common Lifecycle Enumeration) properties
    if os_name and os_version:
        lifecycle = get_distro_lifecycle(os_name, os_version)
        if lifecycle:
            # Initialize properties set if needed
            if component.properties is None:
                component.properties = set()

            def _add_cle_property(name: str, value: str) -> bool:
                """Add a CLE property if not already present."""
                for prop in component.properties:
                    if prop.name == name:
                        return False
                component.properties.add(Property(name=name, value=value))
                return True

            if release_date := lifecycle.get("release_date"):
                if _add_cle_property("cdx:lifecycle:milestone:generalAvailability", release_date):
                    added_fields.append(f"cdx:lifecycle:milestone:generalAvailability ({release_date})")

            if end_of_support := lifecycle.get("end_of_support"):
                if _add_cle_property("cdx:lifecycle:milestone:endOfSupport", end_of_support):
                    added_fields.append(f"cdx:lifecycle:milestone:endOfSupport ({end_of_support})")

            if end_of_life := lifecycle.get("end_of_life"):
                if _add_cle_property("cdx:lifecycle:milestone:endOfLife", end_of_life):
                    added_fields.append(f"cdx:lifecycle:milestone:endOfLife ({end_of_life})")

    return added_fields


def _enrich_self_referencing_components(bom: Bom) -> int:
    """
    Enrich self-referencing components (project's own package in dependencies).

    When a project scans itself, it may include its own package as a dependency.
    Since this package won't be found in external registries (it's the project
    being built), we inherit supplier from the root component metadata.

    Args:
        bom: Bom object to check and enrich

    Returns:
        Number of components enriched
    """
    if not bom.metadata.component:
        return 0

    root_name = bom.metadata.component.name
    if not root_name:
        return 0

    # Get supplier from root component or BOM metadata
    root_supplier = None
    if bom.metadata.component.supplier:
        root_supplier = bom.metadata.component.supplier
    elif bom.metadata.supplier:
        root_supplier = bom.metadata.supplier

    if not root_supplier:
        return 0

    # Get supplier name for publisher field
    supplier_name = root_supplier.name if hasattr(root_supplier, "name") else str(root_supplier)
    if not supplier_name:
        return 0

    enriched_count = 0
    for component in bom.components:
        # Check if component name matches root component (self-referencing)
        if component.name == root_name and not component.publisher:
            component.publisher = supplier_name
            _add_enrichment_source_property(component, "root-component")
            logger.info(f"Enriched self-referencing component: {component.name} with publisher: {supplier_name}")
            enriched_count += 1

    return enriched_count


def _enrich_self_referencing_packages(document: Document) -> int:
    """
    Enrich self-referencing packages in SPDX (project's own package in dependencies).

    Args:
        document: SPDX Document to check and enrich

    Returns:
        Number of packages enriched
    """
    if not document.packages:
        return 0

    # First package is usually the main/root package
    main_package = document.packages[0]
    root_name = main_package.name
    if not root_name:
        return 0

    # Get supplier from main package
    root_supplier = main_package.supplier
    if not root_supplier or isinstance(root_supplier, (SpdxNoAssertion, SpdxNone)):
        return 0

    enriched_count = 0
    for package in document.packages[1:]:  # Skip first (main) package
        # Check if package name matches root package (self-referencing)
        if package.name == root_name:
            if not package.supplier or isinstance(package.supplier, (SpdxNoAssertion, SpdxNone)):
                package.supplier = root_supplier
                _add_enrichment_source_comment(package, "root-package")
                logger.info(f"Enriched self-referencing package: {package.name}")
                enriched_count += 1

    return enriched_count


def _enrich_spdx_os_packages(document: Document) -> Dict[str, int]:
    """
    Enrich OS packages in SPDX with lifecycle data (parity with CycloneDX).

    For SPDX, we detect OS packages via:
    1. primaryPackagePurpose == "OPERATING-SYSTEM" (Trivy uses this)
    2. Parsing document name for distro:version patterns (Syft fallback)

    Lifecycle data is added to the package comment since SPDX doesn't have
    properties like CycloneDX.

    Args:
        document: SPDX Document to enrich

    Returns:
        Enrichment statistics
    """
    import re

    stats = {"os_packages_enriched": 0, "lifecycle_added": 0}

    if not document.packages:
        return stats

    # First, try to find OS package by primaryPackagePurpose
    os_package = None
    os_name = None
    os_version = None

    for pkg in document.packages:
        # Check for OPERATING_SYSTEM purpose (Trivy)
        purpose = getattr(pkg, "primary_package_purpose", None)
        if purpose and purpose.name == "OPERATING_SYSTEM":
            os_package = pkg
            os_name = pkg.name.lower() if pkg.name else ""
            os_version = pkg.version if pkg.version else ""
            break

    # Fallback: parse document name for Syft-style "distro:version" patterns
    doc_name_attr = getattr(document.creation_info, "name", None) if document.creation_info else None
    if not os_package and doc_name_attr:
        # Match patterns like "debian", "alpine", "ubuntu" in document name
        doc_name = doc_name_attr.lower()
        known_distros = [
            "alpine",
            "debian",
            "ubuntu",
            "fedora",
            "centos",
            "rocky",
            "alma",
            "amazon",
            "oracle",
            "opensuse",
        ]
        for distro in known_distros:
            if distro in doc_name:
                # Try to find a container package with matching name
                for pkg in document.packages:
                    purpose = getattr(pkg, "primary_package_purpose", None)
                    if purpose and purpose.name == "CONTAINER":
                        # Parse "debian:12-slim" or "alpine:3.20" from package name
                        pkg_name = pkg.name or ""
                        match = re.match(r"([a-zA-Z-]+):?(\d+\.?\d*)?", pkg_name)
                        if match:
                            os_name = match.group(1).lower()
                            # Try to get version from versionInfo or parse from name
                            if pkg.version:
                                # Clean version: "12-slim" -> "12", "3.20.8" -> "3.20.8"
                                version_match = re.match(r"(\d+\.?\d*\.?\d*)", pkg.version)
                                os_version = version_match.group(1) if version_match else pkg.version
                            elif match.group(2):
                                os_version = match.group(2)
                            os_package = pkg
                            break
                break

    if not os_name:
        return stats

    # Get lifecycle data
    lifecycle = get_distro_lifecycle(os_name, os_version or "")
    if not lifecycle:
        logger.debug(f"No lifecycle data found for {os_name} {os_version}")
        return stats

    stats["os_packages_enriched"] = 1

    # Build lifecycle comment
    lifecycle_parts = []
    if lifecycle.get("release_date"):
        lifecycle_parts.append(f"cdx:lifecycle:milestone:generalAvailability={lifecycle['release_date']}")
    if lifecycle.get("end_of_support"):
        lifecycle_parts.append(f"cdx:lifecycle:milestone:endOfSupport={lifecycle['end_of_support']}")
    if lifecycle.get("end_of_life"):
        lifecycle_parts.append(f"cdx:lifecycle:milestone:endOfLife={lifecycle['end_of_life']}")

    if lifecycle_parts:
        lifecycle_comment = COMMENT_DELIMITER.join(lifecycle_parts)

        # Add to OS package comment if we found one
        if os_package:
            existing_comment = os_package.comment or ""
            if lifecycle_comment not in existing_comment:
                if existing_comment:
                    os_package.comment = f"{existing_comment}{COMMENT_DELIMITER}{lifecycle_comment}"
                else:
                    os_package.comment = lifecycle_comment
                stats["lifecycle_added"] = 1
                logger.info(f"Added lifecycle data to {os_name} {os_version}: {lifecycle_comment}")

    return stats


def _enrich_cyclonedx_bom_with_plugin_architecture(bom: Bom, enricher: Enricher) -> Dict[str, Any]:
    """
    Enrich CycloneDX BOM using the plugin architecture.

    Args:
        bom: Bom object to enrich (modified in place)
        enricher: Enricher instance with configured sources

    Returns:
        Enrichment statistics
    """
    sources: Dict[str, int] = {}
    stats: Dict[str, Any] = {
        "components_enriched": 0,
        "descriptions_added": 0,
        "licenses_added": 0,
        "publishers_added": 0,
        "homepages_added": 0,
        "repositories_added": 0,
        "distributions_added": 0,
        "issue_trackers_added": 0,
        "os_components_enriched": 0,
        "sources": sources,
    }

    total_components = len(bom.components)
    progress_interval = max(1, total_components // 4)  # Report progress at 25%, 50%, 75%

    for idx, component in enumerate(bom.components):
        # Log progress at intervals (CI-friendly, no progress bars)
        if idx > 0 and idx % progress_interval == 0:
            logger.info(f"  Processed {idx}/{total_components} components...")
        added_fields: list[str] = []
        enrichment_source = None
        purl_str = str(component.purl) if component.purl else None

        # Handle OS type components
        if component.type.name.lower() == COMPONENT_TYPE_OPERATING_SYSTEM:
            added_fields = _enrich_os_component(component)
            if added_fields:
                enrichment_source = "purl"
                stats["os_components_enriched"] += 1
                stats["components_enriched"] += 1
                for field_name in added_fields:
                    if "publisher" in field_name:
                        stats["publishers_added"] += 1
                _add_enrichment_source_property(component, enrichment_source)
            continue

        # Use plugin architecture for components with PURLs
        if purl_str:
            metadata = enricher.fetch_metadata(purl_str, merge_results=True)
            if metadata and metadata.has_data():
                primary_source = metadata.source.split(", ")[0] if metadata.source else "unknown"
                added_fields = _apply_metadata_to_cyclonedx_component(component, metadata, source=primary_source)
                if added_fields:
                    enrichment_source = metadata.source
                    # Track by primary source
                    sources[primary_source] = sources.get(primary_source, 0) + 1

        if added_fields:
            stats["components_enriched"] += 1
            if enrichment_source:
                _add_enrichment_source_property(component, enrichment_source.split(", ")[0])
            for field_name in added_fields:
                if "description" in field_name:
                    stats["descriptions_added"] += 1
                elif "licenses" in field_name:
                    stats["licenses_added"] += 1
                elif "publisher" in field_name:
                    stats["publishers_added"] += 1
                elif "homepage" in field_name or "tracker" in field_name:
                    stats["homepages_added"] += 1
                elif "repository" in field_name:
                    stats["repositories_added"] += 1
                elif "distribution" in field_name:
                    stats["distributions_added"] += 1
                elif "issue-tracker" in field_name:
                    stats["issue_trackers_added"] += 1

    return stats


def _enrich_spdx_document_with_plugin_architecture(document: Document, enricher: Enricher) -> Dict[str, Any]:
    """
    Enrich SPDX document using the plugin architecture.

    Args:
        document: Document object to enrich (modified in place)
        enricher: Enricher instance with configured sources

    Returns:
        Enrichment statistics
    """
    sources: Dict[str, int] = {}
    stats: Dict[str, Any] = {
        "components_enriched": 0,
        "descriptions_added": 0,
        "licenses_added": 0,
        "homepages_added": 0,
        "originators_added": 0,
        "suppliers_added": 0,
        "source_info_added": 0,
        "external_refs_added": 0,
        "sources": sources,
    }

    total_packages = len(document.packages)
    progress_interval = max(1, total_packages // 4)  # Report progress at 25%, 50%, 75%

    for idx, package in enumerate(document.packages):
        # Log progress at intervals (CI-friendly, no progress bars)
        if idx > 0 and idx % progress_interval == 0:
            logger.info(f"  Processed {idx}/{total_packages} packages...")
        added_fields: list[str] = []
        enrichment_source = None

        # Find PURL in external references
        purl_str = None
        for ref in package.external_references:
            if ref.reference_type == "purl":
                purl_str = ref.locator
                break

        if purl_str:
            metadata = enricher.fetch_metadata(purl_str, merge_results=True)
            if metadata and metadata.has_data():
                primary_source = metadata.source.split(", ")[0] if metadata.source else "unknown"
                added_fields = _apply_metadata_to_spdx_package(package, metadata, source=primary_source)
                if added_fields:
                    enrichment_source = metadata.source
                    sources[primary_source] = sources.get(primary_source, 0) + 1

        if added_fields:
            stats["components_enriched"] += 1
            if enrichment_source:
                _add_enrichment_source_comment(package, enrichment_source.split(", ")[0])
            for field_name in added_fields:
                if "description" in field_name:
                    stats["descriptions_added"] += 1
                elif "license_declared" in field_name or "license_comment" in field_name:
                    stats["licenses_added"] += 1
                elif "homepage" in field_name:
                    stats["homepages_added"] += 1
                elif "originator" in field_name:
                    stats["originators_added"] += 1
                elif "supplier" in field_name:
                    stats["suppliers_added"] += 1
                elif "sourceInfo" in field_name:
                    stats["source_info_added"] += 1
                elif "externalRef" in field_name:
                    stats["external_refs_added"] += 1

    return stats


def _enrich_spdx3_sbom(input_path: Path, output_path: Path, enricher: Enricher) -> None:
    """Enrich an SPDX 3 SBOM using Payload model objects."""
    from .spdx3 import (
        ExternalReference as Spdx3ExtRef,
    )
    from .spdx3 import (
        ExternalReferenceType as Spdx3ExtRefType,
    )
    from .spdx3 import (
        Organization as Spdx3Org,
    )
    from .spdx3 import (
        get_spdx3_document,
        get_spdx3_packages,
        make_spdx3_creation_info,
        make_spdx3_spdx_id,
        parse_spdx3_file,
        spdx3_license_from_string,
        write_spdx3_file,
    )

    logger.info("Processing SPDX 3 SBOM")

    try:
        payload = parse_spdx3_file(str(input_path))
    except Exception as e:
        raise SBOMValidationError(f"Failed to parse SPDX 3 SBOM: {e}") from e

    packages = get_spdx3_packages(payload)
    if not packages:
        logger.warning("No packages found in SPDX 3 SBOM, skipping enrichment")
        write_spdx3_file(payload, str(output_path))
        return

    logger.info(f"Found {len(packages)} packages to enrich")

    spdx3_sources: Dict[str, int] = {}
    stats: Dict[str, Any] = {
        "components_enriched": 0,
        "descriptions_added": 0,
        "licenses_added": 0,
        "homepages_added": 0,
        "suppliers_added": 0,
        "external_refs_added": 0,
        "sources": spdx3_sources,
    }

    doc = get_spdx3_document(payload)

    for package in packages:
        purl_str = package.package_url
        if not purl_str:
            continue

        metadata = enricher.fetch_metadata(purl_str, merge_results=True)
        if not metadata or not metadata.has_data():
            continue

        added_fields: list[str] = []
        primary_source = metadata.source.split(", ")[0] if metadata.source else "unknown"

        # Description
        if metadata.description and not package.description:
            desc = sanitize_description(metadata.description)
            if desc:
                package.description = desc
                added_fields.append("description")

        # Homepage
        if metadata.homepage and not package.homepage:
            hp = sanitize_url(metadata.homepage)
            if hp:
                package.homepage = hp
                added_fields.append("homepage")

        # Download location
        if metadata.download_url and not package.download_location:
            dl = sanitize_url(metadata.download_url)
            if dl:
                package.download_location = dl
                added_fields.append("download_location")

        # License
        if metadata.licenses and not package.declared_license:
            # Use first license
            license_str = metadata.licenses[0] if metadata.licenses else None
            if license_str:
                lic = sanitize_license(license_str)
                if lic:
                    package.declared_license = spdx3_license_from_string(lic)
                    added_fields.append("declared_license")

        # Supplier
        if metadata.supplier and not package.supplied_by:
            supplier_name = sanitize_supplier(metadata.supplier)
            if supplier_name:
                org_id = make_spdx3_spdx_id()
                org = Spdx3Org(spdx_id=org_id, name=supplier_name, creation_info=make_spdx3_creation_info())
                payload.add_element(org)
                package.supplied_by = [org_id]
                if doc:
                    doc.element.append(org_id)
                added_fields.append("supplier")

        # Repository URL as VCS external reference
        if metadata.repository_url:
            repo = sanitize_url(metadata.repository_url)
            if repo:
                existing_locs = []
                for ref in package.external_reference:
                    existing_locs.extend(ref.locator)
                if repo not in existing_locs:
                    package.external_reference.append(
                        Spdx3ExtRef(
                            external_reference_type=Spdx3ExtRefType.VCS,
                            locator=[repo],
                        )
                    )
                    added_fields.append("externalRef_vcs")

        # Issue tracker
        if metadata.issue_tracker_url:
            issue_url = sanitize_url(metadata.issue_tracker_url)
            if issue_url:
                existing_locs = []
                for ref in package.external_reference:
                    existing_locs.extend(ref.locator)
                if issue_url not in existing_locs:
                    package.external_reference.append(
                        Spdx3ExtRef(
                            external_reference_type=Spdx3ExtRefType.ISSUE_TRACKER,
                            locator=[issue_url],
                        )
                    )
                    added_fields.append("externalRef_issue_tracker")

        if added_fields:
            stats["components_enriched"] += 1
            spdx3_sources[primary_source] = spdx3_sources.get(primary_source, 0) + 1
            for field_name in added_fields:
                if "description" in field_name:
                    stats["descriptions_added"] += 1
                elif "license" in field_name:
                    stats["licenses_added"] += 1
                elif "homepage" in field_name:
                    stats["homepages_added"] += 1
                elif "supplier" in field_name:
                    stats["suppliers_added"] += 1
                elif "externalRef" in field_name:
                    stats["external_refs_added"] += 1

    # Print summary
    from .console import print_enrichment_summary

    print_enrichment_summary(stats, len(packages))

    # Write output
    try:
        write_spdx3_file(payload, str(output_path))
        logger.info(f"Enriched SPDX 3 SBOM written to: {output_path}")
    except Exception as e:
        raise SBOMValidationError(f"Failed to write enriched SPDX 3 SBOM: {e}") from e


def enrich_sbom(input_file: str, output_file: str, validate: bool = True) -> None:
    """
    Enrich SBOM with metadata from multiple data sources using plugin architecture.

    This function uses the plugin-based enrichment system which queries
    data sources in priority order (lower number = higher priority):

    - Priority 1: LicenseDBSource - Pre-computed database with validated SPDX
      licenses for Linux distro packages (Alpine, Wolfi, Ubuntu, Rocky, Alma,
      CentOS, Fedora, Amazon Linux). Fastest and most accurate source.
    - Priority 10: Native sources (PyPI, pub.dev, crates.io, Debian Sources)
    - Priority 40: deps.dev (Google Open Source Insights)
    - Priority 45: ecosyste.ms (multi-ecosystem aggregator)
    - Priority 70: PURL-based extraction (for OS packages, no API)
    - Priority 75: ClearlyDefined (license and attribution data)
    - Priority 90: Repology (fallback, rate-limited)

    After enrichment, the output SBOM is validated against its JSON schema
    (when validate=True).

    Args:
        input_file: Path to input SBOM file
        output_file: Path to save enriched SBOM
        validate: Whether to validate the output SBOM (default: True)

    Raises:
        FileNotFoundError: If input file doesn't exist
        ValueError: If SBOM format is invalid
        SBOMValidationError: If output validation fails
        Exception: For other errors during enrichment
    """
    logger.info(f"Starting SBOM enrichment for: {input_file}")

    input_path = Path(input_file)
    output_path = Path(output_file)

    # Parse input file
    try:
        with open(input_path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Input SBOM file not found: {input_file}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in SBOM file: {e}")

    # Create enricher with default sources
    with Enricher() as enricher:
        # Log registered sources
        sources = enricher.registry.list_sources()
        logger.debug(f"Registered data sources: {[s['name'] for s in sources]}")

        from .spdx3 import is_spdx3

        if data.get("bomFormat") == "CycloneDX":
            _enrich_cyclonedx_sbom(data, input_path, output_path, enricher)
        elif is_spdx3(data):
            _enrich_spdx3_sbom(input_path, output_path, enricher)
        elif data.get("spdxVersion"):
            _enrich_spdx_sbom(input_path, output_path, enricher)
        else:
            raise ValueError("Neither CycloneDX nor SPDX format found in JSON file")

    # Validate the enriched SBOM
    if validate:
        validation_result = validate_sbom_file_auto(str(output_path))
        if validation_result.valid is None:
            fmt = format_display_name(validation_result.sbom_format)
            ver = validation_result.spec_version
            logger.warning(f"Enriched SBOM could not be validated ({fmt} {ver}): {validation_result.error_message}")
        elif not validation_result.valid:
            raise SBOMValidationError(f"Enriched SBOM failed validation: {validation_result.error_message}")
        else:
            fmt = format_display_name(validation_result.sbom_format)
            logger.info(f"Enriched SBOM validated: {fmt} {validation_result.spec_version}")


def _enrich_cyclonedx_sbom(data: Dict[str, Any], input_path: Path, output_path: Path, enricher: Enricher) -> None:
    """Enrich a CycloneDX SBOM."""
    logger.info("Processing CycloneDX SBOM")

    spec_version = data.get("specVersion")
    if spec_version is None:
        raise SBOMValidationError("CycloneDX SBOM is missing required 'specVersion' field")

    # Handle tools format conversion for 1.5+
    if "metadata" in data and "tools" in data["metadata"]:
        tools_data = data["metadata"]["tools"]
        if isinstance(tools_data, list):
            spec_parts = spec_version.split(".")
            major = int(spec_parts[0]) if len(spec_parts) > 0 else 1
            minor = int(spec_parts[1]) if len(spec_parts) > 1 else 0
            is_v15_or_later = (major > 1) or (major == 1 and minor >= 5)

            if is_v15_or_later:
                logger.debug("Converting tools from legacy array to components format")
                components = []
                for tool_data in tools_data:
                    component_data = tool_data.copy()
                    if "vendor" in component_data:
                        component_data["group"] = component_data.pop("vendor")
                    if "type" not in component_data:
                        component_data["type"] = "application"
                    components.append(component_data)
                data["metadata"]["tools"] = {"components": components, "services": []}

    # Sanitize invalid license IDs (e.g., Trivy puts non-SPDX IDs in license.id field)
    sanitize_cyclonedx_licenses(data)

    # Parse BOM
    try:
        bom = Bom.from_json(data)  # type: ignore[attr-defined]
    except Exception as e:
        raise SBOMValidationError(f"Failed to parse CycloneDX SBOM: {e}")

    # Enrich lockfile components (instead of removing them)
    lockfiles_enriched = _enrich_lockfile_components(bom)
    if lockfiles_enriched > 0:
        logger.info(f"Enriched {lockfiles_enriched} lockfile component(s)")

    # Extract components
    components = _extract_components_from_cyclonedx(bom)
    if not components:
        logger.warning("No components with PURLs found in SBOM, skipping enrichment")
        serialized = _sanitize_and_serialize_cyclonedx(bom, spec_version)
        with open(output_path, "w") as f:
            f.write(serialized)
        return

    logger.info(f"Found {len(components)} components to enrich")

    # Enrich using plugin architecture
    stats = _enrich_cyclonedx_bom_with_plugin_architecture(bom, enricher)

    # Enrich self-referencing components (project's own package in dependencies)
    self_ref_enriched = _enrich_self_referencing_components(bom)
    if self_ref_enriched > 0:
        stats["components_enriched"] += self_ref_enriched
        stats["publishers_added"] += self_ref_enriched

    # Print summary
    _log_cyclonedx_enrichment_summary(stats, len(components))

    # Write output
    try:
        serialized = _sanitize_and_serialize_cyclonedx(bom, spec_version)
        with open(output_path, "w") as f:
            f.write(serialized)
        logger.info(f"Enriched SBOM written to: {output_path}")
    except Exception as e:
        raise Exception(f"Failed to write enriched SBOM: {e}")


def _enrich_spdx_sbom(input_path: Path, output_path: Path, enricher: Enricher) -> None:
    """Enrich an SPDX SBOM."""
    logger.info("Processing SPDX SBOM")

    try:
        document = spdx_parse_file(str(input_path))
    except Exception as e:
        raise SBOMValidationError(f"Failed to parse SPDX SBOM: {e}")

    # Enrich lockfile packages (instead of removing them)
    lockfiles_enriched = _enrich_lockfile_packages(document)
    if lockfiles_enriched > 0:
        logger.info(f"Enriched {lockfiles_enriched} lockfile package(s)")

    # Extract packages
    packages = _extract_packages_from_spdx(document)
    if not packages:
        logger.warning("No packages with PURLs found in SBOM, skipping enrichment")
        spdx_write_file(document, str(output_path), validate=False)
        sanitize_spdx_json_file(str(output_path))
        restore_spdx_document_describes(str(output_path))
        return

    logger.info(f"Found {len(packages)} packages to enrich")

    # Enrich using plugin architecture
    stats = _enrich_spdx_document_with_plugin_architecture(document, enricher)

    # Enrich self-referencing packages (project's own package in dependencies)
    self_ref_enriched = _enrich_self_referencing_packages(document)
    if self_ref_enriched > 0:
        stats["components_enriched"] += self_ref_enriched
        stats["suppliers_added"] += self_ref_enriched

    # Enrich OS packages with lifecycle data (parity with CycloneDX)
    os_stats = _enrich_spdx_os_packages(document)
    if os_stats.get("lifecycle_added", 0) > 0:
        stats["os_lifecycle_added"] = os_stats["lifecycle_added"]

    # Print summary
    _log_spdx_enrichment_summary(stats, len(packages))

    # Sanitize PURLs in external references before writing
    sanitize_spdx_purls(document)

    # Write output
    try:
        spdx_write_file(document, str(output_path), validate=False)
        sanitize_spdx_json_file(str(output_path))
        restore_spdx_document_describes(str(output_path))
        logger.info(f"Enriched SBOM written to: {output_path}")
    except Exception as e:
        raise Exception(f"Failed to write enriched SBOM: {e}")


def _log_cyclonedx_enrichment_summary(stats: Dict[str, Any], total_components: int) -> None:
    """Log enrichment summary for CycloneDX using Rich table."""
    from .console import print_enrichment_summary

    print_enrichment_summary(stats, total_components)


def _log_spdx_enrichment_summary(stats: Dict[str, Any], total_packages: int) -> None:
    """Log enrichment summary for SPDX using Rich table."""
    from .console import print_enrichment_summary

    print_enrichment_summary(stats, total_packages)
