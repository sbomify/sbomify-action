"""Dependency expansion orchestration for SBOMs."""

import json
import re
from pathlib import Path
from typing import Any

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from packageurl import PackageURL

from ..console import get_audit_trail
from ..logging_config import logger
from ..serialization import serialize_cyclonedx_bom
from ..spdx3 import is_spdx3
from .expanders.pipdeptree import PipdeptreeExpander
from .models import DiscoveredDependency, ExpansionResult, normalize_python_package_name
from .registry import ExpanderRegistry


def _count_sbom_packages(sbom_data: dict[str, Any]) -> int:
    """Count packages in any SBOM format (CycloneDX, SPDX 2.x, SPDX 3)."""
    if sbom_data.get("bomFormat") == "CycloneDX":
        return len(sbom_data.get("components") or [])
    if sbom_data.get("spdxVersion"):
        return len(sbom_data.get("packages") or [])
    if is_spdx3(sbom_data):
        return sum(
            1
            for e in sbom_data.get("@graph", [])
            if isinstance(e, dict) and (e.get("type") or e.get("@type", "")) in ("software_Package", "Package")
        )
    return 0


def create_default_registry() -> ExpanderRegistry:
    """Create registry with default expanders."""
    registry = ExpanderRegistry()
    registry.register(PipdeptreeExpander())
    return registry


class DependencyEnricher:
    """Orchestrates dependency expansion for SBOMs.

    Uses registered expanders to discover transitive dependencies
    and adds them to the SBOM. Records all additions to the audit trail.
    """

    def __init__(self, registry: ExpanderRegistry | None = None) -> None:
        self._registry = registry or create_default_registry()

    def expand_sbom(
        self,
        sbom_file: str,
        lock_file: str,
    ) -> ExpansionResult:
        """Expand SBOM with discovered transitive dependencies.

        Args:
            sbom_file: Path to SBOM file (modified in place)
            lock_file: Path to lockfile that was used for generation

        Returns:
            ExpansionResult with statistics
        """
        sbom_path = Path(sbom_file)
        lock_path = Path(lock_file)

        # Load SBOM early so we can report accurate original_count
        # even when no transitive dependencies are discovered or
        # expansion is skipped entirely.
        with sbom_path.open("r") as f:
            sbom_data = json.load(f)

        # Find applicable expander
        expander = self._registry.get_expander_for(lock_path)
        if not expander:
            logger.debug(f"No expander supports {lock_path.name}")
            return ExpansionResult(
                original_count=_count_sbom_packages(sbom_data),
                discovered_count=0,
                added_count=0,
                dependencies=[],
                source="none",
            )

        # Check if expansion is possible
        if not expander.can_expand():
            logger.info(
                f"Dependency expansion skipped: {expander.name} cannot run "
                "(packages may not be installed in environment)"
            )
            return ExpansionResult(
                original_count=_count_sbom_packages(sbom_data),
                discovered_count=0,
                added_count=0,
                dependencies=[],
                source=expander.name,
            )

        # Discover transitive dependencies
        logger.info(f"Discovering transitive dependencies with {expander.name}...")
        discovered = expander.expand(lock_path)

        if not discovered:
            logger.info("No transitive dependencies discovered")
            return ExpansionResult(
                original_count=_count_sbom_packages(sbom_data),
                discovered_count=0,
                added_count=0,
                dependencies=[],
                source=expander.name,
            )

        if sbom_data.get("bomFormat") == "CycloneDX":
            result = self._enrich_cyclonedx(sbom_path, sbom_data, discovered, expander.name)
        elif sbom_data.get("spdxVersion"):
            result = self._enrich_spdx(sbom_path, sbom_data, discovered, expander.name)
        elif is_spdx3(sbom_data):
            # SPDX 3 dependency expansion - pass through for now
            logger.debug("SPDX 3 dependency expansion: skipping (not yet supported)")
            result = ExpansionResult(
                original_count=_count_sbom_packages(sbom_data),
                discovered_count=len(discovered),
                added_count=0,
                dependencies=discovered,
                source=expander.name,
            )
        else:
            logger.warning("Unknown SBOM format, skipping dependency expansion")
            result = ExpansionResult(
                original_count=_count_sbom_packages(sbom_data),
                discovered_count=len(discovered),
                added_count=0,
                dependencies=discovered,
                source=expander.name,
            )

        return result

    def _enrich_cyclonedx(
        self,
        sbom_path: Path,
        sbom_data: dict[str, Any],
        discovered: list[DiscoveredDependency],
        source: str,
    ) -> ExpansionResult:
        """Add discovered dependencies to CycloneDX SBOM."""
        bom = Bom.from_json(sbom_data)  # type: ignore[attr-defined]
        original_count = len(bom.components) if bom.components else 0

        # Ensure components collection is initialized in case Bom.from_json
        # yields a Bom with components=None for unusual input.
        if bom.components is None:
            bom.components = type(Bom().components)()

        # Build set of existing PURLs for deduplication
        existing_purls: set[str] = set()
        for comp in bom.components:
            if comp.purl:
                existing_purls.add(str(comp.purl).lower())

        # Add new components
        added_count = 0
        audit = get_audit_trail()

        for dep in discovered:
            # Skip if already exists
            if dep.purl.lower() in existing_purls:
                continue

            # Create new component
            try:
                purl_obj = PackageURL.from_string(dep.purl)
            except Exception as e:
                logger.warning(f"Invalid PURL {dep.purl}: {e}")
                continue

            component = Component(
                type=ComponentType.LIBRARY,
                name=dep.name,
                version=dep.version,
                purl=purl_obj,
            )

            bom.components.add(component)
            added_count += 1

            # Record to audit trail
            parent_info = f"discovered via {dep.parent}" if dep.parent else "discovered as transitive"
            audit.record_enrichment(
                component=dep.purl,
                field="transitive_dependency",
                value=parent_info,
                source=source,
            )

        # Serialize back
        spec_version = sbom_data.get("specVersion", "1.6")
        serialized = serialize_cyclonedx_bom(bom, spec_version)
        with sbom_path.open("w") as f:
            f.write(serialized)

        logger.info(
            f"Dependency expansion: added {added_count} transitive dependencies "
            f"(discovered {len(discovered)}, {original_count} original)"
        )

        return ExpansionResult(
            original_count=original_count,
            discovered_count=len(discovered),
            added_count=added_count,
            dependencies=discovered,
            source=source,
        )

    def _enrich_spdx(
        self,
        sbom_path: Path,
        sbom_data: dict[str, Any],
        discovered: list[DiscoveredDependency],
        source: str,
    ) -> ExpansionResult:
        """Add discovered dependencies to SPDX SBOM."""
        packages = sbom_data.get("packages", [])
        original_count = len(packages)

        # Build set of existing package identifiers (normalized for comparison)
        existing: set[str] = set()
        existing_spdx_ids: set[str] = set()
        for pkg in packages:
            name = pkg.get("name", "")
            version = pkg.get("versionInfo", "")
            normalized = normalize_python_package_name(name)
            existing.add(f"{normalized}@{version}")
            if pkg.get("SPDXID"):
                existing_spdx_ids.add(pkg["SPDXID"])

        # Build a name→SPDXID lookup for existing packages so we can create
        # DEPENDENCY_OF relationships from new packages to their parents.
        name_to_spdx_id: dict[str, str] = {}
        for pkg in packages:
            normalized = normalize_python_package_name(pkg.get("name", ""))
            if pkg.get("SPDXID"):
                name_to_spdx_id[normalized] = pkg["SPDXID"]

        # Determine the document SPDXID for DESCRIBES relationships
        doc_spdx_id = sbom_data.get("SPDXID", "SPDXRef-DOCUMENT")

        relationships = sbom_data.get("relationships", [])

        # Add new packages
        added_count = 0
        audit = get_audit_trail()

        for dep in discovered:
            normalized_name = normalize_python_package_name(dep.name)
            key = f"{normalized_name}@{dep.version}"
            if key in existing:
                continue

            # Create new SPDX package
            # Generate a unique SPDXID. SPDX IDs must contain only letters, numbers,
            # dots, and hyphens. Any character outside [a-zA-Z0-9.-] (e.g. `+` from
            # PEP 440 local versions, `_`, `~`) is replaced with a hyphen.
            # Collision handling below ensures uniqueness within this document.
            safe_name = re.sub(r"[^a-zA-Z0-9.\-]", "-", dep.name)
            safe_version = re.sub(r"[^a-zA-Z0-9.\-]", "-", dep.version)
            base_spdx_id = f"SPDXRef-Package-{safe_name}-{safe_version}"

            # Handle potential collisions by adding a suffix
            spdx_id = base_spdx_id
            suffix = 1
            while spdx_id in existing_spdx_ids:
                spdx_id = f"{base_spdx_id}-{suffix}"
                suffix += 1
            existing_spdx_ids.add(spdx_id)

            new_package = {
                "SPDXID": spdx_id,
                "name": dep.name,
                "versionInfo": dep.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": dep.purl,
                    }
                ],
            }

            packages.append(new_package)
            added_count += 1

            # Track for parent lookups
            name_to_spdx_id[normalized_name] = spdx_id

            # Add DESCRIBES relationship from document to new package
            relationships.append(
                {
                    "spdxElementId": doc_spdx_id,
                    "relatedSpdxElement": spdx_id,
                    "relationshipType": "DESCRIBES",
                }
            )

            # Add DEPENDENCY_OF relationship if we know the parent
            if dep.parent:
                parent_normalized = normalize_python_package_name(dep.parent)
                parent_spdx_id = name_to_spdx_id.get(parent_normalized)
                if parent_spdx_id:
                    relationships.append(
                        {
                            "spdxElementId": spdx_id,
                            "relatedSpdxElement": parent_spdx_id,
                            "relationshipType": "DEPENDENCY_OF",
                        }
                    )

            # Record to audit trail
            parent_info = f"discovered via {dep.parent}" if dep.parent else "discovered as transitive"
            audit.record_enrichment(
                component=dep.purl,
                field="transitive_dependency",
                value=parent_info,
                source=source,
            )

        sbom_data["packages"] = packages
        sbom_data["relationships"] = relationships

        # Write back
        with sbom_path.open("w") as f:
            json.dump(sbom_data, f, indent=2)

        logger.info(
            f"Dependency expansion: added {added_count} transitive dependencies "
            f"(discovered {len(discovered)}, {original_count} original)"
        )

        return ExpansionResult(
            original_count=original_count,
            discovered_count=len(discovered),
            added_count=added_count,
            dependencies=discovered,
            source=source,
        )


def expand_sbom_dependencies(
    sbom_file: str,
    lock_file: str,
) -> ExpansionResult:
    """Expand SBOM with transitive dependencies from installed packages.

    This is the main public API for dependency expansion.

    Args:
        sbom_file: Path to SBOM file (modified in place)
        lock_file: Path to lockfile used for generation

    Returns:
        ExpansionResult with statistics
    """
    enricher = DependencyEnricher()
    return enricher.expand_sbom(sbom_file, lock_file)


def supports_dependency_expansion(lock_file: str) -> bool:
    """Check if dependency expansion is supported for this lockfile.

    Uses the registry to check if any expander supports the lockfile type.

    Args:
        lock_file: Path to lockfile

    Returns:
        True if an expander supports this lockfile type
    """
    registry = create_default_registry()
    expander = registry.get_expander_for(Path(lock_file))
    return expander is not None
