"""Hash enrichment orchestration for SBOMs."""

import json
from pathlib import Path
from typing import Any

from cyclonedx.model import HashAlgorithm as CdxHashAlgorithm
from cyclonedx.model import HashType
from cyclonedx.model.bom import Bom

from ..console import get_audit_trail
from ..logging_config import logger
from ..serialization import serialize_cyclonedx_bom
from ..spdx3 import is_spdx3
from .models import HashAlgorithm, PackageHash, normalize_package_name
from .parsers import (
    CargoLockParser,
    PackageLockParser,
    PipfileLockParser,
    PnpmLockParser,
    PoetryLockParser,
    PubspecLockParser,
    UvLockParser,
    YarnLockParser,
)
from .registry import ParserRegistry


def create_default_registry() -> ParserRegistry:
    """Create registry with all default parsers."""
    registry = ParserRegistry()

    # Python parsers
    registry.register(UvLockParser())
    registry.register(PipfileLockParser())
    registry.register(PoetryLockParser())

    # Rust
    registry.register(CargoLockParser())

    # Dart
    registry.register(PubspecLockParser())

    # JavaScript/Node.js
    registry.register(PackageLockParser())
    registry.register(YarnLockParser())
    registry.register(PnpmLockParser())

    return registry


# Mapping from our HashAlgorithm to CycloneDX HashAlgorithm
_CDX_ALG_MAP = {
    HashAlgorithm.MD5: CdxHashAlgorithm.MD5,
    HashAlgorithm.SHA1: CdxHashAlgorithm.SHA_1,
    HashAlgorithm.SHA256: CdxHashAlgorithm.SHA_256,
    HashAlgorithm.SHA384: CdxHashAlgorithm.SHA_384,
    HashAlgorithm.SHA512: CdxHashAlgorithm.SHA_512,
    HashAlgorithm.SHA3_256: CdxHashAlgorithm.SHA3_256,
    HashAlgorithm.SHA3_384: CdxHashAlgorithm.SHA3_384,
    HashAlgorithm.SHA3_512: CdxHashAlgorithm.SHA3_512,
    HashAlgorithm.BLAKE2B_256: CdxHashAlgorithm.BLAKE2B_256,
    HashAlgorithm.BLAKE2B_384: CdxHashAlgorithm.BLAKE2B_384,
    HashAlgorithm.BLAKE2B_512: CdxHashAlgorithm.BLAKE2B_512,
    HashAlgorithm.BLAKE3: CdxHashAlgorithm.BLAKE3,
}


class HashEnricher:
    """Orchestrates hash enrichment from lockfiles to SBOMs."""

    def __init__(self, registry: ParserRegistry | None = None) -> None:
        self._registry = registry or create_default_registry()

    def enrich_cyclonedx(
        self,
        bom: Bom,
        lock_file_path: Path,
        overwrite_existing: bool = False,
    ) -> dict[str, int]:
        """Enrich CycloneDX BOM components with hashes from lockfile.

        Args:
            bom: CycloneDX BOM to enrich (modified in place)
            lock_file_path: Path to the lockfile
            overwrite_existing: If True, replace existing hashes

        Returns:
            Statistics dict with enrichment results.
        """
        stats = {
            "lockfile_packages": 0,
            "sbom_components": 0,
            "components_matched": 0,
            "hashes_added": 0,
            "hashes_skipped": 0,
        }

        # Parse lockfile
        lockfile_hashes = self._registry.parse_lockfile(lock_file_path)
        stats["lockfile_packages"] = len(set((h.name, h.version) for h in lockfile_hashes))

        if not lockfile_hashes:
            logger.debug("No hashes found in lockfile")
            return stats

        # Build lookup table by normalized (name, version)
        parser = self._registry.get_parser_for(lock_file_path.name)
        ecosystem = parser.ecosystem if parser else "unknown"
        hash_lookup = self._build_hash_lookup(lockfile_hashes, ecosystem)

        # Process components
        if not bom.components:
            return stats

        stats["sbom_components"] = len(bom.components)

        for component in bom.components:
            if not component.name or not component.version:
                continue

            # Try to match component to lockfile hashes
            normalized_name = normalize_package_name(component.name, ecosystem)
            key = (normalized_name, component.version)

            pkg_hashes = hash_lookup.get(key)
            if not pkg_hashes:
                continue

            stats["components_matched"] += 1

            # Check if component already has hashes
            if component.hashes and not overwrite_existing:
                stats["hashes_skipped"] += len(pkg_hashes)
                continue

            # Add hashes to component
            if overwrite_existing:
                component.hashes = set()

            for pkg_hash in pkg_hashes:
                cdx_alg = _CDX_ALG_MAP.get(pkg_hash.algorithm)
                if cdx_alg is None:
                    continue

                # Check if this exact hash already exists
                existing = any(h.alg == cdx_alg and h.content == pkg_hash.value for h in (component.hashes or []))
                if existing:
                    stats["hashes_skipped"] += 1
                    continue

                hash_type = HashType(alg=cdx_alg, content=pkg_hash.value)
                if component.hashes is None:
                    component.hashes = set()
                component.hashes.add(hash_type)
                stats["hashes_added"] += 1

                # Record to audit trail
                audit = get_audit_trail()
                component_id = component.purl or f"{component.name}@{component.version}"
                audit.record_hash_added(str(component_id), pkg_hash.algorithm.value, source="lockfile")

        return stats

    def enrich_spdx(
        self,
        spdx_data: dict[str, Any],
        lock_file_path: Path,
        overwrite_existing: bool = False,
    ) -> dict[str, int]:
        """Enrich SPDX document packages with checksums from lockfile.

        Args:
            spdx_data: SPDX JSON dict to enrich (modified in place)
            lock_file_path: Path to the lockfile
            overwrite_existing: If True, replace existing checksums

        Returns:
            Statistics dict with enrichment results.
        """
        stats = {
            "lockfile_packages": 0,
            "sbom_components": 0,
            "components_matched": 0,
            "hashes_added": 0,
            "hashes_skipped": 0,
        }

        # Parse lockfile
        lockfile_hashes = self._registry.parse_lockfile(lock_file_path)
        stats["lockfile_packages"] = len(set((h.name, h.version) for h in lockfile_hashes))

        if not lockfile_hashes:
            logger.debug("No hashes found in lockfile")
            return stats

        # Build lookup table
        parser = self._registry.get_parser_for(lock_file_path.name)
        ecosystem = parser.ecosystem if parser else "unknown"
        hash_lookup = self._build_hash_lookup(lockfile_hashes, ecosystem)

        # Process packages
        packages = spdx_data.get("packages", [])
        stats["sbom_components"] = len(packages)

        for package in packages:
            name = package.get("name")
            version = package.get("versionInfo")

            if not name or not version:
                continue

            # Try to match package to lockfile hashes
            normalized_name = normalize_package_name(name, ecosystem)
            key = (normalized_name, version)

            pkg_hashes = hash_lookup.get(key)
            if not pkg_hashes:
                continue

            stats["components_matched"] += 1

            # Check if package already has checksums
            checksums = package.get("checksums", [])
            if checksums and not overwrite_existing:
                stats["hashes_skipped"] += len(pkg_hashes)
                continue

            # Add checksums to package
            if overwrite_existing:
                checksums = []

            for pkg_hash in pkg_hashes:
                spdx_alg = pkg_hash.algorithm.spdx_alg

                # Check if this exact checksum already exists
                existing = any(
                    c.get("algorithm") == spdx_alg and c.get("checksumValue") == pkg_hash.value for c in checksums
                )
                if existing:
                    stats["hashes_skipped"] += 1
                    continue

                checksums.append(
                    {
                        "algorithm": spdx_alg,
                        "checksumValue": pkg_hash.value,
                    }
                )
                stats["hashes_added"] += 1

                # Record to audit trail
                audit = get_audit_trail()
                component_id = package.get("SPDXID") or f"{name}@{version}"
                audit.record_hash_added(component_id, pkg_hash.algorithm.value, source="lockfile")

            package["checksums"] = checksums

        return stats

    def _build_hash_lookup(
        self,
        hashes: list[PackageHash],
        ecosystem: str,
    ) -> dict[tuple[str, str], list[PackageHash]]:
        """Build lookup table from list of hashes."""
        lookup: dict[tuple[str, str], list[PackageHash]] = {}

        for h in hashes:
            normalized_name = normalize_package_name(h.name, ecosystem)
            key = (normalized_name, h.version)

            if key not in lookup:
                lookup[key] = []
            lookup[key].append(h)

        return lookup


def enrich_sbom_with_hashes(
    sbom_file: str,
    lock_file: str,
    overwrite_existing: bool = False,
) -> dict[str, int]:
    """Enrich SBOM file with hashes extracted from lockfile.

    This is the main public API for hash enrichment.

    Args:
        sbom_file: Path to SBOM file (modified in place)
        lock_file: Path to lockfile to extract hashes from
        overwrite_existing: If True, replace existing hashes

    Returns:
        Statistics dict with:
        - lockfile_packages: Number of packages found in lockfile
        - sbom_components: Number of components in SBOM
        - components_matched: Number of components matched to lockfile
        - hashes_added: Number of hashes added
        - hashes_skipped: Number of hashes skipped (already present)
    """
    sbom_path = Path(sbom_file)
    lock_path = Path(lock_file)

    # Load SBOM
    with sbom_path.open("r") as f:
        sbom_data = json.load(f)

    enricher = HashEnricher()

    # Detect format and enrich
    if sbom_data.get("bomFormat") == "CycloneDX":
        # CycloneDX format
        bom = Bom.from_json(sbom_data)  # type: ignore[attr-defined]
        stats = enricher.enrich_cyclonedx(bom, lock_path, overwrite_existing)

        # Serialize back
        spec_version = sbom_data.get("specVersion", "1.6")
        serialized = serialize_cyclonedx_bom(bom, spec_version)
        with sbom_path.open("w") as f:
            f.write(serialized)

    elif sbom_data.get("spdxVersion"):
        # SPDX 2.x format
        stats = enricher.enrich_spdx(sbom_data, lock_path, overwrite_existing)

        # Write back
        with sbom_path.open("w") as f:
            json.dump(sbom_data, f, indent=2)

    elif is_spdx3(sbom_data):
        # SPDX 3 format - pass through without hash enrichment for now
        logger.debug("SPDX 3 hash enrichment: skipping (not yet supported)")
        return {
            "lockfile_packages": 0,
            "sbom_components": 0,
            "components_matched": 0,
            "hashes_added": 0,
            "hashes_skipped": 0,
        }

    else:
        logger.warning("Unknown SBOM format, skipping hash enrichment")
        return {
            "lockfile_packages": 0,
            "sbom_components": 0,
            "components_matched": 0,
            "hashes_added": 0,
            "hashes_skipped": 0,
        }

    logger.info(
        f"Hash enrichment: {stats['hashes_added']} hash(es) added to "
        f"{stats['components_matched']}/{stats['sbom_components']} component(s)"
    )

    return stats
