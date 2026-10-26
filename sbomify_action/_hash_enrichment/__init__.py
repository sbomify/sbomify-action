"""Lockfile hash extraction and SBOM enrichment.

This module provides functionality to extract cryptographic hashes from
lockfiles and add them to SBOM components. It supports both CycloneDX
and SPDX formats.

Supported lockfile formats:
- Python: uv.lock, Pipfile.lock, poetry.lock
- Rust: Cargo.lock
- Dart: pubspec.lock
- JavaScript: package-lock.json, yarn.lock, pnpm-lock.yaml
- PlatformIO: platformio.ini (registry checksums for installed libraries)

Example usage:
    from sbomify_action._hash_enrichment import enrich_sbom_with_hashes

    stats = enrich_sbom_with_hashes(
        sbom_file="sbom.json",
        lock_file="uv.lock",
    )
    print(f"Added {stats['hashes_added']} hashes")
"""

from .enricher import HashEnricher, create_default_registry, enrich_sbom_with_hashes
from .models import HashAlgorithm, PackageHash, normalize_package_name
from .protocol import LockfileHashParser
from .registry import ParserRegistry

__all__ = [
    # Main API
    "enrich_sbom_with_hashes",
    # Classes for advanced usage
    "HashEnricher",
    "ParserRegistry",
    "LockfileHashParser",
    # Models
    "PackageHash",
    "HashAlgorithm",
    "normalize_package_name",
    # Factory
    "create_default_registry",
]
