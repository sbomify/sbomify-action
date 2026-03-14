"""Parser for package-lock.json files (npm)."""

import json
from pathlib import Path
from typing import Any

from ..models import PackageHash


class PackageLockParser:
    """Parser for package-lock.json files.

    package-lock.json v2/v3 is a JSON file with structure:
    {
        "packages": {
            "node_modules/package-name": {
                "version": "1.2.3",
                "integrity": "sha512-base64hash..."
            }
        }
    }

    v1 uses "dependencies" instead of "packages".
    """

    name = "npm-package-lock"
    supported_files = ("package-lock.json",)
    ecosystem = "npm"

    def supports(self, lock_file_name: str) -> bool:
        return lock_file_name in self.supported_files

    def parse(self, lock_file_path: Path) -> list[PackageHash]:
        """Parse package-lock.json and extract hashes.

        Returns one hash per unique (name, version) combination.

        Args:
            lock_file_path: Path to package-lock.json file

        Returns:
            List of PackageHash objects (one per package@version).
        """
        with lock_file_path.open("r") as f:
            data = json.load(f)

        hashes: list[PackageHash] = []
        seen: set[tuple[str, str]] = set()  # (name, version)

        # Try v2/v3 format first (packages)
        packages = data.get("packages", {})
        if packages:
            for pkg_path, pkg_data in packages.items():
                if not pkg_path or not isinstance(pkg_data, dict):
                    continue

                # Skip the root package (empty path)
                if pkg_path == "":
                    continue

                # Extract package name from path (e.g., "node_modules/@scope/name")
                name = self._extract_package_name(pkg_path)
                if not name:
                    continue

                version = pkg_data.get("version")
                integrity = pkg_data.get("integrity")

                if not version or not integrity:
                    continue

                # Deduplicate by (name, version)
                key = (name, version)
                if key in seen:
                    continue
                seen.add(key)

                pkg_hash = PackageHash.from_sri(
                    name=name,
                    version=version,
                    sri_hash=integrity,
                    artifact_type="tarball",
                )
                if pkg_hash:
                    hashes.append(pkg_hash)

        # Fall back to v1 format (dependencies)
        if not hashes:
            dependencies = data.get("dependencies", {})
            hashes.extend(self._parse_dependencies(dependencies, seen=set()))

        return hashes

    def _extract_package_name(self, pkg_path: str) -> str | None:
        """Extract package name from node_modules path."""
        # Handle paths like "node_modules/@scope/name" or "node_modules/name"
        if not pkg_path.startswith("node_modules/"):
            return None

        name_part = pkg_path[len("node_modules/") :]

        # Handle nested node_modules (take the last one)
        if "node_modules/" in name_part:
            name_part = name_part.rsplit("node_modules/", 1)[-1]

        return name_part if name_part else None

    def _parse_dependencies(
        self, dependencies: dict[str, Any], seen: set[tuple[str, str]] | None = None
    ) -> list[PackageHash]:
        """Parse v1 format dependencies recursively.

        Deduplicates by (name, version) to avoid returning multiple hashes
        for the same package@version at different nesting levels.
        """
        if seen is None:
            seen = set()

        hashes: list[PackageHash] = []

        for name, pkg_data in dependencies.items():
            if not isinstance(pkg_data, dict):
                continue

            version = pkg_data.get("version")
            integrity = pkg_data.get("integrity")

            if version and integrity:
                # Deduplicate by (name, version)
                key = (name, version)
                if key not in seen:
                    seen.add(key)
                    pkg_hash = PackageHash.from_sri(
                        name=name,
                        version=version,
                        sri_hash=integrity,
                        artifact_type="tarball",
                    )
                    if pkg_hash:
                        hashes.append(pkg_hash)

            # Recurse into nested dependencies
            nested = pkg_data.get("dependencies", {})
            if nested:
                hashes.extend(self._parse_dependencies(nested, seen))

        return hashes
